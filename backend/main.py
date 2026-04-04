"""
Radiology Coach — FastAPI Backend
Production-grade REST API with JWT auth, PostgreSQL, and full CRUD for reports/papers.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import databases
import sqlalchemy
from sqlalchemy import (
    MetaData, Table, Column, Integer, String, Text,
    DateTime, ForeignKey, Boolean, func
)
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import httpx
import re

# ─── CONFIG ──────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/radiology_coach")
JWT_SECRET   = os.getenv("JWT_SECRET", "change-this-in-production-use-256bit-random-string")
JWT_ALGO     = "HS256"
JWT_EXPIRE_H = 24 * 7   # 7 days

# OpenAI Configuration
OPENAI_API_URL = "https://api.openai.com/v1/responses"
OPENAI_MODEL = "gpt-5.4"
# Alternative: "gpt-4o" (better but more expensive)

# ─── DATABASE ────────────────────────────────────────────────────────────────
database = databases.Database(DATABASE_URL)
metadata = MetaData()

users = Table("users", metadata,
    Column("id",           Integer, primary_key=True),
    Column("email",        String(255), unique=True, nullable=False),
    Column("password_hash",String(255), nullable=False),
    Column("name",         String(100)),
    Column("created_at",   DateTime, server_default=func.now()),
    Column("is_active",    Boolean, default=True),
)

reports = Table("reports", metadata,
    Column("id",           Integer, primary_key=True),
    Column("user_id",      Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("subspecialty", String(50)),
    Column("modality",     String(50)),
    Column("mode",         String(20)),
    Column("input_text",   Text),
    Column("impression",   Text),
    Column("differentials",Text),
    Column("feedback",     Text),
    Column("raw_response", Text),
    Column("created_at",   DateTime, server_default=func.now()),
    Column("title",        String(255)),
)

papers = Table("papers", metadata,
    Column("id",           Integer, primary_key=True),
    Column("user_id",      Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("input_mode",   String(20)),
    Column("input_text",   Text),
    Column("title",        String(500)),
    Column("summary",      Text),
    Column("findings",     Text),
    Column("implications", Text),
    Column("raw_response", Text),
    Column("created_at",   DateTime, server_default=func.now()),
)

engine = sqlalchemy.create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"))

# ─── LIFESPAN ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    metadata.create_all(engine)
    await database.connect()
    yield
    await database.disconnect()

app = FastAPI(title="Radiology Coach API", version="1.0.0", lifespan=lifespan)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ─── SCHEMAS ─────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class PolishRequest(BaseModel):
    mode: str
    subspecialty: str
    modality: str
    input_text: str
    api_key: str
    save: bool = False
    title: Optional[str] = None

class DigestRequest(BaseModel):
    input_mode: str
    input_text: str
    api_key: str
    save: bool = False

class UpdateTitleRequest(BaseModel):
    title: str

# ─── AUTH HELPERS ────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def create_token(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_H),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
        user_id = int(payload["sub"])
        print(f"🔍 DEBUG: Decoded user_id = {user_id}")
    except Exception as e:
        print(f"❌ DEBUG: Token decode error: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    row = await database.fetch_one(users.select().where(users.c.id == user_id))
    print(f"🔍 DEBUG: Query result for user_id {user_id}: {row}")
    
    if not row or not row["is_active"]:
        print(f"❌ DEBUG: User {user_id} not found or inactive")
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
@app.post("/auth/register", response_model=TokenResponse)
async def register(req: RegisterRequest):
    existing = await database.fetch_one(users.select().where(users.c.email == req.email))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    if len(req.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")

    uid = await database.execute(users.insert().values(
        email=req.email,
        password_hash=hash_password(req.password),
        name=req.name or req.email.split("@")[0],
        is_active=True,
    ))
    token = create_token(uid, req.email)
    return {"access_token": token, "user": {"id": uid, "email": req.email, "name": req.name}}

@app.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    row = await database.fetch_one(users.select().where(users.c.email == req.email))
    if not row or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(row["id"], row["email"])
    return {"access_token": token, "user": {"id": row["id"], "email": row["email"], "name": row["name"]}}

@app.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {"id": user["id"], "email": user["email"], "name": user["name"]}

# ─── OPENAI PROXY ──────────────────────────────────────────────────────────
async def call_openai(
    api_key: str,
    system: str,
    prompt: str,
    max_tokens: int = 4000,  # Add this parameter
    temperature: float = 0.3,
) -> str:
    """Proxy OpenAI call — user key used per-request, never persisted."""
    async with httpx.AsyncClient(timeout=90) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4o-mini",
                "max_tokens": max_tokens,  # Use the parameter
                "temperature": temperature,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt}
                ]
            }
        )
    
    if resp.status_code != 200:
        try:
            error_data = resp.json()
            error_detail = error_data.get("error", {}).get("message", f"OpenAI error {resp.status_code}")
        except:
            error_detail = resp.text
        raise HTTPException(status_code=502, detail=error_detail)
    
    data = resp.json()
    return data["choices"][0]["message"]["content"]   
def parse_section(text: str, labels: list) -> str:
    for label in labels:
        # Look for markdown headers (## 1. LABEL or **LABEL** or LABEL:)
        patterns = [
            rf'##\s*\d+\.\s*{re.escape(label)}[\s\S]*?(?=\n##\s*\d+\.|\n\*\*|$)',
            rf'\*\*{re.escape(label)}\*\*[\s\S]*?(?=\n\*\*|$)',
            rf'{re.escape(label)}[:\s]*([\s\S]*?)(?=\n[A-Z#]|\Z)'
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(0).strip() if m.group(0) else m.group(1).strip() if m.group(1) else ""
    return ""
    
# ─── REPORT COACH ────────────────────────────────────────────────────────────
@app.post("/reports/polish")
async def polish_report(req: PolishRequest, user=Depends(get_current_user)):
    system = """You are an elite, U.S.-trained senior radiologist with subspecialty expertise. You produce final-signature quality reports with structured, actionable impressions."""

    if req.mode == "a":
        prompt = f"""You are a senior radiologist polishing a radiology report. PRESERVE THE ORIGINAL STRUCTURE EXACTLY.

ORIGINAL REPORT:
{req.input_text}

RULES:
1. Keep ALL sections exactly as written:
   - Patient Information
   - Imaging Study
   - Findings (ALL details must remain unchanged)
   - Any other sections

2. ONLY rewrite the IMPRESSION section following the structure below.

3. IMPRESSION STRUCTURE (use these EXACT sections):

**IMPRESSION**
State the most likely diagnosis first (no hedging if clear). Use structured reasoning where appropriate:
- "Constellation of findings consistent with ..."
- "Favor ... over ... given ..."
- "Sequela of ..."
Be clinically actionable. Do NOT restate findings. Recommend next imaging only if necessary (specific modality/protocol).

**DIFFERENTIAL DIAGNOSIS** (only if needed):
List 2–4 prioritized entities.

**REPORTING PITFALLS**:
List 2–4 commonly missed or high-risk considerations.

**TEACHING PEARL**:
1–2 lines max; focus on key discriminator or management insight.

**LANGUAGE UPGRADE AUDIT**:
Convert weak phrases → strong phrasing (3–6 examples).
Focus on removing hedging, vagueness, redundancy.

**SCORING SYSTEM**:
Include validated imaging scoring system if applicable.
If not applicable, explicitly state: "No validated scoring system applies."

4. Tone:
- Senior radiologist level
- Concise but not overly brief
- No hedging language

5. PROHIBITED:
- "could represent"
- "possibly"
- "cannot rule out"
- "clinical correlation recommended"
- "suggesting"
- "may represent"

OUTPUT:
Return the FULL report with original structure preserved.
ONLY the IMPRESSION section should be rewritten in the required format.

EXAMPLE OF CORRECT IMPRESSION SECTION:

**IMPRESSION**
Constellation of findings consistent with hepatocellular carcinoma (HCC), LI-RADS 5, given arterial hyperenhancement, washout, and capsule in a cirrhotic liver. Lesion 2 is indeterminate, LI-RADS 3. No tumor in vein.

**DIFFERENTIAL DIAGNOSIS**
1. HCC — favored
2. Intrahepatic cholangiocarcinoma — less likely (no targetoid features)
3. Dysplastic nodule — less likely (no APHE)

**REPORTING PITFALLS**
1. Missing washout on portal venous phase → undercall HCC
2. Overcalling capsule on delayed phase → false LR-5
3. Ignoring ancillary features → wrong category

**TEACHING PEARL**
LI-RADS 5 requires nonrim APHE + washout or capsule; size <10mm cannot be LR-5.

**LANGUAGE UPGRADE AUDIT**
- "may represent" → "consistent with"
- "could be" → "favors"
- "suspicious for" → "diagnostic of"

**SCORING SYSTEM**
LI-RADS v2018 applied.

Now produce the polished report with the IMPRESSION section in the required format."""
    
    else:
        # Mode B - Full Report (keep existing)
        prompt = f"""You are a senior radiologist polishing a full radiology report. PRESERVE THE ORIGINAL STRUCTURE EXACTLY.

ORIGINAL REPORT:
{req.input_text}

RULES:
1. Keep ALL sections exactly as written (Patient Information, Imaging Study, Findings)
2. ONLY improve the IMPRESSION section
3. Format impression as numbered bullets (1., 2., 3.)
4. Use proper confidence language
5. PROHIBITED: "could represent", "possibly", "cannot rule out", "clinical correlation recommended"
6. Add management implications when appropriate

OUTPUT: Return the COMPLETE report with original structure preserved, only IMPRESSION improved."""
    
    raw = await call_openai(req.api_key, system, prompt, max_tokens=2500)
    
    if req.mode == "a":
        result = {
            "impression": raw,
            "differentials": "",
            "feedback": "",
            "raw": raw,
            "saved": False,
            "id": None,
        }
    else:
        result = {
            "impression": raw,
            "differentials": "",
            "feedback": "",
            "raw": raw,
            "saved": False,
            "id": None,
        }
    
    if req.save:
        rid = await database.execute(reports.insert().values(
            user_id=user["id"],
            subspecialty=req.subspecialty,
            modality=req.modality,
            mode="impression_only" if req.mode == "a" else "full_report",
            input_text=req.input_text,
            impression=result["impression"],
            differentials="",
            feedback="",
            raw_response=raw,
            title=req.title or f"{req.subspecialty} · {req.modality}",
        ))
        result["saved"] = True
        result["id"] = rid
    
    return result




@app.get("/reports")
async def list_reports(user=Depends(get_current_user), skip: int = 0, limit: int = 50):
    q = reports.select().where(reports.c.user_id == user["id"])\
               .order_by(reports.c.created_at.desc()).offset(skip).limit(limit)
    rows = await database.fetch_all(q)
    return [dict(r) for r in rows]

@app.get("/reports/{report_id}")
async def get_report(report_id: int, user=Depends(get_current_user)):
    row = await database.fetch_one(reports.select().where(
        (reports.c.id == report_id) & (reports.c.user_id == user["id"])
    ))
    if not row: raise HTTPException(404, "Report not found")
    return dict(row)

@app.patch("/reports/{report_id}")
async def update_report_title(report_id: int, req: UpdateTitleRequest, user=Depends(get_current_user)):
    row = await database.fetch_one(reports.select().where(
        (reports.c.id == report_id) & (reports.c.user_id == user["id"])
    ))
    if not row: raise HTTPException(404, "Report not found")
    await database.execute(reports.update().where(reports.c.id == report_id).values(title=req.title))
    return {"ok": True}

@app.delete("/reports/{report_id}")
async def delete_report(report_id: int, user=Depends(get_current_user)):
    row = await database.fetch_one(reports.select().where(
        (reports.c.id == report_id) & (reports.c.user_id == user["id"])
    ))
    if not row: raise HTTPException(404, "Report not found")
    await database.execute(reports.delete().where(reports.c.id == report_id))
    return {"ok": True}

# ─── PAPER DIGEST ────────────────────────────────────────────────────────────
@app.post("/papers/digest")
async def generate_digest(req: DigestRequest, user=Depends(get_current_user)):
    system = """You are a senior radiology attending. Extract surgical decision data from radiology papers.

RULES:
- EVERY number must have a threshold and action (e.g., "gap <2cm → primary repair")
- EVERY verb must be surgical (repair, graft, debride, reconstruct)
- NO generic phrases ("further imaging", "clinical correlation", "consider")
- Use 🔑 once for most critical rule
- Use 🟢 for most likely, 🔴 for critical miss
- Extract ALL differentials from source"""

    prompt = f"""SOURCE:
{req.input_text}

OUTPUT EXACTLY these 11 sections. Use the FORMAT shown.

1. CONSULTANT SUMMARY
[2 sentences. Must include a number that dictates management. Example: "Gap 2.5cm → needs graft (2-6cm range)"]

2. CORE FRAMEWORK
[Decision steps with thresholds. Each step: finding → measurement → action. Example: "Measure gap → <2cm repair; 2-6cm graft; >6cm reconstruction"]

3. HIGH-YIELD RULES
[Bullets. Format: finding + threshold + action. Example: "🔑 Gap <2cm + good tissue → primary repair"]

4. NORMAL VS ABNORMAL
[Only surgical differences. Example: "Acute (edema) → repairable | Chronic (fibrosis) → reconstruction"]

5. DIFFERENTIALS
[Table. Include ALL from source. Example:
| Diagnosis | Key Discriminator | Surgical Action |
|-----------|-------------------|-----------------|
| 🟢 Complete tear | Gap 2.5cm | FHL graft |
| ⚪️ Partial tear | Gap <2cm | Primary repair |
| 🔴 Chronic tear | Gap >6cm | Reconstruction]

6. IMAGING STRATEGY
[Modality → what it answers → stop point. Example: "MRI → measure gap & tissue quality → stop if surgery indicated"]

7. REPORTING
[1 sentence: Diagnosis + surgical action. Example: "Complete rupture with 2.5cm gap → FHL tendon graft"]

8. PEARLS
[Missed finding → consequence. Example: "Underestimating effective gap → failed repair"]

9. EXAM TRAPS
[Pitfall → why wrong → how to avoid. Example: "Calling chronic rupture acute → wrong surgery → check tissue quality"]

10. FAILURE MODE
[1 sentence: surgical consequence. Example: "Failed graft → reoperation needed"]

11. RAPID RECALL
[5-7 surgical anchors. Example:
- Gap <2cm + good tissue = primary repair
- Gap 2-6cm = FHL graft
- Gap >6cm = reconstruction]

Now produce the 11 sections using the EXACT format above. Be SPECIFIC. Use NUMBERS from the source."""
    
    raw = await call_openai(req.api_key, system, prompt, max_tokens=3000)
    
    # Parse sections with multiple patterns
    def parse_section(text, labels):
        for label in labels:
            patterns = [
                rf'(?:^|\n)(?:\d+\.\s*|\#\#?\s*|\*\*){re.escape(label)}.*?\n([\s\S]*?)(?=\n(?:\d+\.\s*|\#\#?\s*|\*\*|$))',
                rf'{re.escape(label)}[:\s]*([\s\S]*?)(?=\n\d+\.\s*|\n\#\#?\s*|\n\*\*|$)',
            ]
            for pattern in patterns:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
        return ""
    
    result = {
        "consultant_summary": parse_section(raw, ["CONSULTANT SUMMARY", "1. CONSULTANT SUMMARY"]),
        "core_framework": parse_section(raw, ["CORE FRAMEWORK", "2. CORE FRAMEWORK"]),
        "high_yield_rules": parse_section(raw, ["HIGH-YIELD RULES", "3. HIGH-YIELD RULES"]),
        "normal_vs_abnormal": parse_section(raw, ["NORMAL VS ABNORMAL", "4. NORMAL VS ABNORMAL"]),
        "differentials": parse_section(raw, ["DIFFERENTIALS", "5. DIFFERENTIALS"]),
        "imaging_strategy": parse_section(raw, ["IMAGING STRATEGY", "6. IMAGING STRATEGY"]),
        "reporting": parse_section(raw, ["REPORTING (ATTENDING LEVEL)", "7. REPORTING", "REPORTING"]),
        "pearls": parse_section(raw, ["PEARLS", "8. PEARLS"]),
        "exam_traps": parse_section(raw, ["EXAM TRAPS", "9. EXAM TRAPS"]),
        "failure_mode": parse_section(raw, ["FAILURE MODE", "10. FAILURE MODE"]),
        "rapid_recall": parse_section(raw, ["RAPID RECALL", "11. RAPID RECALL"]),
        "raw": raw,
        "saved": False,
        "id": None,
    }
    
    if req.save:
        # Combine all sections for storage
        full_summary = "\n\n".join([
            f"1. CONSULTANT SUMMARY\n{result['consultant_summary']}" if result['consultant_summary'] else "",
            f"2. CORE FRAMEWORK\n{result['core_framework']}" if result['core_framework'] else "",
            f"3. HIGH-YIELD RULES\n{result['high_yield_rules']}" if result['high_yield_rules'] else "",
            f"4. NORMAL VS ABNORMAL\n{result['normal_vs_abnormal']}" if result['normal_vs_abnormal'] else "",
            f"5. DIFFERENTIALS\n{result['differentials']}" if result['differentials'] else "",
            f"6. IMAGING STRATEGY\n{result['imaging_strategy']}" if result['imaging_strategy'] else "",
            f"7. REPORTING\n{result['reporting']}" if result['reporting'] else "",
            f"8. PEARLS\n{result['pearls']}" if result['pearls'] else "",
            f"9. EXAM TRAPS\n{result['exam_traps']}" if result['exam_traps'] else "",
            f"10. FAILURE MODE\n{result['failure_mode']}" if result['failure_mode'] else "",
            f"11. RAPID RECALL\n{result['rapid_recall']}" if result['rapid_recall'] else "",
        ])
        
        pid = await database.execute(papers.insert().values(
            user_id=user["id"],
            input_mode=req.input_mode,
            title=req.input_text[:120],
            summary=full_summary[:500] if full_summary else "",
            findings=result["high_yield_rules"],
            implications=result["failure_mode"],
            raw_response=raw,
        ))
        result["saved"] = True
        result["id"] = pid
    
    return result

@app.get("/papers")
async def list_papers(user=Depends(get_current_user), skip: int = 0, limit: int = 50):
    q = papers.select().where(papers.c.user_id == user["id"])\
              .order_by(papers.c.created_at.desc()).offset(skip).limit(limit)
    rows = await database.fetch_all(q)
    return [dict(r) for r in rows]

@app.get("/papers/{paper_id}")
async def get_paper(paper_id: int, user=Depends(get_current_user)):
    row = await database.fetch_one(papers.select().where(
        (papers.c.id == paper_id) & (papers.c.user_id == user["id"])
    ))
    if not row: raise HTTPException(404, "Paper not found")
    return dict(row)

@app.delete("/papers/{paper_id}")
async def delete_paper(paper_id: int, user=Depends(get_current_user)):
    row = await database.fetch_one(papers.select().where(
        (papers.c.id == paper_id) & (papers.c.user_id == user["id"])
    ))
    if not row: raise HTTPException(404, "Paper not found")
    await database.execute(papers.delete().where(papers.c.id == paper_id))
    return {"ok": True}

# ─── HEALTH ──────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "radiology-coach-api"}



from fastapi.staticfiles import StaticFiles
import os

# Serve frontend files
frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
    print(f"✅ Frontend mounted at / from {frontend_path}")
else:
    print(f"❌ Frontend not found at {frontend_path}")
    # Also check if frontend is at different location
    if os.path.exists("/app/frontend"):
        app.mount("/", StaticFiles(directory="/app/frontend", html=True), name="frontend")
        print("✅ Frontend mounted from /app/frontend")