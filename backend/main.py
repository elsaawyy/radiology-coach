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
    system = """You are an elite, U.S.-trained senior radiologist with subspecialty expertise. You produce detailed, evidence-based reports with clinical reasoning."""

    if req.mode == "a":
        # ========== MODE A - Impression Only ==========
        prompt = f"""You are a senior radiologist polishing a radiology report. PRESERVE THE ORIGINAL STRUCTURE EXACTLY.

ORIGINAL REPORT:
{req.input_text}

RULES:
1. Keep ALL sections exactly as written:
   - Patient Information
   - Imaging Study
   - Findings (ALL details must remain unchanged)
   - Any other sections

2. ONLY rewrite the IMPRESSION section.

3. The IMPRESSION must follow this structure EXACTLY:

   A. First paragraph (Narrative Impression):
   - Write a smooth, professional paragraph (NOT bullets)
   - Integrate clinical context (e.g., cirrhosis, hepatitis)
   - Combine all lesions into a flowing sentence
   - Include:
     • lesion size + location
     • arterial enhancement, washout, capsule (if present)
     • LI-RADS category
     • clear diagnosis when appropriate (e.g., HCC)
   - End with a brief statement about background liver and absence/presence of complications

   B. Differential Diagnosis (numbered list):
   - 2–3 items maximum
   - Use confident clinical language:
     • "— favored"
     • "— less likely"
   - Must be clinically relevant (e.g., HCC, iCCA, dysplastic nodule)

   C. Clinical Rationale (short paragraph):
   - Explain WHY the classification (LI-RADS) was assigned
   - Reference major features (APHE, washout, capsule, size)
   - Keep concise but clinically meaningful
   - No long textbook explanations

4. Tone:
- Senior radiologist level
- Concise but not overly brief
- No hedging language

5. PROHIBITED:
- "could represent"
- "possibly"
- "cannot rule out"

OUTPUT:
Return ONLY the IMPRESSION section. Do NOT include Patient Information, Imaging Study, or Findings.
The output should start with "IMPRESSION:" followed by the three parts (A, B, C)."""
    
    else:
        # ========== MODE B - Full Report ==========
        prompt = f"""You are a senior radiologist polishing a full radiology report. PRESERVE THE ORIGINAL STRUCTURE EXACTLY.

ORIGINAL REPORT:
{req.input_text}

RULES:
1. Keep ALL sections exactly as written (Patient Information, Imaging Study, Findings)
2. ONLY improve the IMPRESSION section
3. Format impression as numbered bullets (1., 2., 3.)
4. Use proper confidence language
5. PROHIBITED: "could represent", "possibly", "cannot rule out"
6. Add management implications when appropriate

OUTPUT: Return the COMPLETE report with original structure preserved."""
    
    raw = await call_openai(req.api_key, system, prompt, max_tokens=2000)
    
    if req.mode == "a":
        # For Mode A, extract just the impression section
        # The AI should already return only the impression, but let's clean it
        impression_text = raw.strip()
        # Remove any stray markdown formatting
        impression_text = impression_text.replace('**', '')
        result = {
            "impression": impression_text,
            "differentials": "",
            "feedback": "",
            "raw": impression_text,
            "saved": False,
            "id": None,
        }
    else:
        # For Mode B, return full report
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
    system = """You are a US-trained senior radiology attending teaching a fellow at final readout level.

Your task: Extract surgically actionable data from the provided radiology paper or case.

CRITICAL RULES:
- EVERY NUMBER must have a threshold and an implication (e.g., "gap <2cm → primary repair")
- EVERY VERB must be a surgical action (repair, graft, debride, reconstruct, augment)
- DO NOT use generic radiology language ("further imaging", "clinical correlation", "consider")
- If a variable can change procedure type (repair vs graft vs non-op) → it MUST be included
- DO NOT omit: gap size, effective gap, tissue quality, chronicity, location, instability, associated structures
- Imaging patterns, distribution, enhancement, chronicity take priority over wording rules
- Use 🔑 for the single most important decision-driving fact per section (max 1-2 per section)
- Use 🟢 for most likely diagnosis (only one)
- Use 🔴 for critical miss (must not overlook)"""

    prompt = f"""Here is the article/topic to summarize:

{req.input_text}

OUTPUT STRUCTURE - Use these EXACT 11 sections:

1. CONSULTANT SUMMARY
2-3 sentences. Frame as management/decision problem. Must include a specific measurement or threshold that dictates management. Example: "Complete Achilles rupture with 1.5cm gap → primary repair (gap <2cm)."

2. CORE FRAMEWORK
Stepwise structure. Each step = decision checkpoint with specific threshold. Use "→" to show implication. Example:
- Measure fluid-filled gap → <2cm primary repair; 2-6cm needs graft
- Assess effective gap (degenerative ends) → alters surgical technique
- Check location → mid-substance vs insertional vs myotendinous

3. HIGH-YIELD RULES
Bullet points. Format: finding + threshold + surgical action. Use 🔑 once. Example:
- 🔑 Gap <2cm + good tissue quality → primary end-to-end repair
- Gap 2-6cm → lengthening ± FHL tendon graft
- Gap >6cm → complex reconstruction (turndown/transfer)
- Severe tendinosis at stumps → increases effective gap → alters surgery

4. NORMAL VS ABNORMAL
Only distinctions that change surgical management. Example:
- Acute (fluid gap + edema) → repairable tissue
- Chronic (fibrosis/fatty atrophy) → reconstruction, not simple repair

5. DIFFERENTIALS
Table with 3 columns. Use 🟢, ⚪️, 🔴. Include ALL differentials from source.
| Diagnosis | Key Discriminator (with threshold) | Surgical Next Step |
|-----------|-----------------------------------|---------------------|
| 🟢 most likely | [specific finding + number] | [specific action] |

6. IMAGING STRATEGY
Modality → what it answers → when to stop. Example:
MRI → measure gap, tissue quality, chronicity → stop if surgery indicated

7. REPORTING (ATTENDING LEVEL)
1-2 sentences. Must read like final report impression. Must include management implication. Example:
"Complete Achilles rupture with 1.5cm gap and poor tissue quality → primary repair with possible augmentation"

8. PEARLS
Real-world surgical misses. Format: finding → consequence. Example:
- Underestimating effective gap → failed primary repair
- Missing chronic degeneration → wrong surgical technique

9. EXAM TRAPS
Format strictly: pitfall → why wrong → how to avoid. Example:
- Calling chronic rupture acute → wrong surgical approach → assess tissue quality and fibrosis

10. FAILURE MODE
Direct outcome only. Focus on surgical consequence. Example:
"Failed primary repair due to underestimated effective gap → reoperation needed"

11. RAPID RECALL
5-7 bullets. Ultra-compressed surgical anchors. Example:
- Gap <2cm + good tissue = primary repair
- Gap 2-6cm = FHL graft
- Gap >6cm = complex reconstruction
- Acute = repairable
- Chronic = reconstruction
- Poor tissue quality = augmentation

Now produce the digest using the 11-section structure above. Use the EXACT format shown in the examples. EVERY number must have a threshold and surgical action."""
    
    raw = await call_openai(req.api_key, system, prompt, max_tokens=3500)
    print("\n=== RAW RESPONSE ===\n")
    print(raw)
    print("\n====================\n")
    
    # Parse sections
    result = {
        "summary": parse_section(raw, ["CONSULTANT SUMMARY"]) or raw[:500],
        "findings": parse_section(raw, ["HIGH-YIELD RULES"]),
        "implications": parse_section(raw, ["FAILURE MODE"]),
        "raw": raw,
        "saved": False,
        "id": None,
    }
    
    if req.save:
        pid = await database.execute(papers.insert().values(
            user_id=user["id"],
            input_mode=req.input_mode,
            title=req.input_text[:120],
            summary=result["summary"],
            findings=result["findings"],
            implications=result["implications"],
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