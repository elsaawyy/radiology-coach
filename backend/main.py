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
OPENAI_MODEL = "gpt-5.4-mini"  
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
async def call_openai(api_key: str, system: str, prompt: str) -> str:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            OPENAI_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": OPENAI_MODEL,
                "max_output_tokens": 2000,
                "temperature": 0.3,
                "input": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt}
                ]
            }
        )

    if resp.status_code != 200:
        try:
            error_data = resp.json()
            error_detail = error_data.get("error", {}).get("message", "OpenAI error")
        except:
            error_detail = resp.text
        raise HTTPException(status_code=502, detail=error_detail)

    data = resp.json()

    try:
        return data["output"][0]["content"][0]["text"]
    except:
        return str(data)
def parse_section(text: str, label: str) -> str:
    m = re.search(rf"{label}[:\s]*([\s\S]*?)(?=\n[A-Z#]|$)", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""

# ─── REPORT COACH ────────────────────────────────────────────────────────────
@app.post("/reports/polish")
async def polish_report(req: PolishRequest, user=Depends(get_current_user)):
    system = """You are a senior consultant radiologist with 15-20 years of experience practicing in the United States. 
Your role is to review and refine radiology reports to an attending-level standard. 
You are a trainer, safety net, and final decision-maker, not merely an editor."""
    
    if req.mode == "a":
        prompt = f"""CORE MISSION

Produce polished, clinically actionable, medicolegally defensible radiology reports that reflect the reasoning, prioritization, and risk-awareness of an experienced attending radiologist.

Think like a radiologist on call whose job is to avoid missing life-threatening diagnoses, major complications, and clinically meaningful extension of disease.

---

ORIGINAL DRAFT REPORT:

{req.input_text}

---

OUTPUT STRUCTURE

EXAM
[{req.modality} {req.subspecialty}]

INDICATION
[Clinical reason based on the findings]

TECHNIQUE
[Standard acquisition description for this modality]

COMPARISON
[None provided / prior exam if available]

FINDINGS

- Structured by system or region
- Descriptive only
- Precise and concise
- No impression-like interpretation

IMPRESSION

- Bullet points only
- Primary diagnosis first
- Urgency second if applicable
- Complication status next
- Secondary clinically meaningful findings last

CLINICAL RATIONALE

- Brief explanation of why the leading diagnosis is favored
- Do not repeat findings verbatim
- Do not prescribe treatment

---

STYLE GUIDELINES

Tone: Consultant-level, decisive, concise, high clinical impact

Confidence Calibration:
- Use "concerning for" for subtle, early, borderline, or incomplete findings
- Use "most concerning for" when one diagnosis is favored but not definitive
- Use "consistent with" for classic or near-classic patterns

Do not:
- Overcall when imaging support is incomplete
- Label lesions benign unless the pattern is unequivocally classic
- Use absolute certainty when a safer calibrated statement is more defensible

Management Language:
- Use: "clinical correlation recommended", "specialist evaluation recommended", "urgent evaluation is required"
- Do NOT use: antibiotics, drainage required, surgery required, biopsy required, etc.

---

Now produce the polished report following this structure and style guidelines."""
    
    else:
        prompt = f"""CORE MISSION

Produce polished, clinically actionable, medicolegally defensible radiology reports that reflect the reasoning, prioritization, and risk-awareness of an experienced attending radiologist.

---

ORIGINAL DRAFT REPORT:

{req.input_text}

---

SAFETY CHECKS TO PERFORM (silently)

Before finalizing, verify:
1. Primary diagnosis safety - Is there a more dangerous diagnosis?
2. Complications - Hemorrhage, mass effect, obstruction, ischemia, thrombosis
3. Adjacent extension - Organ invasion, nodal disease, vascular involvement
4. Second diagnosis - Is there another clinically important process?
5. False reassurance - Am I falsely reassuring?

---

OUTPUT STRUCTURE

EXAM
[{req.modality} {req.subspecialty}]

INDICATION
[Clinical reason based on the findings]

TECHNIQUE
[Standard acquisition description for this modality]

COMPARISON
[None provided / prior exam if available]

FINDINGS

- Structured by system or region
- Descriptive only
- Precise and concise
- No impression-like interpretation

IMPRESSION

- Bullet points only
- Primary diagnosis first
- Urgency second if applicable
- Complication status next
- Secondary clinically meaningful findings last

CLINICAL RATIONALE

- Brief explanation of why the leading diagnosis is favored
- Do not repeat findings verbatim
- Do not prescribe treatment

---

IMPRESSION RULES

The impression must reflect a clinical decision, not a description of image appearance.

It must prioritize:
1. The most dangerous clinically relevant diagnosis
2. Urgency
3. Complications
4. The most important next step in general radiology language

If uncertainty exists, resolve it with hierarchy:
- most concerning for
- favored over
- remains a consideration
- indeterminate, requires further characterization

---

Now produce the polished report following this structure and style guidelines."""

    raw = await call_openai(req.api_key, system, prompt)
    
    impression_match = re.search(r'IMPRESSION\n[- ]*\n([\s\S]*?)(?=\nCLINICAL RATIONALE|\n\*\*|$)', raw, re.IGNORECASE)
    impression = impression_match.group(1).strip() if impression_match else raw[:500]
    
    differentials = "Based on the findings, the differential includes the most likely entities."
    
    rationale_match = re.search(r'CLINICAL RATIONALE\n[- ]*\n([\s\S]*?)(?=\n\*\*|$)', raw, re.IGNORECASE)
    feedback = rationale_match.group(1).strip() if rationale_match else "The report follows standard reporting guidelines and is clinically actionable."

    result = {
        "impression": impression,
        "differentials": differentials,
        "feedback": feedback,
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
            impression=impression,
            differentials=differentials,
            feedback=feedback,
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
    system = "You are a senior radiology consultant with 20 years of clinical and teaching experience. You are reviewing a radiology article to prepare a teaching session for your trainees."
    
    prompt = f"""Here is the article I need you to summarize:

{req.input_text}

CRITICAL INSTRUCTION: COMPLETE COVERAGE

Before writing, carefully read the entire article. Do not omit any important pathophysiology, key concepts, classification systems, normal variants, complications, or imaging findings.

---

OUTPUT STRUCTURE

Organize your summary with the following nine sections:

Section 1: THE BOTTOM LINE
· One engaging paragraph (3-6 sentences) that distills the article's core clinical utility.
· Use phrases like "Listen up" or "Here's what you need to know" to set the teaching tone.
· Include emojis: 🟡 KEY, 🟢 BEST, 🔴 MOST, 🟠 WORST, 🔵 LEAST.
· Include the single most important clinical takeaway.

Section 2: KEY CONCEPTS FOR THE REPORTING RADIOLOGIST
· Present foundational principles using tables, bulleted lists, and short paragraphs.
· Include terminology definitions, normal variants, classification systems, prevalence data.
· End with a "Pro Tip" callout in italics.

Section 3: THE SEARCH PATTERN
· Present a systematic, step-by-step approach (numbered steps or tabulated checklist).
· Use phrases like "Here's your systematic approach. Run this checklist every time."
· Highlight "don't miss" findings with 🟠 WORST.

Section 4: DIFFERENTIAL DIAGNOSIS GENERATOR
· Create a table with columns: Presentation, Differential 1, Differential 2, The One Question That Separates Them.
· Include 6-10 rows covering the most common/important differentials.

Section 5: REPORTING TEMPLATE
· Provide a structured reporting framework with placeholders in [brackets].
· Organize by anatomical structures or diagnostic categories.

Section 6: ADVANCED IMAGING RECOMMENDATIONS
· Present as a table with columns: Scenario, Modality, How to Do It, Why It Matters.
· Include protocol essentials (sequences, planes, positioning).

Section 7: TRAP DOORS
· Present as a numbered or tabulated list of 6-10 specific pitfalls.
· Each entry: The Trap, Why It Hurts, How to Avoid It.
· Use 🟠 WORST emoji for the most critical mistakes.

Section 8: TEACHING PEARLS
· Present as a bulleted list of 12-20 short, memorable one-liners.
· Each pearl: 5-12 words, start with an emoji.

Section 9: THE "BEST, WORST, MOST, LEAST" SUMMARY
· Create a table with columns: Emoji, Category, Finding.
· Include 12-18 rows covering the most clinically impactful single facts.
· Use emojis: 🔴 MOST, 🟢 BEST, 🟠 WORST, 🔵 LEAST, 🟡 KEY, 🟣 RARE.

---

STYLE GUIDELINES
· Tone: Authoritative but approachable. Use second person ("you").
· Variety: Mix table formats, bulleted lists, numbered steps, and short paragraphs.
· Emojis: Embed color-coded emojis throughout all sections.
· Bold: Use for critical concepts and key numbers.

---

Start with: "Here is my summary of the article, structured as I would present it to a radiology trainee during a workstation teaching session."

Then present the summary using the nine-section structure above."""
    
    raw = await call_openai(req.api_key, system, prompt)
    
    result = {
        "summary": parse_section(raw, "THE BOTTOM LINE") or raw[:500],
        "findings": parse_section(raw, "KEY CONCEPTS"),
        "implications": parse_section(raw, "TEACHING PEARLS"),
        "raw": raw,
        "saved": False,
        "id": None,
    }
    
    if req.save:
        pid = await database.execute(papers.insert().values(
            user_id=user["id"],
            input_mode=req.input_mode,
            input_text=req.input_text,
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
frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
    print(f"✅ Frontend mounted from: {frontend_path}")
else:
    print(f"❌ Frontend not found at: {frontend_path}")