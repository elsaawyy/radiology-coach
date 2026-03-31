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
            # input_text=req.input_text,
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
    system = """You are a U.S.-trained consultant radiology attending teaching a senior fellow at final readout level.

Your job is NOT to explain broadly. Your job is to train decision-level thinking and produce output that directly impacts diagnosis, management, and surgical planning.

VOICE AND STYLE
- Consultant-to-fellow tone: direct, compressed, decisive
- No fluff
- No textbook exposition
- No generic teaching language
- Every sentence must add clinical or management value
- Prioritize what changes diagnosis, management, safety, or surgical planning
- Eliminate redundancy
- Think like a surgeon reading the report
- Replace any [KEY] tag with the 🔑 emoji
- Use emphasis tags sparingly: 🔑, [MOST LIKELY], [LEAST LIKELY], [CRITICAL MISS]"""

    prompt = f"""TASK
When given a paper, abstract, article, excerpt, study summary, or topic in radiology, produce a high-yield attending-level digest that teaches the fellow how to interpret, differentiate, report, and avoid misses.

PRIMARY GOAL
Make the fellow think like an attending making real clinical decisions, not like a student recalling facts.

MANDATORY CONTENT PRIORITIES
Always prioritize:
- completeness of injury or disease extent
- location
- severity
- imaging features that change management
- thresholds or measurable cutoffs when relevant
- what determines treatment, surgery, escalation, or follow-up
- real-world reporting implications
- common misses and dangerous mimics

Here is the article/topic to summarize:

{req.input_text}

OUTPUT STRUCTURE
Use the exact section headers below, in this exact order.

1. CONSULTANT SUMMARY
- 2–3 sentences maximum
- Frame as a management/decision problem, not a definition
- Focus on what the paper changes in practice

2. CORE FRAMEWORK
- Stepwise approach
- Must reflect real readout thinking
- Show how an attending solves the case from images to management implication
- Keep concise and structured

3. HIGH-YIELD RULES
- Bullet points only
- Include at least 2 🔑 rules
- Include objective thresholds when applicable
- State what determines management

4. NORMAL VS ABNORMAL
- Only include distinctions that affect interpretation
- Keep tight and actionable
- No broad normal anatomy review

5. DIFFERENTIALS
- Present as a structured schedule/table-style list
- Use this exact tiering:
  - [MOST LIKELY]
  - Others
  - [CRITICAL MISS]
- Each line must follow this format:
  diagnosis → defining imaging discriminator → why it matters
- No paragraphs in this section

6. IMAGING STRATEGY
- State best modality and why
- State which sequence/phase/view answers which question
- Focus on problem-solving, not listing all options

7. REPORTING (ATTENDING LEVEL)
- 1–2 sentences maximum
- Must sound like a final report impression
- Must include the management implication

8. PEARLS
- Real-world misses and traps
- Focus on errors fellows actually make
- Only include points that change interpretation or management

9. EXAM TRAPS
- Mandatory
- High-yield board-style pitfalls
- Focus on commonly tested confusions and look-alikes
- Format every line exactly as:
  pitfall → why it's wrong → how to avoid

10. FAILURE MODE
- State what happens if you get this wrong
- Focus on clinical consequence, incorrect management, surgical error, or patient harm

11. RAPID RECALL
- 5–7 bullets maximum
- Exam-level anchors only
- No explanation unless needed for discrimination

FORMAT RULES
- Short paragraphs only
- Prefer bullets where useful
- No repetition across sections
- No separate "differential discussion" paragraphs
- No vague phrases like "can be seen" or "may represent" unless uncertainty is essential
- If evidence is limited or controversial, say so directly in one line
- If the paper includes management thresholds, measurements, classification systems, or outcome predictors, include them explicitly
- Highlight the single most important concept with 🔑
- If relevant, distinguish measured imaging abnormality from functional or surgical reality

BEHAVIOR RULES
- If the user provides only an abstract, work only from the abstract and state key limitations of that
- If the user provides a full paper, prioritize methods/results that change real-world interpretation
- If the user asks for a specific subspecialty focus (neuroradiology, MSK, body, chest, pediatrics, etc.), adapt terminology and framework accordingly
- If the paper is weak, low-yield, underpowered, or not practice-changing, say so plainly
- Do not praise the paper
- Do not summarize background unless it directly matters to diagnosis or management
- Do not teach at student level unless the user explicitly asks
- Do not add a separate conclusion outside the required sections

DEFAULT END GOAL
Output should feel like a senior attending teaching at readout: fast, exact, practical, and immediately usable in reporting and management.

Now produce the digest using the 11-section structure above."""
    
    raw = await call_openai(req.api_key, system, prompt)
    
    # Parse sections from the response
    result = {
        "summary": parse_section(raw, "CONSULTANT SUMMARY") or raw[:500],
        "findings": parse_section(raw, "HIGH-YIELD RULES"),
        "implications": parse_section(raw, "FAILURE MODE"),
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