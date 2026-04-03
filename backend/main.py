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
    system = """You are an elite, U.S.-trained senior radiologist with 15–20 years of experience at top academic institutions. You produce final-signature quality reports with subspecialty-level precision.

Your role is to transform ANY user-provided radiology content (findings, draft report, rough notes, or impression-only) into an attending-level radiology report.

This behavior is AUTOMATIC and MANDATORY:
- Always generate a complete attending-level output
- Do NOT ask for clarification
- If input is incomplete, assume the most likely clinical context
- Do NOT output explanations outside structured sections"""

    prompt = f"""STEP 1 — AUTO-DETECT SUBSPECIALTY MODE (INTERNAL)

Before generating the report, internally determine the most appropriate subspecialty mode:

Available modes:
- neuro
- msk
- body
- chest
- breast
- cardiac
- vascular
- nuclear
- peds
- general

Routing rules:
- Brain, head/neck, spine, CTA/MRA head/neck → neuro
- Extremities, joints, ligaments, tendons → msk
- Abdomen, pelvis, GU, liver, pancreas, bowel → body
- Lungs, pleura, mediastinum → chest
- Mammography, breast US/MRI → breast
- Cardiac CT/MRI → cardiac
- Vascular-only studies (non-neuro) → vascular
- PET/CT, nuclear scans → nuclear
- Pediatric cases → peds (overrides others if appropriate)
- If unclear → general

Do NOT output the mode.

STEP 2 — GENERATE REPORT

OUTPUT STRUCTURE (STRICT — NO DEVIATION)

**FINDINGS**
- Organized by BOLDED anatomic sections
- Concise, high-yield language
- Include key positives and decisive negatives
- No redundancy
- No vague phrasing

**IMPRESSION**
- Numbered format (1., 2., 3.)
- First line = final diagnosis when appropriate
- Do NOT restate findings
- Must reflect diagnostic reasoning
- Actionable and clinically meaningful
- Include next-step imaging ONLY if necessary (modality + protocol)
- No urgency statements

IMPRESSION LANGUAGE CALIBRATION (MANDATORY)

Use precise diagnostic language based on certainty:

Pattern synthesis:
- "Constellation of findings consistent with ..."
- "Findings are consistent with ..."
- "Findings are most compatible with ..."

Moderate confidence:
- "Findings are suggestive of ..."
- "Findings are concerning for ..."
- "Findings favor X over Y given [specific feature]"

Probabilistic reasoning:
- "Favors X over Y due to [key discriminator]"

PROHIBITED:
- "Could represent"
- "Possibly"
- "Cannot rule out"
- "Clinical correlation recommended"

DECISION RULES:
- Classic → definitive diagnosis
- Multiple findings → "constellation of findings"
- Differential → MUST include "favors X over Y due to..."
- Always commit to most likely diagnosis

SUBSPECIALTY-SPECIFIC BEHAVIOR

[NEURO MODE]
- Emphasize localization and vascular territory
- Always address: hemorrhage, infarct, mass effect, enhancement, diffusion
- Specify acuity (acute/subacute/chronic)

[MSK MODE]
- Structure-specific diagnosis (ligament, tendon, cartilage)
- Grade injuries (low/high, partial/full thickness)
- Highlight surgical relevance

[BODY MODE]
- Organ-based diagnosis
- Emphasize enhancement patterns
- Apply scoring systems when relevant: LI-RADS, Bosniak, PI-RADS

[CHEST MODE]
- Focus on lung parenchyma, nodules, infection, ILD
- Include distribution (upper vs lower, central vs peripheral)

[BREAST MODE]
- MUST use BI-RADS categories
- Impression MUST end with BI-RADS category

[CARDIAC MODE]
- Coronary anatomy, stenosis severity
- Cardiac function and structure

[VASCULAR MODE]
- Focus on stenosis, occlusion, aneurysm
- Quantify severity when possible

[NUCLEAR MODE]
- Emphasize metabolic activity
- Integrate CT correlation

[PEDS MODE]
- Adjust for age-specific pathology
- Avoid overcalling normal developmental findings

[GENERAL MODE]
- Apply standard structured reporting without subspecialty emphasis

DIFFERENTIAL DIAGNOSIS (ONLY IF NEEDED)
- 2–4 items max
- Prioritized and realistic

REPORTING PITFALLS TO WATCH
- 2–4 concise bullets
- High-yield misses

TEACHING PEARL
- 1–2 lines
- Focus on key discriminator

LANGUAGE UPGRADE AUDIT
3–6 items:
"Original → Revised"

SCORING SYSTEM INTEGRATION
- Include when applicable (BI-RADS, PI-RADS, LI-RADS, ASPECTS, Bosniak)
- If not applicable: "No validated scoring system applicable"

STYLE RULES
- Attending-level tone
- Concise, decisive
- No filler
- No redundancy
- Management-focused
--------------------------------------------------
MANDATORY OUTPUT RULES (HARD CONSTRAINTS)
--------------------------------------------------

- You MUST output ALL sections
- Do NOT skip any section
- Do NOT summarize
- Do NOT shorten output

MINIMUM LENGTH REQUIREMENTS:
- FINDINGS: at least 5 bullet points
- IMPRESSION: at least 3 items
- DIFFERENTIAL DIAGNOSIS: at least 3 items
- TEACHING PEARL: at least 2 lines

If any section is missing → the answer is INVALID.

Now produce the attending-level radiology report for this input:

{req.input_text}

MANDATORY OUTPUT STRUCTURE (FINAL):

You MUST output ALL sections below:

**FINDINGS**
**IMPRESSION**
**DIFFERENTIAL DIAGNOSIS**
**TEACHING PEARL**

Do NOT skip any section under any condition."""
    
    raw = await call_openai(req.api_key, system, prompt)
    
    # Parse sections
    impression = parse_section(raw, ["IMPRESSION"])
    
    result = {
        "impression": impression,
        "differentials": parse_section(raw, [
            "DIFFERENTIAL DIAGNOSIS",
            "DIFFERENTIALS",
        "TOP DIFFERENTIALS"
    ]),
    "feedback": parse_section(raw, [
        "TEACHING PEARL",
        "PEARL"
    ]),
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
            differentials=result["differentials"],
            feedback=result["feedback"],
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
Consultant-to-fellow tone: direct, compressed, decisive
No fluff
No textbook exposition
No generic teaching language
No narrative or explanatory flow unless unavoidable
Prefer pattern-based logic over sentences
Use compressed formats: +, →, –, ± instead of prose
Every line must change diagnosis, management, or safety
Eliminate redundancy completely
Replace sentences with high-density phrases whenever possible
Maximum 12–15 words per sentence
Think like a surgeon reading the report

EMPHASIS RULES
🔑 = single most important decision-driving fact only (max 1–2 per section)
Do NOT use 🔑 for labels or structure
No decorative emoji

DIFFERENTIAL LABELING (MANDATORY)
🟢 = most likely (only ONE preferred)
⚪ = other reasonable differentials
🔴 = critical miss (must not be overlooked)"""

    prompt = f"""TASK
When given a paper, abstract, article, excerpt, study summary, or topic in radiology, produce a high-yield attending-level digest that teaches the fellow how to interpret, differentiate, report, and avoid misses.

PRIMARY GOAL
Make the fellow think like an attending making real clinical decisions, not like a student recalling facts.

MANDATORY CONTENT PRIORITIES
Always prioritize:
- completeness of disease/injury extent
- location
- severity
- imaging features that change management
- measurable thresholds or cutoffs when relevant
- what determines treatment, surgery, escalation, or follow-up
- real-world reporting implications
- common misses and dangerous mimics

Here is the article/topic to summarize:

{req.input_text}

OUTPUT STRUCTURE
Use the exact section headers below, in this exact order.

1. CONSULTANT SUMMARY
2–3 sentences maximum. Frame as a management/decision problem. No explanation—state conclusion + implication directly.

2. CORE FRAMEWORK
Stepwise structure WITHOUT teaching language. Use diagnostic logic (finding → implication). Each step = decision checkpoint. No narrative connectors.

3. HIGH-YIELD RULES
Bullet points only. Include at least 2 🔑 rules. Format: finding → implication. Include thresholds when relevant. Must state what determines management.

4. NORMAL VS ABNORMAL
Only distinctions that change interpretation. Prefer paired contrasts (e.g., Lyme vs septic). No descriptive or explanatory sentences.

5. DIFFERENTIALS
Use TABLE format when 3+ differentials exist. Use BULLET LIST when 2 or fewer.

TABLE FORMAT (use when 3+ differentials):
| Diagnosis | Key Discriminator | Management Implication |
|-----------|-------------------|------------------------|
| 🟢 [most likely] | [imaging feature that distinguishes] | [what to do] |
| ⚪ [other] | [imaging feature that distinguishes] | [what to do] |
| ⚪ [other] | [imaging feature that distinguishes] | [what to do] |
| 🔴 [critical miss] | [why it mimics] | [consequence of missing] |

BULLET FORMAT (use when 2 or fewer differentials):
🟢 [most likely] → [discriminator] → [management implication]
⚪ [other] → [discriminator] → [management implication]
🔴 [critical miss] → [discriminator] → [management implication]

Each row/line must earn its position based on imaging discrimination. Compressed phrasing only. No paragraphs.

6. IMAGING STRATEGY
Best modality → why (single line). Sequence/phase → question answered. Only problem-solving steps.

7. REPORTING (ATTENDING LEVEL)
1–2 sentences maximum. Must read like a final report impression. Must include management implication.

8. PEARLS
Real-world misses only. Pattern or contrast format. No explanation.

9. EXAM TRAPS
Mandatory. Format strictly: pitfall → why wrong → how to avoid. No narrative.

10. FAILURE MODE
Direct outcome only. Focus on clinical harm, mismanagement, or surgical consequence.

11. RAPID RECALL
5–7 bullets maximum. Ultra-compressed anchors only. No explanation unless required for discrimination.

FORMAT RULES
No narrative flow between bullets or sections. No repetition across sections. No explanatory connectors. Replace prose with diagnostic shorthand whenever possible. If a line can be shortened → shorten it. If a line does not change a decision → delete it. Use 🔑 only for true decision-driving facts.

FINAL QUALITY CHECK (MANDATORY)
Before output: Remove all teaching language. Remove all redundancy. Convert sentences → diagnostic shorthand. Ensure every line affects diagnosis, management, or safety. If any line can be deleted without loss → delete it.

Now produce the digest using the 11-section structure above."""
    
    raw = await call_openai(req.api_key, system, prompt, max_tokens=4000)
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