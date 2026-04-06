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
from typing import Optional, List, Tuple
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import httpx
import re
import json as json_lib

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
    Column("user_prompt",  Text, nullable=True),  # ADDED: store custom prompt
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
    Column("user_prompt",  Text, nullable=True),  # ADDED: store custom prompt
)

engine = sqlalchemy.create_engine(DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://"))

# ─── LIFESPAN ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    metadata.create_all(engine)
    
    # Add user_prompt column to existing tables (safe — IF NOT EXISTS means no crash if already there)
    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text(
                "ALTER TABLE reports ADD COLUMN IF NOT EXISTS user_prompt TEXT"
            ))
            conn.execute(sqlalchemy.text(
                "ALTER TABLE papers ADD COLUMN IF NOT EXISTS user_prompt TEXT"
            ))
            conn.commit()
            print("✅ Database migration: user_prompt columns ensured")
    except Exception as e:
        print(f"Migration note: {e}")
    
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
    user_prompt: Optional[str] = None  # ADDED: custom prompt from frontend

class DigestRequest(BaseModel):
    input_mode: str
    input_text: str
    api_key: str
    save: bool = False
    user_prompt: Optional[str] = None  # ADDED: custom prompt from frontend

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
    max_tokens: int = 6000,
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
                "max_tokens": max_tokens,
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

# ─── PARSING HELPERS (ENHANCED WITH ALIASES) ─────────────────────────────────
def parse_section(text: str, labels: list) -> str:
    """Parse section with multiple label aliases — strips header from content."""
    for label in labels:
        patterns = [
            # Numbered bold: 1. **LABEL** or **1. LABEL**
            rf'\d+\.\s*\*\*{re.escape(label)}\*\*\s*\n([\s\S]*?)(?=\n\d+\.\s*\*\*[A-Z]|\n\*\*[A-Z]|\Z)',
            # Bold only: **LABEL**
            rf'\*\*{re.escape(label)}\*\*\s*\n([\s\S]*?)(?=\n\*\*[A-Z]|\n\d+\.\s*\*\*|\Z)',
            # Plain: LABEL:
            rf'{re.escape(label)}[:\s]*\n([\s\S]*?)(?=\n[A-Z#]|\Z)',
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                # Get the content group and clean it
                content = m.group(1).strip()
                # Remove leading/trailing --- dividers
                content = re.sub(r'^---\s*', '', content).strip()
                content = re.sub(r'\s*---$', '', content).strip()
                return content
    return ""


def parse_report_section(text: str, labels: list) -> str:
    """Parse report section — strips header from content."""
    for label in labels:
        pattern = rf'\*{{0,2}}{re.escape(label)}\*{{0,2}}[:\s]*\n([\s\S]*?)(?=\n\*{{0,2}}[A-Z]|\Z)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            content = match.group(1).strip()
            # Remove --- dividers
            content = re.sub(r'^---\s*', '', content).strip()
            content = re.sub(r'\s*---$', '', content).strip()
            return content
    return ""

# ─── JSON SCHEMAS FOR STRUCTURED PARSING ─────────────────────────────────────
JSON_SCHEMAS = {
    "report_mode_a": {
        "impression": "Polished, definitive impression paragraph (2-4 sentences)",
        "differentials": "Three prioritized differentials with imaging rationale",
        "feedback": "Clinico-radiographic reasoning (3-5 sentences)",
        "audit": "Weak phrase → strong replacement pairs, one per line",
    },
    "paper_digest": {
        "why_this_matters": "1-2 sentences on why this topic affects radiology practice",
        "core_concept": "The single most important idea",
        "key_imaging_findings": "Modality-specific findings with hallmark features",
        "decision_drivers": "Findings that change management with thresholds",
        "differentials": "Prioritized differentials with discriminators (2-4 max)",
        "pitfalls": "Common misinterpretations, mimics, and technical traps",
        "bottom_line": "What to remember on call or boards (1-2 sentences)",
    },
}

JSON_WRAPPER = """
---
CRITICAL OUTPUT FORMAT INSTRUCTION - THIS OVERRIDES ALL OTHER FORMATTING:
Respond ONLY with a valid JSON object. No markdown fences, no text outside the JSON.
Use exactly these keys: {keys}

Field descriptions:
{field_descriptions}

Your response must be parseable by Python's json.loads(). 
Use \\n for newlines inside strings. Do not add any text before or after the JSON.
"""

EXTRACTION_PROMPT = """You are a data extraction assistant. Given the following radiology AI output, extract and return ONLY a JSON object with these exact keys:

{json_schema}

Rules:
- If a field's content is absent from the text, use null for that field.
- Preserve the original wording exactly - do not paraphrase or summarize.
- Return ONLY the JSON object, no other text before or after.

TEXT TO EXTRACT FROM:
{raw_text}"""

async def extract_structure_with_llm(raw: str, feature_key: str, api_key: str) -> dict:
    """Second-pass extraction when primary parsing yields empty results."""
    schema = JSON_SCHEMAS.get(feature_key, {})
    if not schema:
        return {}
    
    schema_desc = "\n".join(f'"{k}": {v}' for k, v in schema.items())
    prompt = EXTRACTION_PROMPT.format(
        json_schema=schema_desc,
        raw_text=raw[:4000],  # Keep it cheap
    )
    
    try:
        reextraction_raw = await call_openai(
            api_key,
            "You are a precise JSON extraction assistant. Respond only with valid JSON.",
            prompt,
            max_tokens=2000,
            temperature=0.0,
        )
        
        # Clean and parse
        clean = reextraction_raw.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        if clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        clean = clean.strip()
        
        return json_lib.loads(clean)
    except Exception as e:
        print(f"LLM re-extraction failed: {e}")
        return {}

def parse_quality_score(parsed: dict, feature_key: str) -> dict:
    """Returns quality metrics about the parsed result."""
    schema_keys = list(JSON_SCHEMAS.get(feature_key, {}).keys())
    if not schema_keys:
        return {"score": 1.0, "degraded": False}
    
    filled = sum(1 for k in schema_keys if parsed.get(k))
    total = len(schema_keys)
    score = filled / total if total else 1.0
    
    return {
        "score": score,
        "filled_fields": filled,
        "total_fields": total,
        "degraded": score < 0.5,
    }

def stringify_parsed_values(parsed: dict) -> dict:
    """
    Ensure all values in the parsed dict are strings, not lists or dicts.
    The AI sometimes returns arrays for fields like 'differentials'.
    The database expects plain text for all columns.
    """
    result = {}
    for key, value in parsed.items():
        if value is None:
            result[key] = ""
        elif isinstance(value, list):
            # Join list items with newlines — preserves readability
            result[key] = "\n".join(
                str(item) if not isinstance(item, dict) 
                else "\n".join(f"{k}: {v}" for k, v in item.items())
                for item in value
            )
        elif isinstance(value, dict):
            # Convert dict to readable key: value lines
            result[key] = "\n".join(f"{k}: {v}" for k, v in value.items())
        else:
            result[key] = str(value)
    return result


async def parse_llm_response(
    raw: str, 
    feature_key: str, 
    output_format: str,
    api_key: Optional[str] = None,
    user_prompt: Optional[str] = None
) -> dict:
    """
    Universal parser - tries JSON first, then regex, then LLM re-extraction.
    """
    
    # TRY 1: JSON parsing (if we requested JSON format)
    if output_format == "json":
        try:
            clean = raw.strip()
            if clean.startswith("```json"):
                clean = clean[7:]
            if clean.startswith("```"):
                clean = clean[3:]
            if clean.endswith("```"):
                clean = clean[:-3]
            clean = clean.strip()
            
            parsed = json_lib.loads(clean)
            
            # Validate that we got all expected keys
            expected_keys = JSON_SCHEMAS.get(feature_key, {}).keys()
            if expected_keys:
                for key in expected_keys:
                    if key not in parsed:
                        parsed[key] = ""
            
            return parsed
            
        except json_lib.JSONDecodeError as e:
            print(f"JSON parse failed: {e}")
            pass
    
    # TRY 2: Regex parsing (existing behavior with enhanced aliases)
    parsed = {}
    if feature_key == "report_mode_a":
        parsed = {
            "impression": parse_report_section(raw, ["IMPRESSION", "FINAL IMPRESSION", "CONCLUSION", "ASSESSMENT", "SUMMARY"]),
            "differentials": parse_report_section(raw, ["DIFFERENTIAL DIAGNOSIS", "DIFFERENTIALS", "DDX", "DIFFERENTIAL"]),
            "feedback": parse_report_section(raw, ["REASONING", "RATIONALE", "CLINICAL REASONING", "EXPLANATION", "TEACHING POINTS"]),
            "audit": parse_report_section(raw, ["LANGUAGE UPGRADE AUDIT", "LANGUAGE AUDIT", "LANGUAGE IMPROVEMENTS", "PHRASING AUDIT"]),
        }
    elif feature_key == "paper_digest":
        parsed = {
            "why_this_matters": parse_section(raw, ["WHY THIS MATTERS", "1. WHY THIS MATTERS", "Why This Matters"]),
            "core_concept": parse_section(raw, ["CORE CONCEPT", "2. CORE CONCEPT", "Core Concept"]),
            "key_imaging_findings": parse_section(raw, ["KEY IMAGING FINDINGS", "3. KEY IMAGING FINDINGS", "Key Imaging Findings"]),
            "decision_drivers": parse_section(raw, ["WHAT ACTUALLY MATTERS", "DECISION DRIVERS", "4. WHAT ACTUALLY MATTERS", "What Actually Matters", "Decision Drivers"]),
            "differentials": parse_section(raw, ["DIFFERENTIAL DIAGNOSIS", "5. DIFFERENTIAL DIAGNOSIS", "Differential Diagnosis"]),
            "pitfalls": parse_section(raw, ["PITFALLS", "6. PITFALLS", "Pitfalls", "HIGH-YIELD MISSES"]),
            "bottom_line": parse_section(raw, ["BOTTOM LINE", "7. BOTTOM LINE", "Bottom Line"]),
        }  # ← THIS CLOSING BRACKET WAS MISSING!
    
    # TRY 3: LLM re-extraction (safety net for custom prompts)
    if user_prompt and api_key:
        quality = parse_quality_score(parsed, feature_key)
        if quality["degraded"]:
            print(f"Parse degraded ({quality['score']:.0%}), attempting LLM re-extraction...")
            llm_parsed = await extract_structure_with_llm(raw, feature_key, api_key)
            if llm_parsed:
                parsed.update(llm_parsed)
                parsed["_reextracted"] = True
    
    return parsed


# ─── REPORT COACH ────────────────────────────────────────────────────────────
@app.post("/reports/polish")
async def polish_report(req: PolishRequest, user=Depends(get_current_user)):
    system = """You are an elite, U.S.-trained senior radiologist with subspecialty expertise. You produce final-signature quality reports with structured, actionable impressions."""

    feature_key = "report_mode_a"
    
    # Build prompt with JSON mode enabled
    if req.user_prompt:
        # User provided custom prompt
        template = req.user_prompt
        if "{{input}}" in template:
            prompt = template.replace("{{input}}", req.input_text)
        else:
            prompt = f"{template}\n\nINPUT TEXT:\n{req.input_text}"
        
        # Add JSON wrapper for structured output
        schema = JSON_SCHEMAS[feature_key]
        wrapper = JSON_WRAPPER.format(
            keys=", ".join(f'"{k}"' for k in schema.keys()),
            field_descriptions="\n".join(f'  "{k}": {v}' for k, v in schema.items()),
        )
        prompt = prompt + wrapper
        output_format = "json"
    else:
        # Use default prompt
        if req.mode == "a":
            prompt = f"""You are a US-trained senior radiologist at final signature level. 
            
Analyze this radiology report and produce ONLY the structured output below. Do NOT repeat the original report.

ORIGINAL REPORT:
{req.input_text}

PROHIBITED LANGUAGE (never use these):
- "could represent", "possibly", "cannot rule out", "clinical correlation recommended"
- "suggesting", "may represent", "suggestive of", "likely representing"

OUTPUT EXACTLY THESE 4 SECTIONS — nothing before, nothing after:

**IMPRESSION**
Write 2-4 sentences. State the primary diagnosis with confidence. Do NOT restate findings — interpret them. Include follow-up recommendation only if clinically necessary (specific modality + timeframe).
Format: Direct, declarative sentences. No bullet points here.

**DIFFERENTIAL DIAGNOSIS**
List 3 prioritized differentials. Each must follow this format:
1. [Diagnosis] — [specific imaging feature that supports it] + [what makes it more/less likely]
2. [Diagnosis] — [specific imaging feature that supports it] + [what makes it more/less likely]  
3. [Diagnosis] — [specific imaging feature that supports it] + [what makes it more/less likely]

**REASONING**
Write 3-5 sentences explaining the clinico-radiographic reasoning. Connect the imaging pattern to the diagnosis. Mention what findings were used and what was excluded. This is the "thinking out loud" section for teaching.

**LANGUAGE UPGRADE AUDIT**
List 3-5 weak phrases found in the original report → replace with strong attending-level phrasing.
Format: "weak phrase" → "strong replacement"

Now produce the output for the report above. Start directly with **IMPRESSION**."""
        else:
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
        output_format = "text"

    raw = await call_openai(req.api_key, system, prompt, max_tokens=6000)

    # Parse response using universal parser
    parsed = await parse_llm_response(
        raw, 
        feature_key, 
        output_format,
        api_key=req.api_key if req.user_prompt else None,
        user_prompt=req.user_prompt
    )
    
    parsed = stringify_parsed_values(parsed)
    
    if req.mode == "a":
        result = {
            "impression": parsed.get("impression", ""),
            "differentials": parsed.get("differentials", ""),
            "feedback": parsed.get("feedback", ""),
            "audit": parsed.get("audit", ""),
            "raw": raw,
            "saved": False,
            "id": None,
            "reextracted": parsed.get("_reextracted", False),
        }
    else:
        # Mode B - just return raw
        result = {
            "impression": raw,
            "differentials": "",
            "feedback": "",
            "audit": "",
            "raw": raw,
            "saved": False,
            "id": None,
            "reextracted": False,
        }

    if req.save:
        rid = await database.execute(reports.insert().values(
            user_id=user["id"],
            subspecialty=req.subspecialty,
            modality=req.modality,
            mode="impression_only" if req.mode == "a" else "full_report",
            input_text=req.input_text,
            impression=result["impression"],
            differentials=result["differentials"],
            feedback=result["feedback"],
            raw_response=raw,
            title=req.title or f"{req.subspecialty} · {req.modality}",
            user_prompt=req.user_prompt,  # Save custom prompt
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
    system = """You are an elite radiology-focused clinical summarizer, trained at a top academic center.
Your job is to convert long articles into high-yield, decision-focused summaries for a radiology fellow. 
The goal is rapid pattern recognition, reporting accuracy, and clinical relevance.

CORE PRIORITY:
Extract and prioritize information that directly impacts:
- Imaging interpretation
- Differential diagnosis
- Reporting language
- Clinical management decisions

Writing style:
- High signal, zero fluff
- Structured like an attending teaching a fellow
- Clear, decisive, non-redundant
- Use radiology terminology appropriately
- Avoid vague phrases (e.g., "may represent" unless necessary)

RULES:
- Do NOT summarize everything — prioritize what impacts diagnosis and management
- DO extract every specific number, threshold, percentage, and measurement 
  from the source text — these are the highest-yield facts
- DO include recent study data and RCT results when present in the article
- DO flag when the article contradicts commonly held beliefs 
  (e.g. actual tear location vs classic teaching)
- Do NOT restate obvious background information
- Do NOT include long anatomy sections unless clinically relevant
- Convert descriptive text into pattern recognition
- If the article is weak or overly descriptive, explicitly compress it to what matters clinically"""

    feature_key = "paper_digest"

    # Build prompt with JSON mode if custom prompt is provided
    if req.user_prompt:
        template = req.user_prompt
        if "{{input}}" in template:
            prompt = template.replace("{{input}}", req.input_text)
        else:
            prompt = f"{template}\n\nINPUT TEXT:\n{req.input_text}"

        # Add JSON wrapper for structured output
        schema = JSON_SCHEMAS[feature_key]
        wrapper = JSON_WRAPPER.format(
            keys=", ".join(f'"{k}"' for k in schema.keys()),
            field_descriptions="\n".join(f'  "{k}": {v}' for k, v in schema.items()),
        )
        prompt = prompt + wrapper
        output_format = "json"
    else:
        # NEW DEFAULT PROMPT
        prompt = f"""You are an elite radiology-focused clinical summarizer, trained at a top academic center.

Your job is to convert long articles into high-yield, decision-focused summaries for a radiology fellow. The goal is rapid pattern recognition, reporting accuracy, and clinical relevance.

CORE PRIORITY:
Extract and prioritize information that directly impacts:
- Imaging interpretation
- Differential diagnosis
- Reporting language
- Clinical management decisions

Writing style:
- High signal, zero fluff
- Structured like an attending teaching a fellow
- Clear, decisive, non-redundant
- Use radiology terminology appropriately
- Avoid vague phrases (e.g., "may represent" unless necessary)

OUTPUT STRUCTURE (STRICT):

1. Why This Matters (1–2 sentences)
   - Focus on how this topic affects radiology practice or decision-making

2. Core Concept
   - The single most important idea

3. Key Imaging Findings
   - Modality-specific (MRI/CT/XR/US)
   - Include hallmark features
   - Include critical negatives when relevant

4. What Actually Matters (Decision Drivers)
   - Findings that change management
   - Thresholds (e.g., size, location, % tear, signal pattern)
   - Surgical vs non-surgical implications

5. Differential Diagnosis (only if relevant)
   - Prioritized (2–4 max)
   - Include discriminators

6. Pitfalls (High-Yield Misses)
   - Common misinterpretations
   - Mimics
   - Technical traps

7. Bottom Line (1–2 sentences)
   - What you should remember on call / boards

RULES:
- Do NOT summarize everything—prioritize what impacts diagnosis and management
- Do NOT restate obvious background information
- Do NOT include long anatomy sections unless clinically relevant
- Convert descriptive text into pattern recognition
- If the article is weak or overly descriptive, explicitly compress it to what matters clinically

OPTIONAL (when applicable):
- Include imaging thresholds or classification systems
- Include "report-ready phrasing"

Make the output feel like a senior attending dictating a high-yield teaching readout.

ARTICLE:
{req.input_text}

Produce the digest now using the exact 7-section structure above. Do not skip any section."""
        output_format = "text"

    raw = await call_openai(req.api_key, system, prompt, max_tokens=6000)

    # Parse response using universal parser
    parsed = await parse_llm_response(
        raw,
        feature_key,
        output_format,
        api_key=req.api_key if req.user_prompt else None,
        user_prompt=req.user_prompt
    )

    parsed = stringify_parsed_values(parsed)

    result = {
        "why_this_matters": parsed.get("why_this_matters", ""),
        "core_concept": parsed.get("core_concept", ""),
        "key_imaging_findings": parsed.get("key_imaging_findings", ""),
        "decision_drivers": parsed.get("decision_drivers", ""),
        "differentials": parsed.get("differentials", ""),
        "pitfalls": parsed.get("pitfalls", ""),
        "bottom_line": parsed.get("bottom_line", ""),
        "raw": raw,
        "saved": False,
        "id": None,
        "reextracted": parsed.get("_reextracted", False),
    }

    if req.save:
        pid = await database.execute(papers.insert().values(
            user_id=user["id"],
            input_mode=req.input_mode,
            title=req.input_text[:120],
            summary=result["bottom_line"],           # Bottom line
            findings=result["decision_drivers"],     # Decision drivers
            implications=result["pitfalls"],         # Pitfalls
            raw_response=raw,
            user_prompt=req.user_prompt,
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

# ─── STATIC FILES ────────────────────────────────────────────────────────────
from fastapi.staticfiles import StaticFiles

# Serve frontend files
frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
    print(f"✅ Frontend mounted at / from {frontend_path}")
else:
    print(f"❌ Frontend not found at {frontend_path}")
    if os.path.exists("/app/frontend"):
        app.mount("/", StaticFiles(directory="/app/frontend", html=True), name="frontend")
        print("✅ Frontend mounted from /app/frontend")

# ─── DEBUG ENDPOINT (remove after testing) ───────────────────────────────────
@app.post("/debug/digest-raw")
async def debug_digest_raw(req: DigestRequest, user=Depends(get_current_user)):
    """Returns raw model output so we can see exactly what the model produces."""
    
    MAX_INPUT_CHARS = 6000
    input_text = req.input_text
    if len(input_text) > MAX_INPUT_CHARS:
        input_text = input_text[:MAX_INPUT_CHARS] + "\n\n[Truncated]"

    system = """You are a US-trained senior radiology attending at final readout level...
    [your existing system prompt]
    """

    prompt = f"""Digest this radiology article/case:
{input_text}
[your existing prompt structure]
"""

    raw = await call_openai(req.api_key, system, prompt, max_tokens=4000)

    # Count which sections were found
    sections_found = []
    sections_missing = []
    for section in ["BOTTOM LINE", "HOW TO SEE IT", "THE RULES", "DIFFERENTIALS", 
                    "IMAGING", "REPORT", "DON'T MISS", "QUICK HITS"]:
        if section in raw.upper():
            sections_found.append(section)
        else:
            sections_missing.append(section)

    return {
        "raw": raw,
        "token_estimate": len(raw.split()),
        "char_count": len(raw),
        "sections_found": sections_found,
        "sections_missing": sections_missing,
        "model_cut_off": len(sections_missing) > 0,
    }