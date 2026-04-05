# prompt_builder.py - CREATE THIS NEW FILE
"""
Centralized prompt construction for all AI features.
Rule: user_prompt is ALWAYS optional. Absence = existing behavior.
"""

import json
from typing import Optional, Tuple

# Fixed system guardrail — always prepended, never user-overridable
SYSTEM_GUARDRAIL = (
    "You are a professional radiology AI assistant producing accurate, "
    "structured, and clinically useful outputs."
)

MAX_PROMPT_CHARS = 12_000   # rough token safety ceiling (~3k tokens)

# ── Default prompts (verbatim from main.py, kept here as source of truth) ──

DEFAULTS = {
    "report_mode_a": """You are a US-trained senior radiologist at final signature level. 
        
Analyze this radiology report and produce ONLY the structured output below. Do NOT repeat the original report.

ORIGINAL REPORT:
{{input}}

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

Now produce the output for the report above. Start directly with **IMPRESSION**.""",

    "report_mode_b": """You are a senior radiologist polishing a full radiology report. PRESERVE THE ORIGINAL STRUCTURE EXACTLY.

ORIGINAL REPORT:
{{input}}

RULES:
1. Keep ALL sections exactly as written (Patient Information, Imaging Study, Findings)
2. ONLY improve the IMPRESSION section
3. Format impression as numbered bullets (1., 2., 3.)
4. Use proper confidence language
5. PROHIBITED: "could represent", "possibly", "cannot rule out", "clinical correlation recommended"
6. Add management implications when appropriate

OUTPUT: Return the COMPLETE report with original structure preserved, only IMPRESSION improved.""",

    "paper_digest": """Digest this radiology article/case into a comprehensive teaching digest:

{{input}}

OUTPUT STRUCTURE — use EXACTLY these 8 sections, numbered and bolded. Follow every instruction per section precisely.

---

1. **BOTTOM LINE**
Write 2–3 sentences maximum. Format:
- Sentence 1: [Key pathology] with [specific measurement] → [surgical decision].
- Sentence 2: [Most important threshold] that changes management.
- Sentence 3 (optional): [Most common clinical pitfall].

---

2. **HOW TO SEE IT**
Minimum 7 bullets. Each bullet MUST follow this format:
- [Sign name]: [how to identify it on imaging] → [surgical or clinical implication]
Mark 🔑 on the single most decision-driving sign.
Include: morphology, measurement technique, location, tissue quality signs, secondary signs, acuity markers, chronicity markers.

---

3. **THE RULES**
Minimum 6 lines. Each line MUST follow EXACTLY this format:
- [Measurement/finding] [threshold] → [surgical action] → [outcome/label]
Cover the full spectrum from mild to severe. Mark 🔑 on the rule that most commonly changes surgical approach.
Example format: Gap <2 cm → primary end-to-end repair → standard approach 🔑

---

4. **DIFFERENTIALS**
Markdown table with EXACTLY these columns: | Diagnosis | Key Discriminator | Next Step |
Minimum 6 rows. Use 🟢 for most likely (1 row), ⚪ for alternatives (4+ rows), 🔴 for critical miss (1 row).
Each discriminator must be a SPECIFIC imaging finding, not a generic description.
Each next step must be a SURGICAL or MANAGEMENT action.

---

5. **IMAGING**
Minimum 5 bullets. Each bullet MUST follow this format:
- [Modality/Sequence] → [specific finding it shows] → [surgical implication]
Cover: MRI sequences (T1, T2, T2 FS, STIR, contrast), ultrasound, CT, X-ray if relevant.
Include what each sequence adds that others cannot.

---

6. **REPORT**
Write a complete, ready-to-paste attending-level radiology report.

FINDINGS:
Write 4–6 sentences. Include: location (precise anatomy), size/gap measurement, tissue quality, secondary signs, comparison if relevant.

IMPRESSION:
Write 2–3 sentences. State diagnosis, severity grade, and direct surgical recommendation.

---

7. **DON'T MISS**
Minimum 5 bullets. Each bullet MUST follow this format:
- [Specific error] → [consequence] → [how to avoid it]
Focus on errors that lead to wrong surgery, delayed treatment, or patient harm.

---

8. **QUICK HITS**
Minimum 8 bullets. Short, dense, board-style facts.
Each bullet = one memorable fact with a number or threshold.
Format: plain bullets, no sub-structure needed.

---

Produce the full digest now. Do not skip sections. Do not truncate. Be exhaustive.""",
}

# ── JSON SCHEMAS for structured parsing ──────────────────────────────────────
JSON_SCHEMAS = {
    "report_mode_a": {
        "impression": "Polished, definitive impression paragraph (2-4 sentences)",
        "differentials": "Three prioritized differentials with imaging rationale",
        "feedback": "Clinico-radiographic reasoning (3-5 sentences)",
        "audit": "Weak phrase → strong replacement pairs, one per line",
    },
    "report_mode_b": {
        "impression": "Polished impression paragraph",
        "differentials": "Prioritized differentials",
        "feedback": "Clinical reasoning",
        "audit": "Language improvements",
    },
    "paper_digest": {
        "bottom_line": "2-3 sentence summary of the key finding",
        "how_to_see_it": "Signs with identification and implications",
        "the_rules": "Measurement thresholds with actions",
        "differentials": "Table of diagnoses with discriminators",
        "imaging": "Modality findings with implications",
        "report": "Complete attending-level radiology report",
        "dont_miss": "Errors with consequences and avoidance",
        "quick_hits": "Board-style facts with numbers",
    },
}

# ── JSON wrapper instruction ─────────────────────────────────────────────────
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

# ── Helper functions ─────────────────────────────────────────────────────────
def inject_input(prompt_template: str, input_text: str) -> str:
    """Safe input injection. If {{input}} placeholder exists → substitute it."""
    if "{{input}}" in prompt_template:
        return prompt_template.replace("{{input}}", input_text)
    return f"{prompt_template.rstrip()}\n\nINPUT:\n{input_text}"

def sanitize(text: str) -> str:
    """Strip null bytes; truncate to token safety ceiling."""
    text = text.replace("\x00", "")
    if len(text) > MAX_PROMPT_CHARS:
        text = text[:MAX_PROMPT_CHARS] + "\n\n[Truncated — prompt exceeded safe limit]"
    return text

def build_system_message(feature_system: Optional[str] = None) -> str:
    """System message always starts with the fixed guardrail."""
    if feature_system:
        return f"{SYSTEM_GUARDRAIL}\n\n{feature_system}"
    return SYSTEM_GUARDRAIL

def build_prompt(
    feature_key: str,
    input_text: str,
    user_prompt: Optional[str] = None,
    use_json_mode: bool = True,
) -> Tuple[str, str]:
    """
    Main entry point for all endpoints.
    
    Returns:
        Tuple of (assembled_prompt, output_format)
        output_format is either "json" or "text"
    """
    # 1. Choose template: user-supplied or hardcoded default
    template = sanitize(user_prompt) if user_prompt and user_prompt.strip() else DEFAULTS[feature_key]

    # 2. Inject input safely
    assembled = inject_input(template, input_text)

    # 3. Add JSON wrapper if JSON mode is enabled AND feature has schema
    if use_json_mode and feature_key in JSON_SCHEMAS:
        schema = JSON_SCHEMAS[feature_key]
        wrapper = JSON_WRAPPER.format(
            keys=", ".join(f'"{k}"' for k in schema.keys()),
            field_descriptions="\n".join(f'  "{k}": {v}' for k, v in schema.items()),
        )
        return sanitize(assembled + wrapper), "json"

    # 4. No JSON mode - return plain text
    return sanitize(assembled), "text"

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