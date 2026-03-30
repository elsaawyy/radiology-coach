# 🩻 Radiology Coach — Production Architecture

A full-stack, multi-user radiology training workspace with JWT auth, PostgreSQL persistence, and a DeepSeek-powered AI backend.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND                                 │
│  index.html (Vanilla JS + Syne/DM Mono fonts)                  │
│  • Auth screens (login / register)                              │
│  • Report Coach  →  POST /reports/polish                        │
│  • Paper Digest  →  POST /papers/digest                         │
│  • Libraries     →  GET  /reports  |  GET /papers               │
│  • DeepSeek key stored in sessionStorage (never sent to DB)     │
└──────────────────────────┬──────────────────────────────────────┘
                           │  HTTPS / REST JSON
┌──────────────────────────▼──────────────────────────────────────┐
│                        BACKEND  (FastAPI)                        │
│  main.py                                                         │
│  ├── /auth/register   POST  → bcrypt hash, JWT issue            │
│  ├── /auth/login      POST  → verify hash, JWT issue            │
│  ├── /auth/me         GET   → decode JWT → user info            │
│  ├── /reports/polish  POST  → proxy DeepSeek, optional DB save  │
│  ├── /reports         GET   → user's saved reports (paginated)  │
│  ├── /reports/:id     GET / PATCH / DELETE                      │
│  ├── /papers/digest   POST  → proxy DeepSeek, optional DB save  │
│  ├── /papers          GET   → user's saved papers (paginated)   │
│  └── /papers/:id      GET / DELETE                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │  asyncpg / SQLAlchemy
┌──────────────────────────▼──────────────────────────────────────┐
│                     PostgreSQL Database                          │
│  users   (id, email, password_hash, name, created_at, is_active)│
│  reports (id, user_id→FK, subspecialty, modality, mode,        │
│           input_text, impression, differentials, feedback,      │
│           raw_response, created_at, title)                      │
│  papers  (id, user_id→FK, input_mode, input_text, title,       │
│           summary, findings, implications, raw_response,        │
│           created_at)                                           │
└─────────────────────────────────────────────────────────────────┘
```

### Security design decisions
| Concern | Approach |
|---|---|
| Passwords | bcrypt hashed (cost factor 12), never stored in plaintext |
| Auth tokens | HS256 JWT, 7-day expiry, validated on every protected route |
| DeepSeek API key | Sent per-request, stored only in `sessionStorage` on client, **never persisted to DB** |
| User isolation | Every DB query filters by `user_id` from JWT — users can only see their own data |
| CORS | Configurable allow-list via `ALLOWED_ORIGINS` env var |

---

## Quick Start (Local Dev)

### Prerequisites
- Docker & Docker Compose
- Python 3.12+ (if running without Docker)
- A DeepSeek API key (`sk-...`)

### 1. Clone and configure

```bash
git clone <your-repo>
cd radiology-coach

cp backend/.env.example backend/.env
# Edit backend/.env:
#   JWT_SECRET=<run: openssl rand -hex 32>
#   DATABASE_URL is pre-filled for Docker
```

### 2. Start with Docker Compose

```bash
docker-compose up --build
# API available at: http://localhost:8000
# Docs (Swagger UI): http://localhost:8000/docs
```

### 3. Serve the frontend

```bash
# Any static server works:
cd frontend
python3 -m http.server 3000
# Open: http://localhost:3000
```

### 4. Use the app
1. Open `http://localhost:3000`
2. Register an account
3. Enter your DeepSeek API key in the key field
4. Start polishing reports!

---

## Running Backend Without Docker

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start a local Postgres (or use Railway/Supabase free tier):
export DATABASE_URL=postgresql://user:pass@localhost:5432/radiology_coach
export JWT_SECRET=$(openssl rand -hex 32)

uvicorn main:app --reload --port 8000
```

---

## Production Deployment

### Backend → Railway / Render / Fly.io

```bash
# Railway (recommended for FastAPI + Postgres):
railway login
railway init
railway add postgresql
railway up

# Set env vars in Railway dashboard:
# DATABASE_URL  → auto-set by Railway Postgres plugin
# JWT_SECRET    → openssl rand -hex 32
# ALLOWED_ORIGINS → https://your-frontend.com
```

### Frontend → Vercel / Netlify / Cloudflare Pages

```bash
# Update API_BASE in frontend/index.html:
const API_BASE = 'https://your-api.railway.app';

# Vercel:
vercel --prod
```

### Production checklist
- [ ] Set `JWT_SECRET` to a real 256-bit random string
- [ ] Set `ALLOWED_ORIGINS` to your frontend domain only
- [ ] Enable HTTPS on both frontend and backend
- [ ] Use a managed Postgres (Railway, Supabase, RDS)
- [ ] Add rate limiting (e.g. `slowapi` for FastAPI)
- [ ] Set up DB backups
- [ ] Consider storing DeepSeek key server-side per-user (encrypted) for better UX

---

## API Reference (auto-generated)

Visit `http://localhost:8000/docs` for the full interactive Swagger UI after starting the backend.

Key endpoints:
```
POST /auth/register      { email, password, name? }
POST /auth/login         { email, password }
GET  /auth/me            → current user info

POST /reports/polish     { mode, subspecialty, modality, input_text, api_key, save? }
GET  /reports            → list user's reports
GET  /reports/:id        → single report
PATCH /reports/:id       { title }
DELETE /reports/:id

POST /papers/digest      { input_mode, input_text, api_key, save? }
GET  /papers             → list user's papers
GET  /papers/:id         → single paper
DELETE /papers/:id
```

---

## File Structure

```
radiology-coach/
├── backend/
│   ├── main.py            ← FastAPI app (all routes, DB models, DeepSeek proxy)
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   └── index.html         ← Single-file frontend (auth + all 3 tabs)
├── docker-compose.yml     ← Postgres + API + (optional) Nginx
└── README.md
```

---

## Extending the System

**Add password reset**: Add a `password_reset_tokens` table + email sending (FastMail).  
**Add team/org support**: Add an `organizations` table and `org_id` FK on users/reports.  
**Encrypt stored API keys**: Use `cryptography.fernet` with a server-side key to optionally persist users' DeepSeek keys.  
**Add search**: PostgreSQL full-text search on `reports.impression` and `papers.summary`.  
**Rate limiting**: `pip install slowapi` and add a limiter to the `/reports/polish` and `/papers/digest` routes.
