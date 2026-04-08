# 🩻 Radiology Coach

**An AI-powered radiology training workspace for fellows and attendings.**

Radiology Coach is a full-stack web application that helps radiologists polish reports, generate high-yield paper digests, and build a personal knowledge library — all backed by a secure, authenticated API.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [Running with Docker Compose](#running-with-docker-compose)
  - [Running Locally without Docker](#running-locally-without-docker)
- [API Reference](#api-reference)
  - [Authentication](#authentication)
  - [Report Polisher](#report-polisher)
  - [Paper Digest](#paper-digest)
  - [AI Library](#ai-library)
  - [Manual Library](#manual-library)
- [Database Schema](#database-schema)
- [Frontend Guide](#frontend-guide)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Deployment](#deployment)

---

## Features

### 🤖 AI Report Polisher
Paste a rough radiology impression or full draft report and get back:
- **Mode A — Impression Only:** Polished impression + Top 3 differentials + clinico-radiographic reasoning + language upgrade audit
- **Mode B — Full Report:** Complete report restructured with improved impression section
- Custom prompt editor with templates (Senior, Teaching, Concise modes)

### 📚 AI Paper Digest
Paste a paper title, URL/DOI, or full abstract and receive a structured 7-section teaching digest:
- Why This Matters · Core Concept · Key Imaging Findings · Decision Drivers · Differentials · Pitfalls · Bottom Line
- Custom prompt editor for tailored output style

### 🗃️ AI Library (Auto-saved)
Automatically saves every AI-generated report and digest. Supports search, Word export, and JSON export.

### 📝 Manual Library *(new)*
A completely separate, user-managed library for saving any radiology content manually:
- Save **Reports** and **Papers** with category tagging (NEURO / MSK / BODY / OTHERS)
- Filter by category, search by title or content
- Add optional source URL and comma-separated tags
- Edit and delete entries
- Export individual items or the full library to formatted Word documents (.doc)

### 🔐 Authentication
Full JWT-based auth with registration, login, 7-day token expiry, and per-user data isolation.

### 🌙 Dark / Light Mode
Full theme switching persisted in localStorage.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Browser                            │
│              index.html (Vanilla JS SPA)                │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTPS / REST JSON
┌───────────────────────▼─────────────────────────────────┐
│              FastAPI Backend  (Python 3.12)              │
│   Auth · Report Polisher · Paper Digest · Libraries     │
│                  Uvicorn ASGI server                    │
└───────────┬───────────────────────┬─────────────────────┘
            │                       │
┌───────────▼──────────┐   ┌────────▼────────────────────┐
│  PostgreSQL 16        │   │  OpenAI API  (user key)     │
│  (via asyncpg /       │   │  gpt-4o-mini                │
│   databases library)  │   │  Called per-request         │
└──────────────────────┘   └─────────────────────────────┘
```

- The **frontend** is a single `index.html` file served as a static file by FastAPI itself — no separate web server needed.
- **OpenAI API keys** are provided by the user at runtime and are never stored server-side.
- All database access is **async** via the `databases` + `asyncpg` stack on top of SQLAlchemy Core.

---

## Project Structure

```
radiology-coach/
├── backend/
│   ├── main.py              # FastAPI app — all routes, DB models, AI proxy
│   ├── prompt_builder.py    # Centralised prompt construction helpers
│   ├── requirements.txt     # Python dependencies
│   ├── Dockerfile           # Backend container image
│   ├── .env                 # Runtime secrets (never commit)
│   ├── .env.example         # Template for .env
│   └── init-db.sql          # PostgreSQL init script (run once by Docker)
├── frontend/
│   └── index.html           # Complete single-page application
└── docker-compose.yml       # Orchestrates db + api services
```

---

## Getting Started

### Prerequisites

| Tool | Version |
|------|---------|
| Docker | 24+ |
| Docker Compose | v2+ |
| Python | 3.12+ *(local dev only)* |
| PostgreSQL | 16 *(local dev only)* |

An **OpenAI API key** (`sk-...`) is required at runtime for AI features. Keys are entered in the UI and used directly — they are never persisted.

---

### Environment Variables

Copy `.env.example` to `.env` inside the `backend/` folder and fill in your values:

```bash
cp backend/.env.example backend/.env
```

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | Full PostgreSQL connection string | `postgresql://radcoach:strongpassword@db:5432/radiology_coach` |
| `JWT_SECRET` | 256-bit random string for signing tokens | `openssl rand -hex 32` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `http://localhost:3000` |
| `APP_ENV` | `development` or `production` | `development` |

> ⚠️ **Never commit your `.env` file to version control.** It is already listed in `.gitignore`.

---

### Running with Docker Compose

This is the recommended way to run the full stack locally.

```bash
# 1. Clone the repository
git clone https://github.com/your-org/radiology-coach.git
cd radiology-coach

# 2. Create your .env file
cp backend/.env.example backend/.env
# Edit backend/.env and set a real JWT_SECRET

# 3. Build and start all services
docker compose up --build

# 4. Open the app
open http://localhost:8000
```

Docker Compose starts two services:

| Service | Port | Description |
|---------|------|-------------|
| `db` | 5432 | PostgreSQL 16 with persistent volume |
| `api` | 8000 | FastAPI + Uvicorn, serves the frontend too |

The database is initialised automatically on first run via `init-db.sql`. All tables are created by SQLAlchemy on startup — no manual migrations needed.

To stop:
```bash
docker compose down          # stop containers
docker compose down -v       # stop and delete the database volume
```

---

### Running Locally without Docker

```bash
# 1. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Create a local PostgreSQL database
createdb radiology_coach
psql radiology_coach < backend/init-db.sql

# 4. Set environment variables
export DATABASE_URL="postgresql://your_user:your_pass@localhost:5432/radiology_coach"
export JWT_SECRET="your-random-secret"

# 5. Copy the frontend into the backend folder
cp -r frontend backend/frontend

# 6. Start the server
cd backend
uvicorn main:app --reload --port 8000
```

The app is now available at `http://localhost:8000`.

---

## API Reference

All protected endpoints require the header:
```
Authorization: Bearer <access_token>
```

Base URL: `https://your-domain.com` (or `http://localhost:8000` locally)

---

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | ❌ | Create account. Body: `{ email, password, name }` |
| `POST` | `/auth/login` | ❌ | Sign in. Body: `{ email, password }` → returns `access_token` |
| `GET` | `/auth/me` | ✅ | Returns current user info |

---

### Report Polisher

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/reports/polish` | ✅ | Polish a report. Returns structured AI output |
| `GET` | `/reports` | ✅ | List all saved AI reports for current user |
| `GET` | `/reports/{id}` | ✅ | Get single report |
| `PATCH` | `/reports/{id}` | ✅ | Update report title |
| `DELETE` | `/reports/{id}` | ✅ | Delete report |

**POST `/reports/polish` body:**
```json
{
  "mode": "a",
  "subspecialty": "Neuro",
  "modality": "MRI",
  "input_text": "Ring-enhancing lesion right temporal lobe...",
  "api_key": "sk-...",
  "save": true,
  "title": "Optional custom title",
  "user_prompt": null
}
```

---

### Paper Digest

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/papers/digest` | ✅ | Generate a paper digest |
| `GET` | `/papers` | ✅ | List all saved AI digests |
| `GET` | `/papers/{id}` | ✅ | Get single digest |
| `DELETE` | `/papers/{id}` | ✅ | Delete digest |

---

### AI Library

The `/reports` and `/papers` endpoints above serve the AI-generated library. See Report Polisher and Paper Digest sections.

---

### Manual Library

All manual library endpoints follow the same pattern for both `reports` and `papers`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/manual/reports` | ✅ | Save a new manual report |
| `POST` | `/manual/papers` | ✅ | Save a new manual paper |
| `GET` | `/manual/reports` | ✅ | List all manual reports for current user |
| `GET` | `/manual/papers` | ✅ | List all manual papers |
| `GET` | `/manual/reports/{id}` | ✅ | Get single manual report |
| `GET` | `/manual/papers/{id}` | ✅ | Get single manual paper |
| `PUT` | `/manual/reports/{id}` | ✅ | Update a manual report |
| `PUT` | `/manual/papers/{id}` | ✅ | Update a manual paper |
| `DELETE` | `/manual/reports/{id}` | ✅ | Delete a manual report |
| `DELETE` | `/manual/papers/{id}` | ✅ | Delete a manual paper |

**POST/PUT body for manual items:**
```json
{
  "title": "LI-RADS v2018 CT/MRI Criteria for HCC",
  "content": "Full report or article text here...",
  "category": "BODY",
  "source_url": "https://doi.org/10.1148/radiol.2018180095",
  "tags": "liver, HCC, CT, MRI, staging"
}
```

Valid `category` values: `NEURO` · `MSK` · `BODY` · `OTHERS`

---

## Database Schema

All tables are created automatically by SQLAlchemy on startup. No migration tool is needed.

```sql
-- User accounts
users (id, email, password_hash, name, created_at, is_active)

-- AI-generated content
reports (id, user_id, subspecialty, modality, mode, input_text,
         impression, differentials, feedback, raw_response,
         title, user_prompt, created_at)

papers  (id, user_id, input_mode, input_text, title, summary,
         findings, implications, raw_response, user_prompt, created_at)

-- Manual library (user-authored)
manual_reports (id, user_id, title, content, category,
                source_url, tags, created_at, updated_at)

manual_papers  (id, user_id, title, content, category,
                source_url, tags, created_at, updated_at)
```

All `user_id` foreign keys use `ON DELETE CASCADE` — deleting a user removes all their data.

---

## Frontend Guide

The entire frontend lives in `frontend/index.html` — a single-file vanilla JS SPA with no build step required.

### Tabs

| Tab | Panel ID | Description |
|-----|----------|-------------|
| Report Assistant | `panel-report` | AI report polisher |
| Paper Digest | `panel-digest` | AI paper summariser |
| Libraries | `panel-library` | AI-generated saves |
| Manual Library | `panel-manual` | User-authored saves |

### Key JavaScript State

```js
token          // JWT token from sessionStorage
user           // Current user object
libData        // { reports: [], papers: [] }  — AI library cache
manualData     // { reports: [], papers: [] }  — Manual library cache
reportMode     // 'a' | 'b'
digestMode     // 'title' | 'url' | 'text'
libTab         // 'reports' | 'papers'  (AI library sub-tab)
manualTab      // 'reports' | 'papers'  (Manual library sub-tab)
manualCat      // 'ALL' | 'NEURO' | 'MSK' | 'BODY' | 'OTHERS'
editingManualItem  // { id, type } | null
```

### Export Functions

| Function | Output |
|----------|--------|
| `exportToWord(item, 'report'\|'paper')` | AI library item → .doc |
| `exportAllToWord()` | All AI library items → .doc |
| `exportLib()` | All AI library items → .json |
| `exportManualToWord(item, type)` | Single manual item → formatted .doc |
| `exportManualItemById(id, type)` | Looks up item then calls above |
| `exportAllManualToWord()` | Entire manual library → .doc |

---

## Configuration

### Changing the OpenAI Model

In `backend/main.py`, find and update:
```python
OPENAI_MODEL = "gpt-4o-mini"   # or "gpt-4o" for higher quality
```

### Changing the API Base URL (Frontend)

In `frontend/index.html`, find and update:
```js
const API_BASE = 'https://your-production-domain.com';
```
For local development this should be `http://localhost:8000`.

### JWT Expiry

In `backend/main.py`:
```python
JWT_EXPIRE_H = 24 * 7   # 7 days — adjust as needed
```

---

## Security Notes

- **API keys are never stored.** The OpenAI key is sent by the client per-request and proxied directly to OpenAI. It is not logged or persisted.
- **Passwords** are hashed with `bcrypt` before storage. Plain-text passwords are never saved.
- **JWT tokens** are signed with `HS256` and expire after 7 days. The secret must be a long random string — generate one with `openssl rand -hex 32`.
- **CORS** is configured via the `ALLOWED_ORIGINS` environment variable. Set it to your exact frontend origin in production, not `*`.
- **Per-user isolation:** every database query filters by `user_id` from the verified JWT. Users cannot access each other's data.
- **SQL injection:** all queries use SQLAlchemy Core parameterised statements — no raw SQL string interpolation.

---

## Deployment

The app is designed to be deployed as a single Docker image. The recommended platform is [Railway](https://railway.app), but any Docker host works.

### Railway (recommended)

1. Push your code to GitHub.
2. Create a new Railway project and add a **PostgreSQL** plugin — Railway injects `DATABASE_URL` automatically.
3. Add your service pointing to the GitHub repo. Set build context to `/` and Dockerfile path to `backend/Dockerfile`.
4. Add environment variables: `JWT_SECRET`, `ALLOWED_ORIGINS`.
5. Deploy. Update `API_BASE` in `index.html` to your Railway public URL.

### Environment checklist for production

- [ ] `JWT_SECRET` set to a 64-character random hex string
- [ ] `DATABASE_URL` pointing to your production database
- [ ] `ALLOWED_ORIGINS` set to your exact frontend origin
- [ ] `APP_ENV=production`
- [ ] HTTPS enabled (Railway handles this automatically)
- [ ] `.env` file excluded from version control

---

## Health Check

```
GET /health
→ { "status": "ok", "service": "radiology-coach-api" }
```

Used by Docker Compose and Railway to verify the API is running.

---

*Built for radiology fellows who want AI-augmented learning without giving up control of their own data.*