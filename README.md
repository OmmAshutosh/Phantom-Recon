# ⚡ PHANTOM RECON v2.1 — Red Team Intelligence Gathering Framework

> **University Cybersecurity Capstone Project**  
> *Autonomous Passive & Active Reconnaissance Engine with FastAPI Core & React 18 Web Console*

---

## 🔒 Legal & Ethical Notice
This framework is developed strictly for **authorized educational penetration testing, academic capstone demonstrations, and security research**. Always obtain documented written authorization prior to initiating reconnaissance against any target. Unauthorized scanning, probing, or enumeration violates international cyber law (including 18 U.S.C. § 1030 CFAA in the United States and equivalent computer misuse acts globally).

---

## 🎯 Architecture Overview

```
PHANTOM RECON v2.1
├── backend/
│   ├── modules/            # 11 Core Python Recon Modules (tested & isolated)
│   ├── main.py             # FastAPI App (WebSocket live streaming, consent gate, rate limiting)
│   ├── database.py         # SQLite persistence layer (WAL mode, async via aiosqlite)
│   ├── config.py           # Server-side API key management & env loader
│   ├── demo.py             # Mock data telemetry generator for offline evaluations
│   ├── test_api.py         # Automated API & consent verification test suite
│   ├── requirements.txt    # Python production dependencies
│   └── Dockerfile          # Containerized deployment for Railway / Render / Fly.io
├── frontend/
│   ├── src/
│   │   ├── components/     # UI widgets (RiskGauge, StatCard, FindingsAccordion, ShareModal)
│   │   ├── pages/          # Scanner, LiveScan, Results, History, ApiConfig, SharedReadout
│   │   ├── api.ts          # API client with VITE_API_URL and WebSocket negotiation
│   │   └── types.ts        # TypeScript data definitions
│   ├── package.json        # React 18, Vite, Tailwind CSS, Lucide React
│   ├── vercel.json         # SPA rewrite routing for Vercel
│   └── netlify.toml        # SPA rewrite routing for Netlify
└── README.md               # Architecture, setup, and deployment manual
```

---

## 🛡️ Backend Hardening & Persistence Layer Review

### The Problem with In-Memory State
In prototype sandboxes, scans and rate limiters often rely on in-memory Python dictionaries (`scans = {}`). This fails in production because:
1. **Zero Crash Resilience:** If the backend process restarts or crashes during a long scan, all in-progress scans, logs, and completed findings vanish.
2. **Multi-Worker Process Isolation:** Production ASGI servers (like Uvicorn/Gunicorn) run multiple worker processes (`--workers 4`). In-memory dictionaries in Worker A are invisible to Worker B, resulting in broken WebSocket streams, missing scans, and bypassed rate limits.

### Why SQLite with WAL Mode is the Right Choice for Capstone
We implemented an asynchronous SQLite persistence engine (`backend/database.py`) powered by `aiosqlite`:

* **Write-Ahead Logging (WAL Mode):** Enabled via `PRAGMA journal_mode = WAL;`. Unlike standard SQLite which locks the entire database file during writes, WAL mode allows concurrent readers to access historical scans and logs simultaneously while the background scan worker writes real-time telemetry.
* **Persistent History & Audit Trail:** Every scan, log message, rate-limit timestamp, and share token is persisted to disk (`phantom.db`).
* **Expiring Read-Only Links:** The `shared_links` table enforces cryptographic tokens with timestamp-based expiration (`expires_at`), allowing external capstone reviewers to evaluate reports without granting administrative or scanner access.

#### Tradeoffs & When to Migrate:
| Feature | SQLite (WAL Mode) | PostgreSQL + Redis |
| :--- | :--- | :--- |
| **Setup Complexity** | Zero external services, single file on disk | Requires managing separate DB & Redis clusters |
| **Hosting Cost** | $0 (included in basic container storage) | Additional database provisioning costs |
| **Concurrency Limit** | Ideal for 1-5 concurrent scans | Scales to thousands of simultaneous distributed scans |
| **Best Used For** | Capstone defense, homelabs, dedicated pentest VMs | Multi-tenant SaaS with distributed worker nodes |

---

## 🔐 Strict Security Non-Negotiables

1. **Mandatory Server-Side Consent:**
   Consent cannot be bypassed by sending raw HTTP requests or inspecting client code. The Pydantic validator on `ScanRequest.consent` actively rejects any request where `consent != True` with `HTTP 422 Unprocessable Entity`:
   ```python
   @field_validator("consent")
   @classmethod
   def enforce_mandatory_consent(cls, v: bool) -> bool:
       if v is not True:
           raise ValueError("Explicit written authorization is legally mandatory before initiating reconnaissance.")
       return v
   ```
2. **Zero API Key Leakage:**
   External API keys (Shodan, VirusTotal, Hunter.io, Netlas, GitHub) reside exclusively in server-side environment variables. The `/api/config/keys` endpoint strictly returns boolean status flags (`{"shodan": true, "hunter": false, ...}`). No secret string ever leaves the server or reaches the browser bundle.

---

## 🚀 Local Development Setup

### 1. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Copy .env.example to .env and configure API keys
cp .env.example .env

# Run FastAPI backend server
uvicorn main:app --reload --port 8000
```
Backend API will be available at `http://localhost:8000` with interactive Swagger docs at `http://localhost:8000/docs`.

### 2. Frontend Setup
```bash
# In a separate terminal, navigate to frontend directory
cd frontend

# Install npm dependencies
npm install

# Start Vite development server (with proxy to localhost:8000)
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 🧪 Demo Mode Fallback (Offline / No Keys Required)

When no external API keys are configured, or when presenting in an offline environment (like a university capstone presentation room):
1. On the **Scanner** page, check the **"Demo Simulation (Mock Data Generator)"** box.
2. Enter an authorized domain (e.g. `scanme.nmap.org` or `example.com`).
3. Accept the legal consent certification and click **Launch Reconnaissance Scan**.
4. The backend streams synthetic, high-fidelity reconnaissance telemetry across all 10 phases over the WebSocket into the Live Terminal, calculating the final risk score and generating the interactive dashboard.

---

## 🌐 Production Deployment Guide

### Option A: Backend on Railway (Recommended)
1. Fork or push this repository to GitHub.
2. Log into [Railway.app](https://railway.app) and click **New Project** → **Deploy from GitHub repo**.
3. Set the **Root Directory** to `/backend`.
4. In the **Variables** tab, add your server-side environment variables:
   * `ALLOWED_ORIGINS`: `https://your-frontend.vercel.app` (or `*`)
   * `SHODAN_API_KEY`: *(Optional)*
   * `VIRUSTOTAL_API_KEY`: *(Optional)*
   * `HUNTER_API_KEY`: *(Optional)*
   * `NETLAS_API_KEY`: *(Optional)*
   * `GITHUB_TOKEN`: *(Optional)*
5. In **Settings** → **Volume**, add a persistent volume mounted at `/data` (sets `PHANTOM_DB_PATH=/data/phantom.db` so scan history survives re-deploys).
6. Copy the generated public URL (e.g., `https://phantom-recon-production.up.railway.app`).

### Option B: Backend on Render
1. Create a **New Web Service** connected to your repo on [Render.com](https://render.com).
2. Set **Root Directory**: `backend`
3. Set **Runtime**: `Python 3` or `Docker`
4. Set **Build Command**: `pip install -r requirements.txt`
5. Set **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Add Environment Variables under the **Environment** tab.

### Frontend Deployment on Vercel / Netlify
1. Connect your repository on [Vercel](https://vercel.com) or [Netlify](https://netlify.com).
2. Set **Root Directory**: `frontend`
3. Set **Build Command**: `npm run build`
4. Set **Output Directory**: `dist`
5. Under **Environment Variables**, add:
   ```env
   VITE_API_URL=https://your-backend-url.up.railway.app
   ```
   *(Do NOT add your secret API keys here — `VITE_API_URL` is the only frontend variable needed).*
6. Deploy! The included `vercel.json` and `netlify.toml` automatically route client-side subpaths (like `/shared/:token`) to `/index.html`.

---

## 📱 Mobile Polish & Responsiveness Audit (375px)

The user interface has been audited and polished down to 375px viewport widths (iPhone SE / compact mobile):
* **Live Scan Terminal:** Uses flexible word-breaking (`break-all`, `whitespace-pre-wrap`), responsive font sizing (`text-[11px] sm:text-xs`), and constrained container overflow preventing unwanted horizontal viewport expansion.
* **Results Dashboard:** Automatically converts multi-column metric grids into stacked responsive cards (`grid-cols-1 md:grid-cols-3 lg:grid-cols-4`).
* **Findings Tables:** Wrapped in isolated horizontal scroll containers with custom scrollbars so large DNS records, certificate SAN arrays, and long subdomains can be inspected without breaking mobile screen layouts.
* **Share Readout View:** Standalone, uncluttered review interface tailored for mobile evaluation by mentors or defense panelists.
