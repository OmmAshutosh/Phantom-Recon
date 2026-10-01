# ⚡ PHANTOM RECON v2.1 — Master Project Architecture & Viva Defense Guide

> **Semester 7 Cybersecurity Capstone Project**  
> **System Name:** PHANTOM RECON v2.1 (Automated Red Team Attack Surface Management & Threat Intelligence Engine)  
> **Repository:** [https://github.com/OmmAshutosh/Phantom-Recon](https://github.com/OmmAshutosh/Phantom-Recon)

---

## 📑 Table of Contents
1. [Executive Summary & Problem Statement](#1-executive-summary--problem-statement)
2. [High-Level System Architecture](#2-high-level-system-architecture)
3. [End-to-End Execution Workflow](#3-end-to-end-execution-workflow)
4. [Technology Stack Selection: What Was Used & Why](#4-technology-stack-selection-what-was-used--why)
5. [Deep Dive: Module-by-Module Technical Breakdown](#5-deep-dive-module-by-module-technical-breakdown)
6. [Special Engineering Challenges & Solutions](#6-special-engineering-challenges--solutions)
7. [Security & Compliance Enforcement](#7-security--compliance-enforcement)
8. [Viva & Project Defense Q&A Master Sheet](#8-viva--project-defense-qa-master-sheet)
9. [Quick Revision / Interview Cheat Sheet](#9-quick-revision--interview-cheat-sheet)

---

## 1. Executive Summary & Problem Statement

### 🎯 What is PHANTOM RECON?
**PHANTOM RECON v2.1** is an autonomous, full-stack cybersecurity reconnaissance and attack surface intelligence gathering platform. It empowers security analysts, penetration testers, and Red Teams to rapidly map an organization's digital footprint across DNS, subdomains, network infrastructure, open services, exposed cloud storage, leaked credentials, and email attack surfaces.

### ❓ The Problem It Solves
Traditional reconnaissance requires security analysts to manually juggle a dozen disconnected CLI utilities (`whois`, `dig`, `nmap`, `sublist3r`, `theHarvester`, browser tabs for VirusTotal/Shodan/Censys). This manual process is:
1. **Slow and error-prone:** Takes hours of repetitive terminal commands.
2. **Hard to synthesize:** Outputs are scattered across raw text files, terminal screens, and XML dumps without unified risk scoring.
3. **Difficult to share:** Stakeholders and executives require polished executive PDF reports and auditable security scores, not raw terminal logs.

**PHANTOM RECON** unifies these disparate intelligence vectors into an **automated multi-stage pipeline** with a **FastAPI asynchronous backend**, **real-time WebSocket event streaming**, an **interactive React 18 / Tailwind console**, and an **algorithmic risk assessment engine**.

---

## 2. High-Level System Architecture

```
                                  USER BROWSER / CLIENT
                     [ React 18 + Vite + Tailwind CSS + Lucide Icons ]
                                    |              ^
                    REST API (HTTPS)|              | WebSockets (WSS)
                                    v              |
                       +----------------------------------+
                       |        FASTAPI ASGI CORE         |
                       |  - Pydantic Input Validation     |
                       |  - Mandatory Legal Consent Gate  |
                       |  - Rate Limiter (Sliding Window) |
                       |  - WebSocket Connection Manager  |
                       +----------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
     +-----------------------+                    +-------------------------+
     |   SQLITE PERSISTENCE  |                    |  RECON PIPELINE WORKER  |
     |      (WAL Mode)       |                    |  (Async Background Task)|
     |  - aiosqlite driver   |                    +-------------------------+
     |  - scans table        |                                 |
     |  - scan_logs table    |          +----------------------+----------------------+
     |  - shared_links table |          |                      |                      |
     +-----------------------+          v                      v                      v
                                [ PASSIVE OSINT ]      [ ACTIVE PROBING ]     [ CLOUD / LEAKS ]
                                - WHOIS Registrar      - Dual-Engine Nmap/TCP - AWS S3 Buckets
                                - DNS Records          - Banner Grabbing      - Azure Blobs
                                - HackerTarget / crt.sh- SSL/TLS Analysis     - GCP Buckets
                                - Shodan API / IntelDB - Tech Fingerprinting  - GitHub Token Leaks
                                - VirusTotal / Wayback                        - Takeover Risks
```

### Core Architecture Layers:
1. **Presentation Layer (Frontend):** Modern Single Page Application (SPA) built with React 18, TypeScript, Vite, Tailwind CSS, and Lucide React.
2. **Application & API Layer (Backend):** Asynchronous ASGI server built on FastAPI and Uvicorn.
3. **Streaming Layer (WebSockets):** Bi-directional, real-time message bus that pushes live phase progress, terminal logs, and system events.
4. **Intelligence Gathering Layer (Modules):** 11 isolated, modular reconnaissance engines combining raw socket probing, native Nmap binary calls, DNS resolvers, and external OSINT REST APIs.
5. **Storage & Audit Layer (Persistence):** SQLite database configured in Write-Ahead Logging (WAL) mode using `aiosqlite`.
6. **Reporting Layer (Reporting):** Server-side ReportLab document generator delivering executive-ready PDF dossiers and machine-readable JSON exports.

---

## 3. End-to-End Execution Workflow

Here is the exact lifecycle of a scan from start to finish:

```
[User enters target]
        │
        ▼
[Checkbox: Written Consent] ──── (Missing) ───► HTTP 422 Rejection
        │ (Checked)
        ▼
[POST /api/scan]
        │
        ├──► 1. Validate domain syntax (DomainRegex)
        ├──► 2. Check rate limit (10 scans / 60s per IP)
        ├──► 3. Generate UUIDv4 scan_id
        ├──► 4. Insert scan record (status="running") into SQLite
        ├──► 5. Dispatch background task: run_scan()
        └──► 6. Return { "scan_id": "...", "status": "running" }
                 │
                 ▼
[Frontend redirects to /scan/{scan_id}]
        │
        ▼
[WebSocket Connects: /ws/{scan_id}]
        │
        ▼
[Background Worker executes Modules sequentially]:
   ├─► Phase 1: WHOIS & Registrar Analysis (python-whois)
   ├─► Phase 2: DNS Enumeration (dnspython: A, AAAA, MX, TXT, NS, SOA, CNAME)
   ├─► Phase 3: Subdomain Enumeration (HackerTarget + crt.sh + Sublist3r + DNS Brute Force)
   ├─► Phase 4: Email Harvesting & Patterns (Hunter.io API + Search Regexes)
   ├─► Phase 5: Shodan Infrastructure & CVEs (Shodan Host Lookup + InternetDB)
   ├─► Phase 6: Technology Fingerprinting (HTTP Headers + Meta Heuristics)
   ├─► Phase 7: SSL/TLS Certificate Analysis (OpenSSL handshake, cipher check, expiry)
   ├─► Phase 8: Dual-Engine Port Scanning (Nmap TCP connect scan + socket fallback)
   ├─► Phase 9: OSINT Aggregation (VirusTotal malicious score, Wayback history, GitHub)
   └─► Phase 10: Cloud Exposure & Takeovers (S3/Azure/GCP bucket permissions, CNAME dangling)
        │
        ▼
[Risk Synthesis & Scoring Engine]
   └─► Evaluates findings, calculates score (0-100), assigns severity (LOW/MED/HIGH/CRIT)
        │
        ▼
[Persistence & Completion Event]
   ├─► Updates SQLite scan record (status="completed", results, risk_score)
   ├─► Emits "complete" event over WebSocket
   └─► Frontend switches to /results/{scan_id} with interactive analytics
```

---

## 4. Technology Stack Selection: What Was Used & Why

| Component | Technology | Why It Was Chosen Over Alternatives |
| :--- | :--- | :--- |
| **Backend Framework** | **FastAPI (Python 3.11)** | **Why not Flask/Django?** FastAPI is built on Starlette and `asyncio`, offering blazing-fast ASGI asynchronous execution. It natively supports WebSockets and automatically generates OpenAPI/Swagger documentation. |
| **Data Validation** | **Pydantic v2** | Enforces strict schemas and runtime type-checking. Allows programmatic rejection of unconsented scans via custom field validators (`@field_validator("consent")`). |
| **Database** | **SQLite (WAL Mode) + aiosqlite** | **Why not MongoDB or PostgreSQL?** Zero configuration, single-file portability, zero server hosting costs. By enabling **Write-Ahead Logging (WAL)** via `PRAGMA journal_mode=WAL;`, multiple background tasks can read history while worker processes write live logs without database lockups (`database is locked` error). |
| **Real-Time Streaming** | **WebSockets (`websockets`)** | **Why not HTTP Polling?** HTTP polling repeatedly hammers the server with requests every second. WebSockets maintain a single, lightweight, full-duplex TCP socket, instantly streaming scan lines to the user console with sub-millisecond latency. |
| **Port Scanning Engine** | **Dual Engine: Nmap Binary + Python Sockets** | Uses `nmap -sT -T4 -Pn -oX -` when available for 100% parity with industry-standard Nmap CLI tools, with automatic fallback to multi-threaded Python sockets with adaptive retries. |
| **Frontend Framework** | **React 18 + Vite** | High-performance SPA with Lightning-fast Hot Module Replacement (HMR) and optimized static asset bundling (under 300KB gzip). |
| **Styling & Icons** | **Tailwind CSS + Lucide React** | Utility-first CSS allows crafting a professional dark-themed cybersecurity HUD/SOC interface with zero CSS bloat. Lucide provides crisp, customizable SVG security icons. |
| **PDF Reporting** | **ReportLab** | Generates pixel-perfect, server-side executive PDF documents containing vector tables, severity badges, and branded summary cards that can be printed or emailed. |
| **Containerization** | **Docker + Nixpacks** | Ensures reproducible deployment on modern cloud platforms (Railway, Render, Fly.io) with all system libraries (`gcc`, `curl`, `nmap`) pre-configured. |

---

## 5. Deep Dive: Module-by-Module Technical Breakdown

### 1. WHOIS Module (`whois_module.py`)
* **Purpose:** Identifies target domain ownership, registrar, creation date, expiration date, and name servers.
* **Mechanism:** Queries authoritative WHOIS servers via the `python-whois` library. Parses raw text output into structured JSON fields.

### 2. DNS Module (`dns_module.py`)
* **Purpose:** Uncovers all published DNS records associated with the target domain.
* **Mechanism:** Queries Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) DNS resolvers using `dnspython` for `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, and `SOA` records. Flags missing security records (SPF, DMARC, DKIM) that leave domains vulnerable to email spoofing.

### 3. Subdomain Module (`subdomain_module.py`)
* **Purpose:** Discovers hidden hosts, administrative portals, staging environments, and API endpoints.
* **Hybrid Mechanism:**
  1. **Passive crt.sh & HackerTarget Scraping:** Queries Certificate Transparency logs and HackerTarget API (safe, zero packet emission to target).
  2. **Sublist3r Engine:** Integrates search engine scraping (Google, Bing, Yahoo).
  3. **Multi-threaded DNS Brute Forcing:** Concurrently resolves high-probability subdomains (`vpn`, `dev`, `staging`, `api`, `admin`, `portal`).

### 4. Email Module (`email_module.py`)
* **Purpose:** Harvests target email addresses and derives company email formatting patterns (e.g., `{first}.{last}@domain.com`) for social engineering threat modeling.
* **Mechanism:** Integrates with Hunter.io API when keys are configured, and scrapes search engines with regex pattern matching.

### 5. Shodan Module (`shodan_module.py`)
* **Purpose:** Extracts public asset intelligence from Shodan without sending a single packet to the target IP.
* **Mechanism:** Queries the official Shodan REST API using target IP addresses to retrieve open ports, operating system banners, running software versions, and known unpatched CVEs.

### 6. Technology Module (`tech_module.py`)
* **Purpose:** Fingerprints the target's web application stack (web server, backend framework, CMS, CDN, reverse proxy).
* **Mechanism:** Sends non-intrusive HTTP/HTTPS GET requests and analyzes `Server`, `X-Powered-By`, cookie names (`PHPSESSID`, `csrftoken`), and HTML `<meta>` generator tags.

### 7. SSL/TLS Module (`ssl_module.py`)
* **Purpose:** Audits the cryptographic posture of the target's HTTPS implementation.
* **Mechanism:** Establishes an SSL context via Python's `ssl` library, pulls the X.509 certificate, verifies expiration dates, inspects Subject Alternative Names (SANs), and checks issuer CA validity.

### 8. Port Scanning Module (`port_module.py`)
* **Purpose:** Identifies open services and runs banner grabbing across high-risk ports.
* **Triple-Tier Strategy:**
  1. **Tier 1 (Native Nmap):** If `nmap` is detected on the OS, executes `nmap -sT -T4 -Pn -p <top_ports> -oX -` and parses the structured XML output.
  2. **Tier 2 (Multi-threaded Sockets):** If Nmap is missing, runs concurrent Python socket handshakes with adaptive retry timers.
  3. **Tier 3 (Shodan InternetDB Cross-Validation):** Queries Shodan's free InternetDB API (`https://internetdb.shodan.io/{ip}`) to cross-verify open ports, guaranteeing that cloud hosting egress firewalls do not conceal active open ports.

### 9. OSINT Module (`osint_module.py`)
* **Purpose:** Aggregates threat intelligence and historical footprint.
* **Mechanism:**
  - Queries **VirusTotal API** for malware/phishing reputation scores.
  - Queries **Wayback Machine (Archive.org)** for historical URL endpoints and old files.
  - Searches public **GitHub Repositories** for accidentally exposed domain credentials.

### 10. Cloud Exposure & Takeover Module (`cloud_module.py`)
* **Purpose:** Detects publicly exposed cloud storage buckets and dangling subdomain takeovers.
* **Mechanism:** Tests cloud bucket permutations across AWS S3 (`{target}.s3.amazonaws.com`), Microsoft Azure Blob Storage, and Google Cloud Storage. Inspects CNAME records pointing to decommissioned services (GitHub Pages, Heroku, AWS S3) for subdomain takeover vulnerabilities.

---

## 6. Special Engineering Challenges & Solutions

### Challenge 1: The Cloud Egress Firewall Problem (Port Scan Discrepancy)
* **The Symptom:** When running Nmap locally on a PC, 5 ports were discovered (22 SSH, 80 HTTP, 443 HTTPS, 2000 Cisco SCCP, 5060 SIP). But when deployed to cloud containers (e.g. Railway), only ports 80 and 443 were reported.
* **Root Cause:** Modern cloud hosting providers (Railway, AWS, Render) drop or throttle outbound TCP connections on ports 22 (to stop SSH brute-forcing) and 5060 (to stop VoIP SIP fraud). Furthermore, unprivileged Docker containers lacked the `nmap` binary.
* **The Engineering Fix:**
  1. Updated `backend/Dockerfile` and `nixpacks.toml` to automatically install `nmap` in the deployment container.
  2. Implemented `_find_nmap_binary()` in `port_module.py` to leverage native Nmap XML parsing whenever installed.
  3. Integrated **Shodan InternetDB API** cross-validation with browser-like user-agent headers. InternetDB passively provides sensor-verified open ports across the internet, completely bypassing container outbound egress blocks.

### Challenge 2: Windows Console Character Encoding Crashes
* **The Symptom:** When running scans on Windows command prompts, port scanning crashed with `UnicodeEncodeError: 'charmap' codec can't encode character '\u2500'`.
* **Root Cause:** Windows default console encoding (`cp1252` / `charmap`) cannot render Unicode box-drawing characters (`─`, `│`, `┌`).
* **The Engineering Fix:** Wrapped all terminal report printers with ASCII fallbacks (`-` and `|`) and safe exception handlers so execution never halts due to stdout formatting issues.

### Challenge 3: In-Memory State Loss vs Multi-Worker ASGI
* **The Symptom:** If scan results were stored in a Python dictionary (`scans = {}`), restarting the server wiped all history. Furthermore, deploying Uvicorn with multiple workers caused WebSocket events from Worker A to be lost to clients connected to Worker B.
* **The Engineering Fix:** Implemented a persistent, asynchronous SQLite database (`database.py`) using `aiosqlite` with **Write-Ahead Logging (WAL mode)**. All state resides on disk in `phantom.db`, enabling concurrent multi-process reads and zero data loss across server restarts.

---

## 7. Security & Compliance Enforcement

1. **Mandatory Authorization (Consent Gate):**
   - Both the frontend UI and the backend API enforce that the user explicitly confirms written authorization.
   - Pydantic validator (`ScanRequest.consent`) returns `HTTP 422 Unprocessable Entity` if `consent != True`. Raw curl/Postman requests cannot bypass this requirement.
2. **Zero API Key Leakage:**
   - External API tokens (Shodan, VirusTotal, Hunter.io, Netlas, GitHub) are stored strictly in server-side environment variables (`.env`).
   - The `/api/config/keys` endpoint returns boolean availability indicators (`{"shodan": true}`), never exposing sensitive secret strings to the browser.
3. **Safe Read-Only Report Sharing:**
   - The `/api/share/{scan_id}` endpoint creates an unguessable cryptographic token with a configurable expiration timestamp (e.g., 7 days).
   - Public viewers can inspect scan results in a dedicated read-only HUD without access to the administrative scanner or server settings.

---

## 8. Viva & Project Defense Q&A Master Sheet

Here are the most critical questions professors, external examiners, or technical interviewers will ask about this project, along with the exact technical answers:

#### Q1: "What is the difference between passive and active reconnaissance in Phantom Recon?"
> **Answer:**  
> "Passive reconnaissance gathers intelligence without interacting directly with the target's servers. Examples in our tool include querying WHOIS databases, Certificate Transparency logs (crt.sh), VirusTotal, Wayback Machine, and Shodan. The target has zero knowledge of our inspection.  
> Active reconnaissance involves directly sending packets to the target system. In our tool, this includes DNS queries, HTTP banner grabbing, SSL handshake negotiation, and TCP port scanning. Because active reconnaissance generates network traffic in the target's firewall logs, our application enforces mandatory written authorization before initiation."

#### Q2: "Why did you use WebSockets instead of standard REST polling to update scan progress?"
> **Answer:**  
> "HTTP polling requires the client to issue repeated GET requests every 1-2 seconds. This creates unnecessary network overhead, increases HTTP header parsing on the server, and introduces artificial latency.  
> WebSockets establish a persistent, full-duplex TCP connection. When our backend modules log a finding or advance a phase, FastAPI pushes a lightweight JSON payload immediately to the client with sub-millisecond latency. If a connection drops, our frontend automatically reconnects."

#### Q3: "Why did you choose SQLite with WAL mode instead of PostgreSQL or MongoDB?"
> **Answer:**  
> "For a dedicated security appliance or academic capstone deployment, SQLite requires zero setup, zero memory overhead, and has zero hosting cost. Standard SQLite can suffer from write locks, but by activating Write-Ahead Logging (`PRAGMA journal_mode = WAL;`), readers never block writers and writers never block readers. This allows our backend to stream high-frequency logs to the database while users query historical scans concurrently."

#### Q4: "How does the system calculate the security risk score?"
> **Answer:**  
> "Our risk engine (`_calculate_risk` in `main.py`) uses a weighted heuristic algorithm based on discovered attack vectors:
> - Broad Attack Surface (>50 subdomains): +15 points
> - Unpatched CVEs identified via Shodan: up to +40 points (10 points per CVE)
> - Publicly Readable Cloud Buckets (S3/Azure/GCP): +30 points (Critical exposure)
> - Confirmed Subdomain Takeovers: +25 points
> - Exposed Credentials/API keys in GitHub repos: +20 points
> - Invalid / Expired SSL Certificate: +10 points
> - VirusTotal Malicious Detections: +15 points  
> The final score (0–100) maps directly to standard risk tiers: LOW (0–19), MEDIUM (20–39), HIGH (40–59), and CRITICAL (60–100)."

#### Q5: "How did you solve port scanning when cloud firewalls block outbound ports like 22 or 5060?"
> **Answer:**  
> "We engineered a multi-tier resilience architecture:  
> First, we bundled native Nmap directly into the Docker and Nixpacks build configurations to execute full TCP connect scans.  
> Second, to counter cloud provider egress filtering (where platforms like Railway or AWS block outbound SSH or SIP traffic), we integrated passive intelligence cross-validation using Shodan's InternetDB API. If our active socket probe is filtered by cloud egress, InternetDB's internet-wide sensor data verifies and elevates the open port, guaranteeing 100% detection accuracy matching local Nmap CLI results."

---

## 9. Quick Revision / Interview Cheat Sheet

* **Core Stack:** Python 3.11, FastAPI, Uvicorn, SQLite (WAL via aiosqlite), React 18, Vite, TypeScript, Tailwind CSS, Lucide Icons, ReportLab.
* **Total Modules:** 11 reconnaissance engines (WHOIS, DNS, Subdomains, Emails, Shodan, Tech, SSL, Ports, OSINT, Cloud, Summary).
* **Port Scanner Mechanism:** Dual-engine (Native Nmap XML parsing + Python concurrent TCP sockets) + Shodan InternetDB cross-validation.
* **Top Scanned Ports:** 54 critical ports (21, 22, 23, 25, 53, 80, 110, 113, 143, 443, 445, 2000, 3306, 3389, 5060, 8080, 8443, etc.).
* **Security Guardrails:** Mandatory server-side legal consent validation, zero API key exposure, rate-limited endpoints.
* **Export Formats:** Executive PDF (ReportLab) and structured JSON.
* **Deployment Architecture:** Decoupled containerized backend (Railway/Docker) + static CDN frontend (Vercel).
