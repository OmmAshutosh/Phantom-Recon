import os
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and stamp total page numbers and running headers/footers."""
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))
        
        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(40, 804, "PHANTOM RECON v2.1 — MASTER ARCHITECTURE, WORKFLOW & COMPARATIVE DOSSIER")
            self.drawRightString(555, 804, "CAPSTONE DEFENSE GUIDE")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.6)
            self.line(40, 798, 555, 798)

        # Running Footer (all pages)
        self.setFont("Helvetica", 8)
        self.drawString(40, 28, "CONFIDENTIAL — AUTHORIZED ACADEMIC CAPSTONE EVALUATION & SECURITY RESEARCH ONLY")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(555, 28, page_text)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.6)
        self.line(40, 38, 555, 38)
        
        self.restoreState()

def build_pdf(filename="PHANTOM_RECON_ARCHITECTURE_AND_COMPARISON_GUIDE.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=45,
        bottomMargin=45
    )

    # Color Palette Definition
    c_primary = colors.HexColor("#0f172a")     # Deep Slate 900
    c_secondary = colors.HexColor("#0369a1")   # Sky 700
    c_accent = colors.HexColor("#1d4ed8")      # Blue 700
    c_dark = colors.HexColor("#1e293b")        # Slate 800
    c_muted = colors.HexColor("#64748b")       # Slate 500
    c_light = colors.HexColor("#f8fafc")       # Slate 50
    c_card = colors.HexColor("#f1f5f9")        # Slate 100
    c_border = colors.HexColor("#cbd5e1")      # Slate 300
    c_success = colors.HexColor("#047857")     # Emerald 700
    c_warning = colors.HexColor("#b45309")     # Amber 700
    c_danger = colors.HexColor("#b91c1c")      # Red 700

    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle("TTitle", fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=c_primary)
    subtitle_style = ParagraphStyle("TSub", fontName="Helvetica", fontSize=11, leading=15, textColor=c_secondary, spaceAfter=10)
    meta_style = ParagraphStyle("TMeta", fontName="Helvetica", fontSize=8.5, leading=12, textColor=c_muted)
    
    h1 = ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=c_primary, spaceBefore=14, spaceAfter=6, keepWithNext=True)
    h2 = ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=c_accent, spaceBefore=10, spaceAfter=4, keepWithNext=True)
    body = ParagraphStyle("Body", fontName="Helvetica", fontSize=8.5, leading=12.5, textColor=c_dark, alignment=TA_JUSTIFY, spaceAfter=4)
    body_bold = ParagraphStyle("BodyB", fontName="Helvetica-Bold", fontSize=8.5, leading=12.5, textColor=c_dark)
    bullet = ParagraphStyle("Bullet", fontName="Helvetica", fontSize=8.5, leading=12.5, textColor=c_dark, leftIndent=10, spaceAfter=2.5)
    callout = ParagraphStyle("Callout", fontName="Helvetica", fontSize=8.5, leading=12, textColor=c_dark, backColor=c_card, borderPadding=6, spaceBefore=4, spaceAfter=6)
    
    table_cell = ParagraphStyle("TCell", fontName="Helvetica", fontSize=7.5, leading=10, textColor=c_dark)
    table_cell_bold = ParagraphStyle("TCellB", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=c_primary)
    table_hdr = ParagraphStyle("THdr", fontName="Helvetica-Bold", fontSize=8, leading=10.5, textColor=colors.white, alignment=TA_CENTER)
    code_inline = ParagraphStyle("Code", fontName="Courier-Bold", fontSize=8, leading=10, textColor=colors.HexColor("#0f766e"))

    story = []

    # ==================== HEADER & COVER BLOCK ====================
    story.append(Paragraph("⚡ PHANTOM RECON v2.1", title_style))
    story.append(Paragraph("Automated Red Team Attack Surface Intelligence, Architecture Dossier & Platform Comparative Analysis", subtitle_style))
    
    meta_box = [
        [
            Paragraph("<b>Project Title:</b> Autonomous Attack Surface Reconnaissance Platform", meta_style),
            Paragraph("<b>Academic Scope:</b> Semester 7 Cybersecurity Capstone Defense", meta_style),
        ],
        [
            Paragraph("<b>Full Stack:</b> React 18 + Vite + FastAPI + Async SQLite WAL + Nmap", meta_style),
            Paragraph("<b>Code Repository:</b> github.com/OmmAshutosh/Phantom-Recon", meta_style),
        ],
        [
            Paragraph("<b>Classification:</b> Master Technical Architecture & Viva Dossier", meta_style),
            Paragraph("<b>Author / Candidate:</b> Ashutosh (OmmAshutosh)", meta_style),
        ]
    ]
    t_meta = Table(meta_box, colWidths=[255, 260])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_card),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('PADDING', (0,0), (-1,-1), 4.5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_secondary, spaceBefore=1, spaceAfter=10))

    # ==================== 1. EXECUTIVE SUMMARY ====================
    story.append(Paragraph("1. Executive Summary & Problem Formulation", h1))
    story.append(Paragraph(
        "In modern enterprise security operations, the reconnaissance phase (OSINT, asset mapping, and infrastructure probing) is the primary determinant of attack path discovery. "
        "However, security analysts and penetration testers are traditionally forced to manage fragmented, disparate command-line tools—such as <i>whois</i> for ownership, "
        "<i>dig</i> for DNS queries, <i>nmap</i> for port probing, <i>sublist3r</i> for subdomains, and separate browser tabs for Shodan and VirusTotal. "
        "This legacy approach causes hours of manual overhead, produces disconnected raw data logs without unified risk prioritization, and fails to provide automated executive deliverables.",
        body
    ))
    story.append(Paragraph(
        "<b>PHANTOM RECON v2.1</b> eliminates this operational friction by uniting 11 specialized passive intelligence and active probing modules into an automated, asynchronous pipeline. "
        "Built on an asynchronous FastAPI core with a React 18 Single Page Application (SPA), the system features <b>real-time WebSocket log streaming</b>, <b>an objective algorithmic risk engine (0–100)</b>, "
        "<b>cloud-resilient dual-engine port scanning</b>, and automated, server-side executive PDF and JSON generation.",
        body
    ))

    # ==================== 2. SYSTEM ARCHITECTURE SPECIFICATION ====================
    story.append(Spacer(1, 4))
    story.append(Paragraph("2. System Architecture Specification & Component Mapping", h1))
    story.append(Paragraph(
        "The architecture is organized into six strictly decoupled layers, ensuring non-blocking asynchronous execution, crash resilience, and modular extensibility:",
        body
    ))

    arch_layers = [
        [Paragraph("Architectural Tier", table_hdr), Paragraph("Technologies & Libraries", table_hdr), Paragraph("Core Responsibilities & Technical Rationale", table_hdr)],
        [
            Paragraph("<b>1. Presentation Layer</b><br/>(Frontend Web HUD)", table_cell_bold),
            Paragraph("React 18, Vite, TypeScript, Tailwind CSS, Lucide React", table_cell),
            Paragraph("Provides a dark-themed Security Operations Center (SOC) dashboard. Features live WebSocket terminal output, animated SVG risk gauges, filterable port matrices, and responsive search views. Total production bundle footprint is under 300KB gzip.", table_cell)
        ],
        [
            Paragraph("<b>2. API Gateway & Policy</b><br/>(ASGI Backend Core)", table_cell_bold),
            Paragraph("FastAPI 0.111, Uvicorn, Pydantic v2", table_cell),
            Paragraph("Asynchronous ASGI server handling HTTP REST endpoints and WebSocket negotiation. Enforces strict domain syntax regex validation, mandatory server-side legal consent gates, and IP sliding-window rate limiting (10 scans/60s).", table_cell)
        ],
        [
            Paragraph("<b>3. Real-Time Streaming</b><br/>(Event Message Bus)", table_cell_bold),
            Paragraph("WebSockets (`websockets` library)", table_cell),
            Paragraph("Maintains full-duplex TCP connections via `ConnectionManager`. Streams live phase indicators, terminal output strings, and progress milestones (0–100%) directly to the browser with sub-millisecond latency, eliminating polling.", table_cell)
        ],
        [
            Paragraph("<b>4. Reconnaissance Worker</b><br/>(Execution Engine)", table_cell_bold),
            Paragraph("Asyncio Workers, ThreadPoolExecutor, Python 3.11", table_cell),
            Paragraph("Dispatches non-blocking scan worker threads. Sequentially executes 11 reconnaissance modules across passive OSINT, active TCP socket handshakes, native Nmap XML parsing, and cloud storage permission probes.", table_cell)
        ],
        [
            Paragraph("<b>5. Persistence & Audit</b><br/>(Data Storage Layer)", table_cell_bold),
            Paragraph("SQLite 3 with WAL Mode (`aiosqlite`)", table_cell),
            Paragraph("File-backed database (`phantom.db`). Write-Ahead Logging allows background scan workers to write high-frequency live logs while concurrent users read historical scans and shared links without database lock errors (`database is locked`).", table_cell)
        ],
        [
            Paragraph("<b>6. Executive Reporting</b><br/>(Deliverable Engine)", table_cell_bold),
            Paragraph("ReportLab 5.0, JSON Serializer", table_cell),
            Paragraph("Generates pixel-perfect, server-side executive PDF dossiers complete with vector tables, severity badges, and branded summary metrics. Also provides structured JSON dumps for SIEM/SOAR integration.", table_cell)
        ],
    ]
    t_layers = Table(arch_layers, colWidths=[90, 130, 295])
    t_layers.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(t_layers)

    # Page Break for Architecture Diagram & End-to-End Workflow
    story.append(PageBreak())

    # ==================== 3. DETAILED ARCHITECTURE TOPOLOGY & WORKFLOW ====================
    story.append(Paragraph("3. End-to-End Operational Workflow & Data Flow Diagram", h1))
    story.append(Paragraph(
        "The following diagram illustrates the precise lifecycle and asynchronous data flow from user initiation to persistent reporting:",
        body
    ))

    flow_diagram_text = (
        "<b>[STEP 1: TARGET SUBMISSION & LEGAL AUTHORIZATION GATE]</b><br/>"
        "User enters domain in React HUD ➔ Checks Mandatory Written Consent box ➔ POST /api/scan.<br/>"
        "<i>Backend Policy:</i> Pydantic validator enforces `consent == True`. If missing, immediately returns `HTTP 422 Unprocessable Entity`.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
        "<b>[STEP 2: SCAN REGISTRATION & ASYNC TASK DISPATCH]</b><br/>"
        "Server validates domain syntax via regex ➔ Generates UUIDv4 `scan_id` ➔ Inserts record into SQLite with `status='running'` ➔<br/>"
        "Returns `{scan_id, status: 'running'}` to client ➔ Spawns background worker via `asyncio.create_task(run_scan())`.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
        "<b>[STEP 3: WEBSOCKET HANDSHAKE & EVENT STREAMING]</b><br/>"
        "React frontend redirects to `/scan/{scan_id}` ➔ Establishes WebSocket `/ws/{scan_id}`.<br/>"
        "ConnectionManager registers client channel ➔ Background worker broadcasts live phase banners, logs, and progress percentages.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
        "<b>[STEP 4: SEQUENTIAL EXECUTION OF 10 RECONNAISSANCE PHASES]</b><br/>"
        "<b>Phase 1: WHOIS</b> (Registrar, Dates) ➔ <b>Phase 2: DNS</b> (A, AAAA, MX, TXT, SPF/DMARC) ➔<br/>"
        "<b>Phase 3: Subdomains</b> (crt.sh, HackerTarget, Sublist3r, DNS Brute) ➔ <b>Phase 4: Emails</b> (Hunter.io, Pattern Regex) ➔<br/>"
        "<b>Phase 5: Shodan OSINT</b> (Exposed Services, CVEs) ➔ <b>Phase 6: Tech Detection</b> (Headers, Cookies, Meta Tags) ➔<br/>"
        "<b>Phase 7: SSL/TLS Audit</b> (Cert Validity, Ciphers, Expiry) ➔ <b>Phase 8: Port Probing</b> (Dual Nmap / Socket / InternetDB) ➔<br/>"
        "<b>Phase 9: OSINT Threats</b> (VirusTotal, Wayback Machine, GitHub) ➔ <b>Phase 10: Cloud Assets</b> (S3/Azure/GCP, Takeovers).<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
        "<b>[STEP 5: ALGORITHMIC RISK SYNTHESIS & SCORING ENGINE]</b><br/>"
        "`_calculate_risk()` computes objective score (0–100) based on weighted factors (CVEs, exposed buckets, takeovers, ports).<br/>"
        "Categorizes target risk posture into LOW, MEDIUM, HIGH, or CRITICAL.<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br/>"
        "<b>[STEP 6: PERSISTENCE, BROADCAST & RESULTS RENDERING]</b><br/>"
        "Results committed to SQLite (`status='completed'`) ➔ WebSocket broadcasts `{type: 'complete', risk_score, results}` ➔<br/>"
        "Frontend renders interactive dashboard at `/results/{scan_id}` with PDF/JSON export and expiring share links."
    )
    t_diag = Table([[Paragraph(flow_diagram_text, body)]], colWidths=[515])
    t_diag.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_card),
        ('BOX', (0,0), (-1,-1), 1, c_secondary),
        ('PADDING', (0,0), (-1,-1), 7),
    ]))
    story.append(t_diag)
    story.append(Spacer(1, 8))

    # ==================== 4. MODULE-BY-MODULE IN-DEPTH SPECIFICATION ====================
    story.append(Paragraph("4. Technical Deep Dive: The 11 Reconnaissance Engines", h1))
    story.append(Paragraph(
        "Each module in Phantom Recon is isolated, self-contained, and designed for high fault-tolerance. If any single external API or service fails, "
        "the remaining modules continue uninterrupted:",
        body
    ))

    mod_specs = [
        [Paragraph("Module", table_hdr), Paragraph("Type", table_hdr), Paragraph("Protocols & Mechanism", table_hdr), Paragraph("Security Impact & Output", table_hdr)],
        [
            Paragraph("<b>1. WHOIS Module</b>", table_cell_bold),
            Paragraph("Passive", table_cell),
            Paragraph("TCP 43 WHOIS queries via `python-whois`. Parses registrar, creation date, expiration, and DNS nameservers.", table_cell),
            Paragraph("Identifies administrative ownership, imminent domain expiration vulnerabilities, and social engineering contacts.", table_cell)
        ],
        [
            Paragraph("<b>2. DNS Module</b>", table_cell_bold),
            Paragraph("Active Query", table_cell),
            Paragraph("Queries Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) via `dnspython` for A, AAAA, MX, TXT, NS, SOA, and CNAME.", table_cell),
            Paragraph("Audits email spoofing defenses. Flags missing or permissive SPF (`~all` vs `-all`), DMARC policies (`p=none`), and DKIM selectors.", table_cell)
        ],
        [
            Paragraph("<b>3. Subdomain Engine</b>", table_cell_bold),
            Paragraph("Hybrid", table_cell),
            Paragraph("4-tier enumeration: (1) crt.sh Certificate Transparency; (2) HackerTarget API; (3) Sublist3r search scrapers; (4) Threaded DNS brute force.", table_cell),
            Paragraph("Maps hidden perimeter assets: staging subdomains, development portals, internal VPN gateways, and microservices.", table_cell)
        ],
        [
            Paragraph("<b>4. Email Harvester</b>", table_cell_bold),
            Paragraph("Passive", table_cell),
            Paragraph("Queries Hunter.io API when keys exist; scrapes search engine snippets using strict regular expression matchers.", table_cell),
            Paragraph("Deduces corporate username and email patterns (`{first}.{last}@domain.com`) used in credential stuffing and phishing simulations.", table_cell)
        ],
        [
            Paragraph("<b>5. Shodan Module</b>", table_cell_bold),
            Paragraph("Passive OSINT", table_cell),
            Paragraph("Queries official Shodan REST API host endpoints with target IPs. Ingests software versions and CVE databases.", table_cell),
            Paragraph("Discovers unpatched CVE vulnerabilities (e.g. Log4j, OpenSSL bugs, RCEs) without triggering target intrusion detection systems.", table_cell)
        ],
        [
            Paragraph("<b>6. Tech Fingerprint</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Issues HTTP/HTTPS GET requests. Inspects `Server`, `X-Powered-By`, cookie signatures (PHPSESSID, csrftoken), and HTML tags.", table_cell),
            Paragraph("Fingerprints web servers (Nginx, Apache), backend frameworks (Django, Laravel, Next.js), CMS (WordPress), and CDN layers (Cloudflare).", table_cell)
        ],
        [
            Paragraph("<b>7. SSL/TLS Audit</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Establishes TLS handshake via Python `ssl` and `socket`. Extracts X.509 cert, issuer, cipher suite, and Subject Alternative Names (SANs).", table_cell),
            Paragraph("Detects expired or self-signed certificates, weak ciphers, and uncovers affiliated domain names embedded inside the SAN certificate list.", table_cell)
        ],
        [
            Paragraph("<b>8. Dual-Engine Port Scan</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Tier 1: Native Nmap (`-sT -T4 -Pn -oX -`).<br/>Tier 2: Concurrent Python socket scanner with retries.<br/>Tier 3: Shodan InternetDB cross-validation.", table_cell),
            Paragraph("Audits 54 critical ports (SSH 22, HTTP 80, HTTPS 443, Cisco 2000, SIP 5060, MySQL 3306, RDP 3389). Grabs service banners.", table_cell)
        ],
        [
            Paragraph("<b>9. OSINT Aggregator</b>", table_cell_bold),
            Paragraph("Passive OSINT", table_cell),
            Paragraph("Queries VirusTotal v3 API for malicious reputation flags, Wayback Machine for archived URL endpoints, and GitHub for repo leaks.", table_cell),
            Paragraph("Uncovers historical endpoints, forgotten sensitive files (`.git`, `config.php`), and domain mentions in public breach datasets.", table_cell)
        ],
        [
            Paragraph("<b>10. Cloud & Takeover</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Permutates domain names against AWS S3, Azure Blob, and GCP buckets. Inspects CNAME pointers for orphaned SaaS endpoints.", table_cell),
            Paragraph("Detects publicly readable or writable cloud storage buckets and flags high-risk subdomain takeovers (pointing to deleted S3, Heroku, etc.).", table_cell)
        ],
        [
            Paragraph("<b>11. Heuristic Risk Engine</b>", table_cell_bold),
            Paragraph("Synthesis", table_cell),
            Paragraph("Applies algorithmic mathematical scoring formula over aggregated findings. Generates executive summary metrics.", table_cell),
            Paragraph("Outputs 0–100 risk score and categorizes target into LOW, MEDIUM, HIGH, or CRITICAL risk tiers for executive decision-making.", table_cell)
        ],
    ]
    t_mod_spec = Table(mod_specs, colWidths=[80, 50, 195, 190])
    t_mod_spec.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_dark),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(t_mod_spec)

    # Page Break for Risk Formula & Competitive Analysis
    story.append(PageBreak())

    # ==================== 5. ALGORITHMIC RISK SCORING FORMULA ====================
    story.append(Paragraph("5. Algorithmic Heuristic Risk Scoring Mathematical Model", h1))
    story.append(Paragraph(
        "Unlike basic recon tools that dump raw strings without context, Phantom Recon implements an objective, deterministic risk calculation "
        "function (`_calculate_risk()` in `backend/main.py`). The formula calculates cumulative risk score \\(R\\) bounded between 0 and 100:",
        body
    ))

    risk_formula_box = [
        [Paragraph(
            "<b>Mathematical Formulation:</b><br/>"
            "&nbsp;&nbsp;&nbsp;&nbsp;<b>R = min( 100, &sum; ( Weight<sub>i</sub> &times; Trigger<sub>i</sub> ) )</b><br/>"
            "Where each risk factor is evaluated against empirical vulnerability severity weights:",
            body_bold
        )]
    ]
    t_form = Table(risk_formula_box, colWidths=[515])
    t_form.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_card),
        ('BOX', (0,0), (-1,-1), 1, c_secondary),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_form)
    story.append(Spacer(1, 4))

    risk_table_data = [
        [Paragraph("Security Risk Factor / Indicator", table_hdr), Paragraph("Weight", table_hdr), Paragraph("Heuristic Evaluation Trigger Condition & Rationale", table_hdr)],
        [
            Paragraph("<b>Publicly Readable Cloud Buckets</b>", table_cell_bold),
            Paragraph("<font color='#b91c1c'><b>+30 pts</b></font>", table_cell),
            Paragraph("Triggered if any AWS S3, Azure Blob, or GCP bucket returns HTTP 200 with directory listing. Represents immediate critical data leakage risk.", table_cell)
        ],
        [
            Paragraph("<b>Confirmed Subdomain Takeover</b>", table_cell_bold),
            Paragraph("<font color='#b91c1c'><b>+25 pts</b></font>", table_cell),
            Paragraph("Triggered when a CNAME points to a decommissioned external provider (e.g. unclaimed GitHub Pages, dead S3 bucket, expired Heroku app).", table_cell)
        ],
        [
            Paragraph("<b>Leaked GitHub Credentials / Repos</b>", table_cell_bold),
            Paragraph("<font color='#b91c1c'><b>+20 pts</b></font>", table_cell),
            Paragraph("Triggered when domain-associated repositories contain exposed secrets (`.env`, private RSA keys, hardcoded API tokens).", table_cell)
        ],
        [
            Paragraph("<b>Unpatched CVE Vulnerabilities</b>", table_cell_bold),
            Paragraph("<font color='#b45309'><b>+10–40 pts</b></font>", table_cell),
            Paragraph("Adds 10 points per confirmed CVE flagged via Shodan service banners (capped at 40 points maximum).", table_cell)
        ],
        [
            Paragraph("<b>Broad External Attack Surface</b>", table_cell_bold),
            Paragraph("<font color='#b45309'><b>+15 pts</b></font>", table_cell),
            Paragraph("Triggered if active subdomains exceed 50. A large attack surface significantly elevates probability of unmonitored shadow IT.", table_cell)
        ],
        [
            Paragraph("<b>VirusTotal Malicious Flags</b>", table_cell_bold),
            Paragraph("<font color='#b45309'><b>+15 pts</b></font>", table_cell),
            Paragraph("Triggered if 1 or more antivirus engines flag the domain or associated URLs as malicious or phishing.", table_cell)
        ],
        [
            Paragraph("<b>Excessive Exposed Public Ports</b>", table_cell_bold),
            Paragraph("<font color='#0369a1'><b>+10 pts</b></font>", table_cell),
            Paragraph("Triggered if >10 public TCP ports are open, indicating lack of perimeter firewall ingress controls.", table_cell)
        ],
        [
            Paragraph("<b>Expired or Invalid SSL/TLS Cert</b>", table_cell_bold),
            Paragraph("<font color='#0369a1'><b>+10 pts</b></font>", table_cell),
            Paragraph("Triggered if the SSL certificate has lapsed, uses an untrusted issuer, or is invalid, exposing users to MITM attacks.", table_cell)
        ],
    ]
    t_risk_table = Table(risk_table_data, colWidths=[155, 60, 300])
    t_risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_risk_table)
    story.append(Spacer(1, 4))

    risk_tier_box = [
        [
            Paragraph("<b>LOW RISK (0–19 pts):</b> Minimal exposed surface, valid TLS, zero unpatched CVEs, cloud assets secured.", table_cell),
            Paragraph("<b>MEDIUM RISK (20–39 pts):</b> Broad attack surface, minor configuration issues, or non-critical port exposures.", table_cell),
        ],
        [
            Paragraph("<b>HIGH RISK (40–59 pts):</b> Confirmed CVEs, leaked tokens, or multiple perimeter services directly exposed.", table_cell),
            Paragraph("<b>CRITICAL RISK (60–100 pts):</b> Publicly readable storage buckets, confirmed subdomain takeovers, or active malware flags.", table_cell),
        ]
    ]
    t_tier = Table(risk_tier_box, colWidths=[255, 260])
    t_tier.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_card),
        ('BOX', (0,0), (-1,-1), 0.5, c_border),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_tier)

    # ==================== 6. EXHAUSTIVE COMPETITIVE ANALYSIS ====================
    story.append(Spacer(1, 6))
    story.append(Paragraph("6. Platform Comparative Analysis: How Phantom Recon Differs from Existing Tools", h1))
    story.append(Paragraph(
        "To rigorously evaluate Phantom Recon against established cybersecurity tools, the following matrix compares core operational dimensions "
        "against <b>Spiderfoot</b>, <b>OWASP Amass</b>, <b>Recon-ng</b>, <b>theHarvester</b>, and <b>Maltego</b>:",
        body
    ))

    comp_headers = [
        Paragraph("Dimension / Feature", table_hdr),
        Paragraph("Phantom Recon v2.1", table_hdr),
        Paragraph("Spiderfoot", table_hdr),
        Paragraph("OWASP Amass", table_hdr),
        Paragraph("Recon-ng", table_hdr),
        Paragraph("theHarvester", table_hdr),
    ]

    comp_matrix = [
        [
            Paragraph("<b>User Interface</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Modern Web HUD (React 18)</b></font>", table_cell),
            Paragraph("Legacy Python Web UI", table_cell),
            Paragraph("CLI Only", table_cell),
            Paragraph("CLI Interactive Shell", table_cell),
            Paragraph("CLI Only", table_cell),
        ],
        [
            Paragraph("<b>Live Telemetry</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>WebSocket Streaming</b></font>", table_cell),
            Paragraph("Slow HTTP Polling", table_cell),
            Paragraph("Terminal stdout text", table_cell),
            Paragraph("Terminal stdout text", table_cell),
            Paragraph("Terminal stdout text", table_cell),
        ],
        [
            Paragraph("<b>Algorithmic Risk Score</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Unified 0–100 Score</b></font>", table_cell),
            Paragraph("No unified 0–100 score", table_cell),
            Paragraph("No risk score", table_cell),
            Paragraph("No risk score", table_cell),
            Paragraph("No risk score", table_cell),
        ],
        [
            Paragraph("<b>Port Scanning Engine</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Dual Nmap + Sockets + OSINT</b></font>", table_cell),
            Paragraph("Basic single socket probe", table_cell),
            Paragraph("Limited DNS focus", table_cell),
            Paragraph("External modules only", table_cell),
            Paragraph("None (Harvesting only)", table_cell),
        ],
        [
            Paragraph("<b>Cloud Storage Auditing</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Native S3/Azure/GCP checks</b></font>", table_cell),
            Paragraph("Requires plugin setup", table_cell),
            Paragraph("DNS permutation only", table_cell),
            Paragraph("Manual script setup", table_cell),
            Paragraph("None", table_cell),
        ],
        [
            Paragraph("<b>Mandatory Consent Gate</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Server-Side Enforced</b></font>", table_cell),
            Paragraph("None (No legal gate)", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
        ],
        [
            Paragraph("<b>Database Architecture</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>SQLite WAL (Zero-cost)</b></font>", table_cell),
            Paragraph("Heavy SQLite / Postgres", table_cell),
            Paragraph("Graph DB / SQLite", table_cell),
            Paragraph("SQLite workspace DB", table_cell),
            Paragraph("Stateless (RAM only)", table_cell),
        ],
        [
            Paragraph("<b>Client-Ready Reporting</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Executive PDF + JSON</b></font>", table_cell),
            Paragraph("CSV / GEXF graph dumps", table_cell),
            Paragraph("Graphviz / JSON dumps", table_cell),
            Paragraph("CSV / HTML reports", table_cell),
            Paragraph("Raw text / XML", table_cell),
        ],
        [
            Paragraph("<b>Expiring Share Links</b>", table_cell_bold),
            Paragraph("<font color='#047857'><b>Tokenized Read-Only HUD</b></font>", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
        ],
    ]
    t_comp = Table([comp_headers] + comp_matrix, colWidths=[95, 90, 82, 82, 82, 84])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_comp)

    # Page Break for Why Use Phantom Recon & Engineering Fixes
    story.append(PageBreak())

    # ==================== 7. WHY USE PHANTOM RECON OVER OTHERS ====================
    story.append(Paragraph("7. Why Phantom Recon Should Be Used Over Other Platforms", h1))
    story.append(Paragraph(
        "Based on the empirical comparative analysis, Phantom Recon provides seven decisive architectural and operational advantages:",
        body
    ))

    advantages = [
        ("1. Unified All-in-One Reconnaissance Pipeline", 
         "Instead of launching 5 different CLI tools and manually reconciling disparate text outputs, Phantom Recon executes a unified, sequential reconnaissance run in under 60 seconds. It captures ownership (WHOIS), DNS records, subdomains, email footprints, Shodan infrastructure, technology stacks, SSL posture, port services, OSINT threat reputation, and cloud storage leaks in a single pass."),
        
        ("2. Actionable Heuristic Risk Prioritization (0–100)",
         "Most OSINT tools (like Amass or theHarvester) dump thousands of lines of raw text, leaving analysts overwhelmed. Phantom Recon synthesizes all discovered indicators into a weighted, objective security score (LOW, MEDIUM, HIGH, CRITICAL) so stakeholders can immediately prioritize remediation."),
        
        ("3. Cloud-Resilient Dual-Engine Port Scanning",
         "When deployed to modern cloud hosting environments (such as Railway, AWS, or Render), outbound TCP connections on ports like 22 (SSH) and 5060 (SIP) are frequently dropped by cloud provider egress firewalls. Phantom Recon uniquely overcomes this through its tri-tier scanning architecture: bundling native Nmap into container build specs, adding adaptive socket retries, and cross-validating with Shodan's free InternetDB API. This guarantees 100% detection parity matching local Nmap CLI results."),
        
        ("4. Real-Time Telemetry via WebSockets (Zero Polling Overhead)",
         "Legacy web interfaces (like Spiderfoot) rely on sluggish HTTP polling that hammers the server and introduces artificial lag. Phantom Recon utilizes a full-duplex WebSocket connection, streaming live terminal outputs and phase progress indicators with sub-millisecond latency."),
        
        ("5. Mandatory Ethical Compliance & Consent Verification",
         "Unlike tools that can be weaponized carelessly, Phantom Recon enforces mandatory legal consent verification at the API layer using Pydantic schema validation. Unconsented scan requests are rejected with `HTTP 422`, establishing strict audit compliance."),
        
        ("6. Client-Ready Executive Deliverables & Expiring Share Links",
         "Consultants and red teams can instantly generate professional executive PDF reports on the server using ReportLab or generate cryptographic, time-limited share links. Clients can view the read-only scan results without gaining administrative scanner privileges."),
        
        ("7. Zero Infrastructure Footprint & Zero Hosting Cost",
         "While enterprise tools require heavy PostgreSQL clusters or Neo4j graph databases, Phantom Recon utilizes an optimized SQLite database with Write-Ahead Logging (WAL mode). It runs completely self-contained in a single Docker container at zero infrastructure cost.")
    ]

    for title, desc in advantages:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", bullet))
        story.append(Spacer(1, 1.5))

    # ==================== 8. KEY ENGINEERING CHALLENGES SOLVED ====================
    story.append(Spacer(1, 4))
    story.append(Paragraph("8. Key Engineering Challenges Solved During Project Development", h1))

    challenges = [
        ("Challenge A: The Cloud Egress Port Scan Anomaly",
         "<i>Problem:</i> Scanning targets from a local PC revealed 5 open ports (22, 80, 443, 2000, 5060), but scanning from the deployed Railway container reported only ports 80 and 443.<br/>"
         "<i>Root Cause:</i> Cloud PaaS container networking drops outbound TCP packets on port 22 (to stop SSH brute-force bots) and port 5060 (to stop VoIP SIP fraud). Furthermore, unprivileged Docker images lacked native Nmap.<br/>"
         "<i>Resolution:</i> (1) Updated `backend/Dockerfile` and `nixpacks.toml` to install `nmap` via apt-get; (2) Implemented native Nmap XML output parsing (`-sT -T4 -Pn -oX -`) in `port_module.py`; and (3) Added passive cross-validation using Shodan's InternetDB API with browser-like user agents, ensuring all verified open ports are detected anywhere."),

        ("Challenge B: High-Concurrency SQLite Database Lockups in Asynchronous FastAPI",
         "<i>Problem:</i> Streaming high-frequency log lines to the database while users queried historical scans resulted in SQLite `database is locked` runtime exceptions.<br/>"
         "<i>Root Cause:</i> Standard SQLite locks the entire database file during write transactions.<br/>"
         "<i>Resolution:</i> Migrated the persistence engine (`backend/database.py`) to asynchronous `aiosqlite` and activated Write-Ahead Logging via `PRAGMA journal_mode = WAL;`. In WAL mode, concurrent readers do not block writers, and writers do not block readers, enabling flawless multi-task concurrency."),

        ("Challenge C: Windows Console Character Encoding Crashes",
         "<i>Problem:</i> Running port scans on Windows command prompts threw `UnicodeEncodeError: 'charmap' codec can't encode character '\\u2500'`.<br/>"
         "<i>Resolution:</i> Wrapped terminal table output formatters with ASCII-safe fallbacks (`-` and `|`) and safe exception handlers, ensuring zero crashes on Windows stdout."),

        ("Challenge D: Server-Side Secret Key Security & Zero Frontend Leakage",
         "<i>Problem:</i> Third-party API keys (Shodan, VirusTotal, Hunter.io) risked exposure if fetched by client scripts.<br/>"
         "<i>Resolution:</i> All API keys are isolated in server environment variables (`.env`). The `/api/config/keys` endpoint strictly returns boolean status flags (`{'shodan': true}`), preventing secret tokens from ever reaching the browser bundle.")
    ]

    for title, desc in challenges:
        story.append(Paragraph(f"<b>{title}</b>", h2))
        story.append(Paragraph(desc, body))
        story.append(Spacer(1, 2))

    # Page Break for Viva Voce Q&A
    story.append(PageBreak())

    # ==================== 9. VIVA VOCE & DEFENSE MASTER Q&A ====================
    story.append(Paragraph("9. Project Defense & Viva Voce Master Q&A Sheet", h1))
    story.append(Paragraph(
        "The following questions represent the core technical inquiries anticipated during capstone project defense, external evaluation, and technical interviews:",
        body
    ))
    story.append(Spacer(1, 4))

    viva_qa = [
        ("Q1: What is the fundamental difference between passive and active reconnaissance in Phantom Recon?",
         "Passive reconnaissance extracts intelligence from publicly accessible, third-party databases without transmitting a single packet to the target's network (e.g. querying WHOIS registrars, crt.sh Certificate Transparency logs, historical Wayback Machine snapshots, VirusTotal reputation tables, and Shodan sensor indexes). The target has zero knowledge of our inspection.<br/>"
         "Active reconnaissance transmits packets directly to the target system (e.g. DNS lookups, HTTP header requests, SSL/TLS handshake negotiation, and TCP port probing). Because active probes generate network logs in the target's firewalls and IDSes, our application enforces mandatory written authorization before initiation."),

        ("Q2: Why did you choose WebSockets over traditional REST polling for scan progress streaming?",
         "REST polling requires the client to repeatedly send HTTP GET requests every second. This introduces heavy HTTP header overhead, wastes server CPU cycles, and creates artificial latency. WebSockets maintain a persistent, full-duplex TCP socket. When a backend module discovers a port or completes a phase, FastAPI pushes a micro-JSON payload immediately with sub-millisecond latency. If a connection drops, the frontend automatically reconnects seamlessly."),

        ("Q3: Why did you choose SQLite with WAL mode over PostgreSQL or MongoDB?",
         "For a dedicated security appliance or academic capstone deployment, external database clusters introduce unnecessary operational costs, network latency, and configuration overhead. Standard SQLite can suffer from file write locks, but by enabling Write-Ahead Logging (`PRAGMA journal_mode = WAL;`), readers never block writers and writers never block readers. This enables our backend to write high-frequency live logs while users query historical scans concurrently with zero lock contention."),

        ("Q4: How does the system calculate the security risk score, and how is it bounded?",
         "The calculation engine in `_calculate_risk()` applies an objective weighted heuristic: Broad attack surface (>50 subdomains) = +15 pts; Unpatched CVEs = up to +40 pts (10 pts per CVE); Publicly readable cloud buckets (S3/Azure/GCP) = +30 pts (Critical); Confirmed subdomain takeovers = +25 pts; Leaked credentials in GitHub = +20 pts; VirusTotal malicious detections = +15 pts; Expired SSL certificate = +10 pts. The score is mathematically bounded via `min(100, sum(weights))` and maps to standard risk tiers: LOW (0–19), MEDIUM (20–39), HIGH (40–59), and CRITICAL (60–100)."),

        ("Q5: How did you solve the cloud egress firewall issue where ports like 22 or 5060 were hidden?",
         "Cloud PaaS containers (such as Railway or AWS) throttle or drop outbound TCP connections on ports 22 (SSH) and 5060 (SIP) to prevent abuse. We solved this with a tri-tier resilience strategy: (1) We bundled native Nmap into the Dockerfile and Nixpacks build specs to execute TCP connect scans (`-sT -T4 -Pn`); (2) We added adaptive socket retries with increased timeouts; and (3) We cross-referenced Shodan's free InternetDB API with browser-like user agents to pull internet-wide sensor observations, guaranteeing 100% detection accuracy matching local Nmap CLI results."),

        ("Q6: How do you prevent unauthorized abuse or illegal scanning with Phantom Recon?",
         "Both the React frontend and the FastAPI backend enforce a strict legal consent gate. The Pydantic request model (`ScanRequest.consent`) executes a field validator that immediately raises a validation error (`HTTP 422 Unprocessable Entity`) if the user does not affirm written authorization. Raw API requests via curl or Postman cannot bypass this requirement."),

        ("Q7: How are API keys managed securely, and why can't a user steal them from the browser bundle?",
         "All third-party API credentials (Shodan, VirusTotal, Hunter.io, Netlas, GitHub) reside exclusively in backend environment variables (`.env`). The client-facing `/api/config/keys` endpoint strictly returns boolean status flags (`{'shodan': true, 'hunter': false}`), ensuring no secret token is ever transmitted over the network or compiled into the client-side JavaScript bundle."),

        ("Q8: What happens if an external OSINT API is down during a scan?",
         "Every module in `backend/modules/` is isolated inside independent `try-except` blocks. If an external service (such as VirusTotal or Shodan) is rate-limited, unreachable, or returns a 500 error, the module logs a warning to the WebSocket stream and returns an empty dictionary. The main scan worker catches the error, marks the phase complete, and proceeds to the next module without halting the scan.")
    ]

    for q, a in viva_qa:
        story.append(Paragraph(f"<b>{q}</b>", h2))
        story.append(Paragraph(a, body))
        story.append(Spacer(1, 2))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated high-detail master dossier: {filename}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "PHANTOM_RECON_ARCHITECTURE_AND_COMPARISON_GUIDE.pdf"
    build_pdf(out_file)
