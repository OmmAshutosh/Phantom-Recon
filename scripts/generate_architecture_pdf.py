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
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 800, "PHANTOM RECON v2.1 — MASTER ARCHITECTURE & COMPARATIVE ANALYSIS")
            self.drawRightString(541, 800, "CAPSTONE DEFENSE DOSSIER")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 794, 541, 794)

        # Footer (all pages)
        self.setFont("Helvetica", 8)
        self.drawString(54, 35, "CONFIDENTIAL — FOR ACADEMIC EVALUATION & SECURITY RESEARCH ONLY")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(541, 35, page_text)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 541, 46)
        
        self.restoreState()

def build_pdf(filename="PHANTOM_RECON_ARCHITECTURE_AND_COMPARISON_GUIDE.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Palette definition
    c_primary = colors.HexColor("#0f172a")     # Slate 900
    c_secondary = colors.HexColor("#0284c7")   # Sky 600
    c_accent = colors.HexColor("#2563eb")      # Blue 600
    c_dark = colors.HexColor("#1e293b")        # Slate 800
    c_muted = colors.HexColor("#64748b")       # Slate 500
    c_light = colors.HexColor("#f8fafc")       # Slate 50
    c_card = colors.HexColor("#f1f5f9")        # Slate 100
    c_border = colors.HexColor("#e2e8f0")      # Slate 200
    c_success = colors.HexColor("#059669")     # Emerald 600
    c_warning = colors.HexColor("#d97706")     # Amber 600
    c_danger = colors.HexColor("#dc2626")      # Red 600

    # Custom typography
    t_title = ParagraphStyle("TTitle", fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=c_primary, alignment=TA_LEFT)
    t_sub = ParagraphStyle("TSub", fontName="Helvetica", fontSize=12, leading=16, textColor=c_secondary, spaceAfter=15)
    t_meta = ParagraphStyle("TMeta", fontName="Helvetica", fontSize=9, leading=13, textColor=c_muted)
    
    h1 = ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=c_primary, spaceBefore=18, spaceAfter=8, keepWithNext=True)
    h2 = ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=c_accent, spaceBefore=12, spaceAfter=6, keepWithNext=True)
    body = ParagraphStyle("Body", fontName="Helvetica", fontSize=9.5, leading=14, textColor=c_dark, alignment=TA_JUSTIFY, spaceAfter=6)
    body_bold = ParagraphStyle("BodyB", fontName="Helvetica-Bold", fontSize=9.5, leading=14, textColor=c_dark)
    bullet = ParagraphStyle("Bullet", fontName="Helvetica", fontSize=9, leading=13, textColor=c_dark, leftIndent=12, spaceAfter=3)
    callout = ParagraphStyle("Callout", fontName="Helvetica", fontSize=9, leading=13, textColor=c_dark, backColor=c_card, borderPadding=8, spaceBefore=6, spaceAfter=8)
    table_cell = ParagraphStyle("TCell", fontName="Helvetica", fontSize=8, leading=11, textColor=c_dark)
    table_cell_bold = ParagraphStyle("TCellB", fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=c_primary)
    table_hdr = ParagraphStyle("THdr", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white, alignment=TA_CENTER)

    story = []

    # ==================== COVER / HEADER ====================
    story.append(Paragraph("⚡ PHANTOM RECON v2.1", t_title))
    story.append(Paragraph("Automated Red Team Attack Surface Intelligence, Architecture & Platform Comparative Analysis", t_sub))
    
    meta_box = [
        [
            Paragraph("<b>Project Type:</b> Cybersecurity Capstone Project (Semester 7)", t_meta),
            Paragraph("<b>Framework:</b> FastAPI + React 18 + Vite + SQLite WAL", t_meta),
        ],
        [
            Paragraph("<b>Repository:</b> github.com/OmmAshutosh/Phantom-Recon", t_meta),
            Paragraph("<b>Classification:</b> Master Technical Defense Dossier", t_meta),
        ]
    ]
    t_meta_table = Table(meta_box, colWidths=[240, 247])
    t_meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_card),
        ('BOX', (0,0), (-1,-1), 1, c_border),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_meta_table)
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_secondary, spaceBefore=2, spaceAfter=15))

    # ==================== 1. EXECUTIVE SUMMARY ====================
    story.append(Paragraph("1. Executive Summary & Problem Formulation", h1))
    story.append(Paragraph(
        "Modern cybersecurity reconnaissance presents a critical operational challenge: security teams, penetration testers, "
        "and blue-team defenders are forced to manually coordinate dozens of fragmented tools (e.g. WHOIS lookups, DNS utilities, "
        "Nmap port scans, sublist3r scripts, Certificate Transparency logs, and browser tabs for Shodan and VirusTotal). "
        "This disjointed approach causes hours of manual overhead, fragmented data with no unified risk scoring, and zero automated executive reporting.",
        body
    ))
    story.append(Paragraph(
        "<b>PHANTOM RECON v2.1</b> solves this problem by delivering a unified, autonomous reconnaissance pipeline. "
        "It integrates 11 specialized passive and active reconnaissance modules, streams real-time execution telemetry over WebSockets, "
        "applies an algorithmic heuristic risk assessment (0–100), and outputs both interactive SOC dashboards and publication-grade PDF dossiers.",
        body
    ))

    # ==================== 2. SYSTEM ARCHITECTURE ====================
    story.append(Spacer(1, 10))
    story.append(Paragraph("2. High-Level System Architecture & Execution Flow", h1))
    story.append(Paragraph(
        "The framework is decoupled into distinct presentation, API orchestration, real-time messaging, reconnaissance worker, and persistence tiers:",
        body
    ))

    arch_table_data = [
        [Paragraph("Layer", table_hdr), Paragraph("Technologies", table_hdr), Paragraph("Architectural Responsibility & Rationale", table_hdr)],
        [
            Paragraph("<b>Frontend HUD</b>", table_cell_bold),
            Paragraph("React 18, Vite, TypeScript, Tailwind CSS, Lucide", table_cell),
            Paragraph("Single Page Application (SPA). Renders interactive SOC interface, real-time log viewers, filterable port matrices, and SVG risk gauges with sub-300KB bundle footprint.", table_cell)
        ],
        [
            Paragraph("<b>API & Gateway</b>", table_cell_bold),
            Paragraph("FastAPI, Uvicorn, Pydantic v2", table_cell),
            Paragraph("Asynchronous ASGI server. Enforces domain syntax validation, mandatory legal consent gates, and IP-based rate limiting before launching background scan workers.", table_cell)
        ],
        [
            Paragraph("<b>Streaming Bus</b>", table_cell_bold),
            Paragraph("WebSockets (WSS)", table_cell),
            Paragraph("Full-duplex real-time channel. Pushes live phase indicators, terminal output strings, and progress milestones (0-100%) to the browser with zero HTTP polling overhead.", table_cell)
        ],
        [
            Paragraph("<b>Recon Engine</b>", table_cell_bold),
            Paragraph("Dual Nmap / Sockets, Python Asyncio, DNS/OSINT", table_cell),
            Paragraph("Orchestrates 11 isolated modules in sequential phases across passive intelligence, active TCP probing, cloud bucket auditing, and credential leak discovery.", table_cell)
        ],
        [
            Paragraph("<b>Persistence</b>", table_cell_bold),
            Paragraph("SQLite + aiosqlite (WAL Mode)", table_cell),
            Paragraph("Crash-resilient disk storage (`phantom.db`). Write-Ahead Logging allows background workers to write live telemetry while users query historical scans concurrently.", table_cell)
        ],
        [
            Paragraph("<b>Reporting</b>", table_cell_bold),
            Paragraph("ReportLab Engine", table_cell),
            Paragraph("Generates standalone executive PDF reports and machine-readable JSON exports directly on the server for automated stakeholder delivery.", table_cell)
        ],
    ]
    t_arch = Table(arch_table_data, colWidths=[80, 140, 267])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(t_arch)

    # Page Break for Module Breakdown & Flow
    story.append(PageBreak())

    # ==================== 3. WORKING FLOW & MODULES ====================
    story.append(Paragraph("3. End-to-End Workflow & 11 Reconnaissance Modules", h1))
    story.append(Paragraph(
        "When an analyst triggers a scan, execution follows a strictly orchestrated, phase-by-phase security pipeline:",
        body
    ))

    flow_box = [
        [Paragraph("<b>Step 1: Submission & Legal Gate</b> — User provides target and explicitly signs the authorization checkbox. Pydantic rejects unconsented scans with HTTP 422.", bullet)],
        [Paragraph("<b>Step 2: Job Dispatch & Streaming Init</b> — Server creates UUIDv4 scan record in SQLite, accepts WebSocket handshake, and spawns `run_scan()` task.", bullet)],
        [Paragraph("<b>Step 3: Phased Recon Execution</b> — The engine executes 10 core intelligence modules sequentially, logging findings live to WebSocket and SQLite.", bullet)],
        [Paragraph("<b>Step 4: Heuristic Risk Scoring</b> — Aggregates CVEs, open ports, cloud exposures, and certificate issues into an objective 0-100 severity score.", bullet)],
        [Paragraph("<b>Step 5: Completion & Reporting</b> — Persists full scan dossier to SQLite, broadcasts completion event, and renders visual analytics and downloadable PDF.", bullet)],
    ]
    t_flow = Table(flow_box, colWidths=[487])
    t_flow.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), c_card),
        ('BOX', (0,0), (-1,-1), 1, c_secondary),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_flow)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Detailed Breakdown of the 11 Core Modules:", h2))

    modules_data = [
        [Paragraph("Module", table_hdr), Paragraph("Type", table_hdr), Paragraph("Mechanism & Output", table_hdr)],
        [
            Paragraph("<b>1. WHOIS</b>", table_cell_bold),
            Paragraph("Passive", table_cell),
            Paragraph("Queries authoritative registrars. Extracts domain owner, registration dates, expiry timeline, and registrar name servers.", table_cell)
        ],
        [
            Paragraph("<b>2. DNS Records</b>", table_cell_bold),
            Paragraph("Active/Query", table_cell),
            Paragraph("Queries 1.1.1.1 / 8.8.8.8 for A, AAAA, MX, TXT, NS, SOA, and CNAME. Evaluates SPF, DMARC, and DKIM email spoofing defenses.", table_cell)
        ],
        [
            Paragraph("<b>3. Subdomains</b>", table_cell_bold),
            Paragraph("Hybrid", table_cell),
            Paragraph("Scrapes Certificate Transparency logs (crt.sh), HackerTarget API, search engine scrapers (Sublist3r), and multi-threaded DNS brute force.", table_cell)
        ],
        [
            Paragraph("<b>4. Email Intelligence</b>", table_cell_bold),
            Paragraph("Passive", table_cell),
            Paragraph("Integrates Hunter.io and search engine pattern regexes to deduce corporate email nomenclature ({first}.{last}@domain.com) for social engineering modeling.", table_cell)
        ],
        [
            Paragraph("<b>5. Shodan Intelligence</b>", table_cell_bold),
            Paragraph("Passive OSINT", table_cell),
            Paragraph("Leverages Shodan host APIs to map pre-indexed open ports, operating systems, and unpatched CVE vulnerabilities without touching the target.", table_cell)
        ],
        [
            Paragraph("<b>6. Tech Fingerprinting</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Inspects HTTP/HTTPS headers (Server, X-Powered-By), framework session cookies (PHPSESSID, csrftoken), and HTML meta generator tags.", table_cell)
        ],
        [
            Paragraph("<b>7. SSL/TLS Audit</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Negotiates SSL handshake via Python ssl. Audits certificate expiration, issuer CA trustworthiness, cipher suites, and Subject Alternative Names (SANs).", table_cell)
        ],
        [
            Paragraph("<b>8. Dual-Engine Port Scan</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Runs native Nmap (-sT -T4 -Pn) XML parsing with fallback to concurrent socket probing, adaptive retries, and Shodan InternetDB cross-validation.", table_cell)
        ],
        [
            Paragraph("<b>9. OSINT Aggregator</b>", table_cell_bold),
            Paragraph("Passive OSINT", table_cell),
            Paragraph("Queries VirusTotal for malicious reputation flags, Wayback Machine for historical endpoints, and GitHub for exposed domain credentials.", table_cell)
        ],
        [
            Paragraph("<b>10. Cloud & Takeover</b>", table_cell_bold),
            Paragraph("Active Probe", table_cell),
            Paragraph("Probes AWS S3, Azure Blob, and GCP bucket permissions for public read exposure. Audits dangling CNAME records for subdomain takeover risks.", table_cell)
        ],
        [
            Paragraph("<b>11. Risk Engine</b>", table_cell_bold),
            Paragraph("Synthesis", table_cell),
            Paragraph("Synthesizes all raw findings into an algorithmic 0-100 risk score, mapping targets to LOW, MEDIUM, HIGH, or CRITICAL risk postures.", table_cell)
        ],
    ]
    t_mod = Table(modules_data, colWidths=[100, 65, 322])
    t_mod.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_dark),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_mod)

    # Page Break for Comparative Analysis
    story.append(PageBreak())

    # ==================== 4. COMPETITIVE ANALYSIS ====================
    story.append(Paragraph("4. Comparative Analysis: How Phantom Recon Differs from Existing Platforms", h1))
    story.append(Paragraph(
        "To understand the unique academic and practical value of Phantom Recon, it is essential to evaluate it against the "
        "prevailing industry tools: <b>Spiderfoot</b>, <b>OWASP Amass</b>, <b>Recon-ng</b>, <b>theHarvester</b>, and <b>Maltego</b>.",
        body
    ))
    story.append(Spacer(1, 4))

    comp_headers = [
        Paragraph("Capability / Feature", table_hdr),
        Paragraph("Phantom Recon v2.1", table_hdr),
        Paragraph("Spiderfoot", table_hdr),
        Paragraph("OWASP Amass", table_hdr),
        Paragraph("Recon-ng", table_hdr),
        Paragraph("theHarvester", table_hdr),
    ]

    comp_rows = [
        [
            Paragraph("<b>User Interface</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Modern Web HUD (React 18)</b></font>", table_cell),
            Paragraph("Legacy Python Web UI", table_cell),
            Paragraph("CLI Only (No native UI)", table_cell),
            Paragraph("CLI Modular Console", table_cell),
            Paragraph("CLI Only", table_cell),
        ],
        [
            Paragraph("<b>Live Telemetry</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>WebSocket Streaming</b></font>", table_cell),
            Paragraph("Slow Polling / Refresh", table_cell),
            Paragraph("Standard stdout text", table_cell),
            Paragraph("Standard stdout text", table_cell),
            Paragraph("Standard stdout text", table_cell),
        ],
        [
            Paragraph("<b>Risk Scoring Engine</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Algorithmic (0-100 Score)</b></font>", table_cell),
            Paragraph("No unified 0-100 score", table_cell),
            Paragraph("No risk score", table_cell),
            Paragraph("No risk score", table_cell),
            Paragraph("No risk score", table_cell),
        ],
        [
            Paragraph("<b>Port Scanning</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Dual Nmap + Sockets + OSINT</b></font>", table_cell),
            Paragraph("Basic socket probe", table_cell),
            Paragraph("Limited / DNS-centric", table_cell),
            Paragraph("External modules only", table_cell),
            Paragraph("None (Harvesting only)", table_cell),
        ],
        [
            Paragraph("<b>Cloud Storage Auditing</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Native S3/Azure/GCP checks</b></font>", table_cell),
            Paragraph("Requires plugin setup", table_cell),
            Paragraph("DNS permutation only", table_cell),
            Paragraph("Manual script setup", table_cell),
            Paragraph("None", table_cell),
        ],
        [
            Paragraph("<b>Mandatory Consent Gate</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Enforced Server-Side</b></font>", table_cell),
            Paragraph("None (No legal gate)", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
            Paragraph("None", table_cell),
        ],
        [
            Paragraph("<b>Database Footprint</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>SQLite WAL (Zero-cost)</b></font>", table_cell),
            Paragraph("Heavy SQLite / Postgres", table_cell),
            Paragraph("Graph DB / SQLite", table_cell),
            Paragraph("SQLite database", table_cell),
            Paragraph("Stateless / Memory only", table_cell),
        ],
        [
            Paragraph("<b>Client-Ready Reporting</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Executive PDF + JSON Export</b></font>", table_cell),
            Paragraph("CSV / GEXF graph dumps", table_cell),
            Paragraph("Graphviz / JSON files", table_cell),
            Paragraph("CSV / HTML reports", table_cell),
            Paragraph("Raw HTML / XML / JSON", table_cell),
        ],
        [
            Paragraph("<b>Expiring Share Links</b>", table_cell_bold),
            Paragraph("<font color='#059669'><b>Tokenized Read-Only HUD</b></font>", table_cell),
            Paragraph("No shareable link system", table_cell),
            Paragraph("No web sharing", table_cell),
            Paragraph("No web sharing", table_cell),
            Paragraph("No web sharing", table_cell),
        ],
    ]

    t_comp = Table([comp_headers] + comp_rows, colWidths=[95, 88, 76, 76, 76, 76])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), c_primary),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, c_light]),
        ('PADDING', (0,0), (-1,-1), 4),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 12))

    # ==================== 5. WHY PHANTOM RECON OVER OTHERS ====================
    story.append(Paragraph("5. Why Phantom Recon Should Be Used Over Other Platforms", h1))
    
    reasons = [
        ("1. Unified All-in-One Reconnaissance Pipeline", 
         "Instead of configuring disparate scripts and merging CLI text files, Phantom Recon automatically runs the entire lifecycle in under 60 seconds: WHOIS, DNS, subdomains, emails, Shodan, technology detection, SSL auditing, Nmap port scanning, OSINT leaks, and cloud bucket security."),
        
        ("2. Actionable Algorithmic Risk Scoring (0–100)",
         "Most OSINT tools merely output endless data tables with no prioritization. Phantom Recon synthesizes all findings into a weighted heuristic score (CRITICAL, HIGH, MEDIUM, LOW) so leadership can immediately understand risk posture without parsing hundreds of log lines."),
        
        ("3. Cloud-Resilient Dual-Engine Port Scanning",
         "Traditional CLI tools fail when deployed in cloud containers (e.g. Railway or AWS) because cloud providers block outbound ports 22 (SSH) and 5060 (SIP). Phantom Recon's hybrid engine combines native Nmap XML parsing, concurrent socket retries, and Shodan InternetDB cross-validation, guaranteeing 100% detection accuracy anywhere."),
        
        ("4. Strict Compliance & Legal Auditability",
         "Phantom Recon cannot be weaponized accidentally. Pydantic-enforced server-side validation requires affirmative legal written consent on every scan request before initiating active probes, and all API keys remain strictly hidden on the server."),
        
        ("5. Executive Deliverables & Secure Sharing",
         "Security consultants can generate publication-grade PDF dossiers with a single click or create time-limited, read-only tokenized URLs for clients to view scan analytics without exposing administrative scanner controls."),
        
        ("6. Zero-Maintenance, Zero-Cost Cloud Deployment",
         "Unlike heavyweight platforms requiring Neo4j or PostgreSQL clusters, Phantom Recon runs on SQLite in Write-Ahead Logging (WAL) mode. It deploys cleanly in a single Docker container on Railway, Render, or local VMs at zero infrastructure cost.")
    ]

    for title, desc in reasons:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", bullet))
        story.append(Spacer(1, 2))

    # Page Break for Viva Defense Sheet
    story.append(PageBreak())

    # ==================== 6. VIVA & DEFENSE MASTER SHEET ====================
    story.append(Paragraph("6. Project Defense & Viva Voce Master Q&A Sheet", h1))
    story.append(Paragraph("Key technical questions examiners and interviewers ask, with model technical answers:", body))
    story.append(Spacer(1, 4))

    qa_list = [
        ("Q1: What is the technical distinction between passive and active reconnaissance in Phantom Recon?",
         "Passive recon extracts threat data from third-party databases without transmitting any packets to the target (e.g. WHOIS, crt.sh certificate logs, Shodan indexes, Wayback Machine, and VirusTotal). The target is unaware of the scan. Active recon directly probes the target's IP (e.g. DNS resolution, SSL handshakes, HTTP banner requests, and TCP port scans). Active recon generates logs in target firewalls, which is why Phantom Recon enforces legal authorization before execution."),

        ("Q2: Why did you choose WebSockets over traditional AJAX / REST polling?",
         "REST polling requires the client to repeatedly send HTTP GET requests every second, creating significant HTTP header overhead, wasting server CPU cycles, and creating artificial display lag. WebSockets establish a single persistent, full-duplex TCP socket. When a backend module discovers a port or completes a phase, FastAPI pushes a micro-payload instantly with sub-millisecond latency."),

        ("Q3: Why use SQLite in WAL mode instead of PostgreSQL or MongoDB?",
         "For an academic capstone or standalone pentest appliance, setting up external database servers introduces unnecessary cost, complex networking, and maintenance overhead. Standard SQLite locks the entire database file during writes. By executing `PRAGMA journal_mode=WAL;` (Write-Ahead Logging), readers do not block writers and writers do not block readers. The backend can write high-frequency scan logs while users query history simultaneously with zero lock contention."),

        ("Q4: How does the system calculate the security risk score?",
         "The calculation engine in `_calculate_risk()` applies weighted risk factors: Broad attack surface (>50 subdomains) = +15; Unpatched CVEs = up to +40; Publicly readable cloud storage buckets = +30 (Critical); Confirmed subdomain takeovers = +25; Leaked credentials in GitHub = +20; VirusTotal malicious detections = +15; Expired SSL certificate = +10. The score maps to standard tiers: LOW (0–19), MEDIUM (20–39), HIGH (40–59), and CRITICAL (60–100)."),

        ("Q5: How did you fix the issue where cloud port scanning missed open ports like 22 and 5060?",
         "Cloud PaaS containers (Railway/AWS) throttle or drop outbound TCP connections on ports 22 (to stop SSH brute-force bots) and 5060 (to stop VoIP SIP fraud). We solved this by: (1) Bundling native Nmap into the Docker/Nixpacks container to execute TCP connect scans (-sT -T4 -Pn); (2) Adding adaptive socket retries; and (3) Cross-referencing Shodan's free InternetDB API with browser-like user agents to pull internet-wide sensor observations, guaranteeing full detection parity with local Nmap."),

        ("Q6: How does Phantom Recon protect sensitive API credentials?",
         "All third-party API keys (Shodan, VirusTotal, Hunter.io, GitHub) reside exclusively in backend environment variables (`.env`). The client-facing `/api/config/keys` endpoint only returns boolean status flags (`{'shodan': true}`), ensuring raw secret keys are never exposed in network responses or frontend bundles.")
    ]

    for q, a in qa_list:
        story.append(Paragraph(f"<b>{q}</b>", h2))
        story.append(Paragraph(a, body))
        story.append(Spacer(1, 3))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated: {filename}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "PHANTOM_RECON_ARCHITECTURE_AND_COMPARISON_GUIDE.pdf"
    build_pdf(out_file)
