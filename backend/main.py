"""
backend/main.py - FastAPI Application for PHANTOM RECON v2.1
============================================================
Features:
- Mandatory server-side consent verification via Pydantic validator
- Persistent SQLite storage with aiosqlite and WAL mode
- WebSocket streaming (/api/scan/{id}/stream) with historical log replay
- Rate limiting per client IP backed by SQLite
- Expiring read-only share readout links (/api/scan/{id}/share and /api/shared/{token})
- Strict zero-leakage API config endpoint (/api/config/keys returns only booleans)
- Non-blocking asynchronous task execution with demo mode fallback
"""

import os
import sys
import json
import asyncio
import uuid
import re
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional, Set

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, HTTPException,
    Depends, Request, Query, status, BackgroundTasks
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field, field_validator

# Ensure stdout and stderr do not crash on Windows charmap/cp1252 encoders
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config as app_config
import demo
import database as db

# ── Lifespan Context ──────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and tables
    await db.init_db()
    yield

app = FastAPI(
    title="PHANTOM RECON v2.1 API",
    description="Red Team Reconnaissance Framework Web Console Backend",
    version="2.1.0",
    lifespan=lifespan
)

# ── CORS Middleware ───────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if "*" in ALLOWED_ORIGINS else ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket Connection Manager ──────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            if scan_id not in self.active_connections:
                self.active_connections[scan_id] = set()
            self.active_connections[scan_id].add(websocket)

    async def disconnect(self, scan_id: str, websocket: WebSocket):
        async with self.lock:
            if scan_id in self.active_connections:
                self.active_connections[scan_id].discard(websocket)
                if not self.active_connections[scan_id]:
                    del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: Dict[str, Any]):
        async with self.lock:
            connections = list(self.active_connections.get(scan_id, []))
        for conn in connections:
            try:
                await conn.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# ── Helper for Logging & Streaming ───────────────────────────
async def stream_log(scan_id: str, level: str, message: str, phase: Optional[str] = None, progress: int = 0):
    await db.add_scan_log(scan_id, level, message, phase, progress)
    await manager.broadcast(scan_id, {
        "type": "log",
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        "phase": phase,
        "progress": progress
    })

# ── Pydantic Request Models ──────────────────────────────────
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, e.g. example.com")
    consent: bool = Field(..., description="Mandatory confirmation of written scanning authorization")
    passive_only: bool = Field(default=False, description="Restrict scan to passive modules only")
    demo_mode: bool = Field(default=False, description="Run in simulated demo mode using mock generator")
    modules: List[str] = Field(
        default_factory=lambda: ["whois", "dns", "subdomain", "email", "shodan", "tech", "ssl", "port", "osint", "cloud"],
        description="List of modules to execute"
    )
    threads: int = Field(default=10, ge=1, le=50)
    timeout: int = Field(default=5, ge=1, le=60)

    @field_validator("consent")
    @classmethod
    def enforce_mandatory_consent(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "Consent verification failed: Explicit written authorization is legally mandatory before initiating reconnaissance."
            )
        return v

    @field_validator("target")
    @classmethod
    def sanitize_and_validate_target(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean.startswith("http://"):
            clean = clean[7:]
        elif clean.startswith("https://"):
            clean = clean[8:]
        clean = clean.split("/")[0].split(":")[0]
        pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(pattern, clean):
            raise ValueError(f"Invalid target domain '{v}'. Please provide a valid domain name (e.g. example.com).")
        return clean

class ShareRequest(BaseModel):
    expires_in_hours: int = Field(default=24, ge=1, le=720, description="Expiration time in hours (1-720)")

# ── Rate Limiter Dependency ──────────────────────────────────
async def verify_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    # Respect X-Forwarded-For if behind a proxy / load balancer
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    
    # 20 scans per hour limit per IP
    allowed = await db.check_rate_limit(client_ip, max_requests=20, window_seconds=3600)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded (maximum 20 scan requests per hour). Please retry later."
        )

# ── Asynchronous Scan Worker ─────────────────────────────────
async def execute_scan(scan_id: str, target: str, passive_only: bool, demo_mode: bool, selected_modules: List[str], threads: int, timeout: int):
    try:
        await db.update_scan_status(scan_id, "running")
        await stream_log(scan_id, "info", f"Initializing PHANTOM RECON v2.1 engine for target: {target}", "INIT", 5)

        # Automatic fallback to demo mode if explicitly chosen OR if run in sandbox demo mode
        if demo_mode:
            await _run_demo_scan(scan_id, target, selected_modules, passive_only)
        else:
            await _run_real_scan(scan_id, target, selected_modules, passive_only, threads, timeout)

    except Exception as exc:
        err_msg = f"Scan execution failed: {str(exc)}"
        await stream_log(scan_id, "error", err_msg, "FAILED", 100)
        await db.update_scan_status(scan_id, "failed", error_message=err_msg)
        await manager.broadcast(scan_id, {
            "type": "error",
            "scan_id": scan_id,
            "message": err_msg
        })

async def _run_demo_scan(scan_id: str, target: str, selected_modules: List[str], passive_only: bool):
    """Executes a simulated scan with timed logs using demo.py mock data."""
    await stream_log(scan_id, "info", "Demo Mode activated — executing simulation with mock engine telemetry.", "DEMO", 10)
    mock_data = demo.generate_mock_results(domain=target)
    
    # Sequence of phases to simulate
    phase_order = [
        ("whois", "WHOIS Lookup & Registrar Intelligence", "whois"),
        ("dns", "DNS Enumeration & Record Analysis", "dns"),
        ("subdomain", "Subdomain Enumeration (Sublist3r + Brute Force)", "subdomains"),
        ("email", "Email & OSINT Harvesting", "emails"),
        ("shodan", "Shodan API: Exposed Services & Vulnerabilities", "shodan"),
        ("tech", "Technology Fingerprinting (Wappalyzer-Style)", "technologies"),
        ("ssl", "SSL/TLS Certificate Analysis", "ssl"),
        ("osint", "OSINT Aggregation (VirusTotal + Wayback + GitHub)", "osint"),
        ("cloud", "Cloud Asset Discovery (S3 / Azure / GCP / GitHub)", "cloud"),
        ("port", "Port Scanning (Top Ports)", "ports"),
    ]

    active_phases = [p for p in phase_order if p[0] in selected_modules and not (passive_only and p[0] == "port")]
    total = len(active_phases)

    for idx, (mod_key, phase_title, res_key) in enumerate(active_phases, start=1):
        pct = 10 + int((idx / (total + 1)) * 80)
        await stream_log(scan_id, "phase", f"PHASE {idx}/{total}: {phase_title.upper()}", mod_key.upper(), pct)
        await asyncio.sleep(0.9)  # Smooth streaming experience for UI

        # Module-specific log messages
        if mod_key == "whois":
            w = mock_data.get("whois", {})
            await stream_log(scan_id, "success", f"Registrar: {w.get('registrar')}, Days to Expiry: {w.get('days_until_expiry')}", mod_key.upper(), pct)
        elif mod_key == "dns":
            d = mock_data.get("dns", {})
            await stream_log(scan_id, "success", f"SPF Record: {d.get('spf')}", mod_key.upper(), pct)
            await stream_log(scan_id, "info", f"DMARC Policy: {d.get('dmarc')}", mod_key.upper(), pct)
        elif mod_key == "subdomain":
            subs = mock_data.get("subdomains", [])
            await stream_log(scan_id, "success", f"Discovered {len(subs)} subdomains across crt.sh & DNS brute force", mod_key.upper(), pct)
            for s in subs[:2]:
                if s.get("takeover_risk"):
                    await stream_log(scan_id, "warning", f"Takeover risk detected on {s.get('subdomain')} -> {s.get('takeover_risk')}", mod_key.upper(), pct)
        elif mod_key == "email":
            emails = [e for e in mock_data.get("emails", []) if isinstance(e, dict) and "email" in e]
            await stream_log(scan_id, "success", f"Harvested {len(emails)} target-affiliated email addresses", mod_key.upper(), pct)
        elif mod_key == "tech":
            techs = [t.get("name") for t in mock_data.get("technologies", {}).get("detected", [])]
            await stream_log(scan_id, "success", f"Fingerprinted technologies: {', '.join(techs)}", mod_key.upper(), pct)
        elif mod_key == "ssl":
            ssl_info = mock_data.get("ssl", {})
            await stream_log(scan_id, "success", f"TLS Protocol: {ssl_info.get('protocol_version')}, Cipher: {ssl_info.get('cipher')}", mod_key.upper(), pct)
        elif mod_key == "cloud":
            await stream_log(scan_id, "info", "Probed AWS S3, Azure Blob, GCP Buckets, and public GitHub repos", mod_key.upper(), pct)
        elif mod_key == "port":
            ports = mock_data.get("ports", [])
            open_p = [str(p.get("port")) for p in ports if p.get("state") == "open"]
            await stream_log(scan_id, "success", f"Open ports identified: {', '.join(open_p)}", mod_key.upper(), pct)

        await asyncio.sleep(0.4)

    # Finalize
    await stream_log(scan_id, "phase", "Compiling Risk Matrix & Reconnaissance Synthesis", "REPORT", 95)
    await asyncio.sleep(0.5)

    summary = mock_data.get("summary", {})
    risk_score = summary.get("risk_score", 25)
    risk_level = summary.get("risk_level", "MEDIUM")

    await db.save_scan_results(scan_id, mock_data, risk_score, risk_level, summary)
    await stream_log(scan_id, "success", f"Reconnaissance complete! Final Risk Assessment: {risk_level} (Score: {risk_score}/100)", "COMPLETE", 100)

    await manager.broadcast(scan_id, {
        "type": "complete",
        "scan_id": scan_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "results": mock_data
    })

async def _run_real_scan(scan_id: str, target: str, selected_modules: List[str], passive_only: bool, threads: int, timeout: int):
    """Executes the 11 Python reconnaissance modules in backend/modules asynchronously."""
    from modules.whois_module import WhoisModule
    from modules.dns_module import DNSModule
    from modules.subdomain_module import SubdomainModule
    from modules.email_module import EmailModule
    from modules.shodan_module import ShodanModule
    from modules.tech_module import TechModule
    from modules.ssl_module import SSLModule
    from modules.port_module import PortModule
    from modules.osint_module import OsintModule
    from modules.cloud_module import CloudModule

    out_dir = os.path.join(os.path.dirname(__file__), "output", f"{target}_{scan_id[:8]}")
    os.makedirs(out_dir, exist_ok=True)

    config = {
        "domain": target,
        "threads": threads,
        "timeout": timeout,
        "verbose": False,
        "wordlist": None,
        "shodan_key": app_config.SHODAN_API_KEY,
        "virustotal_key": app_config.VIRUSTOTAL_API_KEY,
        "netlas_key": app_config.NETLAS_API_KEY,
        "out_dir": out_dir,
    }

    results = {
        "meta": {
            "target": target,
            "scan_id": scan_id,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "tool": "PHANTOM RECON v2.1",
            "passive_only": passive_only,
            "modules_run": selected_modules
        },
        "whois": {},
        "dns": {},
        "subdomains": [],
        "emails": [],
        "shodan": {},
        "technologies": {},
        "ssl": {},
        "ports": [],
        "osint": {},
        "cloud": {},
        "summary": {}
    }

    module_map = [
        ("whois", "WHOIS Lookup & Registrar Intelligence", WhoisModule, "whois"),
        ("dns", "DNS Enumeration & Record Analysis", DNSModule, "dns"),
        ("subdomain", "Subdomain Enumeration (Sublist3r + DNS Brute Force)", SubdomainModule, "subdomains"),
        ("email", "Email Harvesting & Pattern Discovery", EmailModule, "emails"),
        ("shodan", "Shodan API: Exposed Services & Vulnerabilities", ShodanModule, "shodan"),
        ("tech", "Technology Fingerprinting", TechModule, "technologies"),
        ("ssl", "SSL/TLS Certificate Analysis", SSLModule, "ssl"),
        ("osint", "OSINT Aggregation (VirusTotal + Wayback + GitHub)", OsintModule, "osint"),
        ("cloud", "Cloud Asset Discovery (S3 / Azure / GCP / GitHub)", CloudModule, "cloud"),
    ]
    if "port" in selected_modules and not passive_only:
        module_map.append(("port", "Port Scanning (Top Ports)", PortModule, "ports"))

    active_modules = [m for m in module_map if m[0] in selected_modules]
    total = len(active_modules)

    for idx, (mod_key, title, ModClass, res_key) in enumerate(active_modules, start=1):
        progress = int((idx / (total + 1)) * 90)
        await stream_log(scan_id, "phase", f"PHASE {idx}/{total}: {title.upper()}", mod_key.upper(), progress)
        try:
            # Run blocking module code in executor thread to keep event loop responsive
            mod_instance = ModClass(config)
            mod_result = await asyncio.to_thread(mod_instance.run)
            results[res_key] = mod_result
            results[mod_key] = mod_result  # Keep singular alias as well
            await stream_log(scan_id, "success", f"Completed {title}", mod_key.upper(), progress)
        except Exception as err:
            err_str = f"Error in {title}: {str(err)}"
            results[res_key] = {"error": err_str}
            results[mod_key] = {"error": err_str}
            await stream_log(scan_id, "warning", err_str, mod_key.upper(), progress)

    # Risk Calculation
    await stream_log(scan_id, "phase", "Synthesizing Security Risk Assessment", "SUMMARY", 95)
    summary = _calculate_risk(results)
    results["summary"] = summary

    risk_score = summary.get("risk_score", 0)
    risk_level = summary.get("risk_level", "LOW")

    await db.save_scan_results(scan_id, results, risk_score, risk_level, summary)
    await stream_log(scan_id, "success", f"Reconnaissance complete! Final Risk Assessment: {risk_level} ({risk_score}/100)", "COMPLETE", 100)

    await manager.broadcast(scan_id, {
        "type": "complete",
        "scan_id": scan_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "results": results
    })

def _calculate_risk(results: dict) -> dict:
    """Computes comprehensive risk score and identifies key risk factors."""
    subdomains = results.get("subdomains") or results.get("subdomain") or []
    raw_emails = results.get("emails") or results.get("email") or []
    emails = [e for e in raw_emails if isinstance(e, dict) and "email" in e]
    shodan = results.get("shodan", {})
    ports = results.get("ports") or results.get("port") or []
    ssl = results.get("ssl", {})
    cloud = results.get("cloud", {})
    osint = results.get("osint", {})

    open_ports = [p for p in ports if isinstance(p, dict) and p.get("state") == "open"]
    cve_count = 0
    if isinstance(shodan, dict):
        for host in shodan.get("hosts", []):
            cve_count += len(host.get("vulns", []))

    cloud_exposed = cloud.get("exposed_count", 0) if isinstance(cloud, dict) else 0
    confirmed_takeovers = [t for t in (cloud.get("takeover_risks", []) if isinstance(cloud, dict) else []) if t.get("confirmed")]
    leaked_repos = [r for r in (cloud.get("github_repos", []) if isinstance(cloud, dict) else []) if r.get("sensitive_files_found")]
    vt_malicious = osint.get("virustotal", {}).get("malicious", 0) if isinstance(osint, dict) else 0

    risk_score = 0
    risk_factors = []

    if len(subdomains) > 50:
        risk_score += 15
        risk_factors.append(f"Broad attack surface: {len(subdomains)} subdomains identified")
    if cve_count > 0:
        risk_score += min(cve_count * 10, 40)
        risk_factors.append(f"{cve_count} CVEs flagged via Shodan service banners")
    if ssl.get("expired"):
        risk_score += 10
        risk_factors.append("SSL/TLS certificate is expired or invalid")
    if len(open_ports) > 10:
        risk_score += 10
        risk_factors.append(f"{len(open_ports)} exposed public ports discovered")
    if cloud_exposed > 0:
        risk_score += 30
        risk_factors.append(f"CRITICAL: {cloud_exposed} publicly readable cloud storage bucket(s)")
    if confirmed_takeovers:
        risk_score += 25
        risk_factors.append(f"{len(confirmed_takeovers)} confirmed subdomain takeover target(s)")
    if leaked_repos:
        risk_score += 20
        risk_factors.append(f"{len(leaked_repos)} GitHub repo(s) containing exposed credentials/tokens")
    if vt_malicious > 0:
        risk_score += 15
        risk_factors.append(f"VirusTotal detected {vt_malicious} malicious flags")

    risk_level = (
        "CRITICAL" if risk_score >= 60 else
        "HIGH" if risk_score >= 40 else
        "MEDIUM" if risk_score >= 20 else
        "LOW"
    )

    return {
        "subdomains_found": len(subdomains),
        "emails_found": len(emails),
        "open_ports": len(open_ports),
        "cve_count": cve_count,
        "cloud_exposed": cloud_exposed,
        "confirmed_takeovers": len(confirmed_takeovers),
        "leaked_repos": len(leaked_repos),
        "risk_score": min(risk_score, 100),
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "ssl_valid": ssl.get("valid", False),
        "technologies_detected": len(results.get("technologies", {}).get("detected", [])) if isinstance(results.get("technologies"), dict) else 0
    }

# ── REST API Endpoints ────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring, Railway, Render, Fly.io."""
    return {
        "status": "healthy",
        "app": "PHANTOM RECON v2.1",
        "time": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/config/keys")
async def get_api_key_status():
    """
    STRICT SECURITY CONTRACT:
    Returns strictly boolean flags indicating whether each external recon API key
    is configured in server environment variables. Never reveals the secrets.
    """
    return {
        "shodan": bool(app_config.SHODAN_API_KEY),
        "hunter": bool(app_config.HUNTER_API_KEY),
        "virustotal": bool(app_config.VIRUSTOTAL_API_KEY),
        "netlas": bool(app_config.NETLAS_API_KEY),
        "github": bool(app_config.GITHUB_TOKEN),
        "censys": bool(app_config.CENSYS_API_ID and app_config.CENSYS_API_SECRET),
    }

@app.post("/api/scan", dependencies=[Depends(verify_rate_limit)])
async def initiate_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Submits a target for reconnaissance.
    Strictly enforces client consent server-side.
    """
    scan_id = str(uuid.uuid4())
    scan_record = await db.create_scan(
        scan_id=scan_id,
        target=request.target,
        consent_given=request.consent,
        passive_only=request.passive_only,
        demo_mode=request.demo_mode,
        modules=request.modules
    )

    # Spawn background scan execution via FastAPI BackgroundTasks
    background_tasks.add_task(
        execute_scan,
        scan_id=scan_id,
        target=request.target,
        passive_only=request.passive_only,
        demo_mode=request.demo_mode,
        selected_modules=request.modules,
        threads=request.threads,
        timeout=request.timeout
    )

    return {
        "scan_id": scan_id,
        "target": request.target,
        "status": "queued",
        "message": "Scan successfully queued for execution."
    }

@app.get("/api/scan/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieves full scan metadata and findings from SQLite."""
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan

@app.get("/api/scan/{scan_id}/logs")
async def get_scan_logs(scan_id: str):
    """Retrieves all telemetry logs for a given scan."""
    logs = await db.get_scan_logs(scan_id)
    return {"scan_id": scan_id, "logs": logs}

@app.get("/api/scans")
async def list_recent_scans(limit: int = 50, offset: int = 0):
    """Lists historical scans stored in SQLite."""
    scans = await db.list_scans(limit=limit, offset=offset)
    return {"scans": scans, "count": len(scans)}

@app.delete("/api/scan/{scan_id}")
async def delete_scan_record(scan_id: str):
    """Deletes a scan record and its associated logs and shared links."""
    success = await db.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {"status": "deleted", "scan_id": scan_id}

@app.post("/api/scan/{scan_id}/share")
async def create_share_readout(scan_id: str, req: ShareRequest = ShareRequest()):
    """
    Generates an expiring, cryptographically secure read-only token
    for sharing with capstone reviewers without granting access to the full dashboard.
    """
    link_info = await db.create_share_link(scan_id, expires_in_hours=req.expires_in_hours)
    if not link_info:
        raise HTTPException(status_code=404, detail="Scan not found or unable to create share link.")
    return {
        "share_token": link_info["token"],
        "share_url": f"/shared/{link_info['token']}",
        "expires_at": link_info["expires_at"],
        "expires_in_hours": link_info["expires_in_hours"],
        "target": link_info["target"]
    }

@app.get("/api/shared/{token}")
async def get_shared_readout(token: str):
    """
    Accesses a shared, read-only reconnaissance report.
    Validates token expiration. Does NOT require authentication.
    """
    data = await db.get_shared_scan(token)
    if not data:
        raise HTTPException(status_code=404, detail="Shared readout link is invalid or does not exist.")
    if data.get("expired"):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"This shared readout link expired on {data.get('expires_at')}. Please request a new readout link."
        )
    return data

@app.get("/api/scan/{scan_id}/report/html")
async def download_html_report(scan_id: str):
    """Generates and serves a standalone HTML reconnaissance report."""
    scan = await db.get_scan(scan_id)
    if not scan or not scan.get("results"):
        raise HTTPException(status_code=404, detail="Scan results not available.")
    
    from modules.report_module import ReportModule
    out_dir = os.path.join(os.path.dirname(__file__), "output", f"report_{scan_id[:8]}")
    os.makedirs(out_dir, exist_ok=True)
    report_mod = ReportModule({"domain": scan["target"], "out_dir": out_dir})
    paths = report_mod.run(scan["results"])
    html_file = paths.get("html")
    if html_file and os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content)
    raise HTTPException(status_code=500, detail="Failed to compile HTML report.")

# ── WebSocket Real-Time Log Streaming ─────────────────────────
@app.websocket("/api/scan/{scan_id}/stream")
async def websocket_scan_stream(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time terminal output streaming.
    Replays existing logs so refreshed/reconnected clients see full history.
    """
    await manager.connect(scan_id, websocket)
    try:
        # Replay any existing logs stored in SQLite
        logs = await db.get_scan_logs(scan_id)
        for log in logs:
            await websocket.send_json({
                "type": "log",
                "scan_id": scan_id,
                "timestamp": log["timestamp"],
                "level": log["level"],
                "message": log["message"],
                "phase": log["phase"],
                "progress": log["progress"]
            })

        # Check if scan is already completed
        scan = await db.get_scan(scan_id)
        if scan and scan.get("status") in ("completed", "failed"):
            await websocket.send_json({
                "type": "complete" if scan.get("status") == "completed" else "error",
                "scan_id": scan_id,
                "risk_score": scan.get("risk_score", 0),
                "risk_level": scan.get("risk_level", "UNKNOWN"),
                "summary": scan.get("summary", {}),
                "results": scan.get("results", {}),
                "message": scan.get("error_message") or "Scan completed."
            })

        # Keep connection open to receive broadcast messages until client disconnects
        while True:
            # Client can send ping or message if needed
            await websocket.receive_text()

    except WebSocketDisconnect:
        await manager.disconnect(scan_id, websocket)
    except Exception:
        await manager.disconnect(scan_id, websocket)
