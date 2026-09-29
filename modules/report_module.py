"""
Report Generation Module - HTML + PDF
=======================================
Generates professional penetration testing recon reports
suitable for client delivery and portfolio presentation.
"""

import os
import json
from datetime import datetime
from colorama import Fore, Style

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False


class ReportModule:
    """Generates HTML and PDF reconnaissance reports."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.out_dir = config["out_dir"]

    def run(self, results: dict) -> dict:
        paths = {}
        html_path = os.path.join(self.out_dir, f"{self.domain}_recon_report.html")
        pdf_path = os.path.join(self.out_dir, f"{self.domain}_recon_report.pdf")

        print(f"  {Fore.BLUE}[*] Generating HTML report...{Style.RESET_ALL}")
        self._generate_html(results, html_path)
        paths["html"] = html_path

        if REPORTLAB_OK:
            print(f"  {Fore.BLUE}[*] Generating PDF report...{Style.RESET_ALL}")
            try:
                self._generate_pdf(results, pdf_path)
                paths["pdf"] = pdf_path
            except Exception as e:
                print(f"  {Fore.YELLOW}[!] PDF generation error: {e}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}[!] reportlab not installed - skipping PDF{Style.RESET_ALL}")

        return paths

    def _generate_html(self, results: dict, path: str):
        meta = results.get("meta", {})
        summary = results.get("summary", {})
        whois = results.get("whois", {})
        dns = results.get("dns", {})
        subdomains = results.get("subdomains", [])
        emails = results.get("emails", [])
        shodan = results.get("shodan", {})
        technologies = results.get("technologies", {})
        ssl = results.get("ssl", {})
        ports = results.get("ports", [])
        osint = results.get("osint", {})
        cloud = results.get("cloud", {})

        risk_level = summary.get("risk_level", "LOW")
        risk_color = {
            "LOW": "#27ae60",
            "MEDIUM": "#f39c12",
            "HIGH": "#e74c3c",
            "CRITICAL": "#c0392b"
        }.get(risk_level, "#95a5a6")

        scan_date = meta.get("scan_date", datetime.now().isoformat())[:10]

        # Subdomain rows
        sub_rows = ""
        for sub in subdomains[:100]:
            if isinstance(sub, dict) and "subdomain" in sub:
                takeover = sub.get("takeover_risk")
                risk_badge = (
                    f'<span class="badge badge-danger">TAKEOVER RISK</span>'
                    if takeover else ""
                )
                ips = ", ".join(sub.get("ips", [])[:3])
                sources = ", ".join(sub.get("sources", []))
                sub_rows += f"""
                <tr>
                    <td>{sub['subdomain']}</td>
                    <td>{ips}</td>
                    <td>{sources}</td>
                    <td>{risk_badge}</td>
                </tr>"""

        # Email rows
        email_rows = ""
        for em in emails:
            if isinstance(em, dict) and "email" in em:
                conf_color = {"high": "#27ae60", "medium": "#f39c12", "low": "#e74c3c"}.get(
                    em.get("confidence", "low"), "#95a5a6"
                )
                email_rows += f"""
                <tr>
                    <td>{em['email']}</td>
                    <td>{', '.join(em.get('sources', []))}</td>
                    <td style="color:{conf_color}">{em.get('confidence','?').upper()}</td>
                </tr>"""

        # Port rows
        port_rows = ""
        for p in ports:
            if p.get("state") == "open":
                risk_clr = {"CRITICAL": "#c0392b", "HIGH": "#e74c3c",
                            "MEDIUM": "#f39c12", "LOW": "#27ae60"}.get(p.get("risk", "LOW"), "#27ae60")
                banner = (p.get("banner") or "")[:60]
                port_rows += f"""
                <tr>
                    <td>{p.get('ip','')}</td>
                    <td>{p.get('port','')}</td>
                    <td>{p.get('service','')}</td>
                    <td style="color:{risk_clr};font-weight:bold">{p.get('risk','')}</td>
                    <td><code>{banner}</code></td>
                </tr>"""

        # Tech rows
        tech_rows = ""
        for tech in technologies.get("detected", []):
            risk_clr = {"critical": "#c0392b", "high": "#e74c3c",
                        "medium": "#f39c12", "low": "#27ae60",
                        "informational": "#3498db"}.get(tech.get("risk", "low"), "#95a5a6")
            tech_rows += f"""
            <tr>
                <td>{tech.get('name','')}</td>
                <td>{tech.get('version') or '—'}</td>
                <td>{tech.get('category','')}</td>
                <td style="color:{risk_clr};font-weight:bold">{tech.get('risk','').upper()}</td>
            </tr>"""

        # Missing headers
        missing_headers_html = ""
        for h in technologies.get("missing_security_headers", []):
            missing_headers_html += f"<li><code>{h['header']}</code> — {h['description']}</li>"

        # CVE list
        cves = shodan.get("cves", [])
        cve_html = "".join(
            f'<li class="cve-item"><a href="https://nvd.nist.gov/vuln/detail/{c}" '
            f'target="_blank">{c}</a></li>' for c in cves
        ) or "<li>No CVEs detected</li>"

        # Risk factors
        risk_factors_html = "".join(
            f"<li>⚠️ {f}</li>" for f in summary.get("risk_factors", [])
        ) or "<li>No significant risk factors detected</li>"

        # DNS records table
        dns_rows = ""
        for rtype, records in dns.get("records", {}).items():
            for rec in records[:5]:
                dns_rows += f"<tr><td><code>{rtype}</code></td><td>{rec[:120]}</td></tr>"

        # Cloud storage bucket rows (S3 + Azure + GCP)
        cloud_bucket_rows = ""
        all_buckets = (
            cloud.get("s3_buckets", []) +
            cloud.get("azure_containers", []) +
            cloud.get("gcp_buckets", [])
        )
        exposed_buckets = [b for b in all_buckets if b.get("accessible")]
        for b in exposed_buckets:
            cloud_bucket_rows += f"""
            <tr>
                <td>{b.get('provider','')}</td>
                <td><code>{b.get('name','')}</code></td>
                <td><a href="{b.get('url','')}" target="_blank">{b.get('url','')}</a></td>
                <td>{b.get('file_count','?')}</td>
                <td><span class="badge badge-danger">{b.get('severity','CRITICAL')}</span></td>
            </tr>"""

        # Subdomain takeover risk rows (from CloudModule CNAME checks)
        cloud_takeover_rows = ""
        for t in cloud.get("takeover_risks", []):
            conf_badge = (
                '<span class="badge badge-danger">CONFIRMED</span>'
                if t.get("confirmed") else
                '<span class="badge badge-warning">POTENTIAL</span>'
            )
            cloud_takeover_rows += f"""
            <tr>
                <td>{t.get('subdomain','')}</td>
                <td><code>{t.get('cname','')}</code></td>
                <td>{t.get('description','')}</td>
                <td>{conf_badge}</td>
            </tr>"""

        # GitHub repos (from CloudModule)
        github_repo_html = ""
        for r in cloud.get("github_repos", [])[:10]:
            leak_badge = (
                f'<span class="badge badge-danger">{len(r["sensitive_files_found"])} LEAKED FILE(S)</span>'
                if r.get("sensitive_files_found") else ""
            )
            github_repo_html += f"""
            <div class="info-item">
                <a href="{r.get('url','')}" target="_blank">{r.get('name','')}</a>
                — {r.get('language','') or 'N/A'} — ★ {r.get('stars',0)} {leak_badge}
            </div>"""

        # OSINT: VirusTotal + Netlas (legacy key "securitytrails") + Wayback + GitHub dorks
        osint_vt = osint.get("virustotal", {})
        osint_netlas = osint.get("securitytrails", {})   # _netlas_recon writes here
        osint_wayback = osint.get("wayback", {})
        osint_leaks = osint.get("github_leaks", {})

        osint_wayback_rows = ""
        for u in osint_wayback.get("urls", [])[:15]:
            osint_wayback_rows += f"<tr><td><code>{str(u)[:140]}</code></td></tr>"

        osint_leak_html = ""
        for q in osint_leaks.get("queries", [])[:10]:
            repos = ", ".join(q.get("sample_repos", [])) or "—"
            osint_leak_html += f"""
            <div class="info-item">
                <span class="badge badge-danger">{q.get('count',0)} results</span>
                <code>{q.get('query','')}</code>
                <a href="{q.get('url','')}" target="_blank">review</a>
                — repos: {repos}
            </div>"""
        if not osint_leak_html:
            osint_leak_html = '<div class="info-item">No leaked references found</div>'

        osint_combined_subs = osint.get("combined_subdomains", [])

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report - {self.domain}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700;900&display=swap');

  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #1c2128;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #7d8590;
    --accent: #58a6ff;
    --danger: #f85149;
    --warning: #d29922;
    --success: #3fb950;
    --critical: #ff6e6e;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.6; }}

  .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%); border-bottom: 1px solid var(--border); padding: 40px; position: relative; overflow: hidden; }}
  .header::before {{ content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle at 30% 50%, rgba(88,166,255,0.06) 0%, transparent 60%); }}
  .header-inner {{ max-width: 1100px; margin: 0 auto; position: relative; }}
  .tool-badge {{ display: inline-block; background: rgba(88,166,255,0.1); border: 1px solid rgba(88,166,255,0.3); color: var(--accent); font-size: 11px; font-family: 'JetBrains Mono', monospace; padding: 4px 12px; border-radius: 20px; margin-bottom: 16px; letter-spacing: 1px; text-transform: uppercase; }}
  h1 {{ font-size: 32px; font-weight: 900; color: var(--text); margin-bottom: 6px; }}
  h1 span {{ color: var(--accent); }}
  .subtitle {{ color: var(--text-muted); font-size: 14px; margin-bottom: 20px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 20px; }}
  .meta-card {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; }}
  .meta-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
  .meta-value {{ font-size: 15px; font-weight: 600; color: var(--text); font-family: 'JetBrains Mono', monospace; }}

  .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 20px; }}

  .risk-banner {{ background: var(--surface); border: 2px solid {risk_color}; border-radius: 12px; padding: 24px 28px; margin-bottom: 32px; display: flex; align-items: center; gap: 24px; }}
  .risk-score {{ font-size: 52px; font-weight: 900; color: {risk_color}; font-family: 'JetBrains Mono', monospace; line-height: 1; }}
  .risk-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }}
  .risk-level {{ font-size: 22px; font-weight: 700; color: {risk_color}; }}
  .risk-factors {{ flex: 1; }}
  .risk-factors ul {{ list-style: none; padding: 0; }}
  .risk-factors li {{ padding: 3px 0; color: var(--text-muted); font-size: 13px; }}

  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 32px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; transition: border-color 0.2s; }}
  .stat:hover {{ border-color: var(--accent); }}
  .stat-num {{ font-size: 32px; font-weight: 900; font-family: 'JetBrains Mono', monospace; }}
  .stat-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
  .stat.danger .stat-num {{ color: var(--danger); }}
  .stat.warning .stat-num {{ color: var(--warning); }}
  .stat.success .stat-num {{ color: var(--success); }}
  .stat.info .stat-num {{ color: var(--accent); }}

  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 24px; overflow: hidden; }}
  .section-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; cursor: pointer; }}
  .section-icon {{ font-size: 18px; }}
  .section-title {{ font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text); }}
  .section-count {{ margin-left: auto; background: rgba(88,166,255,0.1); color: var(--accent); font-size: 12px; padding: 2px 10px; border-radius: 12px; font-family: 'JetBrains Mono', monospace; }}
  .section-body {{ padding: 20px; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: var(--surface2); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  td {{ padding: 9px 12px; border-bottom: 1px solid rgba(48,54,61,0.5); vertical-align: top; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(88,166,255,0.04); }}
  code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; background: var(--surface2); padding: 2px 6px; border-radius: 4px; color: var(--accent); }}

  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
  .badge-danger {{ background: rgba(248,81,73,0.15); color: var(--danger); border: 1px solid rgba(248,81,73,0.3); }}
  .badge-warning {{ background: rgba(210,153,34,0.15); color: var(--warning); border: 1px solid rgba(210,153,34,0.3); }}
  .badge-info {{ background: rgba(88,166,255,0.1); color: var(--accent); border: 1px solid rgba(88,166,255,0.2); }}

  .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .info-item {{ margin-bottom: 12px; }}
  .info-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px; }}
  .info-value {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--text); word-break: break-all; }}

  .cve-list {{ list-style: none; display: flex; flex-wrap: wrap; gap: 8px; }}
  .cve-item a {{ display: inline-block; background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.3); color: var(--danger); padding: 4px 12px; border-radius: 6px; text-decoration: none; font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600; }}
  .cve-item a:hover {{ background: rgba(248,81,73,0.2); }}

  .footer {{ text-align: center; padding: 40px 20px; color: var(--text-muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 20px; }}
  .disclaimer {{ background: rgba(248,81,73,0.06); border: 1px solid rgba(248,81,73,0.2); border-radius: 8px; padding: 12px 16px; margin-bottom: 32px; font-size: 12px; color: #f85149; }}

  @media (max-width: 600px) {{ .info-grid {{ grid-template-columns: 1fr; }} .meta-grid {{ grid-template-columns: 1fr 1fr; }} }}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="tool-badge">PHANTOM RECON v2.0 — RED TEAM INTELLIGENCE REPORT</div>
    <h1>Recon Report: <span>{self.domain}</span></h1>
    <p class="subtitle">Passive + Active Reconnaissance — Generated {scan_date}</p>
    <div class="meta-grid">
      <div class="meta-card"><div class="meta-label">Target</div><div class="meta-value">{self.domain}</div></div>
      <div class="meta-card"><div class="meta-label">Scan Date</div><div class="meta-value">{scan_date}</div></div>
      <div class="meta-card"><div class="meta-label">Modules Run</div><div class="meta-value">{len(meta.get('modules_run', []))}</div></div>
      <div class="meta-card"><div class="meta-label">Scan Mode</div><div class="meta-value">{'PASSIVE' if meta.get('passive_only') else 'FULL'}</div></div>
    </div>
  </div>
</div>

<div class="container">

  <div class="disclaimer">
    ⚠️ LEGAL NOTICE: This report is for authorized security assessment purposes only.
    Unauthorized use of this data may violate federal and state laws.
    Handle with care — contains sensitive reconnaissance data.
  </div>

  <!-- Risk Banner -->
  <div class="risk-banner">
    <div>
      <div class="risk-label">Risk Score</div>
      <div class="risk-score">{summary.get('risk_score', 0)}</div>
      <div class="risk-label">/ 100</div>
    </div>
    <div style="width:1px;background:var(--border);height:60px"></div>
    <div>
      <div class="risk-label">Risk Level</div>
      <div class="risk-level">{risk_level}</div>
    </div>
    <div class="risk-factors">
      <div class="risk-label" style="margin-bottom:8px">Risk Factors</div>
      <ul>{risk_factors_html}</ul>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat {'danger' if len(subdomains) > 50 else 'info'}">
      <div class="stat-num">{summary.get('subdomains_found', 0)}</div>
      <div class="stat-label">Subdomains</div>
    </div>
    <div class="stat {'warning' if len([e for e in emails if isinstance(e,dict) and 'email' in e]) > 0 else 'success'}">
      <div class="stat-num">{summary.get('emails_found', 0)}</div>
      <div class="stat-label">Emails</div>
    </div>
    <div class="stat {'danger' if summary.get('open_ports', 0) > 5 else 'info'}">
      <div class="stat-num">{summary.get('open_ports', 0)}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat {'danger' if summary.get('cve_count', 0) > 0 else 'success'}">
      <div class="stat-num">{summary.get('cve_count', 0)}</div>
      <div class="stat-label">CVEs Found</div>
    </div>
    <div class="stat info">
      <div class="stat-num">{summary.get('technologies_detected', 0)}</div>
      <div class="stat-label">Technologies</div>
    </div>
    <div class="stat {'success' if summary.get('ssl_valid') else 'danger'}">
      <div class="stat-num">{'✓' if summary.get('ssl_valid') else '✗'}</div>
      <div class="stat-label">SSL Valid</div>
    </div>
  </div>

  <!-- WHOIS Section -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🔍</span>
      <span class="section-title">WHOIS & Registration Data</span>
    </div>
    <div class="section-body">
      <div class="info-grid">
        <div>
          <div class="info-item"><div class="info-label">Registrar</div><div class="info-value">{whois.get('registrar') or '—'}</div></div>
          <div class="info-item"><div class="info-label">Registration Date</div><div class="info-value">{whois.get('creation_date') or '—'}</div></div>
          <div class="info-item"><div class="info-label">Expiration Date</div><div class="info-value">{whois.get('expiration_date') or '—'} ({whois.get('days_until_expiry', '?')} days)</div></div>
          <div class="info-item"><div class="info-label">Last Updated</div><div class="info-value">{whois.get('updated_date') or '—'}</div></div>
        </div>
        <div>
          <div class="info-item"><div class="info-label">Registrant Org</div><div class="info-value">{whois.get('registrant_org') or '—'}</div></div>
          <div class="info-item"><div class="info-label">Registrant Email</div><div class="info-value">{whois.get('registrant_email') or '—'}</div></div>
          <div class="info-item"><div class="info-label">DNSSEC</div><div class="info-value">{whois.get('dnssec') or '—'}</div></div>
          <div class="info-item"><div class="info-label">Resolved IPs</div><div class="info-value">{', '.join(whois.get('ips', []))}</div></div>
        </div>
      </div>
      {'<p style="margin-top:12px"><strong>Nameservers:</strong> ' + ', '.join(f'<code>{ns}</code>' for ns in whois.get('nameservers', [])) + '</p>' if whois.get('nameservers') else ''}
    </div>
  </div>

  <!-- DNS Section -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🌐</span>
      <span class="section-title">DNS Records</span>
      <span class="section-count">{len(dns.get('records', {}))} types</span>
    </div>
    <div class="section-body">
      {'<p style="color:var(--danger);font-weight:600;margin-bottom:12px">⚠️ Zone Transfer SUCCESSFUL — Critical Misconfiguration!</p>' if dns.get('zone_transfer', {}).get('success') else ''}
      {'<p style="color:var(--success);margin-bottom:12px">✓ Zone transfer refused (properly configured)</p>' if not dns.get('zone_transfer', {}).get('success') else ''}
      {'<p style="color:var(--warning);margin-bottom:12px">⚠️ No DMARC record — phishing risk!</p>' if not dns.get('dmarc') else f'<p style="margin-bottom:12px"><strong>DMARC:</strong> <code>{dns.get("dmarc","")[:80]}</code></p>'}
      {'<p style="margin-bottom:12px"><strong>SPF:</strong> <code>' + (dns.get('spf','')[:80] or '') + '</code></p>' if dns.get('spf') else ''}
      <table>
        <thead><tr><th>Type</th><th>Value</th></tr></thead>
        <tbody>{dns_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Subdomains Section -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🔗</span>
      <span class="section-title">Subdomain Enumeration</span>
      <span class="section-count">{len([s for s in subdomains if isinstance(s,dict) and 'subdomain' in s])} found</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Subdomain</th><th>IP(s)</th><th>Sources</th><th>Risk</th></tr></thead>
        <tbody>{sub_rows or '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No subdomains discovered</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <!-- Email Harvesting -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">📧</span>
      <span class="section-title">Email Harvesting & OSINT</span>
      <span class="section-count">{len([e for e in emails if isinstance(e,dict) and 'email' in e])} found</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Email Address</th><th>Sources</th><th>Confidence</th></tr></thead>
        <tbody>{email_rows or '<tr><td colspan="3" style="text-align:center;color:var(--text-muted)">No emails harvested</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <!-- CVEs from Shodan -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🚨</span>
      <span class="section-title">CVEs & Exposed Services (Shodan)</span>
      <span class="section-count" style="{'background:rgba(248,81,73,0.15);color:var(--danger)' if cves else ''}">{len(cves)} CVEs</span>
    </div>
    <div class="section-body">
      <ul class="cve-list">{cve_html}</ul>
      {('<h4 style="margin-top:20px;margin-bottom:10px;color:var(--danger)">High-Risk Exposed Services</h4><table><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Risk</th></tr></thead><tbody>' + ''.join(f'<tr><td>{s.get("ip","")}</td><td>{s.get("port","")}</td><td>{s.get("service","")}</td><td style="color:var(--danger);font-weight:600">{s.get("risk","")}</td></tr>' for s in shodan.get("high_risk_services",[])) + '</tbody></table>') if shodan.get("high_risk_services") else ''}
    </div>
  </div>

  <!-- Technologies -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">⚙️</span>
      <span class="section-title">Technology Fingerprinting</span>
      <span class="section-count">{len(technologies.get('detected',[]))} detected</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Technology</th><th>Version</th><th>Category</th><th>Risk</th></tr></thead>
        <tbody>{tech_rows or '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No technologies fingerprinted</td></tr>'}</tbody>
      </table>
      {f'<h4 style="margin-top:20px;margin-bottom:10px;color:var(--warning)">Missing Security Headers</h4><ul style="list-style:none;padding:0">{missing_headers_html}</ul>' if missing_headers_html else ''}
    </div>
  </div>

  <!-- SSL Section -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🔒</span>
      <span class="section-title">SSL/TLS Certificate Analysis</span>
    </div>
    <div class="section-body">
      <div class="info-grid">
        <div>
          <div class="info-item"><div class="info-label">Valid</div><div class="info-value" style="color:{'var(--success)' if ssl.get('valid') else 'var(--danger)'}">{'✓ Valid' if ssl.get('valid') else '✗ Invalid/Expired'}</div></div>
          <div class="info-item"><div class="info-label">Expires</div><div class="info-value">{ssl.get('not_after','—')} ({ssl.get('days_remaining','?')} days)</div></div>
          <div class="info-item"><div class="info-label">Protocol</div><div class="info-value">{ssl.get('protocol_version','—')}</div></div>
          <div class="info-item"><div class="info-label">Cipher</div><div class="info-value"><code>{ssl.get('cipher','—')}</code></div></div>
        </div>
        <div>
          <div class="info-item"><div class="info-label">Issuer</div><div class="info-value">{ssl.get('issuer',{}).get('organizationName','—')}</div></div>
          <div class="info-item"><div class="info-label">Self-Signed</div><div class="info-value" style="color:{'var(--danger)' if ssl.get('self_signed') else 'var(--success)'}">{'Yes ⚠️' if ssl.get('self_signed') else 'No ✓'}</div></div>
          <div class="info-item"><div class="info-label">Wildcard Cert</div><div class="info-value">{'Yes' if ssl.get('wildcard') else 'No'}</div></div>
          <div class="info-item"><div class="info-label">SANs Count</div><div class="info-value">{len(ssl.get('san_domains',[]))}</div></div>
        </div>
      </div>
      {f'<div style="margin-top:12px"><strong>SAN Domains:</strong> ' + ' '.join(f'<code>{s}</code>' for s in ssl.get("san_domains",[])[:20]) + '</div>' if ssl.get('san_domains') else ''}
    </div>
  </div>

  <!-- Port Scan -->
  {f'''<div class="section">
    <div class="section-header">
      <span class="section-icon">🔭</span>
      <span class="section-title">Port Scan Results</span>
      <span class="section-count">{summary.get("open_ports",0)} open</span>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead>
        <tbody>{port_rows or '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No open ports found</td></tr>'}</tbody>
      </table>
    </div>
  </div>''' if ports else ''}

  <!-- Cloud Asset Discovery -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">☁️</span>
      <span class="section-title">Cloud Asset Discovery</span>
      <span class="section-count" style="{'background:rgba(248,81,73,0.15);color:var(--danger)' if exposed_buckets else ''}">{len(exposed_buckets)} exposed</span>
    </div>
    <div class="section-body">
      {f'<div style="margin-bottom:12px"><span class="badge badge-danger">⚠ {len(exposed_buckets)} PUBLICLY ACCESSIBLE BUCKET(S) FOUND</span></div>' if exposed_buckets else '<p style="color:var(--text-muted)">No publicly accessible cloud storage buckets found.</p>'}
      {f'''<table>
        <thead><tr><th>Provider</th><th>Name</th><th>URL</th><th>Files</th><th>Severity</th></tr></thead>
        <tbody>{cloud_bucket_rows}</tbody>
      </table>''' if cloud_bucket_rows else ''}
      <p style="color:var(--text-muted);font-size:12px;margin-top:8px">{cloud.get('bucket_names_tried',0)} bucket name patterns tested across AWS S3, Azure Blob Storage, and GCP Cloud Storage.</p>

      {f'''<div style="margin-top:20px">
        <div class="info-label" style="margin-bottom:8px">Subdomain Takeover Risks</div>
        <table>
          <thead><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Status</th></tr></thead>
          <tbody>{cloud_takeover_rows}</tbody>
        </table>
      </div>''' if cloud_takeover_rows else ''}

      {f'''<div style="margin-top:20px">
        <div class="info-label" style="margin-bottom:8px">Public GitHub Repositories ({len(cloud.get("github_repos",[]))})</div>
        {github_repo_html}
      </div>''' if cloud.get("github_repos") else ''}
    </div>
  </div>

  <!-- OSINT Aggregation -->
  <div class="section">
    <div class="section-header">
      <span class="section-icon">🕵️</span>
      <span class="section-title">OSINT Aggregation</span>
      <span class="section-count">{len(osint_combined_subs)} combined subdomains</span>
    </div>
    <div class="section-body">
      <div class="info-grid">
        <div>
          <div class="info-item"><div class="info-label">VirusTotal Reputation</div><div class="info-value">{osint_vt.get('reputation','—')}</div></div>
          <div class="info-item"><div class="info-label">Malicious / Suspicious</div><div class="info-value" style="color:{'var(--danger)' if osint_vt.get('malicious',0) > 0 else 'var(--text)'}">{osint_vt.get('malicious',0)} / {osint_vt.get('suspicious',0)}</div></div>
          <div class="info-item"><div class="info-label">Registrar (VT)</div><div class="info-value">{osint_vt.get('registrar','—') or '—'}</div></div>
        </div>
        <div>
          <div class="info-item"><div class="info-label">Netlas — Cloud Hosts Indexed</div><div class="info-value">{len(osint_netlas.get('cloud_hosts',[]))}</div></div>
          <div class="info-item"><div class="info-label">Netlas — Historical IPs</div><div class="info-value">{', '.join(osint_netlas.get('historical_ips',[])[:3]) or '—'}</div></div>
          <div class="info-item"><div class="info-label">Wayback Snapshots</div><div class="info-value">~{osint_wayback.get('total_snapshots','—')}</div></div>
        </div>
      </div>

      {f'''<div style="margin-top:16px">
        <div class="info-label" style="margin-bottom:8px">Archived URLs (Wayback Machine)</div>
        <table><tbody>{osint_wayback_rows}</tbody></table>
      </div>''' if osint_wayback_rows else ''}

      <div style="margin-top:16px">
        <div class="info-label" style="margin-bottom:8px">GitHub Dork Findings ({osint_leaks.get('total_results',0)} total results)</div>
        {osint_leak_html}
      </div>
    </div>
  </div>

</div>

<div class="footer">
  <p>Generated by <strong>PHANTOM RECON v2.0</strong> — {scan_date}</p>
  <p style="margin-top:4px">This report contains sensitive security information. Handle with appropriate care.</p>
  <p style="margin-top:8px;font-size:11px;color:#444">For authorized security testing only. Unauthorized use is illegal.</p>
</div>

</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def _generate_pdf(self, results: dict, path: str):
        """Generate a professional PDF report using ReportLab."""
        meta = results.get("meta", {})
        summary = results.get("summary", {})
        whois = results.get("whois", {})
        subdomains = results.get("subdomains", [])
        emails = results.get("emails", [])
        technologies = results.get("technologies", {})
        cloud = results.get("cloud", {})
        osint = results.get("osint", {})
        ssl = results.get("ssl", {})

        doc = SimpleDocTemplate(path, pagesize=A4,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                     fontSize=22, textColor=colors.HexColor("#1a1a2e"),
                                     spaceAfter=6)
        subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"],
                                        fontSize=11, textColor=colors.HexColor("#666"),
                                        spaceAfter=20)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
                                  fontSize=13, textColor=colors.HexColor("#1a1a2e"),
                                  spaceBefore=16, spaceAfter=8,
                                  borderPad=6,
                                  backColor=colors.HexColor("#f5f5f5"),
                                  leftIndent=6)
        normal = ParagraphStyle("N", parent=styles["Normal"], fontSize=10, spaceAfter=4)
        mono = ParagraphStyle("Mono", parent=styles["Code"], fontSize=9,
                              backColor=colors.HexColor("#f8f8f8"),
                              textColor=colors.HexColor("#333"))

        risk_color_map = {
            "LOW": colors.HexColor("#27ae60"),
            "MEDIUM": colors.HexColor("#f39c12"),
            "HIGH": colors.HexColor("#e74c3c"),
            "CRITICAL": colors.HexColor("#c0392b"),
        }
        risk_clr = risk_color_map.get(summary.get("risk_level", "LOW"), colors.grey)

        # ── Cover ────────────────────────────────────────────────────
        story.append(Paragraph(f"PHANTOM RECON v2.0", subtitle_style))
        story.append(Paragraph(f"Reconnaissance Report: {self.domain}", title_style))
        story.append(Paragraph(f"Scan Date: {meta.get('scan_date','')[:10]} | Mode: {'Passive' if meta.get('passive_only') else 'Full'}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=risk_clr))
        story.append(Spacer(1, 12))

        # Risk summary table
        risk_table_data = [
            ["Metric", "Value"],
            ["Target Domain", self.domain],
            ["Risk Score", f"{summary.get('risk_score', 0)} / 100"],
            ["Risk Level", summary.get("risk_level", "?")],
            ["Subdomains Found", str(summary.get("subdomains_found", 0))],
            ["Emails Harvested", str(summary.get("emails_found", 0))],
            ["CVEs Detected", str(summary.get("cve_count", 0))],
            ["Open Ports", str(summary.get("open_ports", 0))],
            ["Technologies", str(summary.get("technologies_detected", 0))],
            ["SSL Valid", "YES" if summary.get("ssl_valid") else "NO"],
        ]

        risk_table = Table(risk_table_data, colWidths=[2.5*inch, 4*inch])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(risk_table)
        story.append(PageBreak())

        # ── WHOIS ────────────────────────────────────────────────────
        story.append(Paragraph("1. WHOIS Registration Data", h2_style))
        whois_data = [
            ["Field", "Value"],
            ["Registrar", whois.get("registrar") or "N/A"],
            ["Created", whois.get("creation_date") or "N/A"],
            ["Expires", f"{whois.get('expiration_date') or 'N/A'} ({whois.get('days_until_expiry','?')} days)"],
            ["Registrant Org", whois.get("registrant_org") or "N/A"],
            ["IPs", ", ".join(whois.get("ips", [])) or "N/A"],
        ]
        wt = Table(whois_data, colWidths=[2*inch, 5*inch])
        wt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ecf0f1"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(wt)
        story.append(Spacer(1, 12))

        # ── Subdomains ───────────────────────────────────────────────
        story.append(Paragraph(f"2. Subdomains ({len([s for s in subdomains if isinstance(s,dict) and 'subdomain' in s])} found)", h2_style))
        sub_data = [["Subdomain", "IPs", "Sources"]]
        for sub in subdomains[:50]:
            if isinstance(sub, dict) and "subdomain" in sub:
                sub_data.append([
                    sub["subdomain"],
                    ", ".join(sub.get("ips", [])[:2]) or "—",
                    ", ".join(sub.get("sources", []))
                ])
        if len(sub_data) > 1:
            st = Table(sub_data, colWidths=[2.8*inch, 2*inch, 2*inch])
            st.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2980b9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#eaf4fc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bdc3c7")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(st)

        # ── SSL ──────────────────────────────────────────────────────
        story.append(Spacer(1, 12))
        story.append(Paragraph("3. SSL/TLS Analysis", h2_style))
        ssl_data = [
            ["Field", "Value"],
            ["Valid", "YES" if ssl.get("valid") else "NO"],
            ["Expires", f"{ssl.get('not_after','N/A')} ({ssl.get('days_remaining','?')} days)"],
            ["Protocol", ssl.get("protocol_version") or "N/A"],
            ["Issuer", ssl.get("issuer", {}).get("organizationName", "N/A")],
            ["Self-Signed", "YES ⚠" if ssl.get("self_signed") else "No"],
            ["SANs", str(len(ssl.get("san_domains", [])))],
        ]
        st2 = Table(ssl_data, colWidths=[2*inch, 5*inch])
        st2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#27ae60")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#eafaf1"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bdc3c7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(st2)

        # ── Cloud Asset Discovery ────────────────────────────────────
        story.append(Paragraph("4. Cloud Asset Discovery", h2_style))
        all_buckets = (
            cloud.get("s3_buckets", []) +
            cloud.get("azure_containers", []) +
            cloud.get("gcp_buckets", [])
        )
        exposed_buckets = [b for b in all_buckets if b.get("accessible")]

        if exposed_buckets:
            story.append(Paragraph(
                f"⚠ {len(exposed_buckets)} publicly accessible cloud storage bucket(s) found:",
                normal
            ))
            bucket_data = [["Provider", "Name", "Files", "Severity"]]
            for b in exposed_buckets[:15]:
                bucket_data.append([
                    b.get("provider", ""), b.get("name", ""),
                    str(b.get("file_count", "?")), b.get("severity", "CRITICAL")
                ])
            bt = Table(bucket_data, colWidths=[1.3*inch, 2.5*inch, 1*inch, 1.2*inch])
            bt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fdecea"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bdc3c7")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(bt)
        else:
            story.append(Paragraph(
                "No publicly accessible cloud storage buckets found "
                f"({cloud.get('bucket_names_tried', 0)} patterns tested).", normal
            ))

        takeovers = cloud.get("takeover_risks", [])
        if takeovers:
            story.append(Spacer(1, 8))
            story.append(Paragraph(
                f"{len(takeovers)} subdomain takeover risk(s) identified:", normal
            ))
            for t in takeovers[:10]:
                mark = "CONFIRMED" if t.get("confirmed") else "potential"
                story.append(Paragraph(
                    f"• {t.get('subdomain','')} → {t.get('cname','')} ({mark})", mono
                ))

        repos = cloud.get("github_repos", [])
        if repos:
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"Public GitHub repositories ({len(repos)}):", normal))
            for r in repos[:8]:
                leak = f" — {len(r['sensitive_files_found'])} LEAKED FILE(S)" if r.get("sensitive_files_found") else ""
                story.append(Paragraph(f"• {r.get('name','')}{leak}", mono))

        # ── OSINT Aggregation ────────────────────────────────────────
        story.append(Spacer(1, 12))
        story.append(Paragraph("5. OSINT Aggregation", h2_style))
        vt = osint.get("virustotal", {})
        netlas_data = osint.get("securitytrails", {})
        wayback = osint.get("wayback", {})
        leaks = osint.get("github_leaks", {})

        osint_data = [
            ["Source", "Finding"],
            ["VirusTotal Reputation", str(vt.get("reputation", "N/A"))],
            ["VirusTotal Malicious/Suspicious", f"{vt.get('malicious', 0)} / {vt.get('suspicious', 0)}"],
            ["Netlas Cloud Hosts Indexed", str(len(netlas_data.get("cloud_hosts", [])))],
            ["Netlas Historical IPs", ", ".join(netlas_data.get("historical_ips", [])[:3]) or "N/A"],
            ["Wayback Snapshots", str(wayback.get("total_snapshots", "N/A"))],
            ["GitHub Dork Results", str(leaks.get("total_results", 0))],
            ["Combined Subdomains (OSINT)", str(len(osint.get("combined_subdomains", [])))],
        ]
        ot = Table(osint_data, colWidths=[3*inch, 4*inch])
        ot.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#eaf4fb"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bdc3c7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ot)

        # ── Footer ───────────────────────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("Legal Disclaimer", h2_style))
        story.append(Paragraph(
            "This report was generated by PHANTOM RECON for authorized security assessment purposes only. "
            "The information contained herein is confidential and intended solely for the authorized recipient. "
            "Unauthorized use, disclosure, or distribution is strictly prohibited and may be unlawful.",
            normal
        ))

        doc.build(story)