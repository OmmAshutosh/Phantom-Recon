#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         PHANTOM RECON - Automated Passive/Active Recon           ║
║         Red Team Intelligence Gathering Framework v2.0           ║
║         Author: Security Research Tool                           ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL DISCLAIMER:
This tool is for authorized penetration testing and educational
purposes ONLY. Always obtain written permission before scanning
any target. Unauthorized use is illegal and unethical.

Usage:
    python recon.py -d example.com
    python recon.py -d example.com --shodan-key YOUR_API_KEY
    python recon.py -d example.com --modules subdomain,whois,dns,email,shodan,tech
    python recon.py -d example.com --passive-only
    python recon.py --help
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from colorama import Fore, Style, init

import config as app_config

init(autoreset=True)

# ── Banner ──────────────────────────────────────────────────────────────────
BANNER = f"""
{Fore.RED}
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{Fore.YELLOW}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.CYAN}
  ╔═══════════════════════════════════════════════╗
  ║  Red Team Intelligence Framework  v2.0       ║
  ║  Passive + Active Reconnaissance Engine      ║
  ║  Use only on targets you own or have          ║
  ║  written permission to test.                 ║
  ╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

def print_phase(phase_name: str, phase_num: int, total: int):
    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"  PHASE {phase_num}/{total}: {phase_name.upper()}")
    print(f"{'='*65}{Style.RESET_ALL}\n")

def print_success(msg: str):
    print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")

def print_info(msg: str):
    print(f"{Fore.BLUE}  [*] {msg}{Style.RESET_ALL}")

def print_warning(msg: str):
    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")

def print_error(msg: str):
    print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PHANTOM RECON - Automated Red Team Intelligence Gathering Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
MODULES AVAILABLE:
  whois      - WHOIS lookup, registrar info, dates, nameservers
  dns        - DNS enumeration (A, MX, NS, TXT, SOA, CNAME, AAAA)
  subdomain  - Subdomain enumeration via Sublist3r + DNS brute force
  email      - Email harvesting (OSINT search engines, certs, headers)
  shodan     - Shodan API: exposed services, banners, CVEs, geolocation
  tech       - Technology fingerprinting (HTTP headers, meta tags, JS libs)
  ssl        - SSL/TLS certificate analysis
  port       - Port scanning (top 1000 ports via socket probing)
  report     - Generate HTML + PDF reports

EXAMPLES:
  python recon.py -d tesla.com
  python recon.py -d tesla.com --shodan-key abc123 --modules all
  python recon.py -d tesla.com --passive-only
  python recon.py -d tesla.com --modules whois,dns,subdomain
  python recon.py -d tesla.com --threads 20 --output /tmp/recon_results
        """
    )

    parser.add_argument("-d", "--domain", required=True,
                        help="Target domain (e.g. example.com)")
    parser.add_argument("--shodan-key", default=None,
                        help="Shodan API key (get free at shodan.io)")
    parser.add_argument("--modules", default="all",
                        help="Comma-separated modules or 'all' (default: all)")
    parser.add_argument("--passive-only", action="store_true",
                        help="Run passive modules only (no active probing)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Thread count for concurrent tasks (default: 10)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Request timeout in seconds (default: 5)")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: ./output/<domain>_<timestamp>)")
    parser.add_argument("--wordlist", default=None,
                        help="Custom subdomain wordlist path")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip report generation")
    parser.add_argument("--json-only", action="store_true",
                        help="Save results as JSON only")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")

    return parser


def run_recon(args):
    """Main orchestrator for all recon phases."""
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
    from modules.report_module import ReportModule

    domain = args.domain.lower().strip()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Setup output directory
    out_dir = args.output or os.path.join(
        os.path.dirname(__file__), "output", f"{domain}_{timestamp}"
    )
    os.makedirs(out_dir, exist_ok=True)

    # Determine active modules
    all_modules = ["whois", "dns", "subdomain", "email", "shodan", "tech", "ssl", "port", "osint", "cloud"]
    passive_modules = ["whois", "dns", "subdomain", "email", "tech", "ssl", "osint", "cloud"]

    if args.modules == "all":
        selected = passive_modules if args.passive_only else all_modules
    else:
        selected = [m.strip() for m in args.modules.split(",")]

    if args.passive_only:
        selected = [m for m in selected if m in passive_modules]

    # Aggregated results store
    results = {
        "meta": {
            "target": domain,
            "timestamp": timestamp,
            "scan_date": datetime.now().isoformat(),
            "tool": "PHANTOM RECON v2.0",
            "passive_only": args.passive_only,
            "modules_run": selected,
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

    config = {
        "domain": domain,
        "threads": args.threads,
        "timeout": args.timeout,
        "verbose": args.verbose,
        "wordlist": args.wordlist,
        "shodan_key": args.shodan_key or app_config.SHODAN_API_KEY,
        "virustotal_key": app_config.VIRUSTOTAL_API_KEY,
        "netlas_key": app_config.NETLAS_API_KEY,
        "out_dir": out_dir,
    }

    # +1 accounts for the final Report Generation phase, so it gets its
    # own number instead of duplicating the last scan phase (e.g. "8/8"
    # printed twice — once for Cloud Discovery, once for Report Generation)
    total_phases = len(selected) + (0 if args.no_report else 1)
    current_phase = 0

    # ─── Phase: WHOIS ────────────────────────────────────────────────
    if "whois" in selected:
        current_phase += 1
        print_phase("WHOIS Lookup & Registrar Intelligence", current_phase, total_phases)
        mod = WhoisModule(config)
        results["whois"] = mod.run()
        _save_partial(results, out_dir, "whois")

    # ─── Phase: DNS ──────────────────────────────────────────────────
    if "dns" in selected:
        current_phase += 1
        print_phase("DNS Enumeration & Record Analysis", current_phase, total_phases)
        mod = DNSModule(config)
        results["dns"] = mod.run()
        _save_partial(results, out_dir, "dns")

    # ─── Phase: Subdomain Enumeration ────────────────────────────────
    if "subdomain" in selected:
        current_phase += 1
        print_phase("Subdomain Enumeration (Sublist3r + Brute Force)", current_phase, total_phases)
        mod = SubdomainModule(config)
        results["subdomains"] = mod.run()
        _save_partial(results, out_dir, "subdomains")

    # ─── Phase: Email Harvesting ─────────────────────────────────────
    if "email" in selected:
        current_phase += 1
        print_phase("Email & OSINT Harvesting", current_phase, total_phases)
        mod = EmailModule(config)
        results["emails"] = mod.run()
        _save_partial(results, out_dir, "emails")

    # ─── Phase: Shodan ───────────────────────────────────────────────
    if "shodan" in selected:
        current_phase += 1
        print_phase("Shodan API: Exposed Services & Vulnerabilities", current_phase, total_phases)
        mod = ShodanModule(config)
        results["shodan"] = mod.run()
        _save_partial(results, out_dir, "shodan")

    # ─── Phase: Tech Fingerprinting ──────────────────────────────────
    if "tech" in selected:
        current_phase += 1
        print_phase("Technology Fingerprinting (Wappalyzer-Style)", current_phase, total_phases)
        mod = TechModule(config)
        results["technologies"] = mod.run()
        _save_partial(results, out_dir, "technologies")

    # ─── Phase: SSL Analysis ─────────────────────────────────────────
    if "ssl" in selected:
        current_phase += 1
        print_phase("SSL/TLS Certificate Analysis", current_phase, total_phases)
        mod = SSLModule(config)
        results["ssl"] = mod.run()
        _save_partial(results, out_dir, "ssl")

    # ─── Phase: OSINT (VirusTotal / Wayback / GitHub) ────────────────
    if "osint" in selected:
        current_phase += 1
        print_phase("OSINT Aggregation (VirusTotal + Wayback + GitHub)", current_phase, total_phases)
        mod = OsintModule(config)
        results["osint"] = mod.run()
        _save_partial(results, out_dir, "osint")

    # ─── Phase: Cloud Asset Discovery ─────────────────────────────────
    if "cloud" in selected:
        current_phase += 1
        print_phase("Cloud Asset Discovery (S3 / Azure / GCP / GitHub)", current_phase, total_phases)
        mod = CloudModule(config)
        results["cloud"] = mod.run()
        _save_partial(results, out_dir, "cloud")

    # ─── Phase: Port Scanning ────────────────────────────────────────
    if "port" in selected and not args.passive_only:
        current_phase += 1
        print_phase("Port Scanning (Top Ports)", current_phase, total_phases)
        mod = PortModule(config)
        results["ports"] = mod.run()
        _save_partial(results, out_dir, "ports")

    # ─── Build summary ───────────────────────────────────────────────
    results["summary"] = _build_summary(results)

    # ─── Save full JSON ──────────────────────────────────────────────
    json_path = os.path.join(out_dir, f"{domain}_recon_full.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print_success(f"Full JSON saved: {json_path}")

    # ─── Phase: Report Generation ────────────────────────────────────
    if not args.no_report:
        current_phase += 1
        print_phase("Report Generation (HTML + PDF)", current_phase, total_phases)
        mod = ReportModule(config)
        report_paths = mod.run(results)
        print_success(f"HTML Report: {report_paths.get('html', 'N/A')}")
        print_success(f"PDF Report:  {report_paths.get('pdf', 'N/A')}")

    # ─── Final Summary ───────────────────────────────────────────────
    _print_final_summary(results, domain)
    return results


def _save_partial(results: dict, out_dir: str, module_name: str):
    """Save intermediate results after each phase."""
    path = os.path.join(out_dir, f"partial_{module_name}.json")
    with open(path, "w") as f:
        json.dump(results.get(module_name, {}), f, indent=2, default=str)


def _build_summary(results: dict) -> dict:
    """Build a high-level summary of all findings."""
    subdomains = results.get("subdomains", [])
    # EmailModule always appends a {"_meta": "email_patterns", ...} entry
    # to the emails list even when zero real emails are found. Exclude it
    # here so "Emails Harvested" reflects actual discovered addresses.
    emails = [e for e in results.get("emails", [])
              if isinstance(e, dict) and "email" in e]
    shodan = results.get("shodan", {})
    ports = results.get("ports", [])
    ssl = results.get("ssl", {})
    cloud = results.get("cloud", {})
    osint = results.get("osint", {})

    open_ports = [p for p in ports if p.get("state") == "open"]
    cve_count = 0
    if isinstance(shodan, dict):
        for host in shodan.get("hosts", []):
            cve_count += len(host.get("vulns", []))

    cloud_exposed = cloud.get("exposed_count", 0)
    confirmed_takeovers = [
        t for t in cloud.get("takeover_risks", []) if t.get("confirmed")
    ]
    leaked_repos = [
        r for r in cloud.get("github_repos", []) if r.get("sensitive_files_found")
    ]
    vt_malicious = osint.get("virustotal", {}).get("malicious", 0)

    risk_score = 0
    risk_factors = []

    if len(subdomains) > 50:
        risk_score += 15
        risk_factors.append(f"Large attack surface: {len(subdomains)} subdomains discovered")
    if cve_count > 0:
        risk_score += min(cve_count * 10, 40)
        risk_factors.append(f"{cve_count} CVEs found via Shodan")
    if ssl.get("expired"):
        risk_score += 10
        risk_factors.append("SSL certificate expired or expiring soon")
    if len(open_ports) > 10:
        risk_score += 10
        risk_factors.append(f"{len(open_ports)} open ports detected")
    if cloud_exposed > 0:
        risk_score += 30
        risk_factors.append(
            f"CRITICAL: {cloud_exposed} publicly accessible cloud storage bucket(s) — "
            f"verify these actually belong to the target before reporting; bucket "
            f"names can collide with unrelated third-party accounts"
        )
    if confirmed_takeovers:
        risk_score += 25
        risk_factors.append(
            f"{len(confirmed_takeovers)} confirmed subdomain takeover vulnerability(ies)"
        )
    if leaked_repos:
        risk_score += 20
        risk_factors.append(
            f"{len(leaked_repos)} public GitHub repo(s) with leaked credential files"
        )
    if vt_malicious > 0:
        risk_score += 15
        risk_factors.append(f"VirusTotal flags {vt_malicious} malicious detection(s)")

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
        "ssl_valid": ssl.get("valid", "unknown"),
        "technologies_detected": len(results.get("technologies", {}).get("detected", [])),
    }


def _print_final_summary(results: dict, domain: str):
    summary = results.get("summary", {})
    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"  RECON COMPLETE: {domain.upper()}")
    print(f"{'='*65}{Style.RESET_ALL}")

    risk_color = {
        "LOW": Fore.GREEN,
        "MEDIUM": Fore.YELLOW,
        "HIGH": Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT
    }.get(summary.get("risk_level", "LOW"), Fore.WHITE)

    print(f"\n  {Fore.WHITE}FINDINGS OVERVIEW:")
    print(f"  {'─'*40}")
    print(f"  Subdomains Found  : {Fore.GREEN}{summary.get('subdomains_found', 0)}{Style.RESET_ALL}")
    print(f"  Emails Harvested  : {Fore.GREEN}{summary.get('emails_found', 0)}{Style.RESET_ALL}")
    print(f"  Open Ports        : {Fore.YELLOW}{summary.get('open_ports', 0)}{Style.RESET_ALL}")
    print(f"  CVEs Detected     : {Fore.RED}{summary.get('cve_count', 0)}{Style.RESET_ALL}")
    print(f"  Technologies      : {Fore.BLUE}{summary.get('technologies_detected', 0)}{Style.RESET_ALL}")
    print(f"  SSL Valid         : {Fore.GREEN if summary.get('ssl_valid') else Fore.RED}{summary.get('ssl_valid', 'N/A')}{Style.RESET_ALL}")
    print(f"\n  Risk Score        : {risk_color}{summary.get('risk_score', 0)}/100{Style.RESET_ALL}")
    print(f"  Risk Level        : {risk_color}{summary.get('risk_level', 'UNKNOWN')}{Style.RESET_ALL}")

    if summary.get("risk_factors"):
        print(f"\n  {Fore.RED}RISK FACTORS:")
        for f in summary["risk_factors"]:
            print(f"  {Fore.RED}  ▸ {f}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    # Disclaimer confirmation
    print(f"{Fore.RED}{'!'*65}")
    print("  LEGAL NOTICE: Only test targets you own or have written")
    print("  authorization for. Unauthorized scanning is illegal.")
    print(f"{'!'*65}{Style.RESET_ALL}\n")

    try:
        run_recon(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Partial results saved.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[-] Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)