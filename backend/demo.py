"""
demo.py - Mock data generator for testing without network calls.
"""

def generate_mock_results(domain="example.com"):
    """
    Returns a dict with the exact same schema real scan modules return.
    Used by tests and demo mode to generate reports without network access.
    """
    return {
        "meta": {
            "target": domain,
            "scan_date": "2025-05-25T10:00:00",
            "tool": "PHANTOM RECON v2.1"
        },
        "whois": {
            "domain": domain,
            "registrar": "GoDaddy.com, LLC",
            "creation_date": "2005-08-14",
            "expiration_date": "2026-08-14",
            "days_until_expiry": 450,
            "nameservers": ["ns1.example.com", "ns2.example.com"],
            "registrant_org": "Example Corp",
            "registrant_country": "US",
            "ips": ["93.184.216.34"],
            "reverse_dns": {"93.184.216.34": "example.com"},
            "errors": []
        },
        "dns": {
            "records": {
                "A":   ["93.184.216.34"],
                "MX":  ["10 mail.example.com."],
                "NS":  ["ns1.example.com.", "ns2.example.com."],
                "TXT": ["v=spf1 include:_spf.example.com ~all"]
            },
            "zone_transfer": {"attempted": True, "success": False, "records": []},
            "spf":   "v=spf1 include:_spf.example.com ~all",
            "dmarc": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
            "nameservers":  ["ns1.example.com", "ns2.example.com"],
            "mail_servers": [{"priority": "10", "host": "mail.example.com"}],
            "dkim_selectors": ["default", "google"],
            "soa_email": "admin@example.com",
            "errors": []
        },
        "subdomains": [
            {
                "subdomain": "api.example.com",
                "ips":     ["93.184.216.36"],
                "sources": ["crt.sh", "bruteforce"],
                "cname":   None,
                "takeover_risk": None,
                "http_status":   200
            },
            {
                "subdomain": "staging.example.com",
                "ips":     [],
                "sources": ["crt.sh"],
                "cname":   "example-staging.herokuapp.com",
                "takeover_risk": "Heroku — check if app is deployed",
                "http_status":   404
            },
            {
                "subdomain": "mail.example.com",
                "ips":     ["93.184.216.35"],
                "sources": ["bruteforce"],
                "cname":   None,
                "takeover_risk": None,
                "http_status":   None
            },
        ],
        "emails": [
            {
                "email":      "admin@example.com",
                "sources":    ["website", "hunter.io"],
                "confidence": "high",
                "department": "IT",
                "name":       "Admin User",
                "position":   "System Administrator"
            },
            {
                "email":      "info@example.com",
                "sources":    ["website"],
                "confidence": "medium",
                "department": None,
                "name":       None,
                "position":   None
            },
            {
                "_meta":    "email_patterns",
                "patterns": ["{first}.{last}@" + domain]
            }
        ],
        "shodan": {
            "api_key_used":       False,
            "hosts":              [],
            "total_results":      0,
            "open_ports_summary": {"80": 1, "443": 1},
            "technologies":       ["nginx"],
            "cves":               [],
            "high_risk_services": [],
            "countries":          ["United States"],
            "asns":               ["AS15133"],
            "errors":             []
        },
        "technologies": {
            "detected": [
                {
                    "name":     "Nginx",
                    "version":  "1.25.0",
                    "category": "Web Server",
                    "risk":     "low"
                },
                {
                    "name":     "jQuery",
                    "version":  "3.6.0",
                    "category": "JavaScript Framework",
                    "risk":     "low"
                }
            ],
            "missing_security_headers": [
                {"header": "Content-Security-Policy",
                 "description": "CSP — controls XSS"},
                {"header": "Strict-Transport-Security",
                 "description": "HSTS — forces HTTPS"}
            ],
            "version_disclosure": [
                {"header": "Server", "version": "1.25.0",
                 "technology": "Nginx"}
            ],
            "security_headers": {
                "X-Frame-Options":    "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff"
            },
            "errors": []
        },
        "ssl": {
            "subject":          {"commonName": domain},
            "issuer":           {"organizationName": "Let's Encrypt"},
            "valid":            True,
            "expired":          False,
            "self_signed":      False,
            "not_before":       "Jan 01 00:00:00 2025 GMT",
            "not_after":        "Dec 31 23:59:59 2025 GMT",
            "days_remaining":   120,
            "san_domains":      [domain, f"www.{domain}", f"*.{domain}"],
            "protocol_version": "TLSv1.3",
            "cipher":           "TLS_AES_256_GCM_SHA384",
            "wildcard":         True,
            "vulnerabilities":  [],
            "errors":           []
        },
        "ports": [
            {
                "ip":      "93.184.216.34",
                "port":    80,
                "state":   "open",
                "service": "HTTP",
                "banner":  "HTTP/1.1 200 OK",
                "risk":    "LOW"
            },
            {
                "ip":      "93.184.216.34",
                "port":    443,
                "state":   "open",
                "service": "HTTPS",
                "banner":  "HTTP/1.1 200 OK",
                "risk":    "LOW"
            }
        ],
        "cloud": {
            "netlas":           {"skipped": True, "reason": "No API key"},
            "s3_buckets":       [
                {"name": f"{domain.split('.')[0]}-backup",
                 "url":  f"https://{domain.split('.')[0]}-backup.s3.amazonaws.com/",
                 "provider": "AWS S3", "status": 403,
                 "accessible": False, "severity": "INFO",
                 "note": "Bucket exists (private)"}
            ],
            "azure_containers": [],
            "gcp_buckets":      [],
            "github_repos":     [
                {"name":        f"{domain.split('.')[0]}/frontend",
                 "url":         f"https://github.com/{domain.split('.')[0]}/frontend",
                 "description": "Frontend web application",
                 "language":    "TypeScript",
                 "stars":       12,
                 "forks":       3,
                 "updated":     "2025-01-15",
                 "private":     False,
                 "sensitive_files_found": []}
            ],
            "takeover_risks":     [],
            "exposed_count":      0,
            "bucket_names_tried": 53,
            "errors":             []
        },
        "summary": {
            "risk_score":       25,
            "risk_level":       "MEDIUM",
            "risk_factors":     [
                "Subdomain takeover risk: staging.example.com → herokuapp.com",
                "Missing security headers: CSP, HSTS"
            ],
            "subdomains_found": 3,
            "emails_found":     2,
            "cve_count":        0,
            "open_ports":       2,
            "ssl_valid":        True,
            "cloud_exposed":    0
        }
    }


if __name__ == "__main__":
    import argparse, os, json
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock",   action="store_true",
                        help="Generate mock report with no network calls")
    parser.add_argument("--domain", default="example.com",
                        help="Target domain for mock report")
    args = parser.parse_args()

    if args.mock:
        from modules.report_module import ReportModule
        results = generate_mock_results(args.domain)
        out_dir = f"./output/{args.domain}_demo"
        os.makedirs(out_dir, exist_ok=True)

        # Save full JSON
        json_path = os.path.join(out_dir, f"{args.domain}_recon_full.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"  [+] JSON saved: {json_path}")

        # Generate HTML + PDF reports
        paths = ReportModule({"domain": args.domain, "out_dir": out_dir}).run(results)
        print(f"\n{'='*55}")
        print(f"  DEMO REPORTS GENERATED:")
        print(f"{'='*55}")
        print(f"  HTML: {paths.get('html')}")
        print(f"  PDF:  {paths.get('pdf')}")