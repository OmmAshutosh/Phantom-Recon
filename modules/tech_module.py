"""
Technology Fingerprinting Module (Wappalyzer-Style)
=====================================================
HOW IT WORKS:
  Technology detection works by matching known signatures in:

  1. HTTP RESPONSE HEADERS:
     Server: Apache/2.4.41 → reveals web server + version
     X-Powered-By: PHP/7.4 → reveals backend language
     X-Generator: Drupal 9 → reveals CMS
     X-AspNet-Version → reveals .NET version
     CF-RAY → reveals Cloudflare CDN

  2. HTML SOURCE CODE:
     <meta name="generator" content="WordPress 6.3">
     <script src="/wp-content/..."> → WordPress path patterns
     window.__NUXT__ → Nuxt.js
     ng-version → Angular version
     __react → React

  3. COOKIES:
     PHPSESSID → PHP
     JSESSIONID → Java/Tomcat
     _ga → Google Analytics
     __cfduid → Cloudflare

  4. JAVASCRIPT VARIABLES:
     window.jQuery.fn.jquery → jQuery version
     wp.hooks → WordPress
     Drupal.settings → Drupal

  5. CSS CLASS PATTERNS:
     .elementor- → Elementor page builder
     .woocommerce → WooCommerce
     .shopify-section → Shopify

  6. FAVICON HASH (Shodan/FOFA technique):
     MurmurHash of /favicon.ico can uniquely identify software
     e.g., Fortinet, Cisco, Apache Tomcat all have known hashes

RED TEAM VALUE:
  - Identify outdated versions → CVE lookup
  - Map the full technology stack for exploit chaining
  - CMS plugins/themes → known vulnerabilities
  - CDN provider → understand traffic routing
  - WAF detection → inform evasion strategy
"""

import re
import requests
import hashlib
import json
from colorama import Fore, Style


# ── Signature database ───────────────────────────────────────────────────────
TECH_SIGNATURES = {
    # Web Servers
    "Apache": {
        "headers": {"Server": r"Apache(?:/(\d+\.\d+\.\d+))?"},
        "category": "Web Server", "risk": "medium"
    },
    "Nginx": {
        "headers": {"Server": r"nginx(?:/(\d+\.\d+\.\d+))?"},
        "category": "Web Server", "risk": "low"
    },
    "Microsoft IIS": {
        "headers": {"Server": r"Microsoft-IIS(?:/(\d+\.\d+))?"},
        "category": "Web Server", "risk": "medium"
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
        "category": "Web Server", "risk": "low"
    },
    # Languages / Frameworks
    "PHP": {
        "headers": {"X-Powered-By": r"PHP(?:/(\d+\.\d+\.\d+))?"},
        "category": "Language", "risk": "medium"
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r"(.+)"},
        "category": "Framework", "risk": "medium"
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Framework", "risk": "low"
    },
    # CMS
    "WordPress": {
        "html": [r"/wp-content/", r"/wp-includes/", r'content="WordPress (\d+\.\d+)'],
        "cookies": ["wordpress_logged_in", "wp-settings"],
        "category": "CMS", "risk": "high"
    },
    "Drupal": {
        "html": [r"Drupal\.settings", r"/sites/default/files/"],
        "headers": {"X-Generator": r"Drupal (\d+)"},
        "category": "CMS", "risk": "high"
    },
    "Joomla": {
        "html": [r"/media/jui/", r"Joomla!"],
        "category": "CMS", "risk": "high"
    },
    "Magento": {
        "html": [r"Mage\.Cookies", r"/skin/frontend/"],
        "cookies": ["frontend"],
        "category": "E-Commerce", "risk": "high"
    },
    "Shopify": {
        "html": [r"shopify-section", r"cdn\.shopify\.com"],
        "category": "E-Commerce", "risk": "low"
    },
    # JavaScript Frameworks
    "React": {
        "html": [r"__react", r"data-reactroot", r"_reactRootContainer"],
        "category": "JS Framework", "risk": "low"
    },
    "Angular": {
        "html": [r"ng-version=", r"ng-app="],
        "category": "JS Framework", "risk": "low"
    },
    "Vue.js": {
        "html": [r"__vue__", r"data-v-"],
        "category": "JS Framework", "risk": "low"
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"/_next/static/"],
        "category": "JS Framework", "risk": "low"
    },
    "Nuxt.js": {
        "html": [r"window\.__NUXT__"],
        "category": "JS Framework", "risk": "low"
    },
    # CDN / WAF / Security
    "Cloudflare": {
        "headers": {"CF-RAY": r".+", "Server": r"cloudflare"},
        "cookies": ["__cflb", "__cfduid", "cf_clearance"],
        "category": "CDN/WAF", "risk": "informational"
    },
    "AWS CloudFront": {
        "headers": {"Via": r"CloudFront", "X-Amz-Cf-Id": r".+"},
        "category": "CDN", "risk": "informational"
    },
    "Fastly": {
        "headers": {"X-Served-By": r"cache", "Fastly-Debug-Digest": r".+"},
        "category": "CDN", "risk": "informational"
    },
    "Akamai": {
        "headers": {"X-Check-Cacheable": r".+", "X-Akamai-Transformed": r".+"},
        "category": "CDN", "risk": "informational"
    },
    "Sucuri WAF": {
        "headers": {"X-Sucuri-ID": r".+"},
        "category": "WAF", "risk": "informational"
    },
    "ModSecurity": {
        "headers": {"Server": r"Mod_Security|mod_security"},
        "category": "WAF", "risk": "informational"
    },
    # Analytics / Tracking
    "Google Analytics": {
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\("],
        "category": "Analytics", "risk": "informational"
    },
    "Google Tag Manager": {
        "html": [r"googletagmanager\.com/gtm\.js"],
        "category": "Analytics", "risk": "informational"
    },
    # Databases / Backend (via error messages, paths)
    "MySQL": {
        "html": [r"MySQL server", r"mysql_"],
        "category": "Database", "risk": "high"
    },
    "MongoDB": {
        "html": [r"MongoError", r"mongo\.js"],
        "category": "Database", "risk": "high"
    },
    # Email / Auth providers
    "Mailchimp": {
        "html": [r"chimpstatic\.com", r"mc\.us\d+\.list-manage\.com"],
        "category": "Email Service", "risk": "informational"
    },
    "Okta": {
        "html": [r"okta\.com", r"oktacdn\.com"],
        "category": "Identity Provider", "risk": "informational"
    },
    "Auth0": {
        "html": [r"auth0\.com/auth", r"cdn\.auth0\.com"],
        "category": "Identity Provider", "risk": "informational"
    },
    # DevOps exposure
    "Swagger UI": {
        "html": [r"swagger-ui", r"SwaggerUIBundle"],
        "category": "API Documentation", "risk": "high"
    },
    "GraphQL": {
        "html": [r"graphql-playground", r"__typename"],
        "category": "API", "risk": "medium"
    },
    "Kubernetes Dashboard": {
        "html": [r"kubernetes-dashboard"],
        "category": "Orchestration", "risk": "critical"
    },
    # jQuery
    "jQuery": {
        "html": [r'jquery[.-](\d+\.\d+\.\d+)'],
        "category": "JS Library", "risk": "low"
    },
    "Bootstrap": {
        "html": [r"bootstrap\.min\.css", r"bootstrap\.bundle\.min\.js"],
        "category": "UI Framework", "risk": "low"
    },
}


class TechModule:
    """Technology fingerprinting module."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        })

    def run(self) -> dict:
        result = {
            "detected": [],
            "raw_headers": {},
            "cookies_found": [],
            "security_headers": {},
            "missing_security_headers": [],
            "version_disclosure": [],
            "waf_detected": None,
            "cdn_detected": None,
            "cms_detected": None,
            "favicon_hash": None,
            "errors": []
        }

        print(f"  {Fore.BLUE}[*] Fingerprinting technologies on {self.domain}...{Style.RESET_ALL}")

        # Probe target
        response_data = self._probe_target()
        if not response_data:
            result["errors"].append("Could not reach target")
            return result

        # Extract signals
        headers = response_data.get("headers", {})
        html = response_data.get("html", "")
        cookies = response_data.get("cookies", [])

        result["raw_headers"] = dict(headers)
        result["cookies_found"] = cookies

        # Run signature matching
        detected = self._match_signatures(headers, html, cookies)
        result["detected"] = detected

        # Security header analysis
        self._analyze_security_headers(headers, result)

        # Version disclosure check
        self._check_version_disclosure(headers, html, result)

        # WAF/CDN classification
        for tech in detected:
            if tech.get("category") == "WAF":
                result["waf_detected"] = tech["name"]
            if tech.get("category") == "CDN":
                result["cdn_detected"] = tech["name"]
            if tech.get("category") == "CMS":
                result["cms_detected"] = tech["name"]

        # Favicon hash
        result["favicon_hash"] = self._get_favicon_hash()

        # Print summary
        categories = {}
        for tech in detected:
            cat = tech.get("category", "Other")
            categories.setdefault(cat, []).append(tech["name"])

        for cat, techs in categories.items():
            print(f"  {Fore.GREEN}[+] {cat}: {', '.join(techs)}{Style.RESET_ALL}")

        print(f"\n  {Fore.GREEN}[+] {len(detected)} technologies detected{Style.RESET_ALL}")
        return result

    def _probe_target(self) -> dict | None:
        """HTTP probe the target domain."""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.domain}"
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=True, verify=False)
                return {
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "html": resp.text[:50000],
                    "cookies": [c.name for c in resp.cookies],
                }
            except Exception as e:
                continue
        return None

    def _match_signatures(self, headers: dict, html: str, cookies: list) -> list:
        """Match technology signatures against response data."""
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for tech_name, sig in TECH_SIGNATURES.items():
            version = None
            matched = False

            # Header matching
            for header_name, pattern in sig.get("headers", {}).items():
                header_val = headers_lower.get(header_name.lower(), "")
                m = re.search(pattern, header_val, re.IGNORECASE)
                if m:
                    matched = True
                    if m.lastindex and m.lastindex >= 1:
                        try:
                            version = m.group(1)
                        except Exception:
                            pass

            # HTML matching
            for pattern in sig.get("html", []):
                m = re.search(pattern, html, re.IGNORECASE)
                if m:
                    matched = True
                    if m.lastindex and m.lastindex >= 1:
                        try:
                            version = m.group(1)
                        except Exception:
                            pass

            # Cookie matching
            for cookie_name in sig.get("cookies", []):
                if any(cookie_name.lower() in c.lower() for c in cookies):
                    matched = True

            if matched:
                entry = {
                    "name": tech_name,
                    "version": version,
                    "category": sig.get("category", "Other"),
                    "risk": sig.get("risk", "low"),
                }
                detected.append(entry)
                if version:
                    print(f"  {Fore.YELLOW}[!] Detected: {tech_name} v{version}{Style.RESET_ALL}")

        return detected

    def _analyze_security_headers(self, headers: dict, result: dict):
        """
        Check for presence/absence of security response headers.
        Missing security headers are a common finding in pen test reports.
        """
        security_headers = {
            "Strict-Transport-Security": "HSTS - forces HTTPS",
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing prevention",
            "Content-Security-Policy": "XSS/injection policy",
            "Referrer-Policy": "Referrer information control",
            "Permissions-Policy": "Browser feature restrictions",
            "X-XSS-Protection": "Legacy XSS filter",
            "Cross-Origin-Opener-Policy": "Cross-origin isolation",
            "Cross-Origin-Resource-Policy": "Cross-origin resource protection",
        }

        headers_lower = {k.lower(): v for k, v in headers.items()}
        found = {}
        missing = []

        for header, description in security_headers.items():
            val = headers_lower.get(header.lower())
            if val:
                found[header] = val
            else:
                missing.append({"header": header, "description": description})

        result["security_headers"] = found
        result["missing_security_headers"] = missing

        if missing:
            print(f"  {Fore.YELLOW}[!] Missing security headers: "
                  f"{', '.join(m['header'] for m in missing[:4])}...{Style.RESET_ALL}")

    def _check_version_disclosure(self, headers: dict, html: str, result: dict):
        """Flag any version information disclosed in headers or HTML."""
        version_patterns = [
            ("Server", r"(?:Apache|nginx|IIS)/(\d+\.\d+[\.\d]*)"),
            ("X-Powered-By", r"(?:PHP|ASP\.NET)/(\d+\.\d+[\.\d]*)"),
            ("X-AspNet-Version", r"(\d+\.\d+[\.\d]*)"),
            ("X-Runtime", r"(\d+\.\d+[\.\d]*)"),
        ]
        disclosures = []
        for header, pattern in version_patterns:
            val = headers.get(header, "")
            m = re.search(pattern, val, re.IGNORECASE)
            if m:
                disclosures.append({
                    "header": header,
                    "value": val,
                    "version": m.group(1)
                })
                print(f"  {Fore.RED}[!] VERSION DISCLOSURE: {header}: {val}{Style.RESET_ALL}")
        result["version_disclosure"] = disclosures

    def _get_favicon_hash(self) -> str | None:
        """
        Calculate MurmurHash of favicon for Shodan/FOFA fingerprinting.
        Many security tools and products have unique favicon hashes.
        """
        try:
            url = f"https://{self.domain}/favicon.ico"
            resp = self.session.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and resp.content:
                # Use MD5 as simplified version (real Shodan uses MurmurHash)
                return hashlib.md5(resp.content).hexdigest()
        except Exception:
            pass
        return None
