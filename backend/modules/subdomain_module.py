"""
Subdomain Enumeration Module
==============================
HOW IT WORKS:

METHOD 1 - Sublist3r (Passive OSINT aggregation):
  Queries multiple public data sources simultaneously:
  - Search engines: Google, Bing, Yahoo, Baidu (uses dorking: site:example.com)
  - Certificate Transparency logs: crt.sh, Censys
  - DNS datasets: DNSdumpster, VirusTotal, ThreatCrowd
  - No direct contact with target - purely passive

METHOD 2 - Certificate Transparency (crt.sh):
  SSL certificates are logged publicly in CT logs.
  Every cert issued for *.example.com or sub.example.com is recorded.
  We query crt.sh (a public CT log aggregator) API to extract all
  subdomains that have ever had SSL certs issued.
  URL: https://crt.sh/?q=%.example.com&output=json

METHOD 3 - DNS Brute Force (Active):
  Iterates through a wordlist, constructs FQDNs, and attempts DNS
  resolution. Uses concurrent threading for speed.
  Example: admin.example.com, dev.example.com, api.example.com...
  Detects wildcard DNS (* → same IP) to avoid false positives.

METHOD 4 - Common subdomain patterns:
  Checks for known cloud/service patterns like:
  - GitHub Pages: *.github.io records
  - AWS: *.s3.amazonaws.com CNAMEs
  - Heroku/Netlify/Vercel dangling CNAMEs (→ takeover!)

SUBDOMAIN TAKEOVER:
  When a CNAME points to an unclaimed external service, an attacker
  can register that service and serve content under the victim's domain.
  Example: staging.victim.com → CNAME → unregistered.herokuapp.com
"""

import dns.resolver
import dns.exception
import requests
import socket
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

try:
    import sublist3r
    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False


# Built-in wordlist (top ~300 common subdomains)
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "secure", "vpn", "m", "shop", "app", "api", "dev", "staging",
    "test", "beta", "demo", "cdn", "static", "media", "assets", "img",
    "images", "blog", "news", "forum", "help", "support", "docs",
    "portal", "intranet", "extranet", "remote", "gateway", "proxy",
    "wap", "mobile", "iphone", "android", "mx", "mx1", "mx2",
    "email", "webdisk", "autoconfig", "autodiscover", "git", "gitlab",
    "github", "jira", "confluence", "wiki", "kb", "store", "checkout",
    "pay", "payment", "billing", "accounts", "account", "login", "auth",
    "sso", "oauth", "api2", "api3", "v1", "v2", "v3", "graphql",
    "rest", "soap", "rpc", "internal", "corp", "corporate", "staff",
    "hr", "finance", "legal", "marketing", "sales", "it", "helpdesk",
    "monitor", "monitoring", "grafana", "kibana", "elastic", "jenkins",
    "ci", "cd", "build", "deploy", "docker", "k8s", "kubernetes",
    "prod", "production", "uat", "qa", "pre-prod", "preprod",
    "rc", "release", "old", "new", "backup", "bak", "archive",
    "download", "downloads", "upload", "uploads", "files", "file",
    "ftp2", "sftp", "ssh", "vpn2", "openvpn", "cisco", "owa",
    "exchange", "outlook", "office", "sharepoint", "lync",
    "meet", "meeting", "webex", "zoom", "voice", "voip", "phone",
    "sip", "asterisk", "pbx", "callcenter", "crm", "erp", "sap",
    "oracle", "mysql", "postgres", "redis", "memcache", "mongo",
    "elastic", "solr", "search", "analytics", "track", "tracker",
    "pixel", "ad", "ads", "adserver", "click", "link", "go",
    "redirect", "r", "status", "health", "ping", "check",
    "cpanel", "whm", "plesk", "phpmyadmin", "adminer", "webadmin",
    "manage", "manager", "management", "control", "panel",
    "dashboard", "console", "terminal", "shell", "remote-access",
    "rdp", "vnc", "mremote", "aws", "azure", "gcp", "cloud",
    "s3", "blob", "storage", "bucket", "cdn2", "edge",
    "smtp2", "relay", "outbound", "inbound", "lists", "newsletter",
    "unsubscribe", "mail2", "webmail2", "imap", "pop3",
    "ns3", "ns4", "dns", "dns1", "dns2", "resolver",
    "ntp", "time", "update", "updates", "patch", "repo",
    "mirror", "pkg", "apt", "yum", "pip", "npm", "registry",
    "socket", "ws", "wss", "stream", "live", "video", "video2",
    "chat", "im", "slack", "discord", "teams",
]

# Known dangling CNAME patterns for takeover detection
TAKEOVER_SIGNATURES = {
    "github.io": "GitHub Pages - check if page is claimed",
    "herokuapp.com": "Heroku - check if app is deployed",
    "azurewebsites.net": "Azure Web Apps - check if app exists",
    "cloudfront.net": "AWS CloudFront - verify distribution",
    "s3.amazonaws.com": "AWS S3 - check if bucket exists",
    "netlify.app": "Netlify - check if site is deployed",
    "netlify.com": "Netlify - check if site is deployed",
    "vercel.app": "Vercel - check if app is deployed",
    "surge.sh": "Surge - check if project exists",
    "readme.io": "ReadMe - check if docs project exists",
    "ghost.io": "Ghost - check if blog exists",
    "unbounce.com": "Unbounce - check if page is claimed",
    "shopify.com": "Shopify - verify store",
    "wordpress.com": "WordPress.com - check if site exists",
    "tumblr.com": "Tumblr - check if blog is claimed",
    "helpscout.net": "HelpScout - check if site is claimed",
    "zendesk.com": "Zendesk - check if portal exists",
    "freshdesk.com": "Freshdesk - check if portal exists",
    "intercom.io": "Intercom - check if site is claimed",
}


class SubdomainModule:
    """Subdomain Enumeration via multiple methods."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.threads = config.get("threads", 10)
        self.timeout = config.get("timeout", 5)
        self.verbose = config.get("verbose", False)
        self.wordlist_path = config.get("wordlist", None)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 4.0
        try:
            self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "8.8.4.4"]
        except Exception:
            pass
        self._lock = threading.Lock()
        self._found = {}  # subdomain -> details

    def run(self) -> list:
        print(f"  {Fore.BLUE}[*] Starting subdomain enumeration for {self.domain}...{Style.RESET_ALL}")

        # Method 1: HackerTarget passive DNS (high reliability fallback)
        self._hackertarget_enum()

        # Method 2: Certificate Transparency (crt.sh)
        self._crtsh_enum()

        # Method 3: Sublist3r passive OSINT (with safety timeout)
        self._sublist3r_enum()

        # Method 4: DNS brute force
        self._dns_bruteforce()

        # Method 5: Check for takeover vulnerabilities
        self._check_takeover()

        # Deduplicate and sort
        results = sorted(self._found.values(), key=lambda x: x["subdomain"])
        print(f"\n  {Fore.GREEN}[+] Total unique subdomains: {len(results)}{Style.RESET_ALL}")
        return results

    def _get_with_retry(self, url: str, timeout: int, headers: dict = None,
                        retries: int = 1, backoff: float = 1.5):
        """
        GET a URL with one automatic retry on timeout/connection failure.
        """
        last_exc = None
        for attempt in range(retries + 1):
            try:
                return requests.get(url, timeout=timeout, headers=headers or {})
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError) as e:
                last_exc = e
                if attempt < retries:
                    if self.verbose:
                        print(f"  {Fore.YELLOW}    [*] Retry {attempt+1}/{retries} "
                              f"after timeout...{Style.RESET_ALL}")
                    time.sleep(backoff)
                    continue
                raise last_exc

    def _hackertarget_enum(self):
        """Query HackerTarget passive DNS search."""
        print(f"  {Fore.BLUE}[*] Querying HackerTarget passive DNS...{Style.RESET_ALL}")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self._get_with_retry(
                url, timeout=8, headers={"User-Agent": "PhantomRecon/2.0"}
            )
            if resp and resp.status_code == 200 and "error" not in resp.text.lower():
                count = 0
                for line in resp.text.splitlines():
                    parts = line.strip().split(",")
                    if parts:
                        sub = parts[0].strip().lower().lstrip("*.")
                        ip = parts[1].strip() if len(parts) > 1 else None
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            self._add_subdomain(sub, source="hackertarget", ips=[ip] if ip else [])
                            count += 1
                if count:
                    print(f"  {Fore.GREEN}[+] HackerTarget: {count} subdomains found{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                print(f"  {Fore.YELLOW}[!] HackerTarget passive search skipped: {e}{Style.RESET_ALL}")

    def _crtsh_enum(self):
        """Query Certificate Transparency logs via crt.sh API."""
        print(f"  {Fore.BLUE}[*] Querying Certificate Transparency logs (crt.sh)...{Style.RESET_ALL}")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self._get_with_retry(
                url, timeout=12, headers={"User-Agent": "PhantomRecon/2.0"}
            )
            if resp and resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{self.domain}") or name == self.domain:
                            subs.add(name)

                for sub in subs:
                    self._add_subdomain(sub, source="crt.sh")

                print(f"  {Fore.GREEN}[+] crt.sh: {len(subs)} subdomains found{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] crt.sh query unavailable (upstream service limitation): {e}{Style.RESET_ALL}")

    def _sublist3r_enum(self):
        """
        Run Sublist3r for passive subdomain enumeration with strict timeout.
        """
        if not SUBLIST3R_AVAILABLE:
            print(f"  {Fore.YELLOW}[!] Sublist3r not available, skipping{Style.RESET_ALL}")
            return

        print(f"  {Fore.BLUE}[*] Running Sublist3r passive OSINT...{Style.RESET_ALL}")

        import io, sys
        from concurrent.futures import ThreadPoolExecutor, TimeoutError

        subs = []

        def _run_sublist3r():
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            try:
                sys.stdout = io.StringIO()
                sys.stderr = io.StringIO()
                result = sublist3r.main(
                    self.domain, 10, savefile=None, ports=None,
                    silent=True, verbose=False,
                    enable_bruteforce=False, engines=None
                )
                return result if isinstance(result, list) else []
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_run_sublist3r)
                try:
                    subs = future.result(timeout=15)
                except TimeoutError:
                    print(f"  {Fore.YELLOW}[!] Sublist3r timed out after 15s (search engine throttle) -- continuing{Style.RESET_ALL}")
                    subs = []
        except Exception:
            subs = []

        if subs:
            for sub in subs:
                sub = sub.lower().strip()
                if sub.endswith(f".{self.domain}"):
                    self._add_subdomain(sub, source="sublist3r")
            print(f"  {Fore.GREEN}[+] Sublist3r: {len(subs)} subdomains found{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}[!] Sublist3r: no new results (handled by passive & DNS brute force){Style.RESET_ALL}")

    def _dns_bruteforce(self):
        """Brute-force subdomains using wordlist + concurrent DNS resolution."""
        wordlist = self._load_wordlist()
        print(f"  {Fore.BLUE}[*] DNS brute force with {len(wordlist)} words "
              f"({self.threads} threads)...{Style.RESET_ALL}")

        # Wildcard detection: resolve a random non-existent subdomain
        wildcard_ip = self._detect_wildcard()
        if wildcard_ip:
            print(f"  {Fore.YELLOW}[!] Wildcard DNS detected ({wildcard_ip}) "
                  f"- filtering false positives{Style.RESET_ALL}")

        found_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._resolve_subdomain, f"{word}.{self.domain}", wildcard_ip): word
                for word in wordlist
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_count += 1
                    self._add_subdomain(result["subdomain"], source="bruteforce",
                                        ips=result.get("ips", []))

        print(f"  {Fore.GREEN}[+] Brute force: {found_count} new subdomains resolved{Style.RESET_ALL}")

    def _detect_wildcard(self) -> str | None:
        """Check if domain uses wildcard DNS."""
        try:
            bogus = f"phantomrecon-nonexistent-12345.{self.domain}"
            answers = self.resolver.resolve(bogus, "A")
            return str(answers[0])
        except Exception:
            return None

    def _resolve_subdomain(self, fqdn: str, wildcard_ip: str | None) -> dict | None:
        """Attempt to resolve a single FQDN, return details if it resolves."""
        try:
            answers = self.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            # Filter out wildcard IPs
            if wildcard_ip and all(ip == wildcard_ip for ip in ips):
                return None
            return {"subdomain": fqdn, "ips": ips}
        except Exception:
            return None

    def _add_subdomain(self, subdomain: str, source: str, ips: list = None):
        """Thread-safe add to found subdomains dict."""
        subdomain = subdomain.lower().strip().rstrip(".")
        if not subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
            return
        with self._lock:
            if subdomain not in self._found:
                self._found[subdomain] = {
                    "subdomain": subdomain,
                    "sources": [source],
                    "ips": ips or [],
                    "cname": None,
                    "takeover_risk": None,
                    "http_status": None,
                }
                if self.verbose:
                    print(f"  {Fore.GREEN}    [+] {subdomain}{Style.RESET_ALL}")
            else:
                if source not in self._found[subdomain]["sources"]:
                    self._found[subdomain]["sources"].append(source)

    def _check_takeover(self):
        """Check found subdomains for potential subdomain takeover via dangling CNAMEs."""
        print(f"  {Fore.BLUE}[*] Checking for subdomain takeover vulnerabilities...{Style.RESET_ALL}")
        takeover_risks = []

        for sub, details in self._found.items():
            try:
                answers = self.resolver.resolve(sub, "CNAME")
                cname = str(answers[0]).rstrip(".")
                details["cname"] = cname

                for pattern, description in TAKEOVER_SIGNATURES.items():
                    if pattern in cname:
                        details["takeover_risk"] = description
                        takeover_risks.append(sub)
                        print(f"  {Fore.RED}[!!!] TAKEOVER RISK: {sub} → {cname}{Style.RESET_ALL}")
                        print(f"        {description}{Style.RESET_ALL}")
                        break
            except Exception:
                pass

        if not takeover_risks:
            print(f"  {Fore.GREEN}[+] No obvious takeover vulnerabilities found{Style.RESET_ALL}")

    def _load_wordlist(self) -> list:
        """Load wordlist from file or use built-in."""
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, "r") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                print(f"  {Fore.BLUE}[*] Loaded {len(words)} words from {self.wordlist_path}{Style.RESET_ALL}")
                return words
            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Could not load wordlist: {e}, using built-in{Style.RESET_ALL}")
        return BUILTIN_WORDLIST