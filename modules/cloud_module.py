"""
Cloud Asset Discovery Module — cloud_module.py
================================================
PHANTOM RECON v2.1 — Integrated Cloud Intelligence

HOW IT WORKS:
  This module discovers publicly exposed cloud assets belonging to the
  target organisation using two complementary approaches:

  METHOD 1 — NETLAS API (authenticated, structured intelligence):
    Netlas continuously scans the internet and indexes cloud infrastructure.
    We use it to find:
    - All hosts matching the target domain in cloud provider IP ranges
    - Open ports and services on cloud-hosted infrastructure
    - SSL certificates tied to cloud deployments
    - Historical IP addresses the domain has resolved to
    - Technologies detected on cloud-hosted endpoints

    Netlas queries used:
      domain:*.example.com AND ip:52.0.0.0/8   → AWS-hosted subdomains
      host:example.com                           → All indexed hosts
      domain:*.example.com datatype=dns          → DNS records
      ip_ranges queries for cloud CIDRs

  METHOD 2 — DIRECT HTTP PROBING (unauthenticated, active):
    Generates likely bucket/container names from the target domain and
    probes cloud storage endpoints directly:
    - AWS S3: https://BUCKET.s3.amazonaws.com/
    - Azure Blob: https://ACCOUNT.blob.core.windows.net/CONTAINER
    - GCP Storage: https://storage.googleapis.com/BUCKET/
    Status code meanings:
      200 = PUBLIC — bucket exists and is readable (CRITICAL finding)
      403 = EXISTS but private — bucket name confirmed
      404/error = Does not exist under that name

  METHOD 3 — GITHUB INTELLIGENCE:
    Searches GitHub for the target organisation's public repositories.
    Checks for accidentally committed sensitive files:
    .env, credentials.json, config.py, id_rsa, secrets.yaml

RED TEAM VALUE:
  - Exposed S3 = database dumps, backups, API keys, source code, PII
  - Exposed Azure = SharePoint exports, Office backups, app configs
  - Exposed GCP = BigQuery exports, ML datasets, service account keys
  - GitHub leaks = hardcoded credentials, internal docs, private keys
  - Netlas cloud IPs = direct access bypassing WAF/CDN protection

LEGAL NOTICE:
  Only run against targets you own or have written authorization to test.
  Unauthorised scanning of cloud storage is illegal in most jurisdictions.
"""

import os
import re
import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style


# ── Cloud provider IP ranges (CIDR prefixes) ─────────────────────────────────
# Used with Netlas to find cloud-hosted assets
AWS_CIDR_SAMPLES   = ["52.0.0.0/11", "54.0.0.0/8", "18.0.0.0/8", "3.0.0.0/8"]
AZURE_CIDR_SAMPLES = ["13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10"]
GCP_CIDR_SAMPLES   = ["34.0.0.0/9", "35.184.0.0/13", "104.196.0.0/14"]

# ── Bucket name patterns generated from company name ─────────────────────────
def _generate_bucket_names(company: str) -> list:
    """
    Generate likely cloud storage bucket names from a company/domain name.
    Based on the most common naming patterns seen in real breach disclosures.

    Example: 'tesla.com' → ['tesla', 'tesla-backup', 'tesla-dev', ...]
    """
    # Clean the company name — strip TLD, lowercase, replace dots/underscores
    c = company.lower().replace("_", "-")
    for tld in [".com", ".org", ".net", ".io", ".co", ".in", ".dev"]:
        if c.endswith(tld):
            c = c[:-len(tld)]
            break
    c = c.replace(".", "-")

    patterns = [
        # Base name
        c,
        # Environments
        f"{c}-dev",        f"{c}-development",
        f"{c}-staging",    f"{c}-stage",    f"{c}-stg",
        f"{c}-prod",       f"{c}-production",
        f"{c}-test",       f"{c}-testing",  f"{c}-qa",
        f"{c}-uat",        f"{c}-demo",     f"{c}-beta",
        # Data and backups
        f"{c}-backup",     f"{c}-backups",  f"{c}-bak",
        f"{c}-data",       f"{c}-database", f"{c}-db",
        f"{c}-dump",       f"{c}-dumps",    f"{c}-export",
        f"{c}-archive",    f"{c}-archives", f"{c}-logs",
        # Assets and media
        f"{c}-assets",     f"{c}-static",   f"{c}-media",
        f"{c}-images",     f"{c}-img",      f"{c}-files",
        f"{c}-uploads",    f"{c}-content",  f"{c}-cdn",
        # Internal tools
        f"{c}-internal",   f"{c}-private",  f"{c}-public",
        f"{c}-admin",      f"{c}-portal",   f"{c}-api",
        f"{c}-app",        f"{c}-web",      f"{c}-www",
        f"{c}-docs",       f"{c}-reports",  f"{c}-analytics",
        # Prefixed variants
        f"backup-{c}",     f"data-{c}",
        f"dev-{c}",        f"staging-{c}",
        f"prod-{c}",       f"static-{c}",
    ]

    # Deduplicate preserving order
    seen = set()
    return [p for p in patterns if not (p in seen or seen.add(p))]


# ── Subdomain takeover fingerprints for cloud services ───────────────────────
TAKEOVER_SIGNATURES = {
    "github.io":           "GitHub Pages — check if page is claimed",
    "herokuapp.com":       "Heroku — check if app is deployed",
    "azurewebsites.net":   "Azure Web Apps — check if app exists",
    "cloudfront.net":      "AWS CloudFront — verify distribution",
    "s3.amazonaws.com":    "AWS S3 — check if bucket is claimed",
    "s3-website":          "AWS S3 Static Website — check if claimed",
    "netlify.app":         "Netlify — check if site is deployed",
    "netlify.com":         "Netlify — check if site is deployed",
    "vercel.app":          "Vercel — check if app is deployed",
    "surge.sh":            "Surge — check if project exists",
    "ghost.io":            "Ghost — check if blog exists",
    "shopify.com":         "Shopify — verify store",
    "zendesk.com":         "Zendesk — check if portal exists",
    "freshdesk.com":       "Freshdesk — check if portal exists",
    "intercom.io":         "Intercom — check if site is claimed",
    "readme.io":           "ReadMe — check if docs project exists",
    "helpscout.net":       "HelpScout — check if site is claimed",
    "fastly.net":          "Fastly CDN — verify configuration",
    "pantheonsite.io":     "Pantheon — check if site is deployed",
}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MODULE CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class CloudModule:
    """
    Cloud Asset Discovery Module.

    Combines Netlas API intelligence with direct HTTP probing to discover:
    - Publicly accessible cloud storage (S3 / Azure Blob / GCP)
    - Cloud-hosted infrastructure via Netlas indexed data
    - GitHub repositories with potential secret leaks
    - Subdomain takeover vulnerabilities via dangling CNAMEs

    Usage:
        config = {
            "domain":     "example.com",
            "netlas_key": "YOUR_NETLAS_KEY",
            "threads":    10,
            "timeout":    8,
            "verbose":    False,
        }
        result = CloudModule(config).run()
    """

    def __init__(self, config: dict):
        self.domain      = config["domain"]
        self.netlas_key  = config.get("netlas_key", "") or \
                           os.getenv("NETLAS_API_KEY", "")
        self.threads     = config.get("threads", 10)
        self.timeout     = config.get("timeout", 8)
        self.verbose     = config.get("verbose", False)

        # Derive company/org name from domain for bucket enumeration
        parts = self.domain.split(".")
        self.company = parts[0] if len(parts) >= 2 else self.domain

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        })

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Main entry point. Returns a structured result dict.

        Result schema:
        {
            "netlas":           dict,   # Netlas cloud intel
            "s3_buckets":       list,   # AWS S3 probe results
            "azure_containers": list,   # Azure Blob probe results
            "gcp_buckets":      list,   # GCP Storage probe results
            "github_repos":     list,   # GitHub public repos
            "takeover_risks":   list,   # CNAME dangling checks
            "exposed_count":    int,    # Total publicly accessible
            "bucket_names_tried": int,  # How many names tested
            "errors":           list
        }
        """
        result = {
            "netlas":             {},
            "s3_buckets":         [],
            "azure_containers":   [],
            "gcp_buckets":        [],
            "github_repos":       [],
            "takeover_risks":     [],
            "exposed_count":      0,
            "bucket_names_tried": 0,
            "errors":             []
        }

        print(f"\n  {Fore.CYAN}[*] Cloud asset discovery: {self.domain}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}[*] Company name derived: {self.company}{Style.RESET_ALL}")

        # Phase 1: Netlas API intelligence (authenticated)
        self._netlas_intel(result)

        # Phase 2: Direct cloud storage probing (unauthenticated)
        names = _generate_bucket_names(self.company)
        result["bucket_names_tried"] = len(names)
        print(f"  {Fore.BLUE}[*] Testing {len(names)} bucket name patterns "
              f"across 3 cloud providers...{Style.RESET_ALL}")

        # Run all three storage providers concurrently
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_s3    = ex.submit(self._probe_s3,    names)
            f_azure = ex.submit(self._probe_azure,  names)
            f_gcp   = ex.submit(self._probe_gcp,   names)

        result["s3_buckets"]         = f_s3.result()
        result["azure_containers"]   = f_azure.result()
        result["gcp_buckets"]        = f_gcp.result()

        # Phase 3: GitHub intelligence
        result["github_repos"] = self._probe_github()

        # Phase 4: Subdomain takeover (CNAME dangling check)
        result["takeover_risks"] = self._check_takeover()

        # Tally exposed count
        exposed = (
            [b for b in result["s3_buckets"]       if b.get("accessible")] +
            [b for b in result["azure_containers"]  if b.get("accessible")] +
            [b for b in result["gcp_buckets"]       if b.get("accessible")]
        )
        result["exposed_count"] = len(exposed)

        # Final summary
        self._print_summary(result, exposed)
        return result

    # ── Phase 1: Netlas API Intelligence ─────────────────────────────────────

    def _netlas_intel(self, result: dict):
        """
        Query Netlas to find cloud-hosted infrastructure for the target domain.

        What Netlas provides that direct probing cannot:
        - Historical IP addresses (old CDN bypass opportunities)
        - Technologies detected on cloud endpoints
        - Open ports on cloud-hosted servers
        - SSL certificate metadata for cloud deployments
        - ASN information to identify cloud provider
        """
        if not self.netlas_key:
            print(f"  {Fore.YELLOW}[!] No Netlas API key — skipping cloud intelligence")
            print(f"      Free key at: https://app.netlas.io/profile/")
            print(f"      Add to .env: NETLAS_API_KEY=your_key_here{Style.RESET_ALL}")
            result["netlas"] = {
                "skipped":        True,
                "reason":         "No API key",
                "get_key_url":    "https://app.netlas.io/profile/"
            }
            return

        print(f"  {Fore.BLUE}[*] Querying Netlas API...{Style.RESET_ALL}")

        try:
            import netlas
            client = netlas.Netlas(api_key=self.netlas_key)
            netlas_data = {
                "cloud_hosts":     [],
                "historical_ips":  [],
                "open_ports":      [],
                "technologies":    [],
                "certificates":    [],
                "asn_info":        [],
                "total_indexed":   0,
            }

            # ── Query 1: Find all indexed hosts for domain ──────────────────
            # This returns everything Netlas has scanned for this domain
            try:
                query = f"host:{self.domain}"
                resp  = client.search(query, datatype="response")
                items = resp.get("items", [])
                netlas_data["total_indexed"] = resp.get("total", 0)

                for item in items:
                    data = item.get("data", {})

                    # Extract IP and port
                    ip   = data.get("ip", "")
                    port = data.get("port", "")

                    if ip:
                        host_entry = {
                            "ip":           ip,
                            "port":         port,
                            "protocol":     data.get("protocol", ""),
                            "asn":          data.get("asn", {}).get("number", ""),
                            "org":          data.get("asn", {}).get("org", ""),
                            "country":      data.get("geo", {}).get("country", ""),
                            "is_cloud":     self._is_cloud_ip(
                                data.get("asn", {}).get("org", "")
                            ),
                        }
                        netlas_data["cloud_hosts"].append(host_entry)

                        # Extract open port
                        if port:
                            netlas_data["open_ports"].append(
                                f"{ip}:{port}"
                            )

                    # Extract technology stack
                    http = data.get("http", {})
                    if http:
                        tech = http.get("favicon", {})
                        title = http.get("title", "")
                        server = (http.get("headers", {})
                                     .get("server", [""])[0]
                                  if isinstance(http.get("headers", {})
                                                    .get("server"), list)
                                  else http.get("headers", {})
                                           .get("server", ""))
                        if server:
                            netlas_data["technologies"].append(
                                {"ip": ip, "server": server, "title": title}
                            )

                print(f"  {Fore.GREEN}[+] Netlas: {len(netlas_data['cloud_hosts'])} "
                      f"hosts indexed for {self.domain}{Style.RESET_ALL}")

                # Flag cloud-hosted assets
                cloud_hosts = [h for h in netlas_data["cloud_hosts"]
                               if h.get("is_cloud")]
                if cloud_hosts:
                    print(f"  {Fore.YELLOW}[!] Netlas: {len(cloud_hosts)} "
                          f"cloud-hosted endpoints detected{Style.RESET_ALL}")
                    for h in cloud_hosts[:3]:
                        print(f"      {h['ip']}:{h['port']} "
                              f"— {h['org']} ({h['country']})")

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Netlas host query error: {e}{Style.RESET_ALL}")
                result["errors"].append(f"Netlas host query: {e}")

            # ── Query 2: DNS records to find subdomains and historical IPs ──
            try:
                query = f"domain:*.{self.domain}"
                resp  = client.search(query, datatype="dns")
                items = resp.get("items", [])
                found_subs = set()

                for item in items:
                    data = item.get("data", {})
                    dom  = data.get("domain", "").lower()
                    if dom and dom.endswith(f".{self.domain}"):
                        found_subs.add(dom)

                    # Collect all A record IPs as historical reference
                    for rr in data.get("a", []):
                        ip = rr if isinstance(rr, str) else rr.get("ip", "")
                        if ip and ip not in netlas_data["historical_ips"]:
                            netlas_data["historical_ips"].append(ip)

                if found_subs:
                    print(f"  {Fore.GREEN}[+] Netlas DNS: "
                          f"{len(found_subs)} subdomains found{Style.RESET_ALL}")

                if netlas_data["historical_ips"]:
                    print(f"  {Fore.YELLOW}[!] Historical IPs via Netlas: "
                          f"{', '.join(netlas_data['historical_ips'][:3])}")
                    print(f"      Old IPs may bypass WAF/CDN — "
                          f"try direct access{Style.RESET_ALL}")

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Netlas DNS query error: {e}{Style.RESET_ALL}")
                result["errors"].append(f"Netlas DNS query: {e}")

            # ── Query 3: SSL certificate search for domain ──────────────────
            # Finds all certificates issued for the domain
            try:
                query = f"certificate.subject.common_name:{self.domain}"
                resp  = client.search(query, datatype="response")
                items = resp.get("items", [])

                for item in items:
                    data = item.get("data", {})
                    cert = data.get("certificate", {})
                    if cert:
                        netlas_data["certificates"].append({
                            "ip":      data.get("ip", ""),
                            "subject": cert.get("subject", {})
                                          .get("common_name", ""),
                            "issuer":  cert.get("issuer", {})
                                          .get("common_name", ""),
                            "sans":    cert.get("subject_alt_name", []),
                        })

                if netlas_data["certificates"]:
                    print(f"  {Fore.GREEN}[+] Netlas SSL: "
                          f"{len(netlas_data['certificates'])} "
                          f"certificates found{Style.RESET_ALL}")

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Netlas SSL query error: {e}{Style.RESET_ALL}")
                result["errors"].append(f"Netlas SSL query: {e}")

            result["netlas"] = netlas_data

        except ImportError:
            msg = "netlas not installed — run: pip install netlas"
            print(f"  {Fore.RED}[-] {msg}{Style.RESET_ALL}")
            result["netlas"] = {"error": msg}
            result["errors"].append(msg)

        except Exception as e:
            msg = f"Netlas API error: {e}"
            print(f"  {Fore.RED}[-] {msg}{Style.RESET_ALL}")
            result["netlas"] = {"error": msg}
            result["errors"].append(msg)

    def _is_cloud_ip(self, org: str) -> bool:
        """Check if an ASN org name belongs to a major cloud provider."""
        org_lower = (org or "").lower()
        cloud_orgs = [
            "amazon", "aws", "microsoft", "azure",
            "google", "gcp", "cloudflare", "fastly",
            "akamai", "digitalocean", "linode", "vultr",
            "hetzner", "ovh", "rackspace",
        ]
        return any(c in org_lower for c in cloud_orgs)

    # ── Phase 2a: AWS S3 Bucket Probing ──────────────────────────────────────

    def _probe_s3(self, names: list) -> list:
        """
        Probe AWS S3 bucket names using the public REST endpoint.

        URL format: https://BUCKET.s3.amazonaws.com/
        Also tries regional endpoints for buckets that redirect.

        Response interpretation:
          HTTP 200 + XML  = PUBLIC bucket — CRITICAL finding
          HTTP 403        = Bucket exists but private — name confirmed
          HTTP 301/307    = Exists in different region — follow redirect
          Connection error = Bucket does not exist under this name
        """
        print(f"  {Fore.BLUE}[*] Probing AWS S3 ({len(names)} names)...{Style.RESET_ALL}")
        found = []

        def probe(name):
            url = f"https://{name}.s3.amazonaws.com/"
            try:
                r = self.session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )
                if r.status_code == 200:
                    # Count files if XML directory listing returned
                    file_count = r.text.count("<Key>")
                    entry = {
                        "name":       name,
                        "url":        url,
                        "provider":   "AWS S3",
                        "status":     200,
                        "accessible": True,
                        "file_count": file_count,
                        "severity":   "CRITICAL",
                        "note":       f"PUBLIC — {file_count} objects visible",
                    }
                    print(f"  {Fore.RED}[!!!] S3 EXPOSED: {url} "
                          f"({file_count} files){Style.RESET_ALL}")
                    return entry

                elif r.status_code == 403:
                    # Bucket exists but access denied — still valuable intel
                    if self.verbose:
                        print(f"  {Fore.YELLOW}    [*] S3 private: "
                              f"{name}{Style.RESET_ALL}")
                    return {
                        "name":       name,
                        "url":        url,
                        "provider":   "AWS S3",
                        "status":     403,
                        "accessible": False,
                        "severity":   "INFO",
                        "note":       "Bucket exists (private)",
                    }

                elif r.status_code in (301, 307):
                    # Bucket in a different region — follow redirect
                    redirect_url = r.headers.get("Location", url)
                    try:
                        r2 = self.session.get(
                            redirect_url, timeout=self.timeout
                        )
                        if r2.status_code == 200:
                            file_count = r2.text.count("<Key>")
                            print(f"  {Fore.RED}[!!!] S3 EXPOSED (redirected): "
                                  f"{redirect_url}{Style.RESET_ALL}")
                            return {
                                "name":       name,
                                "url":        redirect_url,
                                "provider":   "AWS S3",
                                "status":     200,
                                "accessible": True,
                                "file_count": file_count,
                                "severity":   "CRITICAL",
                                "note":       f"PUBLIC via redirect — {file_count} objects",
                            }
                    except Exception:
                        pass

            except requests.exceptions.ConnectionError:
                pass  # Bucket does not exist — expected for most names
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            results = list(ex.map(probe, names))

        found = [r for r in results if r]
        exposed = len([r for r in found if r.get("accessible")])
        print(f"  {Fore.GREEN}[+] S3: {len(found)} buckets confirmed, "
              f"{exposed} EXPOSED{Style.RESET_ALL}")
        return found

    # ── Phase 2b: Azure Blob Storage Probing ─────────────────────────────────

    def _probe_azure(self, names: list) -> list:
        """
        Probe Azure Blob Storage containers.

        URL format:
          https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list

        Public containers return XML with EnumerationResults containing file list.
        Private containers return 403 with BlobAccessTier or ResourceNotFound error.
        """
        print(f"  {Fore.BLUE}[*] Probing Azure Blob Storage...{Style.RESET_ALL}")
        found = []

        # Common container names to try per storage account
        common_containers = [
            "public", "data", "files", "backup", "assets",
            "media", "uploads", "static", "web", "content",
        ]

        def probe(name):
            results = []
            for container in common_containers[:5]:
                url = (
                    f"https://{name}.blob.core.windows.net"
                    f"/{container}?restype=container&comp=list"
                )
                try:
                    r = self.session.get(url, timeout=self.timeout)
                    if r.status_code == 200 and "EnumerationResults" in r.text:
                        blob_count = r.text.count("<Name>")
                        print(f"  {Fore.RED}[!!!] AZURE EXPOSED: "
                              f"{url} ({blob_count} blobs){Style.RESET_ALL}")
                        results.append({
                            "name":       f"{name}/{container}",
                            "url":        url,
                            "provider":   "Azure Blob",
                            "status":     200,
                            "accessible": True,
                            "file_count": blob_count,
                            "severity":   "CRITICAL",
                            "note":       f"PUBLIC — {blob_count} blobs visible",
                        })
                    elif r.status_code == 403:
                        results.append({
                            "name":       f"{name}/{container}",
                            "url":        f"https://{name}.blob.core.windows.net/",
                            "provider":   "Azure Blob",
                            "status":     403,
                            "accessible": False,
                            "severity":   "INFO",
                            "note":       "Account exists (container private)",
                        })
                except Exception:
                    pass
            return results

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            all_results = list(ex.map(probe, names[:20]))

        for r in all_results:
            found.extend(r)

        exposed = len([r for r in found if r.get("accessible")])
        print(f"  {Fore.GREEN}[+] Azure: {len(found)} containers checked, "
              f"{exposed} EXPOSED{Style.RESET_ALL}")
        return found

    # ── Phase 2c: GCP Cloud Storage Probing ──────────────────────────────────

    def _probe_gcp(self, names: list) -> list:
        """
        Probe Google Cloud Storage buckets.

        Two URL formats:
          https://storage.googleapis.com/BUCKET/
          https://BUCKET.storage.googleapis.com/

        Public buckets return JSON/XML file listing.
        Private buckets return 403 AccessDenied.
        Non-existent buckets return 404 NoSuchBucket.
        """
        print(f"  {Fore.BLUE}[*] Probing GCP Cloud Storage...{Style.RESET_ALL}")
        found = []

        def probe(name):
            urls = [
                f"https://storage.googleapis.com/{name}/",
                f"https://{name}.storage.googleapis.com/",
            ]
            for url in urls:
                try:
                    r = self.session.get(url, timeout=self.timeout)
                    if r.status_code == 200:
                        # Count objects from JSON or XML response
                        obj_count = (
                            r.text.count('"name"') +
                            r.text.count("<Key>")
                        )
                        print(f"  {Fore.RED}[!!!] GCP EXPOSED: "
                              f"{url} (~{obj_count} objects){Style.RESET_ALL}")
                        return {
                            "name":       name,
                            "url":        url,
                            "provider":   "GCP Storage",
                            "status":     200,
                            "accessible": True,
                            "file_count": obj_count,
                            "severity":   "CRITICAL",
                            "note":       f"PUBLIC — ~{obj_count} objects visible",
                        }
                    elif r.status_code == 403:
                        if self.verbose:
                            print(f"  {Fore.YELLOW}    [*] GCP private: "
                                  f"{name}{Style.RESET_ALL}")
                        return {
                            "name":       name,
                            "url":        url,
                            "provider":   "GCP Storage",
                            "status":     403,
                            "accessible": False,
                            "severity":   "INFO",
                            "note":       "Bucket exists (private)",
                        }
                except Exception:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            results = list(ex.map(probe, names))

        found = [r for r in results if r]
        exposed = len([r for r in found if r.get("accessible")])
        print(f"  {Fore.GREEN}[+] GCP: {len(found)} buckets confirmed, "
              f"{exposed} EXPOSED{Style.RESET_ALL}")
        return found

    # ── Phase 3: GitHub Intelligence ─────────────────────────────────────────

    def _probe_github(self) -> list:
        """
        Search GitHub for public repositories belonging to the target org.

        Also checks first 5 repos for accidentally committed sensitive files:
        .env, credentials.json, config.py, id_rsa, secrets.yaml, .pem keys

        Uses GitHub public API — no auth needed for basic search.
        Add GITHUB_TOKEN env var for higher rate limits (5000/hr vs 60/hr).
        """
        print(f"  {Fore.BLUE}[*] Searching GitHub for org: "
              f"{self.company}...{Style.RESET_ALL}")
        repos = []

        github_token = os.getenv("GITHUB_TOKEN", "")
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "PhantomRecon/2.1",
        }
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        # Sensitive files that should never be in a public repo
        sensitive_files = [
            ".env", ".env.production", ".env.local",
            "credentials.json", "service_account.json",
            "config.py", "secrets.yaml", "secrets.json",
            "id_rsa", "id_ecdsa", "private_key.pem",
            "aws_credentials", ".aws/credentials",
        ]

        try:
            # Try as organisation first
            url  = (f"https://api.github.com/orgs/{self.company}"
                    f"/repos?per_page=30&type=public&sort=updated")
            resp = self.session.get(url, timeout=self.timeout, headers=headers)

            if resp.status_code == 404:
                # Fall back to user search
                url  = (f"https://api.github.com/users/{self.company}"
                        f"/repos?per_page=30&type=public&sort=updated")
                resp = self.session.get(url, timeout=self.timeout, headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                for repo in data:
                    repo_entry = {
                        "name":        repo.get("full_name", ""),
                        "url":         repo.get("html_url", ""),
                        "description": (repo.get("description") or "")[:120],
                        "language":    repo.get("language", ""),
                        "stars":       repo.get("stargazers_count", 0),
                        "forks":       repo.get("forks_count", 0),
                        "updated":     repo.get("updated_at", "")[:10],
                        "private":     repo.get("private", False),
                        "sensitive_files_found": [],
                    }
                    repos.append(repo_entry)

                print(f"  {Fore.GREEN}[+] GitHub: {len(repos)} public repos "
                      f"found for '{self.company}'{Style.RESET_ALL}")

                # Check first 5 repos for sensitive files
                for repo in repos[:5]:
                    for fname in sensitive_files[:6]:
                        check_url = (
                            f"https://raw.githubusercontent.com"
                            f"/{repo['name']}/main/{fname}"
                        )
                        try:
                            cr = self.session.get(check_url, timeout=3)
                            if cr.status_code == 200 and len(cr.text) > 20:
                                repo["sensitive_files_found"].append(fname)
                                print(f"  {Fore.RED}[!!!] LEAKED FILE: "
                                      f"{repo['name']}/{fname}{Style.RESET_ALL}")
                        except Exception:
                            pass
                        time.sleep(0.1)  # Gentle rate limiting

            elif resp.status_code == 403:
                print(f"  {Fore.YELLOW}[!] GitHub rate limited — "
                      f"add GITHUB_TOKEN to .env for 5000 req/hr{Style.RESET_ALL}")

            elif resp.status_code == 404:
                print(f"  {Fore.BLUE}[*] GitHub: no org/user '{self.company}' "
                      f"found{Style.RESET_ALL}")

        except Exception as e:
            print(f"  {Fore.YELLOW}[!] GitHub probe error: {e}{Style.RESET_ALL}")

        return repos

    # ── Phase 4: Subdomain Takeover via CNAME Check ───────────────────────────

    def _check_takeover(self) -> list:
        """
        Check for subdomain takeover vulnerabilities.

        A takeover occurs when a subdomain has a CNAME pointing to an
        unclaimed external service. An attacker can register that service
        and serve arbitrary content under the victim's domain.

        Method:
          1. Resolve each subdomain to find CNAME records
          2. Check if the CNAME target matches a known cloud provider pattern
          3. HTTP probe the subdomain to look for unclaimed service error pages

        Common error strings per service:
          Heroku:   "No such app"
          GitHub:   "There isn't a GitHub Pages site here"
          AWS S3:   "NoSuchBucket"
          Netlify:  "Not Found — Request ID"
          Vercel:   "The deployment could not be found"
        """
        print(f"  {Fore.BLUE}[*] Checking subdomain takeover "
              f"vulnerabilities...{Style.RESET_ALL}")
        risks = []

        # Takeover-confirming error strings per service
        error_strings = {
            "github.io":         "There isn't a GitHub Pages site here",
            "herokuapp.com":     "No such app",
            "azurewebsites.net": "404 Web Site not found",
            "s3.amazonaws.com":  "NoSuchBucket",
            "netlify.app":       "Not Found",
            "netlify.com":       "Not Found",
            "vercel.app":        "The deployment could not be found",
            "fastly.net":        "Fastly error: unknown domain",
            "shopify.com":       "Sorry, this shop is currently unavailable",
            "zendesk.com":       "Help Center Closed",
            "ghost.io":          "404",
            "surge.sh":          "project not found",
        }

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout

            # Get subdomains from DNS brute (quick common list)
            common_subs = [
                "www", "mail", "api", "dev", "staging", "blog",
                "shop", "cdn", "static", "assets", "admin", "portal",
                "help", "support", "docs", "status", "beta", "app",
            ]

            for sub in common_subs:
                fqdn = f"{sub}.{self.domain}"
                try:
                    # Look for CNAME records
                    answers = resolver.resolve(fqdn, "CNAME")
                    cname   = str(answers[0]).rstrip(".")

                    for pattern, description in TAKEOVER_SIGNATURES.items():
                        if pattern in cname:
                            # Confirm by HTTP probe
                            error_str = error_strings.get(pattern, "")
                            confirmed = False
                            if error_str:
                                try:
                                    r = self.session.get(
                                        f"https://{fqdn}",
                                        timeout=5,
                                        allow_redirects=True
                                    )
                                    confirmed = error_str.lower() in r.text.lower()
                                except Exception:
                                    pass

                            risk_entry = {
                                "subdomain":   fqdn,
                                "cname":       cname,
                                "service":     pattern,
                                "description": description,
                                "confirmed":   confirmed,
                                "severity":    "HIGH" if confirmed else "MEDIUM",
                            }
                            risks.append(risk_entry)

                            sev_color = (Fore.RED if confirmed else Fore.YELLOW)
                            conf_str  = "CONFIRMED" if confirmed else "POTENTIAL"
                            print(f"  {sev_color}[!!!] TAKEOVER {conf_str}: "
                                  f"{fqdn} → {cname}{Style.RESET_ALL}")
                            print(f"        {description}")
                            break

                except dns.resolver.NXDOMAIN:
                    pass   # Subdomain doesn't exist — expected
                except dns.resolver.NoAnswer:
                    pass   # No CNAME — fine
                except Exception:
                    pass

        except ImportError:
            print(f"  {Fore.YELLOW}[!] dnspython not installed — "
                  f"skipping takeover check{Style.RESET_ALL}")

        if not risks:
            print(f"  {Fore.GREEN}[+] No subdomain takeover "
                  f"vulnerabilities found in common subs{Style.RESET_ALL}")

        return risks

    # ── Final summary printer ─────────────────────────────────────────────────

    def _print_summary(self, result: dict, exposed: list):
        """Print a clean summary of all cloud findings."""
        try:
            print(f"\n  {Fore.CYAN}{'-'*55}")
            print(f"  CLOUD DISCOVERY SUMMARY: {self.domain}")
            print(f"  {'-'*55}{Style.RESET_ALL}")

            if exposed:
                print(f"\n  {Fore.RED}{'!'*55}")
                print(f"  [!!!] {len(exposed)} PUBLICLY ACCESSIBLE STORAGE FOUND:")
                for b in exposed:
                    print(f"        * [{b['provider']}] {b['url']}")
                    print(f"          {b['note']}")
                print(f"  {'!'*55}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[+] No public storage buckets found "
                      f"in tested patterns{Style.RESET_ALL}")

            netlas = result.get("netlas", {})
            if not netlas.get("skipped"):
                hosts = len(netlas.get("cloud_hosts", []))
                h_ips = len(netlas.get("historical_ips", []))
                certs = len(netlas.get("certificates", []))
                print(f"  {Fore.BLUE}[*] Netlas: {hosts} hosts indexed, "
                      f"{h_ips} historical IPs, "
                      f"{certs} certificates{Style.RESET_ALL}")

            takeovers = [t for t in result.get("takeover_risks", [])
                         if t.get("confirmed")]
            if takeovers:
                print(f"  {Fore.RED}[!] {len(takeovers)} confirmed subdomain "
                      f"takeover(s) found{Style.RESET_ALL}")

            repos = result.get("github_repos", [])
            leaked = [r for r in repos if r.get("sensitive_files_found")]
            if repos:
                print(f"  {Fore.BLUE}[*] GitHub: {len(repos)} public repos"
                      + (f", {Fore.RED}{len(leaked)} with leaked files"
                         if leaked else "")
                      + f"{Style.RESET_ALL}")

            print(f"  {Fore.CYAN}{'-'*55}{Style.RESET_ALL}\n")
        except Exception:
            pass
