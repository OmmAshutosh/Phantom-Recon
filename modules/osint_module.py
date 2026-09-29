"""
Enhanced OSINT Module — VirusTotal + SecurityTrails + Wayback
==============================================================
HOW IT WORKS:

VIRUSTOTAL API:
  VirusTotal maintains a massive database of:
  - URLs / domains scanned by 70+ security engines
  - File hashes (malware detection)
  - IP reputation scores
  - Historical DNS resolutions
  - Subdomain relationships
  - Community comments / votes
  - WHOIS data enrichment

  Free API: 500 requests/day, 4 req/min
  https://www.virustotal.com/gui/my-apikey

NETLAS API:
  Netlas maintains historical DNS records:
  - Every A/MX/NS/TXT record ever seen for a domain
  - Reverse DNS (all domains ever hosted on an IP)
  - Historical WHOIS data
  - Subdomain discovery from passive DNS
  - IP/company co-hosted domains

  Free API: 50 requests/day
  https://app.netlas.io/profile

WAYBACK MACHINE:
  The Internet Archive stores snapshots of web pages.
  For recon, we use the CDX API to enumerate:
  - All URLs ever crawled for a domain
  - Historical page content (find old subdomains, emails, tech)
  - Removed content that was once public (credentials, configs)
  - API endpoints from old JS bundles

  URL: http://web.archive.org/cdx/search/cdx
"""

import json
import re
import time

import requests
from colorama import Fore, Style


class OsintModule:
    """
    Enhanced OSINT via VirusTotal, SecurityTrails, Wayback Machine.
    Supplements subdomain + email modules with historical intelligence.
    """

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)
        self.vt_key = config.get("virustotal_key", "")
        self.st_key   = config.get("netlas_key", "")
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
            )
        }

    def run(self) -> dict:
        result = {
            "virustotal": {},
            "netlas": {},
            "wayback": {},
            "github_leaks": {},
            "pastebin_mentions": [],
            "combined_subdomains": [],
            "combined_emails": [],
            "errors": []
        }

        print(f"  {Fore.BLUE}[*] Running enhanced OSINT collection...{Style.RESET_ALL}")

        self._virustotal_recon(result)
        self._netlas_recon(result)
        self._wayback_recon(result)
        self._github_dork(result)

        # Deduplicate and merge findings
        all_subs = set(result["virustotal"].get("subdomains", []) +
                       result["securitytrails"].get("subdomains", []) +
                       result["wayback"].get("subdomains", []))
        result["combined_subdomains"] = sorted(all_subs)

        print(f"  {Fore.GREEN}[+] OSINT combined: {len(result['combined_subdomains'])} "
              f"unique subdomains{Style.RESET_ALL}")
        return result

    # ── VirusTotal ─────────────────────────────────────────────────────────

    def _virustotal_recon(self, result: dict):
        """
        VirusTotal Domain Report:
        GET /api/v3/domains/{domain}
        Returns: subdomains, resolutions, reputation, DNS records, categories
        """
        if not self.vt_key:
            print(f"  {Fore.YELLOW}[!] No VirusTotal API key — skipping "
                  f"(free key at virustotal.com){Style.RESET_ALL}")
            result["virustotal"]["skipped"] = True
            # Fallback: use public VT search without API key
            self._vt_public_fallback(result)
            return

        print(f"  {Fore.BLUE}[*] Querying VirusTotal API...{Style.RESET_ALL}")
        vt = {}

        try:
            # Domain report
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
            resp = requests.get(url, headers={
                **self.headers, "x-apikey": self.vt_key
            }, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})

                vt["reputation"] = attrs.get("reputation", 0)
                vt["harmless"] = attrs.get("last_analysis_stats", {}).get("harmless", 0)
                vt["malicious"] = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                vt["suspicious"] = attrs.get("last_analysis_stats", {}).get("suspicious", 0)
                vt["categories"] = attrs.get("categories", {})
                vt["registrar"] = attrs.get("registrar", "")
                vt["creation_date"] = attrs.get("creation_date", "")
                vt["last_dns_records"] = attrs.get("last_dns_records", [])
                vt["popularity_ranks"] = attrs.get("popularity_ranks", {})

                # Alexa / popularity rank
                ranks = attrs.get("popularity_ranks", {})
                if ranks:
                    top_rank = min(ranks.values(), key=lambda x: x.get("rank", 999999))
                    vt["best_rank"] = top_rank.get("rank")

                if vt.get("malicious", 0) > 0:
                    print(f"  {Fore.RED}[!!!] VirusTotal: {vt['malicious']} engines "
                          f"flagged this domain as MALICIOUS!{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.GREEN}[+] VirusTotal reputation: "
                          f"{vt.get('reputation', 0)} "
                          f"(malicious: {vt.get('malicious', 0)}){Style.RESET_ALL}")

                # Rate limit: 4 req/min on free tier
                time.sleep(0.3)

            elif resp.status_code == 401:
                print(f"  {Fore.RED}[-] VirusTotal: Invalid API key{Style.RESET_ALL}")
            elif resp.status_code == 429:
                print(f"  {Fore.YELLOW}[!] VirusTotal: Rate limit hit{Style.RESET_ALL}")

        except Exception as e:
            result["errors"].append(f"VirusTotal error: {str(e)}")
            print(f"  {Fore.RED}[-] VirusTotal error: {e}{Style.RESET_ALL}")

        # Subdomains via VT
        try:
            url = (f"https://www.virustotal.com/api/v3/domains/{self.domain}"
                   f"/subdomains?limit=40")
            resp = requests.get(url, headers={
                **self.headers, "x-apikey": self.vt_key
            }, timeout=self.timeout)

            if resp.status_code == 200:
                subs_data = resp.json().get("data", [])
                subs = [s["id"] for s in subs_data if "id" in s]
                vt["subdomains"] = subs
                print(f"  {Fore.GREEN}[+] VirusTotal subdomains: {len(subs)}{Style.RESET_ALL}")
                if self.verbose:
                    for s in subs[:5]:
                        print(f"         → {s}")
            time.sleep(0.3)

        except Exception as e:
            vt["subdomains"] = []

        result["virustotal"] = vt

    def _vt_public_fallback(self, result: dict):
        """Query VirusTotal's public search page as fallback (no key needed)."""
        try:
            url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=20"
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                subs = [d["id"] for d in data.get("data", []) if "id" in d]
                result["virustotal"]["subdomains"] = subs
                result["virustotal"]["source"] = "public_ui"
                print(f"  {Fore.GREEN}[+] VirusTotal public: {len(subs)} subdomains{Style.RESET_ALL}")
        except Exception:
            pass

    # ── Netlas ─────────────────────────────────────────────────────

    def _netlas_recon(self, result: dict):
        api_key = self.st_key or ""

        if not api_key:
            print(f"  {Fore.YELLOW}[!] No Netlas API key — skipping")
            print(f"      Free key at: https://app.netlas.io/profile/{Style.RESET_ALL}")
            result["securitytrails"] = {"skipped": True, "reason": "No API key"}
            return

        print(f"  {Fore.BLUE}[*] Querying Netlas API...{Style.RESET_ALL}")

        try:
            from netlas import Netlas
            client = Netlas(api_key=api_key)
            st = {
                "subdomains":    [],
                "current_ips":   [],
                "historical_ips": [],
                "dns_records":   [],
                "source":        "netlas"
            }

            # ── Subdomain enumeration ─────────────────────────────────
            # Wildcard query finds all DNS records for *.domain.com
            try:
                query   = f"domain:*.{self.domain}"
                resp    = client.search(query, datatype="dns")
                items   = resp.get("items", [])
                subs    = set()
                for item in items:
                    data = item.get("data", {})
                    dom  = data.get("domain", "")
                    if dom and dom.endswith(f".{self.domain}"):
                        subs.add(dom.lower())
                    # Also pull A record IPs
                    for rr in data.get("a", []):
                        ip = rr if isinstance(rr, str) else rr.get("ip", "")
                        if ip and ip not in st["current_ips"]:
                            st["current_ips"].append(ip)

                st["subdomains"] = sorted(subs)
                print(f"  {Fore.GREEN}[+] Netlas subdomains: "
                    f"{len(st['subdomains'])} found{Style.RESET_ALL}")

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Netlas subdomain query error: {e}{Style.RESET_ALL}")

            # ── DNS record lookup for root domain ─────────────────────
            try:
                resp  = client.search(f"domain:{self.domain}", datatype="dns")
                items = resp.get("items", [])
                for item in items:
                    data    = item.get("data", {})
                    records = []
                    for rtype in ["a", "aaaa", "mx", "ns", "txt", "cname"]:
                        vals = data.get(rtype, [])
                        if vals:
                            for v in (vals if isinstance(vals, list) else [vals]):
                                val_str = v if isinstance(v, str) else str(v)
                                records.append({"type": rtype.upper(), "value": val_str})
                    st["dns_records"].extend(records)
                    if records:
                        print(f"  {Fore.GREEN}[+] Netlas DNS records: "
                            f"{len(records)} found{Style.RESET_ALL}")

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Netlas DNS query error: {e}{Style.RESET_ALL}")

            # ── Historical IPs via WHOIS ──────────────────────────────
            # Old IPs are gold — they may bypass CDN/WAF (direct access)
            try:
                resp  = client.search(f"domain:{self.domain}", datatype="whois-domain")
                items = resp.get("items", [])
                seen_ips = set(st["current_ips"])
                for item in items:
                    data = item.get("data", {})
                    for ip_field in ["ip", "ip_address", "registrant_ip"]:
                        ip = data.get(ip_field, "")
                        if ip and ip not in seen_ips:
                            st["historical_ips"].append(ip)
                            seen_ips.add(ip)

                if st["historical_ips"]:
                    print(f"  {Fore.YELLOW}[!] Netlas historical IPs: "
                        f"{', '.join(st['historical_ips'][:3])}")
                    print(f"      These may bypass CDN/WAF — try direct access"
                        f"{Style.RESET_ALL}")

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Netlas WHOIS query error: {e}{Style.RESET_ALL}")

            result["securitytrails"] = st

        except ImportError:
            print(f"  {Fore.RED}[-] netlas not installed: pip install netlas{Style.RESET_ALL}")
            result["securitytrails"] = {"error": "netlas not installed"}
        except Exception as e:
            print(f"  {Fore.RED}[-] Netlas error: {e}{Style.RESET_ALL}")
            result["securitytrails"] = {"error": str(e)}

    # ── Wayback Machine ────────────────────────────────────────────────────

    def _wayback_recon(self, result: dict):
        """
        Query the Wayback Machine CDX API for historical URL data.

        CDX API returns tab-separated: urlkey, timestamp, original, mimetype,
        statuscode, digest, length

        Red team uses:
        - Find old /admin, /backup, /config paths
        - Extract JS bundles from old timestamps to find API endpoints
        - Discover subdomains that existed historically
        - Find credentials/tokens in cached pages
        """
        print(f"  {Fore.BLUE}[*] Querying Wayback Machine CDX API...{Style.RESET_ALL}")
        wb = {"urls": [], "subdomains": [], "interesting_paths": [], "total_snapshots": 0}

        try:
            # Get count first
            count_url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}&output=json&fl=timestamp&limit=1&showNumPages=true"
            )
            resp = requests.get(count_url, timeout=15, headers=self.headers)
            if resp.status_code == 200 and resp.text.strip():
                try:
                    wb["total_snapshots"] = int(resp.text.strip())
                    print(f"  {Fore.GREEN}[+] Wayback: ~{wb['total_snapshots']} "
                          f"page snapshots archived{Style.RESET_ALL}")
                except ValueError:
                    pass

        except Exception:
            pass

        try:
            # Get unique subdomains from archived URLs
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
                f"&limit=200&matchType=domain"
            )
            resp = requests.get(url, timeout=20, headers=self.headers)
            if resp.status_code == 200 and resp.text.strip():
                try:
                    data = resp.json()
                    archived_urls = [row[0] for row in data[1:] if row]  # skip header
                    wb["urls"] = archived_urls[:50]

                    # Extract unique subdomains from archived URLs
                    subs = set()
                    interesting = []
                    for orig_url in archived_urls:
                        # Extract subdomain
                        m = re.match(r'https?://([^/]+)/', orig_url)
                        if m:
                            host = m.group(1).lower()
                            if host.endswith(f".{self.domain}"):
                                subs.add(host)

                        # Flag interesting paths
                        path_lower = orig_url.lower()
                        for keyword in [
                            "admin", "backup", "config", "secret", "api/v",
                            "swagger", "credentials", "token", "password",
                            ".env", ".git", "phpinfo", "debug", "test"
                        ]:
                            if keyword in path_lower:
                                interesting.append(orig_url)
                                break

                    wb["subdomains"] = list(subs)
                    wb["interesting_paths"] = interesting[:20]

                    if subs:
                        print(f"  {Fore.GREEN}[+] Wayback subdomains: "
                              f"{len(subs)} discovered{Style.RESET_ALL}")
                    if interesting:
                        print(f"  {Fore.YELLOW}[!] Interesting archived paths: "
                              f"{len(interesting)} found{Style.RESET_ALL}")
                        if self.verbose:
                            for p in interesting[:3]:
                                print(f"         → {p}")

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            result["errors"].append(f"Wayback error: {str(e)}")
            print(f"  {Fore.YELLOW}[!] Wayback query failed: {e}{Style.RESET_ALL}")

        result["wayback"] = wb

    # ── GitHub Dorking ─────────────────────────────────────────────────────

    def _github_dork(self, result: dict):
        """
        Search GitHub for sensitive information related to the domain.
        Looks for: API keys, passwords, hardcoded credentials, internal URLs.

        Uses GitHub Search API — no auth = 10 req/min, with token = 30 req/min
        """
        print(f"  {Fore.BLUE}[*] Searching GitHub for leaked secrets...{Style.RESET_ALL}")
        leaks = {"queries": [], "total_results": 0, "manual_review_urls": []}

        search_terms = [
            f'"{self.domain}" password',
            f'"{self.domain}" secret_key',
            f'"{self.domain}" api_key',
            f'"{self.domain}" access_token',
            f'"@{self.domain}"',
        ]

        headers = {**self.headers, "Accept": "application/vnd.github.v3+json"}
        github_token = ""  # Set via config if available

        if github_token:
            headers["Authorization"] = f"token {github_token}"

        for term in search_terms[:3]:  # Limit to avoid rate limiting
            try:
                resp = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": term, "per_page": 5},
                    headers=headers,
                    timeout=10
                )

                if resp.status_code == 200:
                    data = resp.json()
                    count = data.get("total_count", 0)
                    leaks["total_results"] += count

                    if count > 0:
                        query_result = {
                            "query": term,
                            "count": count,
                            "url": f"https://github.com/search?q={requests.utils.quote(term)}&type=code",
                            "sample_repos": [
                                item.get("repository", {}).get("full_name", "")
                                for item in data.get("items", [])[:3]
                            ]
                        }
                        leaks["queries"].append(query_result)
                        leaks["manual_review_urls"].append(query_result["url"])
                        print(f"  {Fore.RED}[!] GitHub leak: '{term}' → "
                              f"{count} results{Style.RESET_ALL}")
                        print(f"      Review: {query_result['url']}{Style.RESET_ALL}")

                elif resp.status_code == 403:
                    print(f"  {Fore.YELLOW}[!] GitHub rate limit — add token "
                          f"in config.py for more queries{Style.RESET_ALL}")
                    break

                time.sleep(2)  # GitHub rate limit

            except Exception as e:
                print(f"  {Fore.YELLOW}[!] GitHub search error: {e}{Style.RESET_ALL}")
                break

        if leaks["total_results"] == 0:
            print(f"  {Fore.GREEN}[+] GitHub: no obvious leaks found "
                  f"in searched queries{Style.RESET_ALL}")

        result["github_leaks"] = leaks