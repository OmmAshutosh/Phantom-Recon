"""
Email Harvesting & OSINT Module
=================================
HOW IT WORKS:

Email discovery is critical for:
  1. Social engineering / phishing campaigns
  2. Password spraying (common pattern: first.last@domain.com)
  3. Employee enumeration → corporate hierarchy
  4. Finding technical contacts for further exploitation

METHODS:
  1. Hunter.io API - Aggregates public email mentions across the web
     Returns emails + department + confidence score + source URLs
     Free tier: 25 requests/month

  2. Certificate Transparency - SSL certs sometimes contain emails
     in the Subject Alternative Name or Organization fields

  3. DNS SOA email - Zone admin email from SOA record

  4. Web scraping - Scrape target homepage/contact pages for mailto:

  5. Pattern inference - If we find john.smith@domain.com, generate
     likely patterns: j.smith@, jsmith@, john@, smithj@, etc.

  6. Email format guessing - Common corporate formats:
     {first}.{last}@  {first_initial}{last}@  {first}@

OPSEC NOTE:
  Hunter.io and similar APIs log queries. For stealth ops,
  prefer crt.sh scraping and offline dataset queries.
"""

import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style


# Regex for email extraction from raw text/HTML
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE
)

# Obfuscation patterns used by websites to hide emails
OBFUSCATION_PATTERNS = [
    (r"\[at\]", "@"),
    (r"\s+at\s+", "@"),
    (r"\[dot\]", "."),
    (r"\s+dot\s+", "."),
    (r"&#64;", "@"),
    (r"&#46;", "."),
]


class EmailModule:
    """Email and OSINT harvesting module."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.timeout = config.get("timeout", 8)
        self.verbose = config.get("verbose", False)
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }
        self._emails = {}  # email → metadata

    def run(self) -> list:
        print(f"  {Fore.BLUE}[*] Starting email harvesting for: {self.domain}{Style.RESET_ALL}")

        # Method 1: Hunter.io (no API key needed for basic)
        self._hunter_io()

        # Method 2: Web scraping target site
        self._scrape_website()

        # Method 3: Search engine dorks simulation via requests
        self._search_engine_harvest()

        # Method 4: GitHub code search
        self._github_search()

        # Method 5: infer pattern if we have enough samples
        patterns = self._infer_email_patterns()

        results = list(self._emails.values())
        results_clean = sorted(set(r["email"] for r in results))

        output = []
        for email in results_clean:
            data = self._emails.get(email, {})
            output.append({
                "email": email,
                "sources": data.get("sources", []),
                "confidence": data.get("confidence", "low"),
                "department": data.get("department", None),
                "name": data.get("name", None),
                "position": data.get("position", None),
            })

        print(f"\n  {Fore.GREEN}[+] Total unique emails found: {len(output)}{Style.RESET_ALL}")
        if patterns:
            print(f"  {Fore.YELLOW}[*] Likely email format: {patterns[0]}{Style.RESET_ALL}")

        output.append({
            "_meta": "email_patterns",
            "patterns": patterns
        })
        return output

    def _add_email(self, email: str, source: str, confidence: str = "medium",
                   department: str = None, name: str = None, position: str = None):
        """Add an email to the found set."""
        email = email.lower().strip()
        # Validate domain match
        if not email.endswith(f"@{self.domain}"):
            # still keep for correlations but mark as external
            pass
        if email not in self._emails:
            self._emails[email] = {
                "email": email,
                "sources": [source],
                "confidence": confidence,
                "department": department,
                "name": name,
                "position": position,
                "on_target_domain": email.endswith(f"@{self.domain}"),
            }
            if self.verbose:
                print(f"  {Fore.GREEN}    [+] {email} ({source}){Style.RESET_ALL}")
        else:
            if source not in self._emails[email]["sources"]:
                self._emails[email]["sources"].append(source)

    def _get_with_retry(self, url: str, timeout: int, headers: dict = None,
                        retries: int = 1, backoff: float = 1.5):
        """
        GET a URL with one automatic retry on timeout/connection failure.

        Third-party services like web.archive.org occasionally time out
        under load — a single retry after a short backoff clears most of
        these transient failures without slowing down the common case
        (first attempt succeeds) or masking a genuinely dead service
        (still raises after the retry is exhausted).
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

    def _hunter_io(self):
        """
        Query Hunter.io domain search (no API key needed for initial results).
        Hunter.io scrapes the web and indexes emails by domain.
        """
        print(f"  {Fore.BLUE}[*] Querying Hunter.io...{Style.RESET_ALL}")
        try:
            # Public endpoint (limited results without key)
            url = f"https://hunter.io/search/{self.domain}"
            resp = requests.get(url, timeout=self.timeout, headers=self.headers)
            if resp.status_code == 200:
                # Extract any emails from the page HTML
                emails_found = self._extract_emails_from_text(resp.text)
                for email in emails_found:
                    if f"@{self.domain}" in email:
                        self._add_email(email, "hunter.io", confidence="high")
                print(f"  {Fore.GREEN}[+] Hunter.io: {len(emails_found)} emails in page{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Hunter.io query failed: {e}{Style.RESET_ALL}")

    def _scrape_website(self):
        """Scrape target website pages for email addresses."""
        print(f"  {Fore.BLUE}[*] Scraping target website for emails...{Style.RESET_ALL}")
        pages_to_scrape = [
            f"https://{self.domain}",
            f"https://{self.domain}/about",
            f"https://{self.domain}/contact",
            f"https://{self.domain}/team",
            f"https://{self.domain}/careers",
            f"https://{self.domain}/jobs",
            f"https://{self.domain}/staff",
            f"https://www.{self.domain}",
        ]

        scraped_count = 0
        all_emails = set()
        for url in pages_to_scrape:
            try:
                resp = requests.get(url, timeout=self.timeout,
                                    headers=self.headers, allow_redirects=True)
                if resp.status_code == 200:
                    text = resp.text
                    # Apply deobfuscation
                    for pattern, replacement in OBFUSCATION_PATTERNS:
                        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
                    emails = self._extract_emails_from_text(text)
                    for email in emails:
                        if f"@{self.domain}" in email and email not in all_emails:
                            all_emails.add(email)
                            self._add_email(email, f"website:{url}", confidence="high")
                    scraped_count += 1
            except Exception:
                pass

        print(f"  {Fore.GREEN}[+] Website scrape: {len(all_emails)} emails "
              f"from {scraped_count} pages{Style.RESET_ALL}")

    def _search_engine_harvest(self):
        """
        Harvest emails using search engine dork results.
        In a real deployment, use SerpAPI or similar for automated querying.
        Here we query publicly accessible JSON endpoints.
        """
        print(f"  {Fore.BLUE}[*] OSINT search engine harvesting...{Style.RESET_ALL}")

        # Check CommonCrawl index for the domain
        try:
            url = (f"http://index.commoncrawl.org/CC-MAIN-2024-10-index"
                   f"?url=*.{self.domain}&output=json&fl=url&limit=100")
            resp = requests.get(url, timeout=10, headers=self.headers)
            if resp.status_code == 200:
                lines = resp.text.strip().split("\n")
                urls_found = len([l for l in lines if l.strip()])
                print(f"  {Fore.GREEN}[+] CommonCrawl: {urls_found} archived URLs found{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] CommonCrawl query failed: {e}{Style.RESET_ALL}")

        # Check Wayback Machine for email patterns
        # (retry-once-with-backoff: web.archive.org occasionally times out
        # under load — one retry clears most transient failures)
        try:
            url = (f"http://web.archive.org/cdx/search/cdx"
                   f"?url=*.{self.domain}/contact&output=text&fl=original&limit=5")
            resp = self._get_with_retry(url, timeout=10, headers=self.headers)
            if resp.status_code == 200 and resp.text.strip():
                archived_urls = resp.text.strip().split("\n")
                print(f"  {Fore.GREEN}[+] Wayback Machine: {len(archived_urls)} "
                      f"contact-page snapshots found{Style.RESET_ALL}")
                # Could fetch and scrape archived pages
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] Wayback query failed after retry: {e}{Style.RESET_ALL}")

    def _github_search(self):
        """
        Search GitHub for emails accidentally committed.
        Uses public GitHub search API (no auth for basic queries).
        """
        print(f"  {Fore.BLUE}[*] Searching GitHub for leaked emails...{Style.RESET_ALL}")
        try:
            search_terms = [
                f"@{self.domain}",
                f'"{self.domain}" password',
                f'"{self.domain}" secret',
                f'"{self.domain}" api_key',
            ]
            found_items = 0
            for term in search_terms[:1]:  # Rate limit: 1 query
                url = (f"https://api.github.com/search/code"
                       f"?q={requests.utils.quote(term)}&per_page=10")
                resp = requests.get(url, timeout=10, headers={
                    **self.headers,
                    "Accept": "application/vnd.github.v3+json"
                })
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    if total > 0:
                        print(f"  {Fore.RED}[!] GitHub: {total} code results for '{term}'{Style.RESET_ALL}")
                        print(f"      Manual review: https://github.com/search?q={requests.utils.quote(term)}&type=code")
                    found_items += total
                elif resp.status_code == 403:
                    print(f"  {Fore.YELLOW}[!] GitHub rate limit reached (use token for more){Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.YELLOW}[!] GitHub search error: {e}{Style.RESET_ALL}")

    def _infer_email_patterns(self) -> list:
        """
        Infer email naming conventions from discovered emails.
        E.g., if john.doe@example.com and jane.smith@example.com are found,
        pattern is likely {first}.{last}@domain
        """
        domain_emails = [
            e["email"] for e in self._emails.values()
            if e.get("on_target_domain")
        ]

        patterns = []
        if len(domain_emails) >= 2:
            for email in domain_emails[:5]:
                local = email.split("@")[0]
                if "." in local:
                    parts = local.split(".")
                    if len(parts) == 2 and all(p.isalpha() for p in parts):
                        patterns.append("{first}.{last}@" + self.domain)
                elif len(local) > 5 and local.isalpha():
                    patterns.append("{first}{last}@" + self.domain)
                elif len(local) <= 6 and local.isalpha():
                    patterns.append("{first_initial}{last}@" + self.domain)

        return list(dict.fromkeys(patterns))  # deduplicate preserving order

    def _extract_emails_from_text(self, text: str) -> list:
        """Extract all email addresses from raw text or HTML."""
        return list(set(EMAIL_REGEX.findall(text)))