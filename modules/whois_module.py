"""
WHOIS Module - Passive Domain Intelligence
==========================================
HOW IT WORKS:
  whois (Who Is) queries a distributed database of domain registration
  records maintained by ICANN registries. Each TLD has a designated
  WHOIS server. The query goes: client → IANA root WHOIS → TLD WHOIS
  → registrar WHOIS → returns structured text with registrant info.

RED TEAM VALUE:
  - Org name / registrant reveals corporate hierarchy
  - Registration dates reveal when targets acquired assets
  - Nameservers reveal DNS hosting infrastructure
  - Expiring domains can be hijacked (domain takeover)
  - Privacy protection gaps expose employee emails/phones

TOOL: python-whois library wraps the whois protocol (port 43, TCP)
"""

from unittest import result

import whois
import socket
import re
import json
from datetime import datetime
from colorama import Fore, Style


class WhoisModule:
    """
    WHOIS Enumeration Module.

    Queries domain registration data including:
    - Registrant organization, email, phone
    - Registrar name and IANA ID
    - Registration, update, and expiration dates
    - Name servers (important for DNS hijacking research)
    - Domain status codes (clientTransferProhibited, etc.)
    - IP resolution and reverse DNS
    """

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.timeout = config.get("timeout", 5)
        self.verbose = config.get("verbose", False)

    def run(self) -> dict:
        result = {
            "domain": self.domain,
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "days_until_expiry": None,
            "status": [],
            "nameservers": [],
            "registrant_name": None,
            "registrant_org": None,
            "registrant_email": None,
            "registrant_country": None,
            "admin_email": None,
            "tech_email": None,
            "dnssec": None,
            "raw": None,
            "ips": [],
            "reverse_dns": {},
            "errors": []
        }

        # ── WHOIS Query ─────────────────────────────────────────────
        print(f"  {Fore.BLUE}[*] Querying WHOIS database for: {self.domain}{Style.RESET_ALL}")
        try:
            w = whois.whois(self.domain)

            result["registrar"] = str(w.registrar) if w.registrar else None
            result["registrar_url"] = str(w.referral_url) if hasattr(w, "referral_url") and w.referral_url else None
            result["dnssec"] = str(w.dnssec) if hasattr(w, "dnssec") else None

            # Dates (whois may return list or single value)
            def _first(val):
                if isinstance(val, list):
                    return val[0]
                return val

            creation = _first(w.creation_date)
            expiration = _first(w.expiration_date)
            updated = _first(w.updated_date)

            result["creation_date"] = str(creation) if creation else None
            result["expiration_date"] = str(expiration) if expiration else None
            result["updated_date"] = str(updated) if updated else None

            # Days until expiry
            from datetime import datetime, timezone
            if expiration and isinstance(expiration, datetime):

                # Make both datetime objects timezone-aware
                if expiration.tzinfo is None:
                    expiration = expiration.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)

                delta = expiration - now
                result["days_until_expiry"] = delta.days

            # Status codes
            status = w.status or []
            if isinstance(status, str):
                status = [status]
            result["status"] = status

            # Nameservers
            ns = w.name_servers or []
            if isinstance(ns, str):
                ns = [ns]
            result["nameservers"] = [str(n).lower() for n in ns]

            # Registrant info (may be hidden behind privacy protection)
            result["registrant_name"] = str(w.name) if w.name else None
            result["registrant_org"] = str(w.org) if w.org else None
            result["registrant_country"] = str(w.country) if w.country else None
            result["registrant_email"] = str(w.emails[0]) if (
                hasattr(w, "emails") and w.emails
            ) else None
            result["raw"] = str(w.text)[:3000] if w.text else None

            print(f"  {Fore.GREEN}[+] Registrar: {result['registrar']}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}[+] Created: {result['creation_date']}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}[+] Expires: {result['expiration_date']} "
                  f"({result['days_until_expiry']} days){Style.RESET_ALL}")

            if result["days_until_expiry"] and result["days_until_expiry"] < 30:
                print(f"  {Fore.RED}[!] DOMAIN EXPIRING SOON - potential takeover opportunity!{Style.RESET_ALL}")

            print(f"  {Fore.GREEN}[+] Nameservers: {', '.join(result['nameservers'][:4])}{Style.RESET_ALL}")

        except Exception as e:
            result["errors"].append(f"WHOIS query failed: {str(e)}")
            print(f"  {Fore.RED}[-] WHOIS error: {e}{Style.RESET_ALL}")

        # ── IP Resolution ────────────────────────────────────────────
        print(f"  {Fore.BLUE}[*] Resolving IP addresses...{Style.RESET_ALL}")
        try:
            ips = list(set(r[4][0] for r in socket.getaddrinfo(self.domain, None)))
            result["ips"] = ips
            for ip in ips:
                print(f"  {Fore.GREEN}[+] Resolved: {ip}{Style.RESET_ALL}")
                try:
                    rdns = socket.gethostbyaddr(ip)[0]
                    result["reverse_dns"][ip] = rdns
                    print(f"  {Fore.GREEN}    ↳ Reverse DNS: {rdns}{Style.RESET_ALL}")
                except Exception:
                    result["reverse_dns"][ip] = None
        except Exception as e:
            result["errors"].append(f"IP resolution failed: {str(e)}")

        return result
