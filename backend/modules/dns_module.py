"""
DNS Module - Comprehensive DNS Record Enumeration
==================================================
HOW IT WORKS:
  DNS (Domain Name System) maps names to resources. Each record TYPE
  reveals different infrastructure details. We query the authoritative
  nameserver chain using dnspython which implements the DNS wire protocol
  directly (UDP/TCP port 53).

RECORD TYPES AND RED TEAM SIGNIFICANCE:
  A      → IPv4 address. Direct attack target IPs.
  AAAA   → IPv6 address. Often overlooked in firewall rules.
  MX     → Mail servers. Target for phishing/mail relay abuse.
  NS     → Nameservers. DNS zone transfer attempts, NS takeover.
  TXT    → SPF, DKIM, DMARC, verification tokens, API keys leaked.
  SOA    → Zone admin email, serial number (reveals update frequency).
  CNAME  → Alias chains. Subdomain takeover via dangling CNAMEs.
  SRV    → Service discovery (VoIP, Kubernetes, LDAP, etc.)
  CAA    → Certificate Authority restriction (fingerprinting).
  PTR    → Reverse DNS. Internal naming conventions leak.

ZONE TRANSFER (AXFR):
  If zone transfer is misconfigured, a single query dumps ALL DNS
  records for the entire domain. A goldmine for attackers.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
from colorama import Fore, Style


class DNSModule:
    """DNS Enumeration Module with zone transfer attempt."""

    RECORD_TYPES = [
        "A", "AAAA", "MX", "NS", "TXT", "SOA",
        "CNAME", "SRV", "CAA", "PTR", "DNSKEY", "DS"
    ]

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.timeout = config.get("timeout", 5)
        self.verbose = config.get("verbose", False)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2

    def run(self) -> dict:
        result = {
            "records": {},
            "zone_transfer": {"attempted": False, "success": False, "records": []},
            "spf": None,
            "dmarc": None,
            "dkim_selectors": [],
            "mail_servers": [],
            "nameservers": [],
            "soa_email": None,
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "interesting_txt": [],
            "cname_chains": {},
            "errors": []
        }

        # ── Standard Record Queries ──────────────────────────────────
        for rtype in self.RECORD_TYPES:
            records = self._query(rtype)
            if records:
                result["records"][rtype] = records
                print(f"  {Fore.GREEN}[+] {rtype:8s} : {len(records)} record(s){Style.RESET_ALL}")
                if self.verbose:
                    for r in records[:3]:
                        print(f"         → {r}")

        # ── Parse specific records ────────────────────────────────────
        self._parse_a_records(result)
        self._parse_mx_records(result)
        self._parse_ns_records(result)
        self._parse_txt_records(result)
        self._parse_soa_records(result)

        # ── Zone Transfer Attempt (AXFR) ─────────────────────────────
        self._attempt_zone_transfer(result)

        # ── DMARC Check ──────────────────────────────────────────────
        self._check_dmarc(result)

        # ── Common DKIM Selectors ────────────────────────────────────
        self._check_dkim(result)

        return result

    def _query(self, rtype: str) -> list:
        """Query a single record type, return list of string answers."""
        try:
            answers = self.resolver.resolve(self.domain, rtype)
            return [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception as e:
            return []

    def _parse_a_records(self, result: dict):
        ips = result["records"].get("A", [])
        result["ipv4_addresses"] = ips
        aaaaips = result["records"].get("AAAA", [])
        result["ipv6_addresses"] = aaaaips

    def _parse_mx_records(self, result: dict):
        mx_records = result["records"].get("MX", [])
        mail_servers = []
        for r in mx_records:
            parts = r.split()
            if len(parts) == 2:
                mail_servers.append({"priority": parts[0], "host": parts[1].rstrip(".")})
            else:
                mail_servers.append({"priority": "?", "host": r.rstrip(".")})
        result["mail_servers"] = mail_servers
        if mail_servers:
            print(f"  {Fore.YELLOW}[!] Mail servers found: "
                  f"{', '.join(m['host'] for m in mail_servers)}{Style.RESET_ALL}")

    def _parse_ns_records(self, result: dict):
        ns_records = result["records"].get("NS", [])
        result["nameservers"] = [ns.rstrip(".") for ns in ns_records]

    def _parse_txt_records(self, result: dict):
        txt_records = result["records"].get("TXT", [])
        interesting = []
        for txt in txt_records:
            txt_lower = txt.lower()
            if "v=spf1" in txt_lower:
                result["spf"] = txt
                print(f"  {Fore.BLUE}[*] SPF: {txt[:80]}...{Style.RESET_ALL}")
                # Check for SPF weaknesses
                if "+all" in txt:
                    print(f"  {Fore.RED}[!] CRITICAL: SPF uses +all (allows anyone to send!){Style.RESET_ALL}")
                elif "~all" in txt:
                    print(f"  {Fore.YELLOW}[!] SPF uses ~all (softfail, weak policy){Style.RESET_ALL}")
            # Look for interesting TXT records
            for keyword in ["atlassian", "google-site", "stripe", "twilio",
                            "sendgrid", "mailchimp", "docusign", "microsoft",
                            "ahrefs", "hubspot", "verification", "token"]:
                if keyword in txt_lower:
                    interesting.append(txt)
                    break
        result["interesting_txt"] = interesting

    def _parse_soa_records(self, result: dict):
        soa_records = result["records"].get("SOA", [])
        if soa_records:
            parts = soa_records[0].split()
            if len(parts) >= 2:
                # SOA email is in format: admin.example.com → admin@example.com
                email_raw = parts[1].rstrip(".")
                result["soa_email"] = email_raw.replace(".", "@", 1) if "." in email_raw else email_raw
                print(f"  {Fore.YELLOW}[!] SOA Admin Email: {result['soa_email']}{Style.RESET_ALL}")

    def _attempt_zone_transfer(self, result: dict):
        """
        AXFR Zone Transfer Attack:
        If a nameserver is misconfigured to allow ANY client to request
        a full zone transfer, we get ALL DNS records at once.
        This is a critical misconfiguration (high/critical finding).
        """
        result["zone_transfer"]["attempted"] = True
        nameservers = result.get("nameservers", [])
        if not nameservers:
            # Try to get NS from records
            nameservers = self._query("NS")

        print(f"  {Fore.BLUE}[*] Attempting zone transfer (AXFR) against {len(nameservers)} NS...{Style.RESET_ALL}")

        for ns in nameservers[:3]:
            try:
                ns_ip = socket.gethostbyname(ns.rstrip("."))
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10))
                records = []
                for name, node in z.nodes.items():
                    rdatasets = node.rdatasets
                    for rdataset in rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name} {rdataset.rdtype} {rdata}")
                result["zone_transfer"]["success"] = True
                result["zone_transfer"]["records"] = records[:200]
                print(f"  {Fore.RED}[!!!] ZONE TRANSFER SUCCESSFUL via {ns}!{Style.RESET_ALL}")
                print(f"  {Fore.RED}      Retrieved {len(records)} records - CRITICAL misconfiguration!{Style.RESET_ALL}")
                break
            except Exception:
                pass

        if not result["zone_transfer"]["success"]:
            print(f"  {Fore.GREEN}[+] Zone transfer refused (properly configured){Style.RESET_ALL}")

    def _check_dmarc(self, result: dict):
        """Check for DMARC policy at _dmarc.<domain>"""
        try:
            answers = self.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            for answer in answers:
                txt = str(answer)
                if "v=DMARC1" in txt:
                    result["dmarc"] = txt
                    if "p=none" in txt:
                        print(f"  {Fore.YELLOW}[!] DMARC policy is 'none' (monitoring only, weak!){Style.RESET_ALL}")
                    elif "p=quarantine" in txt:
                        print(f"  {Fore.BLUE}[*] DMARC policy is 'quarantine'{Style.RESET_ALL}")
                    elif "p=reject" in txt:
                        print(f"  {Fore.GREEN}[+] DMARC policy is 'reject' (strong){Style.RESET_ALL}")
        except Exception:
            result["dmarc"] = None
            print(f"  {Fore.YELLOW}[!] No DMARC record found - phishing risk!{Style.RESET_ALL}")

    def _check_dkim(self, result: dict):
        """Check common DKIM selector names."""
        common_selectors = [
            "default", "google", "mail", "dkim", "k1", "k2",
            "selector1", "selector2", "email", "smtp", "mxvault",
            "mandrill", "mailchimp", "sendgrid", "postfix", "s1", "s2"
        ]
        found = []
        for sel in common_selectors:
            try:
                ans = self.resolver.resolve(f"{sel}._domainkey.{self.domain}", "TXT")
                if ans:
                    found.append(sel)
                    if self.verbose:
                        print(f"  {Fore.GREEN}[+] DKIM selector found: {sel}{Style.RESET_ALL}")
            except Exception:
                pass
        result["dkim_selectors"] = found
        if found:
            print(f"  {Fore.GREEN}[+] DKIM selectors: {', '.join(found)}{Style.RESET_ALL}")
