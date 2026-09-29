"""
SSL/TLS Certificate Analysis Module
=====================================
HOW IT WORKS:
  SSL certificates are exchanged during the TLS handshake (port 443).
  We connect using Python's ssl module and extract the certificate
  object, which contains rich metadata about the target.

  FIX (v2.1.1): Previously this module used ssl.CERT_NONE only, which
  causes ssock.getpeercert() to return an EMPTY dict {} for many real,
  valid certificates — not just self-signed ones. This produced false
  positives: certs were misreported as "expired" (not_after defaulted
  to epoch 0) and "self-signed" ({} == {} is True). The fix below tries
  CERT_OPTIONAL first (returns a fully populated cert dict for properly
  signed certs), then falls back to CERT_NONE only for genuinely
  self-signed/untrusted certs. Empty-dict results are now reported as
  "certificate could not be parsed" instead of false expired/self-signed.

RED TEAM VALUE:
  1. Expiry dates → expired/expiring certs → MITM opportunity
  2. Subject Alternative Names (SANs) → discover additional subdomains
     A wildcard cert *.example.com or a multi-SAN cert may list
     internal hostnames, staging environments, or hidden subdomains
  3. Organization / OU fields → corporate structure info
  4. Issuer → CA in use (Let's Encrypt = automated, low-cost setup)
  5. Weak protocols → TLS 1.0/1.1 deprecated, SSLv3 → POODLE attack
  6. Self-signed → no CA validation, often internal/staging servers
  7. CT Poison → see if cert is logged in public CT logs
"""

import ssl
import socket
import datetime
import hashlib
from colorama import Fore, Style


class SSLModule:
    """SSL/TLS Certificate Analysis Module."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)

    def run(self) -> dict:
        result = {
            "subject": {},
            "issuer": {},
            "valid": False,
            "expired": False,
            "self_signed": False,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "san_domains": [],
            "protocol_version": None,
            "cipher": None,
            "serial_number": None,
            "fingerprint_sha256": None,
            "wildcard": False,
            "vulnerabilities": [],
            "errors": []
        }

        print(f"  {Fore.BLUE}[*] Analyzing SSL/TLS certificate for {self.domain}...{Style.RESET_ALL}")

        # ── Pass 1: CERT_OPTIONAL — returns a populated cert dict for ──
        # ── properly-signed certificates (the common case)            ──
        cert, der_cert, cipher, tls_version, conn_error = self._connect(ssl.CERT_OPTIONAL)

        # ── Pass 2: fall back to CERT_NONE only if pass 1 gave nothing ──
        # ── (covers genuinely self-signed / untrusted internal certs)  ──
        if not cert or not cert.get("notAfter"):
            cert2, der2, cipher2, tls2, err2 = self._connect(ssl.CERT_NONE)
            if der2:
                der_cert = der2
            if cipher2:
                cipher = cipher2
            if tls2:
                tls_version = tls2
            if not conn_error:
                conn_error = err2
            if cert2 and cert2.get("notAfter"):
                cert = cert2

        if conn_error:
            result["errors"].append(conn_error)
            return result

        if not tls_version and not cipher and not der_cert:
            # Both passes failed to connect at all
            result["errors"].append("Could not establish SSL/TLS connection")
            return result

        result["protocol_version"] = tls_version
        result["cipher"] = cipher[0] if cipher else None

        # ── Parse certificate fields (only if we actually got cert data) ──
        if cert and cert.get("notAfter"):

            def _safe_cert_time(t_str):
                """Parse cert time string safely across Python/OpenSSL variants."""
                if not t_str:
                    return None
                try:
                    return ssl.cert_time_to_seconds(t_str)
                except Exception:
                    pass
                for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%b  %d %H:%M:%S %Y %Z"):
                    try:
                        return datetime.datetime.strptime(t_str, fmt).replace(
                            tzinfo=datetime.timezone.utc).timestamp()
                    except Exception:
                        continue
                return None

            not_before = _safe_cert_time(cert.get("notBefore", ""))
            not_after = _safe_cert_time(cert.get("notAfter", ""))
            now = datetime.datetime.utcnow().timestamp()

            result["not_before"] = cert.get("notBefore")
            result["not_after"] = cert.get("notAfter")

            if not_after is not None:
                result["days_remaining"] = int((not_after - now) / 86400)
                result["expired"] = now > not_after
                if not_before is not None:
                    result["valid"] = not_before <= now <= not_after

            # Subject
            subject = dict(x[0] for x in cert.get("subject", []))
            result["subject"] = subject
            print(f"  {Fore.GREEN}[+] Subject: {subject.get('commonName', 'N/A')}{Style.RESET_ALL}")

            # Issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result["issuer"] = issuer
            print(f"  {Fore.GREEN}[+] Issuer: {issuer.get('organizationName', 'N/A')}{Style.RESET_ALL}")

            # Serial number
            result["serial_number"] = cert.get("serialNumber")

            # Self-signed check — only meaningful when subject/issuer are non-empty
            if subject and issuer and subject == issuer:
                result["self_signed"] = True
                print(f"  {Fore.YELLOW}[!] Self-signed certificate detected{Style.RESET_ALL}")

            # SANs - Subject Alternative Names (key for subdomain discovery!)
            san_list = []
            for san_type, san_value in cert.get("subjectAltName", []):
                if san_type == "DNS":
                    san_list.append(san_value)
                    if san_value.startswith("*."):
                        result["wildcard"] = True
            result["san_domains"] = san_list
            print(f"  {Fore.GREEN}[+] SANs: {len(san_list)} domains in certificate{Style.RESET_ALL}")
            if self.verbose:
                for san in san_list[:10]:
                    print(f"         → {san}")

            # Expiry warnings
            if result["expired"]:
                print(f"  {Fore.RED}[!!!] CERTIFICATE EXPIRED! ({result['not_after']}){Style.RESET_ALL}")
                result["vulnerabilities"].append("Certificate expired")
            elif result["days_remaining"] is not None and result["days_remaining"] < 30:
                print(f"  {Fore.RED}[!] Certificate expiring in {result['days_remaining']} days!{Style.RESET_ALL}")
                result["vulnerabilities"].append(f"Certificate expiring in {result['days_remaining']} days")
            elif result["days_remaining"] is not None:
                print(f"  {Fore.GREEN}[+] Certificate valid for {result['days_remaining']} days{Style.RESET_ALL}")

        else:
            print(f"  {Fore.YELLOW}[!] Could not retrieve certificate details "
                  f"(server may require SNI, or connection was intercepted){Style.RESET_ALL}")
            result["errors"].append(
                "Certificate data unavailable — server returned no parsable certificate"
            )

        # ── Fingerprint (always available if we have DER bytes) ──────────
        if der_cert:
            result["fingerprint_sha256"] = hashlib.sha256(der_cert).hexdigest()

        # ── TLS Version check ─────────────────────────────────────────────
        if tls_version:
            if tls_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                result["vulnerabilities"].append(f"Deprecated TLS version: {tls_version}")
                print(f"  {Fore.RED}[!] Deprecated protocol: {tls_version}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[+] Protocol: {tls_version}{Style.RESET_ALL}")

        # ── Cipher strength ────────────────────────────────────────────────
        if cipher:
            cipher_name = cipher[0]
            if any(weak in cipher_name for weak in ["RC4", "DES", "NULL", "EXPORT", "anon"]):
                result["vulnerabilities"].append(f"Weak cipher: {cipher_name}")
                print(f"  {Fore.RED}[!] Weak cipher: {cipher_name}{Style.RESET_ALL}")

        return result

    # ── Helper ─────────────────────────────────────────────────────────────

    def _connect(self, verify_mode: int):
        """
        Open a TLS connection with the given verify_mode.
        Returns (cert_dict, der_bytes, cipher_tuple, version_str, error_str).
        error_str is set only for connection-level failures (refused, timeout,
        SSL handshake failure) — not for an empty/unparsed cert dict.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = verify_mode

            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    return cert, der_cert, cipher, tls_version, None

        except ssl.SSLError as e:
            return None, None, None, None, f"SSL error: {str(e)}"
        except ConnectionRefusedError:
            return None, None, None, None, "Port 443 closed or refused"
        except socket.timeout:
            return None, None, None, None, "Connection timed out"
        except Exception as e:
            return None, None, None, None, str(e)