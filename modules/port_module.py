"""
Port Scanning Module (Active Reconnaissance)
=============================================
HOW IT WORKS:
  Port scanning is ACTIVE reconnaissance - we send packets to the target.
  Always obtain written authorization before running this module.

  TCP CONNECT SCAN (what we use):
  - Full TCP 3-way handshake (SYN → SYN-ACK → ACK)
  - Clean connection, easy to detect/log
  - Reliable: open = connection succeeds, closed = RST received
  - Uses Python socket library (no root required)

  BANNER GRABBING:
  After connecting to an open port, send a probe string and read
  the response. Services often identify themselves:
  SSH-2.0-OpenSSH_8.4
  220 mail.example.com ESMTP Postfix
  HTTP/1.1 200 OK\r\nServer: Apache/2.4.41

RED TEAM TARGETS (by port):
  22  SSH   → Password spraying, key reuse, old versions
  25  SMTP  → Open relay check, user enumeration (VRFY/EXPN)
  80/443 HTTP/S → Web application attacks
  445 SMB  → EternalBlue (MS17-010), password spraying
  3389 RDP → BlueKeep, brute force, MFA bypass
  5985/5986 WinRM → PowerShell remoting, lateral movement
  3306 MySQL/5432 Postgres → DB exposure, default creds
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 465, 587, 993, 995, 1080, 1433, 1521,
    2375, 2376, 3306, 3389, 4443, 5432, 5900, 5985, 5986,
    6379, 7001, 7443, 8080, 8081, 8443, 8888, 9000,
    9200, 9300, 10000, 27017, 28017, 50070,
]

SERVICE_PROBES = {
    80: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    25: b"EHLO phantom.recon\r\n",
    21: b"",
    22: b"",
    3306: b"",
    6379: b"*1\r\n$4\r\nPING\r\n",
    9200: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
}

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
    139: "NetBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle-DB", 2375: "Docker-API",
    2376: "Docker-TLS", 3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 7001: "WebLogic",
    7443: "HTTPS-Alt2", 8080: "HTTP-Alt", 8081: "HTTP-Alt2",
    8443: "HTTPS-Alt3", 8888: "Jupyter/Alt", 9000: "SonarQube/PHP-FPM",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    10000: "Webmin", 27017: "MongoDB", 28017: "MongoDB-HTTP",
    50070: "Hadoop-HDFS",
}


class PortModule:
    """Active TCP port scanner with banner grabbing."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.threads = config.get("threads", 20)
        self.timeout = config.get("timeout", 2)
        self.verbose = config.get("verbose", False)

    def run(self) -> list:
        print(f"  {Fore.BLUE}[*] Resolving target IP addresses...{Style.RESET_ALL}")

        # Resolve target IPs
        try:
            target_ips = list(set(r[4][0] for r in socket.getaddrinfo(self.domain, None)))
        except Exception as e:
            print(f"  {Fore.RED}[-] DNS resolution failed: {e}{Style.RESET_ALL}")
            return []

        print(f"  {Fore.BLUE}[*] Scanning {len(target_ips)} IPs, "
              f"{len(TOP_PORTS)} ports each ({self.threads} threads)...{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[!] Active scan - ensure you have authorization!{Style.RESET_ALL}\n")

        all_results = []
        for ip in target_ips[:3]:  # Limit to 3 IPs
            print(f"  {Fore.BLUE}[*] Scanning {ip}...{Style.RESET_ALL}")
            results = self._scan_ip(ip)
            open_count = len([r for r in results if r["state"] == "open"])
            print(f"  {Fore.GREEN}[+] {ip}: {open_count}/{len(TOP_PORTS)} ports open{Style.RESET_ALL}")
            all_results.extend(results)

        # Print open ports table
        open_ports = [r for r in all_results if r["state"] == "open"]
        if open_ports:
            print(f"\n  {Fore.YELLOW}OPEN PORTS SUMMARY:")
            print(f"  {'─'*55}")
            print(f"  {'IP':<18} {'PORT':<8} {'SERVICE':<20} {'BANNER':<20}")
            print(f"  {'─'*55}")
            for port_info in sorted(open_ports, key=lambda x: x["port"]):
                banner_short = (port_info.get("banner") or "")[:20]
                print(f"  {Fore.GREEN}{port_info['ip']:<18} "
                      f"{port_info['port']:<8} "
                      f"{port_info['service']:<20} "
                      f"{banner_short}{Style.RESET_ALL}")

        return all_results

    def _scan_ip(self, ip: str) -> list:
        """Scan all TOP_PORTS on a single IP."""
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port): port
                for port in TOP_PORTS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        return results

    def _scan_port(self, ip: str, port: int) -> dict:
        """Attempt TCP connection to a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                code = s.connect_ex((ip, port))
                if code == 0:
                    banner = self._grab_banner(ip, port)
                    service = PORT_SERVICE_MAP.get(port, "unknown")
                    if self.verbose:
                        print(f"  {Fore.GREEN}    OPEN: {ip}:{port} ({service}){Style.RESET_ALL}")
                    return {
                        "ip": ip,
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                        "risk": self._assess_port_risk(port),
                    }
                else:
                    return {"ip": ip, "port": port, "state": "closed",
                            "service": PORT_SERVICE_MAP.get(port, "unknown")}
        except Exception:
            return {"ip": ip, "port": port, "state": "error",
                    "service": PORT_SERVICE_MAP.get(port, "unknown")}

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> str | None:
        """Try to grab service banner."""
        try:
            probe = SERVICE_PROBES.get(port, b"")
            if isinstance(probe, bytes) and b"{host}" in probe:
                probe = probe.replace(b"{host}", self.domain.encode())

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                if probe:
                    s.send(probe)
                data = s.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
                return banner[:200] if banner else None
        except Exception:
            return None

    def _assess_port_risk(self, port: int) -> str:
        risk_map = {
            23: "CRITICAL",  # Telnet - unencrypted
            2375: "CRITICAL",  # Docker API - unauthenticated
            6379: "HIGH",    # Redis - often no auth
            9200: "HIGH",    # Elasticsearch - often no auth
            27017: "HIGH",   # MongoDB - often no auth
            3389: "HIGH",    # RDP - brute force target
            5900: "HIGH",    # VNC - often weak auth
            21: "MEDIUM",    # FTP - plaintext
            1521: "MEDIUM",  # Oracle DB
            1433: "MEDIUM",  # MSSQL
            3306: "MEDIUM",  # MySQL
            5432: "MEDIUM",  # PostgreSQL
            8888: "MEDIUM",  # Jupyter Notebook
        }
        return risk_map.get(port, "LOW")
