"""
Port Scanning Module (Active Reconnaissance & Service Fingerprinting)
====================================================================
HOW IT WORKS:
  Port scanning is ACTIVE reconnaissance - we send packets to the target.
  Always obtain written authorization before running this module.

  SCANNING STRATEGY:
  1. Native Nmap Engine (High accuracy & stealth):
     - If Nmap binary is detected on the host (Linux, Docker, or Windows),
       runs unprivileged TCP Connect Scan (-sT -T4 -Pn) against target ports.
     - Parses structured XML results for 100% parity with Nmap CLI.
  2. Multi-threaded TCP Socket Scanner (Built-in engine):
     - Fallback when Nmap is not present.
     - Concurrent TCP socket connections with adaptive timeout & retries.
  3. OSINT Port Cross-Validation (Cloud Egress Resilience):
     - Passive Shodan InternetDB intelligence cross-reference.
     - Detects open ports that might be dropped by cloud provider outbound
       firewalls (e.g. cloud host blocking outbound port 22 or 5060).
  4. Banner Grabbing:
     - Grabs service identification banners for all discovered open ports.
"""

import os
import socket
import shutil
import subprocess
import json
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 113, 135, 139, 143,
    443, 445, 465, 587, 993, 995, 1080, 1433, 1521,
    2000, 2375, 2376, 3000, 3306, 3389, 4443, 5000, 5060,
    5432, 5900, 5985, 5986, 6379, 7001, 7443, 8000, 8008,
    8080, 8081, 8443, 8880, 8888, 9000, 9200, 9300, 9929,
    10000, 10443, 27017, 28017, 31337, 50070,
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
    80: "HTTP", 110: "POP3", 111: "RPC", 113: "ident", 135: "MSRPC",
    139: "NetBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle-DB", 2000: "Cisco-SCCP",
    2375: "Docker-API", 2376: "Docker-TLS", 3000: "NodeJS/Dev",
    3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt", 5000: "Flask/UPnP",
    5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS", 6379: "Redis", 7001: "WebLogic",
    7443: "HTTPS-Alt2", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Alt", 8081: "HTTP-Alt2", 8443: "HTTPS-Alt3",
    8880: "HTTP-Alt", 8888: "Jupyter/Alt", 9000: "SonarQube/PHP-FPM",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    9929: "NPing-Echo", 10000: "Webmin", 10443: "HTTPS-Alt",
    27017: "MongoDB", 28017: "MongoDB-HTTP", 31337: "Elite",
    50070: "Hadoop-HDFS",
}


def _find_nmap_binary() -> str | None:
    """Locate Nmap executable on system across Linux and Windows."""
    candidates = [
        "nmap",
        "nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]
    for c in candidates:
        found = shutil.which(c) or (os.path.isfile(c) and c)
        if found:
            return str(found)
    return None


class PortModule:
    """Active TCP port scanner with Nmap integration, fallback sockets, and banner grabbing."""

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.threads = config.get("threads", 30)
        self.timeout = config.get("timeout", 3.0)
        self.verbose = config.get("verbose", False)
        self.nmap_bin = _find_nmap_binary()

    def run(self) -> list:
        print(f"  {Fore.BLUE}[*] Resolving target IP addresses...{Style.RESET_ALL}")

        # Resolve target IPs (force IPv4 for standard TCP socket probing)
        try:
            target_ips = list(set(r[4][0] for r in socket.getaddrinfo(self.domain, None, socket.AF_INET)))
        except Exception as e:
            print(f"  {Fore.RED}[-] DNS resolution failed: {e}{Style.RESET_ALL}")
            return []

        scanner_engine = "Nmap Engine" if self.nmap_bin else "Multi-threaded Socket Scanner"
        print(f"  {Fore.BLUE}[*] Scanning {len(target_ips)} IPs, "
              f"{len(TOP_PORTS)} ports each using {scanner_engine}...{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[!] Active scan - ensure you have authorization!{Style.RESET_ALL}\n")

        all_results = []
        for ip in target_ips[:3]:  # Limit to 3 IPs
            print(f"  {Fore.BLUE}[*] Scanning {ip}...{Style.RESET_ALL}")
            results = self._scan_ip(ip)
            open_count = len([r for r in results if r["state"] == "open"])
            print(f"  {Fore.GREEN}[+] {ip}: {open_count} open port(s) discovered{Style.RESET_ALL}")
            all_results.extend(results)

        # Print open ports table safely (without crashing on Windows stdout encoding)
        try:
            open_ports = [r for r in all_results if r["state"] == "open"]
            if open_ports:
                print(f"\n  {Fore.YELLOW}OPEN PORTS SUMMARY:")
                print(f"  {'-'*65}")
                print(f"  {'IP':<18} {'PORT':<8} {'SERVICE':<18} {'BANNER':<20}")
                print(f"  {'-'*65}")
                for port_info in sorted(open_ports, key=lambda x: x["port"]):
                    banner_short = (port_info.get("banner") or "")[:20]
                    print(f"  {Fore.GREEN}{port_info['ip']:<18} "
                          f"{port_info['port']:<8} "
                          f"{port_info['service']:<18} "
                          f"{banner_short}{Style.RESET_ALL}")
        except Exception:
            pass

        return all_results

    def _scan_ip(self, ip: str) -> list:
        """Scan target IP using Nmap if available, otherwise native sockets + InternetDB."""
        results = None

        # 1. Primary: Run native Nmap if available
        if self.nmap_bin:
            results = self._scan_with_nmap(ip)

        # 2. Fallback: Run multi-threaded socket scanner if Nmap missing or failed
        if not results:
            results = self._scan_with_sockets(ip)

        # 3. Cross-validate with Shodan InternetDB to ensure cloud egress firewalls
        # (e.g. Railway blocking outbound ports 22/5060) do not suppress open ports
        try:
            intel_ports = self._query_internetdb(ip)
            for p_num in intel_ports:
                existing = next((r for r in results if r["port"] == p_num), None)
                service = PORT_SERVICE_MAP.get(p_num, "unknown")
                if existing:
                    if existing["state"] != "open":
                        existing["state"] = "open"
                        if not existing.get("banner"):
                            existing["banner"] = f"{service} active (Verified via InternetDB)"
                else:
                    results.append({
                        "ip": ip,
                        "port": p_num,
                        "state": "open",
                        "service": service,
                        "banner": f"{service} active (Verified via InternetDB)",
                        "risk": self._assess_port_risk(p_num),
                    })
        except Exception:
            pass

        # Sort so all open ports are prioritized at the top, then by port number
        results.sort(key=lambda x: (0 if x["state"] == "open" else 1, x["port"]))
        return results

    def _scan_with_nmap(self, ip: str) -> list | None:
        """Execute Nmap TCP connect scan and parse XML output."""
        ports_arg = ",".join(str(p) for p in TOP_PORTS)
        cmd = [self.nmap_bin, "-sT", "-T4", "-Pn", "-p", ports_arg, "-oX", "-", ip]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if proc.returncode != 0 or "<nmaprun" not in proc.stdout:
                return None

            root = ET.fromstring(proc.stdout)
            discovered = {}
            for port_elem in root.findall(".//port"):
                p_id = int(port_elem.attrib.get("portid"))
                state = port_elem.find("state").attrib.get("state", "closed")
                s_elem = port_elem.find("service")
                s_name = s_elem.attrib.get("name") if s_elem is not None else PORT_SERVICE_MAP.get(p_id, "unknown")
                discovered[p_id] = {
                    "ip": ip,
                    "port": p_id,
                    "state": state,
                    "service": s_name,
                    "banner": None,
                    "risk": self._assess_port_risk(p_id),
                }

            # Attempt banner grabbing for open ports
            for p_id, info in discovered.items():
                if info["state"] == "open":
                    info["banner"] = self._grab_banner(ip, p_id, timeout=1.5)

            # Ensure all TOP_PORTS are represented in results
            results = []
            for p in TOP_PORTS:
                if p in discovered:
                    results.append(discovered[p])
                else:
                    results.append({
                        "ip": ip,
                        "port": p,
                        "state": "closed",
                        "service": PORT_SERVICE_MAP.get(p, "unknown"),
                        "banner": None,
                        "risk": self._assess_port_risk(p),
                    })

            return results
        except Exception:
            return None

    def _scan_with_sockets(self, ip: str) -> list:
        """Scan all TOP_PORTS on a single IP using multi-threaded TCP sockets."""
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

        # Retry closed ports that are commonly rate-limited or sensitive
        closed_important = [r for r in results if r["state"] != "open" and r["port"] in (22, 80, 443, 2000, 3389, 5060, 8080)]
        for item in closed_important:
            retried = self._scan_port(ip, item["port"], retry_timeout=3.5)
            if retried["state"] == "open":
                item["state"] = "open"
                item["banner"] = retried.get("banner")

        return results

    def _query_internetdb(self, ip: str) -> list:
        """Query free Shodan InternetDB API for verified open ports with standard browser UA."""
        try:
            req = urllib.request.Request(
                f"https://internetdb.shodan.io/{ip}",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                return data.get("ports", [])
        except Exception:
            pass
        return []

    def _scan_port(self, ip: str, port: int, retry_timeout: float | None = None) -> dict:
        """Attempt TCP connection to a single port."""
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        timeout = retry_timeout or self.timeout
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
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
            return {"ip": ip, "port": port, "state": "closed",
                    "service": PORT_SERVICE_MAP.get(port, "unknown")}

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> str | None:
        """Try to grab service banner."""
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        try:
            probe = SERVICE_PROBES.get(port, b"")
            if isinstance(probe, bytes) and b"{host}" in probe:
                probe = probe.replace(b"{host}", self.domain.encode())

            with socket.socket(family, socket.SOCK_STREAM) as s:
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
