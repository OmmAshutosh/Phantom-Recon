"""
Shodan API Module - Internet-Wide Port & Service Intelligence
=============================================================
WHAT IS SHODAN?
  Shodan is a search engine for internet-connected devices. Unlike
  Google which indexes websites, Shodan indexes banners - the first
  response from a server when you connect to it on any port.

  Shodan's crawler (Masscan-based) scans the ENTIRE IPv4 space
  continuously on hundreds of ports, storing:
  - Service banner / response
  - Software versions
  - SSL certificate details
  - HTTP headers
  - Geographic location
  - ASN / ISP info
  - CVE matches (via banner parsing)

HOW WE USE IT:
  1. Domain search → find all IPs associated with the domain
  2. For each IP: get full host info (open ports, services, vulns)
  3. Organization search → find ALL assets belonging to org
  4. CVE extraction → known vulnerabilities in detected versions
  5. Technology fingerprinting from service banners

API MODES:
  - Free API key: basic host lookups, 1 result/query
  - Membership ($49/mo): full search, export, filters
  - Enterprise: streaming API, bulk exports

WITHOUT API KEY:
  We use the Shodan free web search as a fallback.
  https://www.shodan.io/search?query=hostname:example.com

KEY SHODAN SEARCH FILTERS:
  hostname:example.com          → all hosts matching domain
  org:"Company Name"            → all hosts in org's netblock
  net:192.168.1.0/24            → CIDR range
  port:22 country:US            → SSH servers in US
  product:nginx version:1.14    → specific software versions
  vuln:CVE-2021-44228           → Log4j vulnerable hosts
  http.title:"Login"            → pages with Login in title
  ssl.cert.subject.cn:*.domain  → wildcard cert hosts
"""

import json
import socket
import requests
from colorama import Fore, Style

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


class ShodanModule:
    """Shodan API intelligence module."""

    # Ports with high red-team value
    INTERESTING_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
        135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 2375: "Docker",
        2376: "Docker-TLS", 3306: "MySQL", 3389: "RDP",
        4443: "HTTPS-Alt", 5432: "PostgreSQL", 5900: "VNC",
        5984: "CouchDB", 6379: "Redis", 7001: "WebLogic",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
        9200: "Elasticsearch", 9300: "Elasticsearch",
        27017: "MongoDB", 28017: "MongoDB-HTTP",
    }

    def __init__(self, config: dict):
        self.domain = config["domain"]
        self.api_key = config.get("shodan_key")
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)

    def run(self) -> dict:
        result = {
            "api_key_used": bool(self.api_key),
            "hosts": [],
            "total_results": 0,
            "open_ports_summary": {},
            "technologies": [],
            "cves": [],
            "high_risk_services": [],
            "countries": [],
            "asns": [],
            "errors": []
        }

        if not SHODAN_AVAILABLE:
            result["errors"].append("shodan library not installed")
            return result

        if self.api_key:
            print(f"  {Fore.BLUE}[*] Querying Shodan API for: {self.domain}{Style.RESET_ALL}")
            self._query_with_api(result)
        else:
            print(f"  {Fore.YELLOW}[!] No Shodan API key - using web fallback{Style.RESET_ALL}")
            print(f"      Get free key at: https://account.shodan.io{Style.RESET_ALL}")
            self._query_fallback(result)

        self._analyze_findings(result)
        return result

    def _query_with_api(self, result: dict):
        """Full Shodan API query with CVEs and service details."""
        try:
            api = shodan.Shodan(self.api_key)

            # Search by hostname
            query = f"hostname:{self.domain}"
            print(f"  {Fore.BLUE}[*] Shodan query: {query}{Style.RESET_ALL}")
            search_result = api.search(query, limit=100)
            result["total_results"] = search_result.get("total", 0)
            print(f"  {Fore.GREEN}[+] Total Shodan results: {result['total_results']}{Style.RESET_ALL}")

            for match in search_result.get("matches", []):
                host_data = self._parse_shodan_match(match)
                result["hosts"].append(host_data)

                # Collect CVEs
                for cve in host_data.get("vulns", []):
                    if cve not in result["cves"]:
                        result["cves"].append(cve)
                        print(f"  {Fore.RED}[!!!] CVE FOUND: {cve} on {host_data['ip']}{Style.RESET_ALL}")

                # Collect open ports
                for port in host_data.get("ports", []):
                    result["open_ports_summary"][str(port)] = result["open_ports_summary"].get(str(port), 0) + 1

        except shodan.APIError as e:
            result["errors"].append(f"Shodan API error: {str(e)}")
            print(f"  {Fore.RED}[-] Shodan API error: {e}{Style.RESET_ALL}")
            if "No information available" in str(e):
                print(f"  {Fore.YELLOW}[!] Domain not indexed by Shodan{Style.RESET_ALL}")
        except Exception as e:
            result["errors"].append(str(e))
            print(f"  {Fore.RED}[-] Shodan error: {e}{Style.RESET_ALL}")

    def _query_fallback(self, result: dict):
        """
        Fallback when no API key: resolve domain IPs and check
        Shodan's free host endpoint + attempt manual port checks.
        """
        try:
            ips = self._resolve_domain_ips()
            print(f"  {Fore.BLUE}[*] Resolved {len(ips)} IPs for {self.domain}{Style.RESET_ALL}")

            for ip in ips[:5]:  # Limit to 5 IPs
                print(f"  {Fore.BLUE}[*] Checking Shodan for: {ip}{Style.RESET_ALL}")
                try:
                    url = f"https://api.shodan.io/shodan/host/{ip}?key=demo"
                    resp = requests.get(url, timeout=self.timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        host_data = {
                            "ip": ip,
                            "ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "org": data.get("org", ""),
                            "country": data.get("country_name", ""),
                            "os": data.get("os", ""),
                            "vulns": list(data.get("vulns", {}).keys()),
                            "services": [],
                            "tags": data.get("tags", []),
                        }
                        result["hosts"].append(host_data)
                        print(f"  {Fore.GREEN}[+] {ip}: {len(host_data['ports'])} open ports{Style.RESET_ALL}")
                    elif resp.status_code == 401:
                        # API key required - suggest getting one
                        print(f"  {Fore.YELLOW}[!] Shodan requires API key for detailed results{Style.RESET_ALL}")
                        # Fall back to basic port check
                        open_ports = self._basic_port_check(ip)
                        if open_ports:
                            result["hosts"].append({
                                "ip": ip, "ports": open_ports,
                                "hostnames": [self.domain],
                                "source": "socket_probe"
                            })
                except Exception:
                    pass

        except Exception as e:
            result["errors"].append(str(e))

    def _parse_shodan_match(self, match: dict) -> dict:
        """Parse a Shodan search match into structured data."""
        # Extract service/product info from data field
        services = []
        for service_data in match.get("data", []) if isinstance(match.get("data"), list) else [match]:
            service_info = {
                "port": service_data.get("port", 0),
                "protocol": service_data.get("transport", "tcp"),
                "product": service_data.get("product", ""),
                "version": service_data.get("version", ""),
                "banner": str(service_data.get("data", ""))[:200],
                "cpe": service_data.get("cpe23", []),
            }
            services.append(service_info)

        return {
            "ip": match.get("ip_str", ""),
            "hostname": match.get("hostnames", []),
            "org": match.get("org", ""),
            "isp": match.get("isp", ""),
            "asn": match.get("asn", ""),
            "country": match.get("location", {}).get("country_name", ""),
            "city": match.get("location", {}).get("city", ""),
            "lat": match.get("location", {}).get("latitude"),
            "lon": match.get("location", {}).get("longitude"),
            "os": match.get("os", ""),
            "ports": match.get("ports", []),
            "vulns": list(match.get("vulns", {}).keys()),
            "tags": match.get("tags", []),
            "services": services,
            "timestamp": match.get("timestamp", ""),
        }

    def _resolve_domain_ips(self) -> list:
        """Resolve domain to IPs using socket."""
        try:
            infos = socket.getaddrinfo(self.domain, None)
            return list(set(i[4][0] for i in infos))
        except Exception:
            return []

    def _basic_port_check(self, ip: str, ports: list = None) -> list:
        """Quick TCP port connectivity check (no Shodan needed)."""
        if ports is None:
            ports = list(self.INTERESTING_PORTS.keys())[:30]
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        return open_ports

    def _analyze_findings(self, result: dict):
        """Identify high-risk services and summarize findings."""
        high_risk = []
        for host in result["hosts"]:
            for port in host.get("ports", []):
                service = self.INTERESTING_PORTS.get(port)
                if service and port in [21, 23, 2375, 3389, 5900, 6379, 9200, 27017]:
                    risk_info = {
                        "ip": host.get("ip"),
                        "port": port,
                        "service": service,
                        "risk": self._get_port_risk(port),
                    }
                    high_risk.append(risk_info)
                    print(f"  {Fore.RED}[!] HIGH RISK: {service} (:{port}) "
                          f"exposed on {host.get('ip')}{Style.RESET_ALL}")

        result["high_risk_services"] = high_risk

        # Collect unique countries and ASNs
        result["countries"] = list(set(h.get("country") for h in result["hosts"] if h.get("country")))
        result["asns"] = list(set(h.get("asn") for h in result["hosts"] if h.get("asn")))

        if result["cves"]:
            print(f"\n  {Fore.RED}{'!'*50}")
            print(f"  [!!!] {len(result['cves'])} CVEs DETECTED:")
            for cve in result["cves"]:
                print(f"        ▸ {cve}")
            print(f"  {'!'*50}{Style.RESET_ALL}")

    def _get_port_risk(self, port: int) -> str:
        risk_map = {
            21: "FTP often transmits credentials in plaintext",
            23: "Telnet is completely unencrypted - CRITICAL",
            2375: "Docker API exposed - container escape possible",
            3389: "RDP - common ransomware entry point",
            5900: "VNC - often weak/no auth",
            6379: "Redis - commonly unauthenticated, RCE possible",
            9200: "Elasticsearch - often no auth, data exposure",
            27017: "MongoDB - often no auth configured",
        }
        return risk_map.get(port, "Potentially sensitive service exposed")
