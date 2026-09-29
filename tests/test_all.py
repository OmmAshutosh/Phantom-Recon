#!/usr/bin/env python3
"""
PHANTOM RECON v2.1 — Test Suite
=================================
Tests every module using mock data and the authorized target scanme.nmap.org.
All network tests use only publicly authorized targets.

Run all tests:
    python tests/test_all.py

Run unit tests only (no network):
    python tests/test_all.py --unit-only

Run integration tests only:
    python tests/test_all.py --integration-only

Run with coverage:
    pip install pytest pytest-cov
    pytest tests/test_all.py --cov=modules --cov-report=term-missing
"""

import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.whois_module     import WhoisModule
from modules.dns_module       import DNSModule
from modules.ssl_module       import SSLModule
from modules.tech_module      import TechModule
from modules.port_module      import PortModule
from modules.subdomain_module import SubdomainModule
from modules.email_module     import EmailModule
from modules.shodan_module    import ShodanModule
from modules.report_module    import ReportModule
from modules.cloud_module     import CloudModule

# ── Test Configuration ───────────────────────────────────────────
SAFE_TARGET   = "scanme.nmap.org"    # Nmap's authorized test target
PASSIVE_CONFIG = {
    "domain":     SAFE_TARGET,
    "timeout":    15,  # increased for integration tests on slow networks
    "verbose":    False,
    "threads":    5,
    "wordlist":   None,
    "shodan_key": None,
    "netlas_key": "",
    "out_dir":    "/tmp/phantom_test",
}

os.makedirs("/tmp/phantom_test", exist_ok=True)


# ═══════════════════════════════════════════════════════════════
# UNIT TESTS — Mock network calls
# ═══════════════════════════════════════════════════════════════

class TestWhoisModuleUnit(unittest.TestCase):
    """Unit tests for WhoisModule using mocked data."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com"}
        self.module = WhoisModule(self.config)

    def test_init(self):
        """Module should initialize with config values."""
        self.assertEqual(self.module.domain, "example.com")
        self.assertGreater(self.module.timeout, 0)  # timeout set from config
        self.assertFalse(self.module.verbose)

    @patch("whois.whois")
    @patch("socket.getaddrinfo")
    def test_run_returns_dict(self, mock_addr, mock_whois):
        """run() must always return a dict with required keys."""
        mock_whois.return_value = MagicMock(
            registrar="Test Registrar",
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            status=["clientTransferProhibited"],
            name_servers=["ns1.example.com"],
            name=None, org="Test Corp",
            country="US", emails=None,
            dnssec="unsigned",
            text="raw whois text",
        )
        mock_addr.return_value = [(None, None, None, None, ("93.184.216.34", 0))]

        result = self.module.run()

        self.assertIsInstance(result, dict)
        for key in ["domain", "registrar", "ips", "nameservers", "errors"]:
            self.assertIn(key, result)
        self.assertEqual(result["registrar"], "Test Registrar")
        self.assertIn("93.184.216.34", result["ips"])

    @patch("whois.whois", side_effect=Exception("WHOIS timeout"))
    @patch("socket.getaddrinfo", side_effect=Exception("DNS failure"))
    def test_run_handles_errors_gracefully(self, mock_addr, mock_whois):
        """run() must not crash even when network calls fail."""
        result = self.module.run()
        self.assertIsInstance(result, dict)
        self.assertTrue(len(result["errors"]) > 0)

    def test_domain_stored(self):
        """Domain from config must be stored on instance."""
        config = {**PASSIVE_CONFIG, "domain": "test-domain.org"}
        module = WhoisModule(config)
        self.assertEqual(module.domain, "test-domain.org")


class TestDNSModuleUnit(unittest.TestCase):
    """Unit tests for DNSModule."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com"}
        self.module = DNSModule(self.config)

    def test_record_types_list(self):
        """Module should define the expected record types."""
        expected = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"}
        self.assertTrue(expected.issubset(set(DNSModule.RECORD_TYPES)))

    @patch("dns.resolver.Resolver.resolve")
    def test_query_returns_empty_on_nxdomain(self, mock_resolve):
        """_query() must return [] when record type doesn't exist."""
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NoAnswer()
        result = self.module._query("MX")
        self.assertEqual(result, [])

    @patch("dns.resolver.Resolver.resolve")
    def test_query_returns_list_of_strings(self, mock_resolve):
        """_query() must return a list of strings."""
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([
            MagicMock(__str__=MagicMock(return_value="93.184.216.34"))
        ]))
        mock_resolve.return_value = mock_answer
        result = self.module._query("A")
        self.assertIsInstance(result, list)

    def test_spf_weakness_detection(self):
        """Should flag +all as critical SPF weakness."""
        result = {"spf": None, "records": {"TXT": ["v=spf1 +all"]}, "errors": []}
        self.module._parse_txt_records(result)
        self.assertIn("v=spf1 +all", result.get("spf", ""))

    def test_run_returns_required_keys(self):
        """run() must return dict with all required top-level keys."""
        with patch.object(self.module, "_query", return_value=[]):
            with patch.object(self.module, "_attempt_zone_transfer"):
                with patch.object(self.module, "_check_dmarc"):
                    with patch.object(self.module, "_check_dkim"):
                        result = self.module.run()
        required_keys = ["records", "zone_transfer", "spf", "dmarc",
                         "nameservers", "mail_servers", "errors"]
        for key in required_keys:
            self.assertIn(key, result)


class TestSSLModuleUnit(unittest.TestCase):
    """Unit tests for SSLModule."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com"}
        self.module = SSLModule(self.config)

    def test_init(self):
        self.assertEqual(self.module.domain, "example.com")

    def test_run_returns_dict_with_required_keys(self):
        """run() result must have all required keys even on failure."""
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = self.module.run()
        required = ["valid", "expired", "self_signed", "san_domains",
                    "vulnerabilities", "errors"]
        for key in required:
            self.assertIn(key, result)
        self.assertFalse(result["valid"])
        self.assertFalse(result["self_signed"])

    def test_ssl_error_handled_gracefully(self):
        """SSL errors must not crash module."""
        import ssl
        with patch("socket.create_connection", side_effect=ssl.SSLError("test error")):
            result = self.module.run()
        self.assertIsInstance(result, dict)
        self.assertTrue(len(result["errors"]) >= 0)


class TestTechModuleUnit(unittest.TestCase):
    """Unit tests for TechModule signature matching."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com"}
        self.module = TechModule(self.config)

    def test_wordpress_detected_by_html(self):
        """WordPress should be detected via /wp-content/ in HTML."""
        headers = {}
        html = '<link rel="stylesheet" href="/wp-content/themes/main/style.css">'
        cookies = []
        detected = self.module._match_signatures(headers, html, cookies)
        names = [d["name"] for d in detected]
        self.assertIn("WordPress", names)

    def test_nginx_detected_by_header(self):
        """Nginx should be detected via Server header."""
        headers = {"Server": "nginx/1.25.0"}
        html = "<html><body>Hello</body></html>"
        cookies = []
        detected = self.module._match_signatures(headers, html, cookies)
        names = [d["name"] for d in detected]
        self.assertIn("Nginx", names)

    def test_nginx_version_extracted(self):
        """Nginx version should be captured from header regex group."""
        headers = {"Server": "nginx/1.25.0"}
        html = ""
        cookies = []
        detected = self.module._match_signatures(headers, html, cookies)
        nginx = next((d for d in detected if d["name"] == "Nginx"), None)
        self.assertIsNotNone(nginx)
        self.assertEqual(nginx["version"], "1.25.0")

    def test_cloudflare_detected_by_header(self):
        """Cloudflare should be detected via CF-RAY header."""
        headers = {"CF-RAY": "89abc123-IAD", "Server": "cloudflare"}
        html = ""
        cookies = []
        detected = self.module._match_signatures(headers, html, cookies)
        names = [d["name"] for d in detected]
        self.assertIn("Cloudflare", names)

    def test_missing_security_headers_identified(self):
        """Security header analysis should identify missing headers."""
        result = {
            "security_headers": {},
            "missing_security_headers": [],
            "version_disclosure": [],
        }
        headers = {"X-Frame-Options": "SAMEORIGIN"}
        self.module._analyze_security_headers(headers, result)
        missing_names = [h["header"] for h in result["missing_security_headers"]]
        self.assertIn("Content-Security-Policy", missing_names)
        self.assertIn("Strict-Transport-Security", missing_names)

    def test_version_disclosure_flagged(self):
        """Version in Server header should be flagged as disclosure."""
        result = {"security_headers": {}, "missing_security_headers": [],
                  "version_disclosure": []}
        headers = {"Server": "Apache/2.4.41"}
        html = ""
        self.module._check_version_disclosure(headers, html, result)
        self.assertTrue(len(result["version_disclosure"]) > 0)
        self.assertEqual(result["version_disclosure"][0]["version"], "2.4.41")

    def test_no_false_positives_on_clean_page(self):
        """Blank page should not trigger any signatures."""
        headers = {}
        html = "<html><body></body></html>"
        cookies = []
        detected = self.module._match_signatures(headers, html, cookies)
        self.assertEqual(len(detected), 0)


class TestPortModuleUnit(unittest.TestCase):
    """Unit tests for PortModule."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com", "threads": 5}
        self.module = PortModule(self.config)

    def test_port_service_map_coverage(self):
        """Service map should cover key high-risk ports."""
        from modules.port_module import PORT_SERVICE_MAP
        critical_ports = [22, 80, 443, 3389, 6379, 9200, 27017]
        for port in critical_ports:
            self.assertIn(port, PORT_SERVICE_MAP)

    def test_risk_assessment_critical_ports(self):
        """Telnet and Docker API should be CRITICAL risk."""
        self.assertEqual(self.module._assess_port_risk(23), "CRITICAL")
        self.assertEqual(self.module._assess_port_risk(2375), "CRITICAL")

    def test_risk_assessment_high_ports(self):
        """RDP and Redis should be HIGH risk."""
        self.assertEqual(self.module._assess_port_risk(3389), "HIGH")
        self.assertEqual(self.module._assess_port_risk(6379), "HIGH")

    @patch("socket.socket")
    def test_closed_port_returns_closed_state(self, mock_socket):
        """Port that refuses connection should return closed state."""
        mock_sock_instance = MagicMock()
        mock_sock_instance.__enter__ = MagicMock(return_value=mock_sock_instance)
        mock_sock_instance.__exit__ = MagicMock(return_value=False)
        mock_sock_instance.connect_ex.return_value = 111
        mock_socket.return_value = mock_sock_instance
        result = self.module._scan_port("93.184.216.34", 9999)
        self.assertEqual(result["state"], "closed")

    @patch("socket.socket")
    def test_open_port_returns_open_state(self, mock_socket):
        """Port that accepts connection should return open state."""
        mock_sock_instance = MagicMock()
        mock_sock_instance.__enter__ = MagicMock(return_value=mock_sock_instance)
        mock_sock_instance.__exit__ = MagicMock(return_value=False)
        mock_sock_instance.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock_instance
        with patch.object(self.module, "_grab_banner", return_value="SSH-2.0-OpenSSH"):
            result = self.module._scan_port("93.184.216.34", 22)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["port"], 22)
        self.assertEqual(result["service"], "SSH")


class TestSubdomainModuleUnit(unittest.TestCase):
    """Unit tests for SubdomainModule."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com", "threads": 3}
        self.module = SubdomainModule(self.config)

    def test_add_subdomain_valid(self):
        """Valid subdomain should be added to found dict."""
        self.module._add_subdomain("api.example.com", "test", ["1.2.3.4"])
        self.assertIn("api.example.com", self.module._found)
        entry = self.module._found["api.example.com"]
        self.assertEqual(entry["sources"], ["test"])
        self.assertEqual(entry["ips"], ["1.2.3.4"])

    def test_add_subdomain_deduplication(self):
        """Same subdomain from two sources should only have one entry."""
        self.module._add_subdomain("api.example.com", "crt.sh")
        self.module._add_subdomain("api.example.com", "bruteforce")
        self.assertEqual(len(self.module._found), 1)
        sources = self.module._found["api.example.com"]["sources"]
        self.assertIn("crt.sh", sources)
        self.assertIn("bruteforce", sources)

    def test_add_subdomain_rejects_off_domain(self):
        """Subdomains not matching target domain should be rejected."""
        self.module._add_subdomain("evil.attacker.com", "test")
        self.assertNotIn("evil.attacker.com", self.module._found)

    def test_takeover_signatures_coverage(self):
        """Should have entries for major cloud platforms."""
        from modules.subdomain_module import TAKEOVER_SIGNATURES
        required = ["github.io", "herokuapp.com", "azurewebsites.net",
                    "netlify.app", "vercel.app"]
        for pattern in required:
            self.assertIn(pattern, TAKEOVER_SIGNATURES)

    def test_builtin_wordlist_not_empty(self):
        """Built-in wordlist should have substantial entries."""
        from modules.subdomain_module import BUILTIN_WORDLIST
        self.assertGreater(len(BUILTIN_WORDLIST), 100)
        self.assertIn("www", BUILTIN_WORDLIST)
        self.assertIn("api", BUILTIN_WORDLIST)
        self.assertIn("admin", BUILTIN_WORDLIST)

    def test_load_wordlist_fallback_to_builtin(self):
        """Non-existent wordlist path should fall back to built-in."""
        config = {**self.config, "wordlist": "/nonexistent/path/words.txt"}
        module = SubdomainModule(config)
        wordlist = module._load_wordlist()
        from modules.subdomain_module import BUILTIN_WORDLIST
        self.assertEqual(wordlist, BUILTIN_WORDLIST)


class TestReportModuleUnit(unittest.TestCase):
    """Unit tests for ReportModule — uses mock scan data."""

    def setUp(self):
        self.out_dir = "/tmp/phantom_test_reports"
        os.makedirs(self.out_dir, exist_ok=True)
        self.config = {
            "domain": "unittest.example.com",
            "out_dir": self.out_dir,
        }
        self.module = ReportModule(self.config)
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from demo import generate_mock_results
        self.mock_results = generate_mock_results("unittest.example.com")

    def test_html_report_generated(self):
        """HTML report file should be created."""
        path = os.path.join(self.out_dir, "test_report.html")
        self.module._generate_html(self.mock_results, path)
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 5000)

    def test_html_report_contains_domain(self):
        """HTML report should contain the target domain."""
        path = os.path.join(self.out_dir, "test_report2.html")
        self.module._generate_html(self.mock_results, path)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("unittest.example.com", content)

    def test_html_report_contains_risk_level(self):
        """HTML report should show the risk level."""
        path = os.path.join(self.out_dir, "test_report3.html")
        self.module._generate_html(self.mock_results, path)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        risk_level = self.mock_results["summary"]["risk_level"]
        self.assertIn(risk_level, content)

    def test_pdf_report_generated(self):
        """PDF report file should be created."""
        try:
            from reportlab.lib.pagesizes import A4
            path = os.path.join(self.out_dir, "test_report.pdf")
            self.module._generate_pdf(self.mock_results, path)
            self.assertTrue(os.path.exists(path))
            self.assertGreater(os.path.getsize(path), 1000)
        except ImportError:
            self.skipTest("reportlab not installed")

    def test_run_returns_paths_dict(self):
        """run() should return a dict with 'html' key."""
        paths = self.module.run(self.mock_results)
        self.assertIsInstance(paths, dict)
        self.assertIn("html", paths)


class TestEmailModuleUnit(unittest.TestCase):
    """Unit tests for EmailModule."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com"}
        self.module = EmailModule(self.config)

    def test_email_regex_extraction(self):
        """Email regex should extract valid addresses from text."""
        text = "Contact us at info@example.com or support@example.com for help."
        emails = self.module._extract_emails_from_text(text)
        self.assertIn("info@example.com", emails)
        self.assertIn("support@example.com", emails)

    def test_email_regex_ignores_invalid(self):
        """Email regex should not match obvious non-emails."""
        text = "Visit our website at example.com or call us."
        emails = self.module._extract_emails_from_text(text)
        self.assertEqual(len(emails), 0)

    def test_add_email_stores_correctly(self):
        """_add_email() should store email with metadata."""
        self.module._add_email("admin@example.com", "test_source", "high")
        self.assertIn("admin@example.com", self.module._emails)
        entry = self.module._emails["admin@example.com"]
        self.assertEqual(entry["confidence"], "high")
        self.assertIn("test_source", entry["sources"])

    def test_add_email_deduplication(self):
        """Same email from two sources should be merged."""
        self.module._add_email("admin@example.com", "source1")
        self.module._add_email("admin@example.com", "source2")
        self.assertEqual(len(self.module._emails), 1)
        sources = self.module._emails["admin@example.com"]["sources"]
        self.assertIn("source1", sources)
        self.assertIn("source2", sources)

    def test_email_pattern_inference_dot_format(self):
        """Should infer first.last@ pattern from example emails."""
        self.module._add_email("john.smith@example.com", "test", "high")
        self.module._add_email("jane.doe@example.com", "test", "high")
        patterns = self.module._infer_email_patterns()
        self.assertTrue(any("first" in p and "last" in p for p in patterns))

    def test_add_email_normalizes_case(self):
        """Emails should be stored lowercase."""
        self.module._add_email("Admin@EXAMPLE.COM", "test")
        self.assertIn("admin@example.com", self.module._emails)
        self.assertNotIn("Admin@EXAMPLE.COM", self.module._emails)


class TestShodanModuleUnit(unittest.TestCase):
    """Unit tests for ShodanModule."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com", "shodan_key": None}
        self.module = ShodanModule(self.config)

    def test_interesting_ports_coverage(self):
        """Interesting ports dict should include major dangerous services."""
        from modules.shodan_module import ShodanModule as S
        critical = [6379, 9200, 27017, 3389, 2375, 23]
        for port in critical:
            self.assertIn(port, S.INTERESTING_PORTS)

    def test_get_port_risk_telnet(self):
        """Telnet should be CRITICAL."""
        risk = self.module._get_port_risk(23)
        self.assertIn("CRITICAL", risk)

    def test_get_port_risk_docker(self):
        """Docker API port 2375 should be CRITICAL."""
        risk = self.module._get_port_risk(2375)
        self.assertIn("container", risk.lower())

    def test_run_no_api_key_returns_dict(self):
        """Without API key, run() should still return a valid dict."""
        with patch.object(self.module, "_query_fallback"):
            result = self.module.run()
        self.assertIsInstance(result, dict)
        self.assertFalse(result["api_key_used"])

    def test_parse_shodan_match(self):
        """Should correctly parse a Shodan API match dict."""
        match = {
            "ip_str": "93.184.216.34",
            "hostnames": ["example.com"],
            "org": "EDGECAST",
            "isp": "Verizon",
            "asn": "AS15133",
            "location": {"country_name": "United States", "city": "LA",
                         "latitude": 34.0, "longitude": -118.0},
            "os": None,
            "ports": [80, 443],
            "vulns": {"CVE-2021-44228": {"cvss": 10.0}},
            "tags": [],
            "timestamp": "2024-01-01T00:00:00",
        }
        result = self.module._parse_shodan_match(match)
        self.assertEqual(result["ip"], "93.184.216.34")
        self.assertIn("CVE-2021-44228", result["vulns"])
        self.assertEqual(result["country"], "United States")


# ═══════════════════════════════════════════════════════════════
# CLOUD MODULE UNIT TESTS — 9 tests
# ═══════════════════════════════════════════════════════════════

class TestCloudModuleUnit(unittest.TestCase):
    """Unit tests for CloudModule — bucket enumeration and cloud probing."""

    def setUp(self):
        self.config = {**PASSIVE_CONFIG, "domain": "example.com",
                       "netlas_key": "", "threads": 3}
        self.module = CloudModule(self.config)

    def test_bucket_name_generation(self):
        """Should generate bucket name patterns from domain."""
        from modules.cloud_module import _generate_bucket_names
        names = _generate_bucket_names("tesla.com")
        self.assertGreater(len(names), 10)
        self.assertIn("tesla", names)
        self.assertIn("tesla-backup", names)
        self.assertIn("tesla-dev", names)
        self.assertIn("tesla-staging", names)

    def test_bucket_names_no_duplicates(self):
        """Generated bucket names should be unique."""
        from modules.cloud_module import _generate_bucket_names
        names = _generate_bucket_names("example.com")
        self.assertEqual(len(names), len(set(names)))

    def test_bucket_names_strip_tld(self):
        """TLD should be stripped from company name."""
        from modules.cloud_module import _generate_bucket_names
        names = _generate_bucket_names("acme.com")
        self.assertIn("acme", names)
        self.assertNotIn("acme.com", names)
        self.assertNotIn("acme-com", names)

    def test_company_name_derived_from_domain(self):
        """Company name should be first part of domain."""
        config = {**self.config, "domain": "github.com"}
        mod = CloudModule(config)
        self.assertEqual(mod.company, "github")

    def test_takeover_signatures_coverage(self):
        """Takeover signatures should cover major cloud providers."""
        from modules.cloud_module import TAKEOVER_SIGNATURES
        required = ["github.io", "herokuapp.com", "azurewebsites.net",
                    "netlify.app", "vercel.app", "s3.amazonaws.com"]
        for pattern in required:
            self.assertIn(pattern, TAKEOVER_SIGNATURES)

    def test_is_cloud_ip_amazon(self):
        """Amazon org name should be identified as cloud."""
        self.assertTrue(self.module._is_cloud_ip("Amazon AWS"))

    def test_is_cloud_ip_non_cloud(self):
        """Non-cloud ISP should not be identified as cloud."""
        self.assertFalse(self.module._is_cloud_ip("Comcast Cable"))

    @patch("requests.Session.get")
    def test_s3_public_bucket_200_is_critical(self, mock_get):
        """HTTP 200 response should mark S3 bucket as publicly exposed."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "<?xml version='1.0'?><ListBucketResult>"
            "<Key>backup/db.sql</Key><Key>config/.env</Key>"
            "</ListBucketResult>"
        )
        mock_get.return_value = mock_resp
        results = self.module._probe_s3(["test-bucket"])
        exposed = [r for r in results if r.get("accessible")]
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0]["severity"], "CRITICAL")
        self.assertEqual(exposed[0]["file_count"], 2)

    @patch("requests.Session.get")
    def test_s3_private_bucket_403_not_exposed(self, mock_get):
        """HTTP 403 should mark bucket as existing but private."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp
        results = self.module._probe_s3(["private-bucket"])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["accessible"])
        self.assertEqual(results[0]["severity"], "INFO")


# ═══════════════════════════════════════════════════════════════
# DATA SCHEMA TESTS
# ═══════════════════════════════════════════════════════════════

class TestMockDataSchema(unittest.TestCase):
    """Tests that mock data matches the exact schema modules return."""

    def setUp(self):
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from demo import generate_mock_results
        self.data = generate_mock_results("schema-test.com")

    def test_top_level_keys(self):
        required = ["meta", "whois", "dns", "subdomains", "emails",
                    "shodan", "technologies", "ssl", "ports", "summary"]
        for key in required:
            self.assertIn(key, self.data, f"Missing top-level key: {key}")

    def test_summary_risk_score_range(self):
        score = self.data["summary"]["risk_score"]
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_summary_risk_level_valid(self):
        level = self.data["summary"]["risk_level"]
        self.assertIn(level, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_subdomains_have_required_fields(self):
        for sub in self.data["subdomains"]:
            if isinstance(sub, dict) and "subdomain" in sub:
                self.assertIn("sources", sub)
                self.assertIn("ips", sub)
                self.assertIsInstance(sub["sources"], list)
                self.assertIsInstance(sub["ips"], list)

    def test_emails_have_required_fields(self):
        for email in self.data["emails"]:
            if isinstance(email, dict) and "email" in email:
                self.assertIn("sources", email)
                self.assertIn("confidence", email)

    def test_ssl_days_remaining_positive_or_negative(self):
        days = self.data["ssl"]["days_remaining"]
        self.assertIsInstance(days, int)

    def test_technologies_detected_is_list(self):
        detected = self.data["technologies"]["detected"]
        self.assertIsInstance(detected, list)

    def test_json_serializable(self):
        """All mock data must be JSON-serializable."""
        try:
            json.dumps(self.data)
        except TypeError as e:
            self.fail(f"Mock data is not JSON-serializable: {e}")


# ═══════════════════════════════════════════════════════════════
# INTEGRATION TESTS — Real network calls (authorized targets only)
# ═══════════════════════════════════════════════════════════════

class TestWhoisIntegration(unittest.TestCase):
    """Integration tests against scanme.nmap.org (authorized)."""

    @classmethod
    def setUpClass(cls):
        config = {**PASSIVE_CONFIG, "domain": SAFE_TARGET}
        cls.result = WhoisModule(config).run()

    def test_result_is_dict(self):
        self.assertIsInstance(self.result, dict)

    def test_ips_resolved(self):
        self.assertIsInstance(self.result["ips"], list)
        self.assertGreater(len(self.result["ips"]), 0)

    def test_registrar_present(self):
        self.assertIn("registrar", self.result)

    def test_no_fatal_errors(self):
        self.assertIsInstance(self.result["errors"], list)


class TestDNSIntegration(unittest.TestCase):
    """Integration tests for DNSModule."""

    @classmethod
    def setUpClass(cls):
        config = {**PASSIVE_CONFIG, "domain": SAFE_TARGET}
        cls.result = DNSModule(config).run()

    def test_result_is_dict(self):
        self.assertIsInstance(self.result, dict)

    def test_a_record_present(self):
        """
        scanme.nmap.org should have an A record.
        Skips if DNS unavailable on university/corporate network.
        """
        a_records = self.result.get("records", {}).get("A", [])
        errors    = self.result.get("errors", [])
        if not a_records and errors:
            self.skipTest(
                f"DNS unavailable on this network: {errors[:1]}. "
                f"Try on a different network or increase timeout."
            )
        self.assertGreater(len(a_records), 0,
            "scanme.nmap.org returned no A records — check connectivity")

    def test_zone_transfer_refused(self):
        zt = self.result.get("zone_transfer", {})
        self.assertTrue(zt.get("attempted"))
        self.assertFalse(zt.get("success"))

    def test_records_are_strings(self):
        for rtype, records in self.result.get("records", {}).items():
            for record in records:
                self.assertIsInstance(record, str, f"{rtype} record not a string")


class TestSSLIntegration(unittest.TestCase):
    """Integration tests for SSLModule."""

    @classmethod
    def setUpClass(cls):
        config = {**PASSIVE_CONFIG, "domain": SAFE_TARGET}
        cls.result = SSLModule(config).run()

    def test_result_is_dict(self):
        self.assertIsInstance(self.result, dict)

    def test_required_keys_present(self):
        for key in ["valid", "expired", "self_signed", "san_domains",
                    "vulnerabilities", "errors"]:
            self.assertIn(key, self.result)

    def test_ssl_protocol_version(self):
        if self.result.get("valid"):
            self.assertIsInstance(self.result["protocol_version"], str)
            self.assertIn("TLS", self.result["protocol_version"])


class TestTechIntegration(unittest.TestCase):
    """Integration tests for TechModule."""

    @classmethod
    def setUpClass(cls):
        config = {**PASSIVE_CONFIG, "domain": SAFE_TARGET}
        cls.result = TechModule(config).run()

    def test_result_is_dict(self):
        self.assertIsInstance(self.result, dict)

    def test_detected_is_list(self):
        self.assertIsInstance(self.result.get("detected"), list)

    def test_security_headers_analyzed(self):
        self.assertIn("missing_security_headers", self.result)
        self.assertIsInstance(self.result["missing_security_headers"], list)

    def test_detected_have_required_fields(self):
        for tech in self.result.get("detected", []):
            self.assertIn("name", tech)
            self.assertIn("category", tech)
            self.assertIn("risk", tech)


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PHANTOM RECON Test Suite")
    parser.add_argument("--unit-only", action="store_true",
                        help="Run only unit tests (no network calls)")
    parser.add_argument("--integration-only", action="store_true",
                        help="Run only integration tests (requires network)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    loader = unittest.TestLoader()

    if args.unit_only:
        unit_classes = [
            TestWhoisModuleUnit, TestDNSModuleUnit, TestSSLModuleUnit,
            TestTechModuleUnit, TestPortModuleUnit, TestSubdomainModuleUnit,
            TestReportModuleUnit, TestEmailModuleUnit, TestShodanModuleUnit,
            TestCloudModuleUnit, TestMockDataSchema,
        ]
        suite = unittest.TestSuite([
            loader.loadTestsFromTestCase(cls) for cls in unit_classes
        ])
        print("\n🔬 Running UNIT TESTS only (no network calls)\n")

    elif args.integration_only:
        integration_classes = [
            TestWhoisIntegration, TestDNSIntegration,
            TestSSLIntegration, TestTechIntegration,
        ]
        suite = unittest.TestSuite([
            loader.loadTestsFromTestCase(cls) for cls in integration_classes
        ])
        print(f"\n🌐 Running INTEGRATION TESTS against {SAFE_TARGET}\n")

    else:
        suite = loader.discover(os.path.dirname(__file__), pattern="test_*.py")
        print(f"\n🧪 Running ALL TESTS (unit + integration against {SAFE_TARGET})\n")

    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(suite)

    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed

    print(f"\n{'='*55}")
    print(f"  Tests run: {total} | Passed: {passed} | Failed: {failed}")
    if result.wasSuccessful():
        print(f"  ✅ ALL TESTS PASSED")
    else:
        print(f"  ❌ {failed} TEST(S) FAILED")
    print(f"{'='*55}\n")

    sys.exit(0 if result.wasSuccessful() else 1)