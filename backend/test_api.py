"""
backend/test_api.py - Unit test suite for FastAPI backend endpoints & persistence
"""

import os
import sys
import unittest
import time
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main as app_module

class TestFastAPIBackend(unittest.TestCase):
    def setUp(self):
        self.client_ctx = TestClient(app_module.app)
        self.client = self.client_ctx.__enter__()

    def tearDown(self):
        self.client_ctx.__exit__(None, None, None)

    def test_health_check(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "healthy")

    def test_api_keys_strictly_boolean(self):
        resp = self.client.get("/api/config/keys")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        expected_keys = ["shodan", "hunter", "virustotal", "netlas", "github", "censys"]
        for k in expected_keys:
            self.assertIn(k, data)
            self.assertIsInstance(data[k], bool)

    def test_consent_rejection(self):
        # Without consent, must fail with 422
        resp = self.client.post("/api/scan", json={
            "target": "example.com",
            "consent": False
        })
        self.assertEqual(resp.status_code, 422)

    def test_consent_acceptance_and_demo_scan(self):
        resp = self.client.post("/api/scan", json={
            "target": "scanme.nmap.org",
            "consent": True,
            "demo_mode": True,
            "modules": ["whois", "dns"]
        })
        self.assertEqual(resp.status_code, 200)
        scan_id = resp.json()["scan_id"]
        self.assertTrue(scan_id)

        # In TestClient, BackgroundTasks run during request completion
        s_resp = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(s_resp.status_code, 200)
        scan_data = s_resp.json()
        self.assertEqual(scan_data["status"], "completed")
        self.assertIn("summary", scan_data)
        self.assertIn("risk_score", scan_data)

        # Test Share Readout feature
        share_resp = self.client.post(f"/api/scan/{scan_id}/share", json={"expires_in_hours": 24})
        self.assertEqual(share_resp.status_code, 200)
        share_token = share_resp.json()["share_token"]
        self.assertTrue(share_token)

        # Fetch shared readout
        readout_resp = self.client.get(f"/api/shared/{share_token}")
        self.assertEqual(readout_resp.status_code, 200)
        readout_data = readout_resp.json()
        self.assertFalse(readout_data["expired"])
        self.assertEqual(readout_data["scan"]["target"], "scanme.nmap.org")
        self.assertIn("results", readout_data["scan"])

if __name__ == "__main__":
    unittest.main()
