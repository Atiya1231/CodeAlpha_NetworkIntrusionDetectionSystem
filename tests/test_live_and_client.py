"""Verification script testing Flask test_client and Live HTTP server endpoints."""

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from nids.web import create_app


class TestEndpointVerification(unittest.TestCase):
    """Test both URLs using Flask test_client and confirm HTTP 200 and correct template content."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="nids_verify_")
        self.db_path = os.path.join(self.temp_dir, "verify.sqlite")

        class VerifyConfig(Config):
            TESTING = True
            DATABASE_PATH = self.db_path

        self.app = create_app(VerifyConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        if hasattr(self.app, "db_manager"):
            self.app.db_manager.stop_worker()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_flask_test_client_root_landing_page(self):
        """1. Verify GET / renders landing.html with status 200 and required elements."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("NIDS | Next-Gen Network Intrusion Detection & Defense", html)
        self.assertIn("landing.css", html)
        self.assertIn("hero-headline", html)
        self.assertIn("Protect. Detect.", html)
        self.assertIn("Secure.", html)
        self.assertIn("/dashboard", html)
        self.assertIn("Launch SOC Console", html)
        self.assertIn("Suricata 8.0", html)

    def test_flask_test_client_root_with_query_param(self):
        """2. Verify GET /?utm_source=chatgpt.com renders landing.html with status 200."""
        res = self.client.get("/?utm_source=chatgpt.com")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("NIDS | Next-Gen Network Intrusion Detection & Defense", html)
        self.assertIn("landing.css", html)
        self.assertIn("hero-headline", html)

    def test_flask_test_client_dashboard(self):
        """3. Verify GET /dashboard renders existing index.html with status 200 and SOC elements."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("NIDS | Security Operations Center", html)
        self.assertIn("dashboard.js", html)
        self.assertIn("style.css", html)
        self.assertIn("chart.umd.min.js", html)
        self.assertIn("section-overview", html)
        self.assertIn("section-alerts", html)
        self.assertIn("section-traffic", html)
        self.assertIn("section-capture", html)
        self.assertIn("section-status", html)
        self.assertIn("alert-modal", html)
        self.assertIn("Public Portal", html)

        # Verify Public Portal links point to '/'
        self.assertIn('href="/" class="nav-item nav-item-portal" id="public-portal-link"', html)
        self.assertIn('id="btn-back-home"', html)
        self.assertIn('href="/" class="btn btn-secondary btn-sm" id="btn-back-home"', html)

    def test_public_portal_navigation_from_all_sections(self):
        """4. Verify Public Portal anchor is globally accessible across all dashboard tabs."""
        res = self.client.get("/dashboard")
        html = res.get_data(as_text=True)
        # Verify sidebar nav contains public-portal-link outside of section containers
        self.assertIn('id="public-portal-link"', html)
        # Verify topbar action group contains btn-back-home
        self.assertIn('id="btn-back-home"', html)

        # Verify dashboard.js does not prevent default navigation on non-data-section links
        js_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "nids", "web", "static", "js", "dashboard.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js_code = f.read()
        self.assertIn('.nav-item[data-section]', js_code)
        self.assertIn('window.location.href = targetUrl', js_code)

    def test_flask_test_client_api_endpoints_preserved(self):
        """4. Verify existing dashboard API endpoints remain intact and functional."""
        res_sys = self.client.get("/api/system/status")
        self.assertEqual(res_sys.status_code, 200)
        sys_data = res_sys.get_json()
        self.assertEqual(sys_data["status"], "success")

        res_cap = self.client.get("/api/capture/status")
        self.assertEqual(res_cap.status_code, 200)
        cap_data = res_cap.get_json()
        self.assertIn("capture_status", cap_data)

        res_alerts = self.client.get("/api/alerts")
        self.assertEqual(res_alerts.status_code, 200)
        alerts_data = res_alerts.get_json()
        self.assertIn("alerts", alerts_data)

        res_traffic = self.client.get("/api/traffic/stats")
        self.assertEqual(res_traffic.status_code, 200)

        res_suricata = self.client.get("/api/suricata/status")
        self.assertEqual(res_suricata.status_code, 200)

        res_response = self.client.get("/api/response/status")
        self.assertEqual(res_response.status_code, 200)


def test_live_server():
    """Verify live HTTP server at http://127.0.0.1:5000."""
    print("=" * 60)
    print("TESTING LIVE SERVER AT http://127.0.0.1:5000")
    print("=" * 60)

    # 1. Landing page with query parameter
    url_landing = "http://127.0.0.1:5000/?utm_source=chatgpt.com"
    req1 = urllib.request.Request(url_landing, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req1, timeout=5) as r1:
        body1 = r1.read().decode("utf-8")
        status1 = r1.status
        has_title = "NIDS | Next-Gen Network Intrusion Detection & Defense" in body1
        has_css = "landing.css" in body1
        has_cta = "Launch SOC Console" in body1
        print(f"[*] GET {url_landing}")
        print(f"    Status: {status1}")
        print(f"    Has Landing Title: {has_title}")
        print(f"    Has landing.css: {has_css}")
        print(f"    Has CTA 'Launch SOC Console': {has_cta}")
        assert status1 == 200 and has_title and has_css and has_cta

    # 2. Dashboard
    url_dash = "http://127.0.0.1:5000/dashboard"
    req2 = urllib.request.Request(url_dash, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req2, timeout=5) as r2:
        body2 = r2.read().decode("utf-8")
        status2 = r2.status
        has_soc_title = "NIDS | Security Operations Center" in body2
        has_dash_js = "dashboard.js" in body2
        has_sections = "section-overview" in body2 and "section-alerts" in body2
        print(f"[*] GET {url_dash}")
        print(f"    Status: {status2}")
        print(f"    Has SOC Title: {has_soc_title}")
        print(f"    Has dashboard.js: {has_dash_js}")
        print(f"    Has SOC sections: {has_sections}")
        assert status2 == 200 and has_soc_title and has_dash_js and has_sections

    # 3. API preservation
    url_api = "http://127.0.0.1:5000/api/system/status"
    with urllib.request.urlopen(url_api, timeout=5) as r3:
        status3 = r3.status
        data3 = json.loads(r3.read().decode("utf-8"))
        print(f"[*] GET {url_api}")
        print(f"    Status: {status3}")
        print(f"    Phase: {data3.get('phase')}")
        print(f"    System Status: {data3.get('status')}")
        assert status3 == 200 and data3.get("status") == "success"

    print("=" * 60)
    print("ALL LIVE SERVER CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    test_live_server()
    print("\nRUNNING UNITTEST SUITE (test_client)...")
    unittest.main()
