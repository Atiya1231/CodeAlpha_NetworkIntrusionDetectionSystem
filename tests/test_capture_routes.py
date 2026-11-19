"""Tests for Web API Capture Controls and Traffic Telemetry Endpoints (Phase 7).

Verifies:
1. GET /api/capture/interfaces - Interface discovery API.
2. GET /api/capture/status - Capture lifecycle state inspection.
3. POST /api/capture/start - Validation, explicit binding, duplicate prevention (409), error handling.
4. POST /api/capture/stop - Graceful stop invocation and statistics reporting.
5. GET /api/traffic/stats - Real traffic volume, packet counts, and flow metrics.
6. GET /api/system/status - Multi-module operational status inspection.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from config import Config
from nids.capture.engine import CaptureStatus
from nids.web import create_app


class TestCaptureRoutes(unittest.TestCase):
    """Integration tests for web capture controls and traffic endpoints."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_cap_routes_")
        self.db_path = os.path.join(self.test_dir, "cap_routes.sqlite")

        class TestConfig(Config):
            TESTING = True
            DATABASE_PATH = self.db_path

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        # Ensure capture is stopped cleanly
        if hasattr(self.app, "capture_engine"):
            self.app.capture_engine.stop_capture()
        if hasattr(self.app, "db_manager"):
            self.app.db_manager.stop_worker()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_interfaces_endpoint(self):
        """1. Verify GET /api/capture/interfaces returns non-empty list of network interfaces."""
        res = self.client.get("/api/capture/interfaces")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("interfaces", data)
        self.assertIsInstance(data["interfaces"], list)

    def test_get_capture_status_initial_state(self):
        """2. Verify GET /api/capture/status initially reports IDLE and not running."""
        res = self.client.get("/api/capture/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["capture_status"], "IDLE")
        self.assertFalse(data["is_running"])
        self.assertIn("stats", data)

    def test_start_capture_missing_interface_returns_400(self):
        """3. Verify POST /api/capture/start rejects empty interface identifier with 400 Bad Request."""
        res = self.client.post("/api/capture/start", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Explicit 'interface' is required", data["message"])

        res_blank = self.client.post("/api/capture/start", json={"interface": "   "})
        self.assertEqual(res_blank.status_code, 400)

    def test_start_capture_success_and_duplicate_prevention(self):
        """4. Verify start_capture starts engine and prevents duplicate calls (409 Conflict)."""
        mock_engine = MagicMock()
        mock_engine.status = CaptureStatus.IDLE
        mock_engine.selected_interface = "MockAdapter"
        mock_engine.start_capture.return_value = True

        self.app.capture_engine = mock_engine

        res = self.client.post("/api/capture/start", json={"interface": "MockAdapter"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("MockAdapter", data["message"])

        # Simulate engine now RUNNING
        mock_engine.status = CaptureStatus.RUNNING
        res_dup = self.client.post("/api/capture/start", json={"interface": "MockAdapter"})
        self.assertEqual(res_dup.status_code, 409)
        self.assertIn("already running", res_dup.get_json()["message"])

    def test_start_capture_permission_error_handling(self):
        """5. Verify PermissionError returns 403 Forbidden with clear elevation guidance."""
        mock_engine = MagicMock()
        mock_engine.status = CaptureStatus.IDLE
        mock_engine.start_capture.side_effect = PermissionError("Access denied")
        self.app.capture_engine = mock_engine

        res = self.client.post("/api/capture/start", json={"interface": "eth0"})
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Administrator privileges required", data["message"])

    def test_stop_capture_endpoint(self):
        """6. Verify POST /api/capture/stop calls engine stop cleanly."""
        mock_engine = MagicMock()
        mock_engine.status = CaptureStatus.STOPPED
        mock_engine.stats.to_dict.return_value = {"total_packets": 10}
        mock_engine.stop_capture.return_value = True
        self.app.capture_engine = mock_engine

        res = self.client.post("/api/capture/stop")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["capture_status"], "STOPPED")

    def test_get_traffic_stats_endpoint(self):
        """7. Verify GET /api/traffic/stats returns live flow tracking telemetry."""
        res = self.client.get("/api/traffic/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("traffic", data)
        self.assertIn("active_flows", data)
        self.assertIn("completed_flows", data)

    def test_get_system_status_comprehensive_metadata(self):
        """8. Verify GET /api/system/status reports capture, detection, and storage metadata."""
        res = self.client.get("/api/system/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["phase"].startswith("Phase"))
        self.assertIn("capture_status", data)
        self.assertIn("detection", data)
        self.assertIn("storage", data)


    def test_index_dashboard_template_renders(self):
        """9. Verify GET /dashboard renders index.html and GET / renders landing.html with required assets."""
        res_landing = self.client.get("/")
        self.assertEqual(res_landing.status_code, 200)
        landing_html = res_landing.get_data(as_text=True)
        self.assertIn("NIDS | Next-Gen Network Intrusion Detection & Defense", landing_html)
        self.assertIn("landing.css", landing_html)
        self.assertIn("hero-headline", landing_html)
        self.assertIn("/dashboard", landing_html)

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

    def test_start_capture_generic_failure_returns_500(self):
        """10. Verify start_capture returning False without permission error returns 500."""
        mock_engine = MagicMock()
        mock_engine.status = CaptureStatus.IDLE
        mock_engine.start_capture.return_value = False
        mock_engine.last_error = "Driver interface binding timed out"
        self.app.capture_engine = mock_engine

        res = self.client.post("/api/capture/start", json={"interface": "eth0"})
        self.assertEqual(res.status_code, 500)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("binding timed out", data["message"])


if __name__ == "__main__":
    unittest.main()
