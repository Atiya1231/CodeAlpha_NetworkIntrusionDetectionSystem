"""Test suite for Incident Response, Containment Mechanisms, and Security Audits.

Verifies:
1. Contextual response recommendation generation for detection rules and Suricata alerts.
2. Safe, audited, reversible manual IP blocking manager and safety validation guards.
3. Incident response REST endpoints (status updates with notes, manual block/unblock, recommendations).
4. Security remediations (path traversal prevention, defense-in-depth HTTP security headers).
5. Basic packet structure analysis metadata extraction (layer hierarchy and IP version).
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from config import Config
from nids.capture.metadata import PacketMetadata, extract_metadata
from nids.detection.models import DetectionEvent, Severity
from nids.response import (
    ActionPriority,
    BlockStatus,
    IPBlockingManager,
    get_recommended_response,
)
from nids.storage.database import Database
from nids.web import create_app


class TestRecommendationEngine(unittest.TestCase):
    """Verify contextual response recommendations across rule types and severities."""

    def test_port_scan_recommendation(self):
        """Verify PortScan rule generates elevated reconnaissance investigation guidance."""
        rec = get_recommended_response(
            rule_id="NIDS_RULE_001",
            title="Port Scan Detected",
            severity="HIGH",
            evidence={"distinct_ports_scanned": 25},
            source_ip="192.168.1.100",
        )
        self.assertEqual(rec.priority, ActionPriority.ELEVATED)
        self.assertIn("reconnaissance", rec.recommended_action.lower())
        self.assertIn("192.168.1.100", rec.recommended_action)
        self.assertIsNotNone(rec.suggested_firewall_rule)
        self.assertIn("NIDS_Block_192.168.1.100", rec.suggested_firewall_rule)

    def test_syn_flood_recommendation(self):
        """Verify SYN flood rule generates immediate DoS mitigation steps."""
        rec = get_recommended_response(
            rule_id="NIDS_RULE_002",
            title="TCP SYN Flood Detected",
            severity="CRITICAL",
            evidence={"syn_packet_count": 150},
            source_ip="10.0.0.99",
        )
        self.assertEqual(rec.priority, ActionPriority.IMMEDIATE)
        self.assertIn("syn cookies", rec.recommended_action.lower())
        self.assertIn("10.0.0.99", rec.suggested_firewall_rule)

    def test_traffic_spike_recommendation(self):
        """Verify Traffic Spike rule advises flow volume inspection and backup verification."""
        rec = get_recommended_response(
            rule_id="NIDS_RULE_003",
            title="Traffic Spike Detected",
            severity="MEDIUM",
            evidence={"window_bytes": 10500000},
            source_ip="172.16.0.5",
        )
        self.assertIn("exfiltration", rec.recommended_action.lower())
        self.assertIn("backup", rec.suggested_mitigation.lower())

    def test_suricata_malware_recommendation(self):
        """Verify Suricata malware signature generates immediate endpoint isolation guidance."""
        rec = get_recommended_response(
            rule_id="SURICATA_2010935",
            title="ET TROJAN Cobalt Strike Beacon Observed",
            severity="CRITICAL",
            source_ip="192.168.1.45",
        )
        self.assertEqual(rec.priority, ActionPriority.IMMEDIATE)
        self.assertIn("isolate", rec.recommended_action.lower())
        self.assertIn("memory dump", rec.suggested_mitigation.lower())

    def test_suricata_protocol_anomaly_recommendation(self):
        """Verify protocol anomaly generates header review advice."""
        rec = get_recommended_response(
            rule_id="SURICATA_2200029",
            title="SURICATA TLS Certificate Invalid Chain",
            severity="MEDIUM",
            source_ip="203.0.113.8",
        )
        self.assertIn("certificate", rec.recommended_action.lower())
        self.assertIn("tls", rec.suggested_mitigation.lower())


class TestSafeIPBlockingManager(unittest.TestCase):
    """Verify safety controls, reversibility, and validation in IPBlockingManager."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_blocking.sqlite")
        self.db = Database(self.db_path)
        self.manager = IPBlockingManager(database=self.db, enabled=True, simulation_mode=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_disabled_by_default_rejects_action(self):
        """Verify blocking is rejected when manager is disabled."""
        disabled_mgr = IPBlockingManager(database=self.db, enabled=False, simulation_mode=True)
        with self.assertRaises(PermissionError):
            disabled_mgr.block_ip("198.51.100.1", reason="Test", authorized=True)

    def test_unauthorized_call_rejected(self):
        """Verify blocking is rejected when explicit user authorization is absent."""
        with self.assertRaises(ValueError) as ctx:
            self.manager.block_ip("198.51.100.1", reason="Test", authorized=False)
        self.assertIn("authorization", str(ctx.exception).lower())

    def test_protected_addresses_strictly_rejected(self):
        """Verify loopback, broadcast, link-local, and multicast cannot be blocked."""
        protected_ips = [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "169.254.1.1",
            "invalid_ip_string",
        ]
        for ip in protected_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    self.manager.block_ip(ip, reason="Test", authorized=True)

    def test_successful_simulation_block_and_reversibility(self):
        """Verify successful block in simulation mode and clean reversible unblock."""
        target_ip = "198.51.100.42"
        rec = self.manager.block_ip(
            ip_address=target_ip,
            reason="Port scan reconnaissance",
            alert_id=1,
            analyst="SOC Lead",
            authorized=True,
        )

        self.assertEqual(rec.ip_address, target_ip)
        self.assertEqual(rec.status, BlockStatus.ACTIVE)
        self.assertTrue(rec.is_simulated)
        self.assertTrue(self.manager.is_ip_blocked(target_ip))
        self.assertIn("netsh", rec.command_preview)

        # Verify active listing
        active_blocks = self.manager.list_blocked_ips(active_only=True)
        self.assertEqual(len(active_blocks), 1)
        self.assertEqual(active_blocks[0]["ip_address"], target_ip)

        # Reversible Unblock
        unblocked = self.manager.unblock_ip(target_ip, analyst="SOC Lead", authorized=True)
        self.assertTrue(unblocked)
        self.assertFalse(self.manager.is_ip_blocked(target_ip))

        # Check unblock history
        all_blocks = self.manager.list_blocked_ips(active_only=False)
        self.assertEqual(len(all_blocks), 1)
        self.assertEqual(all_blocks[0]["status"], "REMOVED")
        self.assertIsNotNone(all_blocks[0]["unblocked_at"])


class TestIncidentResponseRoutes(unittest.TestCase):
    """Verify Flask REST API response endpoints, headers, and security controls."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_routes.sqlite")

        class TestConfig(Config):
            TESTING = True
            DATABASE_PATH = self.db_path
            RESPONSE_BLOCKING_ENABLED = True
            BLOCKING_SIMULATION_MODE = True

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

        # Insert a sample alert
        self.alert_id = self.app.db_manager.insert_alert({
            "title": "Port Scan Detected",
            "rule_id": "NIDS_RULE_001",
            "severity": "HIGH",
            "source_ip": "198.51.100.77",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "description": "25 ports scanned in 5 seconds",
            "status": "NEW",
        })

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_security_headers_present(self):
        """Verify defense-in-depth security headers are present on all responses."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertIn("Content-Security-Policy", res.headers)

    def test_get_alert_recommendation_endpoint(self):
        """Verify GET /api/alerts/<id>/recommendation returns explainable guidance."""
        res = self.client.get(f"/api/alerts/{self.alert_id}/recommendation")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("reconnaissance", data["recommendation"]["recommended_action"].lower())

    def test_acknowledge_and_resolve_with_analyst_notes(self):
        """Verify alert status transition records analyst notes and responder identity."""
        res = self.client.post(
            f"/api/alerts/{self.alert_id}/acknowledge",
            json={"notes": "Investigating host ownership", "responder": "Analyst Alice"},
        )
        self.assertEqual(res.status_code, 200)
        alert = res.get_json()["alert"]
        self.assertEqual(alert["status"], "ACKNOWLEDGED")
        self.assertEqual(alert["response_notes"], "Investigating host ownership")
        self.assertEqual(alert["responder"], "Analyst Alice")

        # Resolve with final resolution notes
        res2 = self.client.post(
            f"/api/alerts/{self.alert_id}/resolve",
            json={"notes": "Authorized vulnerability scan confirmed", "responder": "Analyst Alice"},
        )
        self.assertEqual(res2.status_code, 200)
        alert2 = res2.get_json()["alert"]
        self.assertEqual(alert2["status"], "RESOLVED")
        self.assertEqual(alert2["response_notes"], "Authorized vulnerability scan confirmed")

    def test_respond_workflow_with_manual_block(self):
        """Verify complete incident response workflow with explicit authorized IP block."""
        res = self.client.post(
            f"/api/alerts/{self.alert_id}/respond",
            json={
                "action": "ACKNOWLEDGE",
                "notes": "Host confirmed malicious; applying containment",
                "responder": "SOC Tier 2",
                "block_ip": True,
                "authorized": True,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIsNotNone(data["blocked_ip"])
        self.assertEqual(data["blocked_ip"]["ip_address"], "198.51.100.77")
        self.assertTrue(data["blocked_ip"]["is_simulated"])

    def test_response_status_and_block_ip_endpoints(self):
        """Verify GET /api/response/status and manual block/unblock endpoints."""
        status_res = self.client.get("/api/response/status")
        self.assertEqual(status_res.status_code, 200)
        self.assertTrue(status_res.get_json()["enabled"])

        # Manual block
        block_res = self.client.post(
            "/api/response/block-ip",
            json={"ip": "203.0.113.99", "reason": "Threat intel feed match", "authorized": True},
        )
        self.assertEqual(block_res.status_code, 200)

        # Unblock
        unblock_res = self.client.post(
            "/api/response/unblock-ip",
            json={"ip": "203.0.113.99", "authorized": True},
        )
        self.assertEqual(unblock_res.status_code, 200)

    def test_path_traversal_rejection_in_ingest_sample(self):
        """Verify path traversal attempts in sample fixture ingestion are blocked."""
        malicious_paths = [
            "../../../../Windows/win.ini",
            "C:\\Windows\\System32\\cmd.exe",
            "../../../etc/passwd",
        ]
        for path in malicious_paths:
            with self.subTest(path=path):
                res = self.client.post(
                    "/api/suricata/ingest-sample",
                    json={"sample_path": path},
                )
                self.assertIn(res.status_code, (400, 403, 404))
                if res.status_code == 403:
                    self.assertIn("traversal", res.get_json()["message"].lower())


class TestPacketStructureAnalysis(unittest.TestCase):
    """Verify basic packet structure analysis and zero payload storage in PacketMetadata."""

    def test_packet_structure_hierarchy_extraction(self):
        """Verify layer hierarchy and IP version are extracted without storing raw payloads."""
        pkt = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=443, flags="S")
        meta = extract_metadata(pkt, interface_name="eth0")

        self.assertEqual(meta.ip_version, 4)
        self.assertIn("Ether", meta.layers)
        self.assertIn("IP", meta.layers)
        self.assertIn("TCP", meta.layers)

        # Verify serialization includes structure
        d = meta.to_dict()
        self.assertEqual(d["ip_version"], 4)
        self.assertEqual(d["layers"], meta.layers)
        # Verify no raw payload field is stored
        self.assertNotIn("payload", d)
        self.assertNotIn("raw", d)

    def test_ipv6_structure_extraction(self):
        """Verify IPv6 structure identification."""
        pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5000, dport=5000)
        meta = extract_metadata(pkt)

        self.assertEqual(meta.ip_version, 6)
        self.assertIn("IPv6", meta.layers)
        self.assertIn("UDP", meta.layers)


if __name__ == "__main__":
    unittest.main()
