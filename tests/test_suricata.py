"""Tests for Suricata Deep Inspection Integration (Phase 8).

Verifies:
1. Safe line-by-line EVE JSON parsing (alert, dns, http, tls, flow, anomaly).
2. Robustness against malformed JSON, empty lines, and comments.
3. Severity mapping from Suricata 1-4 to standardized NIDS Severity.
4. Schema translation from EveRecord to DetectionEvent (confidence="SURICATA_SIGNATURE").
5. Incremental file tailing and byte offset tracking with EveLogReader.
6. Partial line buffering and newline boundary protection.
7. File rotation and truncation detection (size shrinkage reset).
8. State persistence across reader instances via JSON state file.
9. SuricataService background worker lifecycle (start/stop) and poll_once.
10. One-shot batch ingestion and sample fixture processing.
11. Asynchronous SQLite alert persistence integration.
12. Flask REST endpoints (/api/suricata/status, /api/suricata/ingest-sample).
13. Alert filtering by confidence="SURICATA_SIGNATURE".
"""

import json
import os
import shutil
import tempfile
import time
import unittest

from config import Config
from nids.detection.models import DetectionEvent, Severity
from nids.storage import AlertRepository, AsyncAlertWriter, Database, DatabaseManager
from nids.suricata import (
    EveAlertData,
    EveEventType,
    EveLogReader,
    EveRecord,
    SuricataService,
    eve_to_detection_event,
    map_suricata_severity,
    parse_eve_line,
)
from nids.web import create_app


class TestEveParserAndMapping(unittest.TestCase):
    """Unit tests for EVE JSON parsing and DetectionEvent schema conversion."""

    def test_parse_valid_alert_event(self):
        """1. Verify parsing of complete Suricata alert JSON record."""
        raw = json.dumps({
            "timestamp": "2026-11-14T12:00:00.123456+0000",
            "flow_id": 1844674407370955161,
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "src_port": 54321,
            "dest_ip": "10.0.0.1",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2010935,
                "rev": 3,
                "signature": "ET SCAN Potential SSH Brute Force",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        })

        record = parse_eve_line(raw)
        self.assertIsNotNone(record)
        self.assertEqual(record.event_type, EveEventType.ALERT)
        self.assertTrue(record.is_alert())
        self.assertEqual(record.src_ip, "192.168.1.100")
        self.assertEqual(record.src_port, 54321)
        self.assertEqual(record.dest_ip, "10.0.0.1")
        self.assertEqual(record.dest_port, 22)
        self.assertEqual(record.proto, "TCP")
        self.assertEqual(record.alert.signature_id, 2010935)
        self.assertEqual(record.alert.category, "Attempted Information Leak")
        self.assertEqual(record.alert.severity, 2)

    def test_parse_telemetry_events(self):
        """2. Verify parsing of DNS, HTTP, TLS, Flow, and Anomaly records."""
        # DNS
        dns_raw = json.dumps({
            "timestamp": "2026-11-14T12:00:01.000000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.50",
            "dest_ip": "8.8.8.8",
            "proto": "UDP",
            "dns": {"type": "query", "rrname": "c2.evil.com", "rrtype": "A"},
        })
        dns_rec = parse_eve_line(dns_raw)
        self.assertIsNotNone(dns_rec)
        self.assertEqual(dns_rec.event_type, EveEventType.DNS)
        self.assertFalse(dns_rec.is_alert())
        self.assertEqual(dns_rec.dns["rrname"], "c2.evil.com")

        # HTTP
        http_raw = json.dumps({
            "timestamp": "2026-11-14T12:00:02.000000+0000",
            "event_type": "http",
            "src_ip": "192.168.1.50",
            "dest_ip": "1.2.3.4",
            "proto": "TCP",
            "http": {"hostname": "evil.com", "url": "/beacon", "http_method": "GET", "status": 200},
        })
        http_rec = parse_eve_line(http_raw)
        self.assertEqual(http_rec.event_type, EveEventType.HTTP)
        self.assertEqual(http_rec.http["url"], "/beacon")

        # TLS
        tls_raw = json.dumps({
            "timestamp": "2026-11-14T12:00:03.000000+0000",
            "event_type": "tls",
            "src_ip": "192.168.1.50",
            "dest_ip": "1.2.3.4",
            "proto": "TCP",
            "tls": {"sni": "secure.bank.com", "version": "TLSv1.3"},
        })
        tls_rec = parse_eve_line(tls_raw)
        self.assertEqual(tls_rec.event_type, EveEventType.TLS)
        self.assertEqual(tls_rec.tls["sni"], "secure.bank.com")

        # Flow
        flow_raw = json.dumps({
            "timestamp": "2026-11-14T12:00:04.000000+0000",
            "event_type": "flow",
            "proto": "TCP",
            "flow": {"pkts_toserver": 10, "bytes_toserver": 1000, "state": "closed"},
        })
        flow_rec = parse_eve_line(flow_raw)
        self.assertEqual(flow_rec.event_type, EveEventType.FLOW)

        # Anomaly
        anom_raw = json.dumps({
            "timestamp": "2026-11-14T12:00:05.000000+0000",
            "event_type": "anomaly",
            "proto": "TCP",
            "anomaly": {"event": "STREAM_BAD_WINDOW"},
        })
        anom_rec = parse_eve_line(anom_raw)
        self.assertEqual(anom_rec.event_type, EveEventType.ANOMALY)

    def test_parser_resilience_to_malformed_input(self):
        """3. Verify parser skips empty, comment, and corrupted lines without crashing."""
        self.assertIsNone(parse_eve_line(""))
        self.assertIsNone(parse_eve_line("   \n"))
        self.assertIsNone(parse_eve_line("# This is a comment"))
        self.assertIsNone(parse_eve_line("{ broken json line"))
        self.assertIsNone(parse_eve_line('{"incomplete": true,'))
        self.assertIsNone(parse_eve_line("[1, 2, 3]"))  # JSON array instead of dict

    def test_severity_mapping(self):
        """4. Verify Suricata 1-4 numeric and string severities map accurately."""
        self.assertEqual(map_suricata_severity(1), Severity.CRITICAL)
        self.assertEqual(map_suricata_severity(2), Severity.HIGH)
        self.assertEqual(map_suricata_severity(3), Severity.MEDIUM)
        self.assertEqual(map_suricata_severity(4), Severity.LOW)
        self.assertEqual(map_suricata_severity("1"), Severity.CRITICAL)
        self.assertEqual(map_suricata_severity("HIGH"), Severity.HIGH)
        self.assertEqual(map_suricata_severity("UNKNOWN"), Severity.INFO)
        self.assertEqual(map_suricata_severity(None), Severity.INFO)

    def test_eve_to_detection_event_mapping(self):
        """5. Verify alert EveRecord transforms into standardized DetectionEvent."""
        raw = json.dumps({
            "timestamp": "2026-11-14T10:15:26.678901+0000",
            "flow_id": 567890,
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": "10.0.0.45",
            "src_port": 4444,
            "dest_ip": "192.168.1.200",
            "dest_port": 445,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "gid": 1,
                "signature_id": 2024217,
                "rev": 2,
                "signature": "ET EXPLOIT SMBv3 Remote Code Execution",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
            "flow": {"pkts_toserver": 4, "bytes_toserver": 420},
        })
        record = parse_eve_line(raw)
        event = eve_to_detection_event(record)

        self.assertIsNotNone(event)
        self.assertEqual(event.rule_id, "SURICATA-2024217")
        self.assertEqual(event.detection_name, "ET EXPLOIT SMBv3 Remote Code Execution")
        self.assertEqual(event.severity, Severity.CRITICAL)
        self.assertEqual(event.confidence, "SURICATA_SIGNATURE")
        self.assertEqual(event.source_ip, "10.0.0.45")
        self.assertEqual(event.destination_ip, "192.168.1.200")
        self.assertEqual(event.protocol, "TCP")
        self.assertIn("Attempted Administrator Privilege Gain", event.description)
        self.assertIn("suricata:2024217:10.0.0.45:192.168.1.200", event.deduplication_key)

        # Evidence dictionary verification (metadata only, zero raw frame bytes)
        self.assertEqual(event.evidence["suricata_sid"], 2024217)
        self.assertEqual(event.evidence["source_port"], 4444)
        self.assertEqual(event.evidence["destination_port"], 445)
        self.assertEqual(event.evidence["flow_summary"]["pkts_toserver"], 4)
        self.assertNotIn("raw_packet", event.evidence)

    def test_non_alert_returns_none_for_detection_event(self):
        """6. Verify telemetry events (DNS/HTTP/TLS) do not convert to DetectionEvents."""
        raw = json.dumps({
            "timestamp": "2026-11-14T10:15:20.000000+0000",
            "event_type": "dns",
            "dns": {"rrname": "example.com"},
        })
        record = parse_eve_line(raw)
        self.assertIsNone(eve_to_detection_event(record))


class TestEveLogReader(unittest.TestCase):
    """Unit tests for incremental file reading, offset tracking, and rotation handling."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_eve_reader_")
        self.eve_path = os.path.join(self.test_dir, "test_eve.json")
        self.state_path = os.path.join(self.test_dir, "offset_state.json")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_reader_handles_missing_file_gracefully(self):
        """7. Verify reading a non-existent file returns empty list without error."""
        reader = EveLogReader(file_path=os.path.join(self.test_dir, "does_not_exist.json"))
        lines = reader.read_new_lines()
        self.assertEqual(lines, [])
        self.assertEqual(reader.offset, 0)

    def test_incremental_line_reading_and_offset_tracking(self):
        """8. Verify lines are read incrementally and offset advances correctly."""
        reader = EveLogReader(file_path=self.eve_path)

        # Write first line
        with open(self.eve_path, "wb") as f:
            f.write(b'{"line": 1}\n')

        lines = reader.read_new_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], '{"line": 1}')
        first_offset = reader.offset
        self.assertGreater(first_offset, 0)

        # Calling again with no new data
        lines_empty = reader.read_new_lines()
        self.assertEqual(lines_empty, [])
        self.assertEqual(reader.offset, first_offset)

        # Append second line
        with open(self.eve_path, "ab") as f:
            f.write(b'{"line": 2}\n')

        lines_second = reader.read_new_lines()
        self.assertEqual(len(lines_second), 1)
        self.assertEqual(lines_second[0], '{"line": 2}')
        self.assertGreater(reader.offset, first_offset)

    def test_partial_line_buffering(self):
        """9. Verify incomplete lines without newline are not consumed until completed."""
        reader = EveLogReader(file_path=self.eve_path)

        # Write complete line followed by partial line
        with open(self.eve_path, "wb") as f:
            f.write(b'{"complete": 1}\n{"partial":')

        lines = reader.read_new_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], '{"complete": 1}')

        # Complete the partial line
        with open(self.eve_path, "ab") as f:
            f.write(b' "finished"}\n')

        lines2 = reader.read_new_lines()
        self.assertEqual(len(lines2), 1)
        self.assertEqual(lines2[0], '{"partial": "finished"}')

    def test_file_rotation_and_truncation_detection(self):
        """10. Verify file truncation resets offset to 0 and reads fresh records."""
        reader = EveLogReader(file_path=self.eve_path)

        # Write large content
        with open(self.eve_path, "wb") as f:
            for i in range(10):
                f.write(f'{{"record": {i}}}\n'.encode("utf-8"))

        lines = reader.read_new_lines()
        self.assertEqual(len(lines), 10)
        old_offset = reader.offset

        # Truncate file (simulating log rotation / overwrite)
        with open(self.eve_path, "wb") as f:
            f.write(b'{"rotated": true}\n')

        # Size is now much smaller than old_offset
        lines_rotated = reader.read_new_lines()
        self.assertEqual(len(lines_rotated), 1)
        self.assertEqual(lines_rotated[0], '{"rotated": true}')
        self.assertLess(reader.offset, old_offset)

    def test_state_persistence_across_instances(self):
        """11. Verify offset state is saved to JSON and restored by new reader instance."""
        reader1 = EveLogReader(file_path=self.eve_path, state_path=self.state_path)

        with open(self.eve_path, "wb") as f:
            f.write(b'{"init": 1}\n{"init": 2}\n')

        reader1.read_new_lines()
        saved_offset = reader1.offset
        self.assertTrue(os.path.exists(self.state_path))

        # Instantiate brand new reader pointing to same state file
        reader2 = EveLogReader(file_path=self.eve_path, state_path=self.state_path)
        self.assertEqual(reader2.offset, saved_offset)

        # Append new line
        with open(self.eve_path, "ab") as f:
            f.write(b'{"init": 3}\n')

        new_lines = reader2.read_new_lines()
        self.assertEqual(len(new_lines), 1)
        self.assertEqual(new_lines[0], '{"init": 3}')


class TestSuricataServiceIntegration(unittest.TestCase):
    """Integration tests for SuricataService background worker and SQLite persistence."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_suricata_svc_")
        self.db_path = os.path.join(self.test_dir, "suricata_test.sqlite")
        self.eve_path = os.path.join(self.test_dir, "live_eve.json")
        self.sample_path = os.path.join(self.test_dir, "sample_fixture.json")

        self.db = Database(self.db_path)
        self.repo = AlertRepository(self.db)
        self.writer = AsyncAlertWriter(self.repo, max_queue_size=100)
        self.writer.start()

        # Seed sample fixture file
        sample_records = [
            json.dumps({
                "timestamp": "2026-11-14T10:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "192.168.1.10",
                "src_port": 12345,
                "dest_ip": "10.0.0.1",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {
                    "gid": 1,
                    "signature_id": 2011111,
                    "rev": 1,
                    "signature": "ET TROJAN Sample C2 Traffic",
                    "category": "A Network Trojan was detected",
                    "severity": 1,
                    "action": "allowed",
                },
            }),
            json.dumps({
                "timestamp": "2026-11-14T10:00:01.000000+0000",
                "event_type": "dns",
                "src_ip": "192.168.1.10",
                "dest_ip": "8.8.8.8",
                "proto": "UDP",
                "dns": {"rrname": "c2.test.local"},
            }),
            json.dumps({
                "timestamp": "2026-11-14T10:00:02.000000+0000",
                "event_type": "alert",
                "src_ip": "192.168.1.20",
                "src_port": 54321,
                "dest_ip": "10.0.0.2",
                "dest_port": 443,
                "proto": "TCP",
                "alert": {
                    "gid": 1,
                    "signature_id": 2022222,
                    "rev": 2,
                    "signature": "ET SCAN Suspicious Port Sweep",
                    "category": "Attempted Information Leak",
                    "severity": 2,
                    "action": "allowed",
                },
            }),
        ]
        with open(self.sample_path, "w", encoding="utf-8") as f:
            for rec in sample_records:
                f.write(rec + "\n")

    def tearDown(self):
        self.writer.stop(timeout=3.0)
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_service_lifecycle_and_poll_once(self):
        """12. Verify service start, stop, and polling against live file."""
        captured_alerts = []

        service = SuricataService(
            eve_path=self.eve_path,
            sample_path=self.sample_path,
            on_alert=lambda ev: captured_alerts.append(ev),
            poll_interval=0.1,
        )

        self.assertFalse(service.is_running)
        service.start()
        self.assertTrue(service.is_running)

        # Write alert to live eve file
        with open(self.eve_path, "wb") as f:
            f.write(json.dumps({
                "timestamp": "2026-11-14T11:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "10.10.10.10",
                "dest_ip": "10.10.10.1",
                "alert": {"signature_id": 2033333, "signature": "Live Alert Test", "severity": 1},
            }).encode("utf-8") + b"\n")

        # Give tailer worker a brief moment to poll
        time.sleep(0.3)
        service.stop(timeout=2.0)
        self.assertFalse(service.is_running)

        self.assertGreaterEqual(len(captured_alerts), 1)
        self.assertEqual(captured_alerts[0].rule_id, "SURICATA-2033333")
        self.assertEqual(captured_alerts[0].confidence, "SURICATA_SIGNATURE")

    def test_sample_fixture_ingestion_and_sqlite_persistence(self):
        """13. Verify batch sample ingestion persists mapped alerts to SQLite via AsyncAlertWriter."""
        service = SuricataService(
            eve_path=self.eve_path,
            sample_path=self.sample_path,
            on_alert=self.writer.enqueue,
        )

        res = service.ingest_sample_fixture()
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["lines_read"], 3)
        self.assertEqual(res["events_parsed"], 3)
        self.assertEqual(res["alerts_persisted"], 2)

        # Wait for async writer to persist alerts
        time.sleep(0.2)

        # Verify DB records
        alerts = self.repo.get_recent_alerts(limit=10)
        self.assertEqual(len(alerts), 2)

        # Verify fields in DB
        alert_sids = {a["rule_id"] for a in alerts}
        self.assertIn("SURICATA-2011111", alert_sids)
        self.assertIn("SURICATA-2022222", alert_sids)

        for a in alerts:
            self.assertEqual(a["confidence"], "SURICATA_SIGNATURE")
            self.assertIn(a["severity"], ("CRITICAL", "HIGH"))

        # Verify status summary
        status = service.get_status()
        self.assertEqual(status["mode"], "fixture")
        self.assertEqual(status["stats"]["alerts_count"], 2)
        self.assertEqual(status["stats"]["dns_count"], 1)


class TestSuricataFlaskAPIRoutes(unittest.TestCase):
    """Integration tests for Suricata web REST API endpoints."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_suricata_routes_")
        self.db_path = os.path.join(self.test_dir, "routes_test.sqlite")
        self.eve_path = os.path.join(self.test_dir, "api_eve.json")
        self.sample_path = os.path.join(self.test_dir, "api_sample.json")

        # Create controlled test sample
        sample_line = json.dumps({
            "timestamp": "2026-11-14T12:30:00.000000+0000",
            "event_type": "alert",
            "src_ip": "172.16.0.5",
            "src_port": 3389,
            "dest_ip": "10.0.0.99",
            "dest_port": 50000,
            "proto": "TCP",
            "alert": {
                "gid": 1,
                "signature_id": 2099999,
                "rev": 1,
                "signature": "ET SCAN RDP Exploit Attempt",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
        })
        with open(self.sample_path, "w", encoding="utf-8") as f:
            f.write(sample_line + "\n")

        class RouteTestConfig(Config):
            TESTING = True
            DATABASE_PATH = self.db_path
            SURICATA_EVE_PATH = self.eve_path
            SURICATA_SAMPLE_PATH = self.sample_path
            SURICATA_ENABLED = False

        self.app = create_app(RouteTestConfig)
        self.client = self.app.test_client()

    def tearDown(self):
        if hasattr(self.app, "suricata_service"):
            self.app.suricata_service.stop()
        if hasattr(self.app, "db_manager"):
            self.app.db_manager.stop_worker()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_suricata_status_endpoint(self):
        """14. Verify GET /api/suricata/status returns service operational metadata."""
        res = self.client.get("/api/suricata/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["status"], "success")
        self.assertIn("mode", data)
        self.assertIn("file_offset", data)
        self.assertIn("stats", data)
        self.assertIn("total_lines_read", data["stats"])
        self.assertIn("alerts_count", data["stats"])

    def test_post_ingest_sample_endpoint(self):
        """15. Verify POST /api/suricata/ingest-sample triggers fixture ingestion and persistence."""
        res = self.client.post("/api/suricata/ingest-sample")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["ingestion"]["events_parsed"], 1)
        self.assertEqual(data["ingestion"]["alerts_persisted"], 1)

        # Verify alert appears in /api/alerts
        res_alerts = self.client.get("/api/alerts")
        self.assertEqual(res_alerts.status_code, 200)
        alerts_data = res_alerts.get_json()
        self.assertEqual(alerts_data["total"], 1)
        self.assertEqual(alerts_data["alerts"][0]["rule_id"], "SURICATA-2099999")
        self.assertEqual(alerts_data["alerts"][0]["confidence"], "SURICATA_SIGNATURE")

    def test_filter_alerts_by_confidence_suricata(self):
        """16. Verify GET /api/alerts?confidence=SURICATA_SIGNATURE isolates signature alerts."""
        # 1. Ingest Suricata sample
        self.client.post("/api/suricata/ingest-sample")

        # 2. Insert heuristic alert
        self.app.db_manager.insert_detection_event(
            DetectionEvent.create(
                rule_id="RULE-PORT-SCAN",
                detection_name="Heuristic Port Scan",
                severity=Severity.HIGH,
                description="Heuristic test alert",
                evidence={},
                threshold_used=20,
                confidence="HEURISTIC_INDICATOR",
            )
        )

        # 3. Query all alerts
        res_all = self.client.get("/api/alerts")
        self.assertEqual(res_all.get_json()["total"], 2)

        # 4. Filter by confidence=SURICATA_SIGNATURE
        res_suricata = self.client.get("/api/alerts?confidence=SURICATA_SIGNATURE")
        data_s = res_suricata.get_json()
        self.assertEqual(data_s["total"], 1)
        self.assertEqual(data_s["alerts"][0]["confidence"], "SURICATA_SIGNATURE")

        # 5. Filter by confidence=HEURISTIC_INDICATOR
        res_heur = self.client.get("/api/alerts?confidence=HEURISTIC_INDICATOR")
        data_h = res_heur.get_json()
        self.assertEqual(data_h["total"], 1)
        self.assertEqual(data_h["alerts"][0]["confidence"], "HEURISTIC_INDICATOR")

    def test_system_status_reflects_suricata_integration(self):
        """17. Verify GET /api/system/status reports suricata_integrated=True with telemetry."""
        res = self.client.get("/api/system/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data["suricata_integrated"])
        self.assertIn("suricata", data)
        self.assertIn("mode", data["suricata"])
        self.assertTrue(data["phase"].startswith("Phase 8"))


if __name__ == "__main__":
    unittest.main()

