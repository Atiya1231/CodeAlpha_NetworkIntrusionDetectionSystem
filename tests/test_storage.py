"""Tests for Phase 6: Persistent SQLite Alert Management and Web APIs.

Verifies:
1. SQLite connection lifecycle, PRAGMAs (WAL mode, timeouts), and transactions.
2. Idempotent schema initialization and table migration on existing databases.
3. AlertRepository CRUD operations, JSON serialization, and status transitions.
4. Bounded asynchronous alert writer lifecycle, graceful shutdown, capacity drops, and error handling.
5. Thread-safe concurrent writes under simulated load.
6. Passive DetectionEngine integration with automatic persistence via on_event callback.
7. Flask REST API endpoints:
   - GET /api/alerts (with pagination, all filters, parameter validation, sensible page clamping)
   - GET /api/alerts/<id>
   - POST & PATCH /api/alerts/<id>/acknowledge (valid and prohibited transitions)
   - POST & PATCH /api/alerts/<id>/resolve (valid and prohibited transitions)
   - GET /api/alerts/stats (dedicated statistics endpoint)
   - GET /api/stats/summary (backward compatibility)
   - GET /api/system/status
"""

import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from config import Config
from nids.capture.metadata import PacketMetadata
from nids.detection.engine import DetectionEngine
from nids.detection.models import DetectionEvent, Severity
from nids.detection.rules import PortScanRule
from nids.storage import AlertRepository, AlertStatus, AsyncAlertWriter, Database, DatabaseManager
from nids.web import create_app


class TestDatabaseEngine(unittest.TestCase):
    """Unit tests for low-level SQLite Database engine and migrations."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_test_db_")
        self.db_path = os.path.join(self.test_dir, "test.sqlite")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_db_initialization_fresh(self):
        """1. Verify tables and indices are created cleanly on a new database."""
        db = Database(self.db_path)
        with db.connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cursor.fetchall()}
            self.assertIn("alerts", tables)
            self.assertIn("traffic_stats", tables)

            cursor = conn.execute("PRAGMA table_info(alerts)")
            columns = {row["name"] for row in cursor.fetchall()}
            expected_columns = {
                "id", "event_id", "rule_id", "title", "severity",
                "source_ip", "source_port", "destination_ip", "destination_port",
                "protocol", "timestamp", "description", "raw_evidence",
                "evidence", "threshold_used", "confidence", "deduplication_key",
                "status", "created_at", "updated_at", "acknowledged_at", "resolved_at"
            }
            self.assertTrue(expected_columns.issubset(columns))

    def test_db_idempotent_migration_on_legacy_schema(self):
        """2. Verify missing columns are added idempotently without dropping existing rows."""
        # Create a legacy Phase 1 table without Phase 6 columns
        legacy_sql = """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            timestamp TEXT NOT NULL,
            description TEXT NOT NULL,
            raw_evidence TEXT
        );
        INSERT INTO alerts (title, severity, timestamp, description)
        VALUES ('Legacy Port Scan', 'HIGH', '2026-11-14T10:00:00Z', 'Legacy alert payload');
        """
        conn = sqlite3.connect(self.db_path)
        conn.executescript(legacy_sql)
        conn.close()

        # Initialize Database which triggers schema migration
        db = Database(self.db_path)

        with db.connection() as c:
            # Verify legacy row is preserved
            cur = c.execute("SELECT * FROM alerts WHERE id = 1")
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["title"], "Legacy Port Scan")
            self.assertEqual(row["status"], "NEW")

            # Verify all new columns exist
            cur_info = c.execute("PRAGMA table_info(alerts)")
            cols = {r["name"] for r in cur_info.fetchall()}
            self.assertIn("event_id", cols)
            self.assertIn("rule_id", cols)
            self.assertIn("evidence", cols)
            self.assertIn("status", cols)

    def test_pragmas_and_row_factory(self):
        """3. Verify connection PRAGMAs and row factory configuration."""
        db = Database(self.db_path)
        with db.connection() as conn:
            cur = conn.execute("PRAGMA foreign_keys")
            self.assertEqual(cur.fetchone()[0], 1)
            # Verify Row access by name
            cur_row = conn.execute("SELECT 1 AS test_val")
            row = cur_row.fetchone()
            self.assertEqual(row["test_val"], 1)

    def test_atomic_transaction_rollback(self):
        """4. Verify atomic rollback on unhandled exception within transaction."""
        db = Database(self.db_path)

        with self.assertRaises(RuntimeError):
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO alerts (title, severity, timestamp, description, created_at, updated_at) "
                    "VALUES ('Temp Alert', 'LOW', '2026-11-14', 'Test', '2026-11-14', '2026-11-14')"
                )
                raise RuntimeError("Simulated transaction failure")

        with db.connection() as conn:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE title = 'Temp Alert'")
            self.assertEqual(cur.fetchone()["cnt"], 0)


class TestAlertRepositoryCRUD(unittest.TestCase):
    """Unit tests for AlertRepository operations, filtering, and status transitions."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_repo_test_")
        self.db_path = os.path.join(self.test_dir, "repo_test.sqlite")
        self.db = Database(self.db_path)
        self.repo = AlertRepository(self.db)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _sample_detection_event(
        self,
        rule_id: str = "RULE-PORT-SCAN",
        severity: Severity = Severity.HIGH,
        source_ip: str = "192.168.1.100",
        destination_ip: str = "192.168.1.50",
        timestamp: float = 1700000000.0,
    ) -> DetectionEvent:
        return DetectionEvent.create(
            rule_id=rule_id,
            detection_name="Port Scan Detected",
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="TCP",
            description="Host probed 15 distinct ports in 3.2 seconds",
            evidence={"probed_ports": [22, 80, 443, 8080], "distinct_port_count": 4},
            threshold_used=10,
            confidence="HIGH_CONFIDENCE_HEURISTIC",
            deduplication_key=f"{source_ip}:{destination_ip}:scan",
            timestamp=timestamp,
        )

    def test_insert_and_retrieve_detection_event(self):
        """5. Verify inserting DetectionEvent populates all fields correctly."""
        event = self._sample_detection_event()
        row_id = self.repo.insert_detection_event(event)
        self.assertGreater(row_id, 0)

        alert = self.repo.get_alert_by_id(row_id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["event_id"], event.event_id)
        self.assertEqual(alert["rule_id"], event.rule_id)
        self.assertEqual(alert["title"], event.detection_name)
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["source_ip"], "192.168.1.100")
        self.assertEqual(alert["destination_ip"], "192.168.1.50")
        self.assertEqual(alert["protocol"], "TCP")
        self.assertEqual(alert["status"], AlertStatus.NEW.value)
        self.assertEqual(alert["evidence_parsed"]["distinct_port_count"], 4)

    def test_get_alert_by_event_id(self):
        """6. Verify retrieving alert by unique event_id string."""
        event = self._sample_detection_event()
        self.repo.insert_detection_event(event)

        alert = self.repo.get_alert_by_event_id(event.event_id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["event_id"], event.event_id)

        # Nonexistent event_id returns None
        self.assertIsNone(self.repo.get_alert_by_event_id("non-existent-uuid"))

    def test_backward_compatible_insert_alert(self):
        """7. Verify insert_alert accepts legacy dictionary format."""
        legacy_data = {
            "title": "Legacy SYN Alert",
            "severity": "CRITICAL",
            "source_ip": "10.0.0.1",
            "source_port": 12345,
            "destination_ip": "10.0.0.2",
            "destination_port": 80,
            "protocol": "TCP",
            "description": "Flooding SYN packets detected",
        }
        row_id = self.repo.insert_alert(legacy_data)
        self.assertGreater(row_id, 0)

        alert = self.repo.get_alert_by_id(row_id)
        self.assertEqual(alert["title"], "Legacy SYN Alert")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["status"], "NEW")

    def test_get_recent_alerts_filtering_and_pagination(self):
        """8. Verify pagination (limit/offset) and filters (severity, status)."""
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL, Severity.HIGH]
        for idx, sev in enumerate(severities):
            ev = self._sample_detection_event(rule_id=f"RULE-{idx}", severity=sev)
            self.repo.insert_detection_event(ev)

        # Total count
        all_alerts = self.repo.get_recent_alerts(limit=10)
        self.assertEqual(len(all_alerts), 5)

        # Pagination: limit 2, offset 1
        page = self.repo.get_recent_alerts(limit=2, offset=1)
        self.assertEqual(len(page), 2)

        # Filter by severity
        high_alerts = self.repo.get_recent_alerts(severity="HIGH")
        self.assertEqual(len(high_alerts), 2)
        for a in high_alerts:
            self.assertEqual(a["severity"], "HIGH")

    def test_filter_by_rule_id_and_ips(self):
        """9. Verify filtering by rule_id, source_ip, and destination_ip."""
        self.repo.insert_detection_event(self._sample_detection_event(
            rule_id="RULE-PORT-SCAN", source_ip="192.168.1.10", destination_ip="10.0.0.1"
        ))
        self.repo.insert_detection_event(self._sample_detection_event(
            rule_id="RULE-SYN-FLOOD", source_ip="192.168.1.20", destination_ip="10.0.0.2"
        ))

        # Filter by rule_id
        res_rule = self.repo.get_recent_alerts(rule_id="RULE-PORT-SCAN")
        self.assertEqual(len(res_rule), 1)
        self.assertEqual(res_rule[0]["rule_id"], "RULE-PORT-SCAN")

        # Filter by source_ip
        res_src = self.repo.get_recent_alerts(source_ip="192.168.1.20")
        self.assertEqual(len(res_src), 1)
        self.assertEqual(res_src[0]["source_ip"], "192.168.1.20")

        # Filter by destination_ip
        res_dst = self.repo.get_recent_alerts(destination_ip="10.0.0.1")
        self.assertEqual(len(res_dst), 1)
        self.assertEqual(res_dst[0]["destination_ip"], "10.0.0.1")

    def test_filter_by_date_range(self):
        """10. Verify date range filtering with start_date and end_date."""
        # Insert alert at 2026-01-01T00:00:00Z
        ts1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        # Insert alert at 2026-06-01T00:00:00Z
        ts2 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()

        self.repo.insert_detection_event(self._sample_detection_event(timestamp=ts1))
        self.repo.insert_detection_event(self._sample_detection_event(timestamp=ts2))

        # Filter range covering only ts1
        res1 = self.repo.get_recent_alerts(start_date="2026-01-01", end_date="2026-01-02")
        self.assertEqual(len(res1), 1)

        # Filter range covering both
        res_both = self.repo.get_recent_alerts(start_date="2026-01-01", end_date="2026-06-30")
        self.assertEqual(len(res_both), 2)

    def test_alert_lifecycle_status_transitions(self):
        """11. Verify alert transitions: NEW -> ACKNOWLEDGED -> RESOLVED with timestamps."""
        event = self._sample_detection_event()
        alert_id = self.repo.insert_detection_event(event)

        initial = self.repo.get_alert_by_id(alert_id)
        self.assertEqual(initial["status"], AlertStatus.NEW.value)
        self.assertIsNone(initial["acknowledged_at"])
        self.assertIsNone(initial["resolved_at"])

        # Transition to ACKNOWLEDGED
        ack_success = self.repo.update_alert_status(alert_id, "ACKNOWLEDGED")
        self.assertTrue(ack_success)
        acknowledged = self.repo.get_alert_by_id(alert_id)
        self.assertEqual(acknowledged["status"], AlertStatus.ACKNOWLEDGED.value)
        self.assertIsNotNone(acknowledged["acknowledged_at"])

        # Idempotent acknowledgment
        ack_again = self.repo.update_alert_status(alert_id, "ACKNOWLEDGED")
        self.assertTrue(ack_again)

        # Transition to RESOLVED
        res_success = self.repo.update_alert_status(alert_id, "RESOLVED")
        self.assertTrue(res_success)
        resolved = self.repo.get_alert_by_id(alert_id)
        self.assertEqual(resolved["status"], AlertStatus.RESOLVED.value)
        self.assertIsNotNone(resolved["resolved_at"])

    def test_prohibited_status_transitions_raise(self):
        """12. Verify prohibited transitions (RESOLVED -> ACKNOWLEDGED/NEW, ACKNOWLEDGED -> NEW) raise ValueError."""
        event = self._sample_detection_event()
        alert_id = self.repo.insert_detection_event(event)

        # Resolve the alert directly (shortcut NEW -> RESOLVED)
        self.repo.update_alert_status(alert_id, "RESOLVED")

        # Prohibited: Transition from RESOLVED back to ACKNOWLEDGED
        with self.assertRaises(ValueError) as ctx:
            self.repo.update_alert_status(alert_id, "ACKNOWLEDGED")
        self.assertIn("already resolved", str(ctx.exception))

        # Prohibited: Transition from RESOLVED back to NEW
        with self.assertRaises(ValueError):
            self.repo.update_alert_status(alert_id, "NEW")

        # Create another alert, acknowledge it, and test moving back to NEW
        id2 = self.repo.insert_detection_event(self._sample_detection_event())
        self.repo.update_alert_status(id2, "ACKNOWLEDGED")
        with self.assertRaises(ValueError) as ctx2:
            self.repo.update_alert_status(id2, "NEW")
        self.assertIn("reopening", str(ctx2.exception))

    def test_invalid_status_string_rejection(self):
        """13. Verify attempting to set an unmapped status raises ValueError."""
        event = self._sample_detection_event()
        alert_id = self.repo.insert_detection_event(event)

        with self.assertRaises(ValueError):
            self.repo.update_alert_status(alert_id, "INVALID_STATE")

        # Updating nonexistent alert returns False
        self.assertFalse(self.repo.update_alert_status(99999, "ACKNOWLEDGED"))

    def test_get_alert_statistics_and_summary(self):
        """14. Verify alert statistics and summary compute severity, status, and rule counts accurately."""
        self.repo.insert_detection_event(self._sample_detection_event(rule_id="RULE-PORT-SCAN", severity=Severity.LOW))
        id_high1 = self.repo.insert_detection_event(self._sample_detection_event(rule_id="RULE-PORT-SCAN", severity=Severity.HIGH))
        id_high2 = self.repo.insert_detection_event(self._sample_detection_event(rule_id="RULE-SYN-FLOOD", severity=Severity.HIGH))
        self.repo.insert_detection_event(self._sample_detection_event(rule_id="RULE-TRAFFIC-SPIKE", severity=Severity.CRITICAL))

        # Acknowledge 1, resolve 1
        self.repo.update_alert_status(id_high1, "ACKNOWLEDGED")
        self.repo.update_alert_status(id_high2, "RESOLVED")

        stats = self.repo.get_alert_statistics()
        self.assertEqual(stats["total_alerts"], 4)
        self.assertEqual(stats["new_alerts"], 2)
        self.assertEqual(stats["acknowledged_alerts"], 1)
        self.assertEqual(stats["resolved_alerts"], 1)
        self.assertEqual(stats["severity_counts"]["LOW"], 1)
        self.assertEqual(stats["severity_counts"]["HIGH"], 2)
        self.assertEqual(stats["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(stats["rule_counts"]["RULE-PORT-SCAN"], 2)
        self.assertEqual(stats["rule_counts"]["RULE-SYN-FLOOD"], 1)
        self.assertEqual(stats["rule_counts"]["RULE-TRAFFIC-SPIKE"], 1)

        summary = self.repo.get_alert_summary()
        self.assertEqual(summary["total_alerts"], 4)
        self.assertEqual(summary["status_counts"]["NEW"], 2)


class TestAsyncAlertWriter(unittest.TestCase):
    """Unit tests for bounded asynchronous persistence worker."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_async_test_")
        self.db_path = os.path.join(self.test_dir, "async_test.sqlite")
        self.db = Database(self.db_path)
        self.repo = AlertRepository(self.db)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _sample_event(self, idx: int) -> DetectionEvent:
        return DetectionEvent.create(
            rule_id="RULE-ASYNC",
            detection_name=f"Async Event {idx}",
            severity=Severity.MEDIUM,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            description=f"Test event {idx}",
            evidence={"idx": idx},
            threshold_used=1,
        )

    def test_async_writer_lifecycle_and_drain(self):
        """15. Verify writer starts, consumes events, and gracefully flushes queue on stop."""
        writer = AsyncAlertWriter(self.repo, max_queue_size=100)
        writer.start()
        self.assertTrue(writer.is_running)

        for i in range(15):
            writer.enqueue(self._sample_event(i))

        # Stop with graceful drain
        writer.stop(timeout=5.0)
        self.assertFalse(writer.is_running)

        stats = writer.get_stats()
        self.assertEqual(stats["total_enqueued"], 15)
        self.assertEqual(stats["total_persisted"], 15)
        self.assertEqual(stats["total_dropped"], 0)

        # Check DB rows
        summary = self.repo.get_alert_summary()
        self.assertEqual(summary["total_alerts"], 15)

    def test_async_writer_bounded_capacity_drop(self):
        """16. Verify fixed queue capacity prevents memory explosion and drops excess items."""
        # Create a small queue without starting the worker thread
        writer = AsyncAlertWriter(self.repo, max_queue_size=5)
        # Prevent auto-start
        writer._stop_event.set()

        for i in range(12):
            writer.enqueue(self._sample_event(i))

        stats = writer.get_stats()
        self.assertEqual(stats["queue_size"], 5)
        self.assertEqual(stats["total_enqueued"], 5)
        self.assertEqual(stats["total_dropped"], 7)

    def test_async_writer_error_handling(self):
        """17. Verify SQLite errors on persist are caught without crashing worker."""
        mock_repo = MagicMock()
        mock_repo.insert_detection_event.side_effect = sqlite3.OperationalError("Disk I/O error")

        writer = AsyncAlertWriter(mock_repo, max_queue_size=10)
        writer.start()

        writer.enqueue(self._sample_event(1))
        time.sleep(0.1)
        writer.stop(timeout=2.0)

        stats = writer.get_stats()
        self.assertEqual(stats["total_errors"], 1)
        self.assertFalse(writer.is_running)


class TestStorageConcurrency(unittest.TestCase):
    """Verify thread-safety and WAL concurrency under simulated parallel load."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_conc_test_")
        self.db_path = os.path.join(self.test_dir, "concurrent.sqlite")
        self.db_manager = DatabaseManager(self.db_path)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_concurrent_alert_writes(self):
        """18. Verify multiple worker threads can write alerts concurrently without locking errors."""
        threads = []
        errors = []
        num_threads = 5
        writes_per_thread = 10

        def worker(thread_idx: int):
            try:
                for i in range(writes_per_thread):
                    event = DetectionEvent.create(
                        rule_id=f"THREAD-{thread_idx}",
                        detection_name=f"Worker {thread_idx} event {i}",
                        severity=Severity.MEDIUM,
                        source_ip=f"192.168.1.{thread_idx}",
                        destination_ip="10.0.0.1",
                        description=f"Thread {thread_idx} write {i}",
                        evidence={"worker": thread_idx, "iteration": i},
                        threshold_used=1,
                    )
                    self.db_manager.insert_detection_event(event)
            except Exception as e:
                errors.append(e)

        for t_id in range(num_threads):
            t = threading.Thread(target=worker, args=(t_id,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        self.assertEqual(len(errors), 0, f"Concurrent database write errors: {errors}")
        summary = self.db_manager.get_alert_summary()
        self.assertEqual(summary["total_alerts"], num_threads * writes_per_thread)


class TestDetectionEnginePersistenceIntegration(unittest.TestCase):
    """Verify DetectionEngine automatically persists DetectionEvents to SQLite via on_event callback."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_integ_test_")
        self.db_path = os.path.join(self.test_dir, "engine_integ.sqlite")
        self.db_manager = DatabaseManager(self.db_path)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detection_engine_persists_to_db(self):
        """19. Verify DetectionEngine on_event callback saves alerts into SQLite automatically."""
        engine = DetectionEngine(
            register_defaults=False,
            on_event=self.db_manager.insert_detection_event,
        )
        rule = PortScanRule(threshold=3, window_sec=10.0, cooldown_sec=0.0)
        engine.register_rule(rule)

        src_ip = "192.168.10.50"
        dest_ip = "192.168.10.1"

        # Send packets to 3 distinct ports to trigger PortScanRule
        for port in [21, 22, 23]:
            meta = PacketMetadata(
                timestamp=100.0,
                timestamp_iso="2026-11-14T10:00:00+00:00",
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=40000,
                destination_port=port,
                protocol="TCP",
                packet_length=64,
                tcp_flags="S",
                interface_name="eth0",
            )
            engine.inspect(meta, timestamp=100.0)

        memory_events = engine.get_events()
        self.assertEqual(len(memory_events), 1)

        db_alerts = self.db_manager.get_recent_alerts(limit=10)
        self.assertEqual(len(db_alerts), 1)
        persisted = db_alerts[0]
        self.assertEqual(persisted["rule_id"], "RULE-PORT-SCAN")
        self.assertEqual(persisted["source_ip"], src_ip)
        self.assertEqual(persisted["destination_ip"], dest_ip)
        self.assertEqual(persisted["status"], "NEW")


class TestFlaskAlertAPIRoutes(unittest.TestCase):
    """Integration tests for Flask REST API endpoints and alert lifecycle."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="nids_flask_test_")
        self.db_path = os.path.join(self.test_dir, "flask_test.sqlite")

        class TestConfig(Config):
            TESTING = True
            DATABASE_PATH = self.db_path

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.db_manager = self.app.db_manager

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _seed_alert(
        self,
        title: str = "Probe Alert",
        severity: str = "HIGH",
        rule_id: str = "RULE-1",
        source_ip: str = "10.0.0.100",
        destination_ip: str = "10.0.0.1",
        timestamp: str = "2026-11-14T10:00:00+00:00",
    ) -> int:
        return self.db_manager.insert_alert({
            "title": title,
            "severity": severity,
            "rule_id": rule_id,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": "TCP",
            "description": "Test alert payload",
            "timestamp": timestamp,
        })

    def test_api_get_alerts_pagination_and_metadata(self):
        """20. Test GET /api/alerts pagination metadata (page, per_page, total, total_pages)."""
        for i in range(15):
            self._seed_alert(f"Alert {i}", "LOW")

        res = self.client.get("/api/alerts?page=2&per_page=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["total"], 15)
        self.assertEqual(data["page"], 2)
        self.assertEqual(data["per_page"], 5)
        self.assertEqual(data["total_pages"], 3)
        self.assertEqual(data["count"], 5)
        self.assertEqual(len(data["alerts"]), 5)

    def test_api_get_alerts_out_of_bounds_page(self):
        """21. Test GET /api/alerts for out-of-bounds page returns empty list with valid metadata."""
        for i in range(3):
            self._seed_alert(f"Alert {i}", "MEDIUM")

        res = self.client.get("/api/alerts?page=10&per_page=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["alerts"], [])

    def test_api_get_alerts_max_per_page_capping(self):
        """22. Test GET /api/alerts caps sensible maximum per_page to 100."""
        res = self.client.get("/api/alerts?per_page=500")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["per_page"], 100)

    def test_api_get_alerts_parameter_validation(self):
        """23. Test GET /api/alerts rejects invalid query parameters with 400 Bad Request."""
        # Invalid page
        r1 = self.client.get("/api/alerts?page=-1")
        self.assertEqual(r1.status_code, 400)
        r2 = self.client.get("/api/alerts?page=abc")
        self.assertEqual(r2.status_code, 400)

        # Invalid per_page
        r3 = self.client.get("/api/alerts?per_page=0")
        self.assertEqual(r3.status_code, 400)

        # Invalid severity
        r4 = self.client.get("/api/alerts?severity=SUPER_HIGH")
        self.assertEqual(r4.status_code, 400)

        # Invalid status
        r5 = self.client.get("/api/alerts?status=DELETED")
        self.assertEqual(r5.status_code, 400)

        # Invalid start_date
        r6 = self.client.get("/api/alerts?start_date=not-a-date")
        self.assertEqual(r6.status_code, 400)

        # start_date > end_date
        r7 = self.client.get("/api/alerts?start_date=2026-11-20&end_date=2026-11-10")
        self.assertEqual(r7.status_code, 400)

    def test_api_get_alerts_multi_filter(self):
        """24. Test GET /api/alerts with rule_id, source_ip, destination_ip, and date filters."""
        self._seed_alert(
            "Scan 1", severity="HIGH", rule_id="RULE-PORT-SCAN",
            source_ip="192.168.1.50", destination_ip="10.0.0.1",
            timestamp="2026-05-01T12:00:00+00:00"
        )
        self._seed_alert(
            "Syn 1", severity="CRITICAL", rule_id="RULE-SYN-FLOOD",
            source_ip="192.168.1.60", destination_ip="10.0.0.2",
            timestamp="2026-05-15T12:00:00+00:00"
        )

        # Filter by rule_id
        res_rule = self.client.get("/api/alerts?rule_id=RULE-PORT-SCAN")
        self.assertEqual(res_rule.get_json()["total"], 1)

        # Filter by source_ip
        res_src = self.client.get("/api/alerts?source_ip=192.168.1.60")
        self.assertEqual(res_src.get_json()["total"], 1)

        # Filter by date range
        res_date = self.client.get("/api/alerts?start_date=2026-05-10&end_date=2026-05-20")
        self.assertEqual(res_date.get_json()["total"], 1)
        self.assertEqual(res_date.get_json()["alerts"][0]["rule_id"], "RULE-SYN-FLOOD")

    def test_api_patch_and_post_acknowledge(self):
        """25. Test POST and PATCH /api/alerts/<id>/acknowledge endpoints."""
        id1 = self._seed_alert("To Ack POST", "HIGH")
        id2 = self._seed_alert("To Ack PATCH", "HIGH")

        # POST
        res_post = self.client.post(f"/api/alerts/{id1}/acknowledge")
        self.assertEqual(res_post.status_code, 200)
        self.assertEqual(res_post.get_json()["alert"]["status"], "ACKNOWLEDGED")

        # PATCH
        res_patch = self.client.patch(f"/api/alerts/{id2}/acknowledge")
        self.assertEqual(res_patch.status_code, 200)
        self.assertEqual(res_patch.get_json()["alert"]["status"], "ACKNOWLEDGED")

        # 404 for nonexistent
        res_404 = self.client.patch("/api/alerts/99999/acknowledge")
        self.assertEqual(res_404.status_code, 404)

    def test_api_patch_and_post_resolve(self):
        """26. Test POST and PATCH /api/alerts/<id>/resolve endpoints."""
        id1 = self._seed_alert("To Res POST", "CRITICAL")
        id2 = self._seed_alert("To Res PATCH", "CRITICAL")

        # POST
        res_post = self.client.post(f"/api/alerts/{id1}/resolve")
        self.assertEqual(res_post.status_code, 200)
        self.assertEqual(res_post.get_json()["alert"]["status"], "RESOLVED")

        # PATCH
        res_patch = self.client.patch(f"/api/alerts/{id2}/resolve")
        self.assertEqual(res_patch.status_code, 200)
        self.assertEqual(res_patch.get_json()["alert"]["status"], "RESOLVED")

        # 404 for nonexistent
        res_404 = self.client.patch("/api/alerts/99999/resolve")
        self.assertEqual(res_404.status_code, 404)

    def test_api_prohibited_status_transition_returns_400(self):
        """27. Test attempting a prohibited transition via API returns 400 Bad Request."""
        alert_id = self._seed_alert("Resolved Alert", "HIGH")
        # Resolve alert
        self.client.post(f"/api/alerts/{alert_id}/resolve")

        # Attempt to acknowledge already resolved alert -> 400
        res = self.client.post(f"/api/alerts/{alert_id}/acknowledge")
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("already resolved", data["message"])

    def test_api_dedicated_alerts_stats(self):
        """28. Test dedicated GET /api/alerts/stats endpoint."""
        id1 = self._seed_alert("A1", "LOW", rule_id="RULE-SCAN")
        id2 = self._seed_alert("A2", "HIGH", rule_id="RULE-SYN")
        self.client.post(f"/api/alerts/{id2}/acknowledge")

        res = self.client.get("/api/alerts/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        stats = data["stats"]
        self.assertEqual(stats["total_alerts"], 2)
        self.assertEqual(stats["new_alerts"], 1)
        self.assertEqual(stats["acknowledged_alerts"], 1)
        self.assertEqual(stats["resolved_alerts"], 0)
        self.assertEqual(stats["severity_counts"]["LOW"], 1)
        self.assertEqual(stats["severity_counts"]["HIGH"], 1)
        self.assertEqual(stats["rule_counts"]["RULE-SCAN"], 1)
        self.assertEqual(stats["rule_counts"]["RULE-SYN"], 1)

    def test_api_stats_summary_backward_compat(self):
        """29. Test GET /api/stats/summary maintains backward compatibility."""
        id1 = self._seed_alert("A1", "LOW")
        id2 = self._seed_alert("A2", "HIGH")
        self.client.post(f"/api/alerts/{id2}/acknowledge")

        res = self.client.get("/api/stats/summary")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["summary"]["total_alerts"], 2)
        self.assertEqual(data["summary"]["LOW"], 1)
        self.assertEqual(data["summary"]["HIGH"], 1)
        self.assertEqual(data["summary"]["status_counts"]["ACKNOWLEDGED"], 1)

    def test_api_system_status(self):
        """30. Test GET /api/system/status reports system and phase metadata."""
        res = self.client.get("/api/system/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["phase"].startswith("Phase"))
        self.assertIn("capture_status", data)
        self.assertIn("engine", data)


if __name__ == "__main__":
    unittest.main()
