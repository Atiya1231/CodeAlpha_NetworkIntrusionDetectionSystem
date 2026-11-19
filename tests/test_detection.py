"""Automated Unit Tests for NIDS Intrusion Detection Engine.

Validates heuristic detection rules, threshold boundaries, sliding time windows,
cooldown deduplication, JSON serialization, concurrency, and TrafficAnalyzer integration.
"""

import json
import threading
import time
import unittest

from nids.analysis.traffic_analyzer import TrafficAnalyzer
from nids.capture.metadata import PacketMetadata
from nids.detection.engine import DetectionEngine
from nids.detection.models import DetectionEvent, Severity
from nids.detection.rules import (
    PortScanRule,
    SuspiciousFlowRule,
    SynFloodRule,
    TrafficSpikeRule,
)


def make_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 40000,
    dst_port: int = 80,
    protocol: str = "TCP",
    tcp_flags: str = "ACK",
    length: int = 64,
    timestamp: float = 1000.0,
) -> PacketMetadata:
    """Helper to construct synthetic PacketMetadata instances with deterministic timestamps."""
    return PacketMetadata(
        timestamp=timestamp,
        timestamp_iso="2026-11-14T04:00:00+00:00",
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        packet_length=length,
        tcp_flags=tcp_flags,
        interface_name="eth0",
    )


class TestDetectionEngine(unittest.TestCase):
    """Test suite for DetectionEngine and heuristic security rules."""

    def test_engine_initialization(self):
        """1. Verify engine initialization registers default rules, zero metrics, and empty events."""
        engine = DetectionEngine(max_events=500)
        self.assertEqual(len(engine._rules), 4)
        self.assertEqual(engine.total_inspections, 0)
        self.assertEqual(engine.total_events_generated, 0)
        self.assertEqual(len(engine.get_events()), 0)

        summary = engine.get_summary()
        self.assertEqual(summary["total_rules_count"], 4)
        self.assertEqual(summary["active_rules_count"], 4)
        self.assertEqual(summary["total_events_generated"], 0)

    def test_no_event_for_normal_traffic(self):
        """2. Verify standard benign traffic does not trigger any detection events."""
        engine = DetectionEngine()

        # Simulate normal web browsing traffic (few packets, standard ports)
        for i in range(10):
            meta = make_packet(
                src_ip="192.168.1.50",
                dst_ip="93.184.216.34",
                src_port=50000 + i,
                dst_port=443,
                protocol="TCP",
                tcp_flags="ACK",
                timestamp=1000.0 + i * 0.5,
            )
            events = engine.inspect(meta)
            self.assertEqual(len(events), 0)

        self.assertEqual(len(engine.get_events()), 0)
        self.assertEqual(engine.total_events_generated, 0)

    def test_port_scan_detection(self):
        """3. Verify probing distinct destination ports on a single target triggers port scan event."""
        engine = DetectionEngine()
        target_ip = "10.0.0.5"
        scanner_ip = "192.168.1.200"

        events_triggered = []
        # Probing 20 distinct ports (matches default threshold = 20)
        for port in range(1, 21):
            meta = make_packet(
                src_ip=scanner_ip,
                dst_ip=target_ip,
                src_port=40000 + port,
                dst_port=port,
                protocol="TCP",
                tcp_flags="SYN",
                timestamp=1000.0 + (port * 0.1),
            )
            events = engine.inspect(meta)
            if events:
                events_triggered.extend(events)

        self.assertEqual(len(events_triggered), 1)
        event = events_triggered[0]
        self.assertEqual(event.rule_id, "RULE-PORT-SCAN")
        self.assertEqual(event.severity, Severity.HIGH)
        self.assertEqual(event.source_ip, scanner_ip)
        self.assertEqual(event.destination_ip, target_ip)
        self.assertEqual(event.evidence["distinct_ports_contacted"], 20)
        self.assertIn("probed 20 distinct ports", event.description)

    def test_port_scan_threshold_boundary(self):
        """4. Verify port scan rule fires at exactly the threshold, but not at threshold - 1."""
        rule = PortScanRule(threshold=5, window_sec=10.0, cooldown_sec=60.0)

        # 4 distinct ports (threshold - 1 = 4)
        for p in range(1, 5):
            meta = make_packet(dst_port=p, timestamp=1000.0 + p)
            event = rule.inspect(meta)
            self.assertIsNone(event)

        # 5th distinct port (reaches threshold 5)
        meta5 = make_packet(dst_port=5, timestamp=1005.0)
        event5 = rule.inspect(meta5)
        self.assertIsNotNone(event5)
        self.assertEqual(event5.evidence["distinct_ports_contacted"], 5)

    def test_port_scan_time_window_expiration(self):
        """5. Verify probed ports outside the rolling window expire and do not trigger scan."""
        rule = PortScanRule(threshold=3, window_sec=5.0, cooldown_sec=60.0)

        # Port 1 at t=10.0
        # Port 2 at t=12.0
        rule.inspect(make_packet(dst_port=80, timestamp=10.0))
        rule.inspect(make_packet(dst_port=81, timestamp=12.0))

        # Port 3 at t=20.0 (ports 80 and 81 at t=10 and 12 are outside the 5s window!)
        event = rule.inspect(make_packet(dst_port=82, timestamp=20.0))
        self.assertIsNone(event, "Expired ports outside window should not trigger threshold")

    def test_port_scan_cooldown_and_deduplication(self):
        """6. Verify cooldown suppresses duplicate alerts for continuing scan traffic."""
        rule = PortScanRule(threshold=3, window_sec=10.0, cooldown_sec=60.0)

        # Trigger initial alert with 3 ports
        for p in range(1, 4):
            event = rule.inspect(make_packet(dst_port=p, timestamp=100.0 + p))
        self.assertIsNotNone(event)

        # Continuing scan immediately at t=105.0 (within 60s cooldown)
        event_cooldown = rule.inspect(make_packet(dst_port=4, timestamp=105.0))
        self.assertIsNone(event_cooldown, "Should be suppressed by cooldown")

        # After cooldown (t=165.0 > 100 + 60), if 3 new ports probed, fires again
        rule.inspect(make_packet(dst_port=10, timestamp=162.0))
        rule.inspect(make_packet(dst_port=11, timestamp=163.0))
        event_after = rule.inspect(make_packet(dst_port=12, timestamp=165.0))
        self.assertIsNotNone(event_after, "Alert should fire again after cooldown period")

    def test_syn_activity_detection(self):
        """7. Verify high volume of TCP SYN requests triggers SYN flood rule."""
        rule = SynFloodRule(threshold=10, window_sec=5.0, cooldown_sec=60.0)

        alert_event = None
        for i in range(10):
            meta = make_packet(
                src_ip="192.168.1.10",
                dst_ip="10.0.0.1",
                protocol="TCP",
                tcp_flags="SYN",
                timestamp=1000.0 + (i * 0.1),
            )
            res = rule.inspect(meta)
            if res:
                alert_event = res

        self.assertIsNotNone(alert_event)
        self.assertEqual(alert_event.rule_id, "RULE-SYN-FLOOD")
        self.assertEqual(alert_event.severity, Severity.HIGH)
        self.assertEqual(alert_event.evidence["syn_packet_count"], 10)

    def test_syn_threshold_boundary(self):
        """8. Verify SYN rule does not fire on non-SYN packets or below threshold."""
        rule = SynFloodRule(threshold=5, window_sec=5.0)

        # 10 SYN-ACK packets (handshake responses) should NOT trigger SYN flood
        for i in range(10):
            meta = make_packet(protocol="TCP", tcp_flags="SYN, ACK", timestamp=1000.0 + i)
            self.assertIsNone(rule.inspect(meta))

        # 4 raw SYN packets (threshold - 1 = 4)
        for i in range(4):
            meta = make_packet(protocol="TCP", tcp_flags="SYN", timestamp=1000.0 + i)
            self.assertIsNone(rule.inspect(meta))

        # 5th SYN packet reaches threshold
        meta5 = make_packet(protocol="TCP", tcp_flags="SYN", timestamp=1004.5)
        self.assertIsNotNone(rule.inspect(meta5))

    def test_traffic_spike_detection(self):
        """9. Verify sudden surge in packet volume triggers traffic spike rule."""
        rule = TrafficSpikeRule(threshold=20, window_sec=2.0, cooldown_sec=30.0)

        spike_alert = None
        for i in range(20):
            meta = make_packet(length=500, timestamp=100.0 + (i * 0.05))
            res = rule.inspect(meta)
            if res:
                spike_alert = res

        self.assertIsNotNone(spike_alert)
        self.assertEqual(spike_alert.rule_id, "RULE-TRAFFIC-SPIKE")
        self.assertEqual(spike_alert.severity, Severity.MEDIUM)
        self.assertEqual(spike_alert.evidence["packets_in_window"], 20)

    def test_traffic_spike_baseline_behavior(self):
        """10. Verify low frequency traffic below threshold does not trigger spike."""
        rule = TrafficSpikeRule(threshold=50, window_sec=2.0)

        for i in range(10):
            meta = make_packet(timestamp=100.0 + i)
            self.assertIsNone(rule.inspect(meta))

    def test_severity_assignment(self):
        """11. Verify correct severity classifications across rules."""
        scan_rule = PortScanRule()
        syn_rule = SynFloodRule()
        spike_rule = TrafficSpikeRule()
        susp_rule = SuspiciousFlowRule()

        self.assertEqual(scan_rule.severity, Severity.HIGH)
        self.assertEqual(syn_rule.severity, Severity.HIGH)
        self.assertEqual(spike_rule.severity, Severity.MEDIUM)
        self.assertEqual(susp_rule.severity, Severity.LOW)

    def test_json_serialization(self):
        """12. Verify DetectionEvent to_dict() produces valid, serializable JSON."""
        event = DetectionEvent.create(
            rule_id="RULE-TEST",
            detection_name="Test Anomaly",
            severity=Severity.HIGH,
            description="Unit test verification event",
            evidence={"metric": 42, "status": "active"},
            threshold_used=10,
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol="TCP",
            timestamp=1700000000.0,
        )

        d = event.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["source_ip"], "192.168.1.1")

        # Ensure json.dumps completes without error
        serialized = json.dumps(d)
        self.assertIn('"severity": "HIGH"', serialized)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["rule_id"], "RULE-TEST")

    def test_missing_metadata_handling(self):
        """13. Verify engine safely handles None, empty IPs, and non-IP frames."""
        engine = DetectionEngine()

        self.assertEqual(engine.inspect(None), [])

        bad_pkt = make_packet(src_ip="", dst_ip=None, dst_port=None, protocol="OTHER")
        events = engine.inspect(bad_pkt)
        self.assertEqual(events, [])

    def test_concurrent_event_processing(self):
        """14. Verify thread safety under concurrent inspection across worker threads."""
        engine = DetectionEngine()
        threads = []

        def worker(w_id: int):
            for i in range(25):
                # Unique port scans per worker
                meta = make_packet(
                    src_ip=f"10.0.{w_id}.1",
                    dst_ip="192.168.1.1",
                    src_port=5000 + i,
                    dst_port=100 + i,
                    protocol="TCP",
                    tcp_flags="SYN",
                    timestamp=1000.0 + (i * 0.1),
                )
                engine.inspect(meta)

        for w_id in range(4):
            t = threading.Thread(target=worker, args=(w_id,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(engine.total_inspections, 100)
        self.assertGreater(engine.total_events_generated, 0)
        summary = engine.get_summary()
        self.assertEqual(summary["total_inspections"], 100)

    def test_bounded_event_retention(self):
        """15. Verify event buffer enforces maximum capacity bounds."""
        engine = DetectionEngine(max_events=5, register_defaults=False)
        rule = SuspiciousFlowRule(cooldown_sec=0.1)
        engine.register_rule(rule)

        # Trigger 8 suspicious port 0 probes
        for i in range(8):
            meta = make_packet(src_ip=f"1.1.1.{i}", dst_port=0, protocol="TCP", timestamp=100.0 + i)
            engine.inspect(meta)

        self.assertEqual(len(engine.get_events()), 5)
        self.assertEqual(engine.total_events_generated, 8)

    def test_rule_enable_disable_configuration(self):
        """16. Verify disabling a rule suppresses its event generation."""
        engine = DetectionEngine()
        self.assertTrue(engine.disable_rule("RULE-PORT-SCAN"))

        rule = engine.get_rule("RULE-PORT-SCAN")
        self.assertFalse(rule.enabled)

        # Send port scan traffic
        for p in range(1, 25):
            meta = make_packet(dst_port=p, timestamp=100.0 + p)
            events = engine.inspect(meta)
            self.assertEqual(events, [])

        self.assertEqual(engine.total_events_generated, 0)

        # Re-enable rule
        self.assertTrue(engine.enable_rule("RULE-PORT-SCAN"))
        self.assertTrue(rule.enabled)

    def test_detection_summary_statistics(self):
        """17. Verify summary statistics accurately reflect events grouped by severity and rule."""
        engine = DetectionEngine()
        rule = SuspiciousFlowRule(cooldown_sec=1.0)
        engine.register_rule(rule)

        # Trigger port 0 probe
        meta = make_packet(dst_port=0, protocol="TCP", timestamp=50.0)
        engine.inspect(meta)

        summary = engine.get_summary()
        self.assertEqual(summary["total_events_generated"], 1)
        self.assertEqual(summary["events_by_severity"]["MEDIUM"], 1)
        self.assertGreaterEqual(summary["events_by_rule"]["RULE-SUSPICIOUS-FLOW"], 1)

    def test_no_duplicate_events_during_sustained_traffic(self):
        """18. Verify sustained flooding traffic produces only 1 event within the cooldown window."""
        rule = SynFloodRule(threshold=5, window_sec=5.0, cooldown_sec=30.0)

        events_generated = 0
        for i in range(100):
            meta = make_packet(protocol="TCP", tcp_flags="SYN", timestamp=100.0 + (i * 0.1))
            res = rule.inspect(meta)
            if res:
                events_generated += 1

        self.assertEqual(events_generated, 1, "Sustained flood should only alert once within cooldown window")

    def test_traffic_analyzer_integration(self):
        """19. Verify passive DetectionEngine integrates cleanly with TrafficAnalyzer pipeline."""
        engine = DetectionEngine()
        analyzer = TrafficAnalyzer(detection_engine=engine)

        # Feed port scan traffic through analyzer
        for p in range(1, 21):
            meta = make_packet(dst_port=p, timestamp=100.0 + (p * 0.1))
            analyzer.process_packet(meta)

        summary = analyzer.get_summary()
        self.assertIn("detection", summary)
        self.assertEqual(summary["detection"]["total_events_generated"], 1)
        self.assertEqual(len(engine.get_events()), 1)

    def test_suspicious_flow_pattern_naked_fin(self):
        """20. Verify standalone naked TCP FIN packet is caught by SuspiciousFlowRule."""
        rule = SuspiciousFlowRule(cooldown_sec=10.0)
        meta = make_packet(protocol="TCP", tcp_flags="FIN", timestamp=100.0)
        event = rule.inspect(meta)

        self.assertIsNotNone(event)
        self.assertEqual(event.rule_id, "RULE-SUSPICIOUS-FLOW")
        self.assertEqual(event.detection_name, "Naked TCP FIN Scan Indicator")


if __name__ == "__main__":
    unittest.main()

