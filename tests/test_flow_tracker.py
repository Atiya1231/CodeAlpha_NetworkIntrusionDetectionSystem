"""Automated Unit Tests for NIDS Traffic Analysis and Flow Tracking.

Validates bidirectional flow key normalization, forward/reverse telemetry accounting,
idle-flow expiration, capacity bounds, concurrent updates, and capture engine integration.
"""

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from nids.analysis.flow_tracker import FlowTracker
from nids.analysis.models import FlowKey, FlowStatus, NetworkFlow, TrafficStats
from nids.analysis.traffic_analyzer import TrafficAnalyzer
from nids.capture.engine import PacketCaptureEngine
from nids.capture.metadata import PacketMetadata


def make_metadata(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: str = "TCP",
    length: int = 100,
    timestamp: float = 1000.0,
    tcp_flags: str = "SYN",
) -> PacketMetadata:
    """Helper to construct synthetic PacketMetadata instances with deterministic fields."""
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


class TestFlowTracker(unittest.TestCase):
    """Test suite for FlowTracker session grouping, accounting, and expiration."""

    def test_tcp_flow_creation(self):
        """1. Verify initial TCP packet creates an active NetworkFlow with correct metadata."""
        tracker = FlowTracker()
        pkt = make_metadata(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=5000, dst_port=80, protocol="TCP", length=60)
        res = tracker.process_packet(pkt)

        self.assertIsNotNone(res)
        flow, is_fwd = res
        self.assertTrue(is_fwd)
        self.assertEqual(flow.protocol, "TCP")
        self.assertEqual(flow.initiator_ip, "192.168.1.10")
        self.assertEqual(flow.initiator_port, 5000)
        self.assertEqual(flow.responder_ip, "10.0.0.1")
        self.assertEqual(flow.responder_port, 80)
        self.assertEqual(flow.total_packets, 1)
        self.assertEqual(flow.total_bytes, 60)
        self.assertEqual(flow.status, FlowStatus.ACTIVE)
        self.assertIn("SYN", flow.tcp_flags)

    def test_udp_flow_creation(self):
        """2. Verify UDP packet creates a distinct UDP flow without TCP flags."""
        tracker = FlowTracker()
        pkt = make_metadata(src_ip="192.168.1.20", dst_ip="8.8.8.8", src_port=5353, dst_port=53, protocol="UDP", length=80, tcp_flags=None)
        res = tracker.process_packet(pkt)

        self.assertIsNotNone(res)
        flow, is_fwd = res
        self.assertEqual(flow.protocol, "UDP")
        self.assertEqual(flow.initiator_port, 5353)
        self.assertEqual(flow.responder_port, 53)
        self.assertEqual(flow.tcp_flags, set())

    def test_icmp_flow_creation_without_ports(self):
        """3. Verify ICMP packet creates flow without transport ports."""
        tracker = FlowTracker()
        pkt = make_metadata(src_ip="192.168.1.1", dst_ip="1.1.1.1", src_port=None, dst_port=None, protocol="ICMP", length=64, tcp_flags=None)
        res = tracker.process_packet(pkt)

        self.assertIsNotNone(res)
        flow, is_fwd = res
        self.assertEqual(flow.protocol, "ICMP")
        self.assertIsNone(flow.initiator_port)
        self.assertIsNone(flow.responder_port)
        self.assertEqual(flow.total_packets, 1)

    def test_bidirectional_packet_grouping(self):
        """4. Verify A -> B and B -> A packets are grouped into the same single flow."""
        tracker = FlowTracker()
        pkt_fwd = make_metadata(src_ip="192.168.1.5", dst_ip="93.184.216.34", src_port=49152, dst_port=443, protocol="TCP", length=64)
        pkt_rev = make_metadata(src_ip="93.184.216.34", dst_ip="192.168.1.5", src_port=443, dst_port=49152, protocol="TCP", length=1460, tcp_flags="ACK")

        res1 = tracker.process_packet(pkt_fwd)
        res2 = tracker.process_packet(pkt_rev)

        self.assertIsNotNone(res1)
        self.assertIsNotNone(res2)
        flow1, is_fwd1 = res1
        flow2, is_fwd2 = res2

        self.assertEqual(flow1.flow_id, flow2.flow_id)
        self.assertTrue(is_fwd1)
        self.assertFalse(is_fwd2)
        self.assertEqual(tracker.active_flow_count, 1)
        self.assertEqual(flow1.total_packets, 2)
        self.assertEqual(flow1.forward_packets, 1)
        self.assertEqual(flow1.reverse_packets, 1)

    def test_different_protocols_remain_separate(self):
        """5. Verify TCP and UDP traffic between identical endpoints form distinct flows."""
        tracker = FlowTracker()
        tcp_pkt = make_metadata(src_ip="10.0.0.5", dst_ip="10.0.0.6", src_port=53, dst_port=53, protocol="TCP")
        udp_pkt = make_metadata(src_ip="10.0.0.5", dst_ip="10.0.0.6", src_port=53, dst_port=53, protocol="UDP")

        res_tcp = tracker.process_packet(tcp_pkt)
        res_udp = tracker.process_packet(udp_pkt)

        self.assertNotEqual(res_tcp[0].flow_id, res_udp[0].flow_id)
        self.assertEqual(tracker.active_flow_count, 2)

    def test_different_endpoint_combinations_remain_separate(self):
        """6. Verify different port pairs between identical IPs form separate flows."""
        tracker = FlowTracker()
        pkt1 = make_metadata(src_ip="192.168.1.1", dst_ip="192.168.1.2", src_port=1000, dst_port=80)
        pkt2 = make_metadata(src_ip="192.168.1.1", dst_ip="192.168.1.2", src_port=1001, dst_port=80)

        res1 = tracker.process_packet(pkt1)
        res2 = tracker.process_packet(pkt2)

        self.assertNotEqual(res1[0].flow_id, res2[0].flow_id)
        self.assertEqual(tracker.active_flow_count, 2)

    def test_forward_and_reverse_packet_counters(self):
        """7. Verify directional packet counters increment accurately."""
        tracker = FlowTracker()
        p1 = make_metadata(src_ip="A", dst_ip="B", src_port=1, dst_port=2)
        p2 = make_metadata(src_ip="A", dst_ip="B", src_port=1, dst_port=2)
        p3 = make_metadata(src_ip="B", dst_ip="A", src_port=2, dst_port=1)

        tracker.process_packet(p1)
        tracker.process_packet(p2)
        res = tracker.process_packet(p3)

        flow = res[0]
        self.assertEqual(flow.forward_packets, 2)
        self.assertEqual(flow.reverse_packets, 1)
        self.assertEqual(flow.total_packets, 3)

    def test_forward_and_reverse_byte_counters(self):
        """8. Verify directional byte counters increment accurately."""
        tracker = FlowTracker()
        p_fwd = make_metadata(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=10, dst_port=20, length=150)
        p_rev = make_metadata(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=20, dst_port=10, length=500)

        tracker.process_packet(p_fwd)
        res = tracker.process_packet(p_rev)

        flow = res[0]
        self.assertEqual(flow.forward_bytes, 150)
        self.assertEqual(flow.reverse_bytes, 500)
        self.assertEqual(flow.total_bytes, 650)

    def test_first_seen_and_last_seen_timestamps(self):
        """9. Verify first_seen and last_seen timestamps update, handling out-of-order safely."""
        tracker = FlowTracker()
        # Arrival order: ts=100.0, then ts=150.0, then out-of-order ts=80.0
        p1 = make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, timestamp=100.0)
        p2 = make_metadata(src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=2, dst_port=1, timestamp=150.0)
        p3 = make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, timestamp=80.0)

        tracker.process_packet(p1)
        tracker.process_packet(p2)
        res = tracker.process_packet(p3)

        flow = res[0]
        self.assertEqual(flow.first_seen, 80.0)
        self.assertEqual(flow.last_seen, 150.0)

    def test_flow_duration_calculation(self):
        """10. Verify duration calculation returns positive delta even if packet timestamps jitter."""
        tracker = FlowTracker()
        p1 = make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, timestamp=10.0)
        p2 = make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2, timestamp=15.5)

        tracker.process_packet(p1)
        res = tracker.process_packet(p2)
        flow = res[0]
        self.assertEqual(flow.duration, 5.5)

    def test_idle_flow_expiration(self):
        """11. Verify flows exceeding idle_timeout are expired deterministically using simulated time."""
        tracker = FlowTracker(idle_timeout=10.0)

        # Flow 1: last seen at t=100.0
        p1 = make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=1, timestamp=100.0)
        # Flow 2: last seen at t=108.0
        p2 = make_metadata(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=2, dst_port=2, timestamp=108.0)

        tracker.process_packet(p1)
        tracker.process_packet(p2)
        self.assertEqual(tracker.active_flow_count, 2)

        # Test at simulated time t=112.0:
        # Flow 1 idle = 112 - 100 = 12.0s (> 10s timeout) -> Expired
        # Flow 2 idle = 112 - 108 = 4.0s (<= 10s timeout) -> Kept active
        expired = tracker.expire_flows(now=112.0)

        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].initiator_ip, "1.1.1.1")
        self.assertEqual(expired[0].status, FlowStatus.CLOSED)
        self.assertEqual(tracker.active_flow_count, 1)
        self.assertEqual(tracker.completed_flow_count, 1)

    def test_active_flow_retrieval(self):
        """12. Verify get_active_flows returns snapshot of active sessions."""
        tracker = FlowTracker()
        tracker.process_packet(make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=10, dst_port=20))
        tracker.process_packet(make_metadata(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=30, dst_port=40))

        active = tracker.get_active_flows()
        self.assertEqual(len(active), 2)
        self.assertTrue(all(f.status == FlowStatus.ACTIVE for f in active))

    def test_completed_flow_retrieval(self):
        """13. Verify get_completed_flows returns expired/closed flows up to limit."""
        tracker = FlowTracker(idle_timeout=5.0)
        tracker.process_packet(make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=10, dst_port=20, timestamp=50.0))
        tracker.expire_flows(now=60.0)

        completed = tracker.get_completed_flows(limit=10)
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].status, FlowStatus.CLOSED)

    def test_empty_traffic_handling(self):
        """14. Verify operations on empty tracker return safe defaults without throwing."""
        tracker = FlowTracker()
        self.assertEqual(tracker.active_flow_count, 0)
        self.assertEqual(tracker.completed_flow_count, 0)
        self.assertEqual(tracker.get_active_flows(), [])
        self.assertEqual(tracker.get_completed_flows(), [])
        self.assertEqual(tracker.expire_flows(), [])
        self.assertEqual(tracker.close_all_flows(), [])

    def test_concurrent_flow_updates(self):
        """15. Verify thread safety under concurrent packet insertion across multiple threads."""
        tracker = FlowTracker()
        threads = []

        def worker(thread_idx: int):
            for i in range(50):
                pkt = make_metadata(
                    src_ip=f"10.0.{thread_idx}.{i % 5}",
                    dst_ip="172.16.0.1",
                    src_port=1000 + (i % 5),
                    dst_port=80,
                    length=100,
                )
                tracker.process_packet(pkt)

        for t_idx in range(5):
            t = threading.Thread(target=worker, args=(t_idx,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Each thread generated 5 unique endpoint keys -> 25 total active flows
        self.assertEqual(tracker.active_flow_count, 25)
        total_tracked_pkts = sum(f.total_packets for f in tracker.get_active_flows())
        self.assertEqual(total_tracked_pkts, 250)

    def test_maximum_flow_capacity_eviction(self):
        """16. Verify capacity limit evicts oldest flow when max_active_flows is reached."""
        tracker = FlowTracker(max_active_flows=3)

        # Insert 3 flows at timestamps 10, 20, 30
        p1 = make_metadata(src_ip="1.1.1.1", dst_ip="10.0.0.1", src_port=1, dst_port=80, timestamp=10.0)
        p2 = make_metadata(src_ip="2.2.2.2", dst_ip="10.0.0.1", src_port=2, dst_port=80, timestamp=20.0)
        p3 = make_metadata(src_ip="3.3.3.3", dst_ip="10.0.0.1", src_port=3, dst_port=80, timestamp=30.0)
        tracker.process_packet(p1)
        tracker.process_packet(p2)
        tracker.process_packet(p3)
        self.assertEqual(tracker.active_flow_count, 3)

        # Insert 4th flow at timestamp 40 -> triggers eviction of p1 (oldest, t=10.0)
        p4 = make_metadata(src_ip="4.4.4.4", dst_ip="10.0.0.1", src_port=4, dst_port=80, timestamp=40.0)
        tracker.process_packet(p4)

        self.assertEqual(tracker.active_flow_count, 3)
        self.assertEqual(tracker.completed_flow_count, 1)
        active_ips = [f.initiator_ip for f in tracker.get_active_flows()]
        self.assertNotIn("1.1.1.1", active_ips)
        self.assertIn("4.4.4.4", active_ips)

    def test_malformed_or_incomplete_metadata_handling(self):
        """17. Verify malformed metadata (None IPs, missing fields) is handled without crashing."""
        tracker = FlowTracker()

        # Non-IP or missing addresses
        bad_pkt1 = make_metadata(src_ip="", dst_ip="10.0.0.1")
        bad_pkt2 = make_metadata(src_ip=None, dst_ip=None)
        bad_pkt3 = make_metadata(src_ip="1.1.1.1", dst_ip=None)

        self.assertIsNone(tracker.process_packet(bad_pkt1))
        self.assertIsNone(tracker.process_packet(bad_pkt2))
        self.assertIsNone(tracker.process_packet(bad_pkt3))
        self.assertEqual(tracker.active_flow_count, 0)

    def test_close_all_active_flows_behavior(self):
        """18. Verify close_all_flows retires all active sessions into completed queue."""
        tracker = FlowTracker()
        tracker.process_packet(make_metadata(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2))
        tracker.process_packet(make_metadata(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=3, dst_port=4))
        self.assertEqual(tracker.active_flow_count, 2)

        closed = tracker.close_all_flows()
        self.assertEqual(len(closed), 2)
        self.assertEqual(tracker.active_flow_count, 0)
        self.assertEqual(tracker.completed_flow_count, 2)
        self.assertTrue(all(f.status == FlowStatus.CLOSED for f in closed))


class TestTrafficAnalyzer(unittest.TestCase):
    """Test suite for high-level TrafficAnalyzer telemetry coordination."""

    def test_traffic_analyzer_volume_and_protocol_accounting(self):
        """19. Verify TrafficAnalyzer aggregates packets, bytes, protocols, and directions accurately."""
        analyzer = TrafficAnalyzer()

        # Forward TCP
        analyzer.process_packet(make_metadata(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=100, dst_port=80, protocol="TCP", length=200))
        # Reverse TCP
        analyzer.process_packet(make_metadata(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=100, protocol="TCP", length=800))
        # UDP packet
        analyzer.process_packet(make_metadata(src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=5353, dst_port=53, protocol="UDP", length=60))
        # Non-IP packet (e.g. ARP/raw frame)
        analyzer.process_packet(make_metadata(src_ip=None, dst_ip=None, protocol="OTHER", length=42))

        summary = analyzer.get_summary()
        self.assertEqual(summary["total_packets"], 4)
        self.assertEqual(summary["total_bytes"], 1102)
        self.assertEqual(summary["tcp_packets"], 2)
        self.assertEqual(summary["udp_packets"], 1)
        self.assertEqual(summary["other_packets"], 1)
        self.assertEqual(summary["total_forward_packets"], 3)
        self.assertEqual(summary["total_reverse_packets"], 1)
        self.assertEqual(summary["active_flows"], 2)

    def test_capture_callback_integration(self):
        """20. Verify TrafficAnalyzer cleanly hooks into PacketCaptureEngine on_packet callback."""
        analyzer = TrafficAnalyzer()
        captured_flow_ids = []

        def capture_callback(meta: PacketMetadata):
            flow = analyzer.process_packet(meta)
            if flow:
                captured_flow_ids.append(flow.flow_id)

        # Simulate capture engine invoking callback
        p1 = make_metadata(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=1234, dst_port=80, protocol="TCP")
        p2 = make_metadata(src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=80, dst_port=1234, protocol="TCP")

        capture_callback(p1)
        capture_callback(p2)

        self.assertEqual(len(captured_flow_ids), 2)
        # Both packets should resolve to the exact same flow ID
        self.assertEqual(captured_flow_ids[0], captured_flow_ids[1])
        summary = analyzer.get_summary()
        self.assertEqual(summary["active_flows"], 1)
        self.assertEqual(summary["total_packets"], 2)


if __name__ == "__main__":
    unittest.main()

