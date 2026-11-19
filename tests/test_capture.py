"""Automated Unit Tests for NIDS Network Packet Capture Engine.

Tests metadata extraction, protocol decoding, statistics, state transitions,
error handling, and stop controls using synthetic Scapy packets and AsyncSniffer mocking
without requiring live physical network traffic.
"""

import logging
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
import scapy.all as scapy_all

# Suppress Scapy runtime and routing warnings during testing
scapy_all.conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from nids.capture.engine import CaptureStats, CaptureStatus, PacketCaptureEngine
from nids.capture.interfaces import NetworkInterface, find_interface, get_available_interfaces
from nids.capture.metadata import PacketMetadata, extract_metadata


class MockAsyncSniffer:
    """Accurately mimics Scapy AsyncSniffer lifecycle, stop_cb, and internal threading."""

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.exception = kwargs.get("_initial_exception")
        self._stop_event = threading.Event()
        self._emitted_count = 0

    def start(self):
        if self.kwargs.get("_raise_on_start"):
            raise self.kwargs["_raise_on_start"]
        self.running = True
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
        cb = self.kwargs.get("started_callback")
        if cb:
            cb()

    def _worker(self):
        prn = self.kwargs.get("prn")
        count = self.kwargs.get("count", 0)
        packets = self.kwargs.get("_packets_to_emit", [])

        # Emit packets if provided
        for pkt in packets:
            if self._stop_event.is_set():
                break
            if prn:
                prn(pkt)
            self._emitted_count += 1
            if count > 0 and self._emitted_count >= count:
                break
            time.sleep(0.01)

        # Stay blocked in loop until stopped (models idle socket or indefinite sniffing)
        while not self._stop_event.is_set():
            if count > 0 and self._emitted_count >= count:
                break
            time.sleep(0.01)

        self.running = False

    def stop(self, join=True):
        self._stop_event.set()
        self.running = False
        if join and self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)


class TestPacketMetadataExtraction(unittest.TestCase):
    """Test suite for extracting metadata from synthetic Scapy packet objects."""

    def test_tcp_metadata_extraction(self):
        """Verify extraction of TCP packet telemetry, ports, and flags."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=44321, dport=80, flags="SA")
        meta = extract_metadata(pkt, interface_name="eth0")

        self.assertIsInstance(meta, PacketMetadata)
        self.assertEqual(meta.source_ip, "192.168.1.50")
        self.assertEqual(meta.destination_ip, "10.0.0.1")
        self.assertEqual(meta.source_port, 44321)
        self.assertEqual(meta.destination_port, 80)
        self.assertEqual(meta.protocol, "TCP")
        self.assertIn("SYN", meta.tcp_flags)
        self.assertIn("ACK", meta.tcp_flags)
        self.assertEqual(meta.interface_name, "eth0")
        self.assertEqual(meta.packet_length, len(pkt))
        self.assertGreater(meta.timestamp, 0)
        self.assertTrue(meta.timestamp_iso.endswith("+00:00") or "T" in meta.timestamp_iso)

    def test_udp_metadata_extraction(self):
        """Verify extraction of UDP packet telemetry and ports."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="10.1.1.100", dst="8.8.8.8") / UDP(sport=53210, dport=53)
        meta = extract_metadata(pkt, interface_name="wlan0")

        self.assertEqual(meta.source_ip, "10.1.1.100")
        self.assertEqual(meta.destination_ip, "8.8.8.8")
        self.assertEqual(meta.source_port, 53210)
        self.assertEqual(meta.destination_port, 53)
        self.assertEqual(meta.protocol, "UDP")
        self.assertIsNone(meta.tcp_flags)
        self.assertEqual(meta.interface_name, "wlan0")

    def test_icmp_metadata_extraction(self):
        """Verify extraction of ICMP packet telemetry without transport ports."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(type=8)
        meta = extract_metadata(pkt, interface_name="eth0")

        self.assertEqual(meta.source_ip, "127.0.0.1")
        self.assertEqual(meta.destination_ip, "127.0.0.1")
        self.assertIsNone(meta.source_port)
        self.assertIsNone(meta.destination_port)
        self.assertEqual(meta.protocol, "ICMP")
        self.assertIsNone(meta.tcp_flags)

    def test_non_ip_packet_handling(self):
        """Verify graceful handling of packets without IP layer (e.g. ARP or raw Ethernet)."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="192.168.1.10", pdst="192.168.1.1")
        meta = extract_metadata(pkt, interface_name="eth0")

        self.assertIsNone(meta.source_ip)
        self.assertIsNone(meta.destination_ip)
        self.assertIsNone(meta.source_port)
        self.assertIsNone(meta.destination_port)
        self.assertEqual(meta.protocol, "OTHER")
        self.assertEqual(meta.packet_length, len(pkt))

    def test_protocol_classification(self):
        """Verify protocol categorization across diverse headers."""
        tcp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP() / TCP()
        udp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP() / UDP()
        icmp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP() / ICMP()
        raw_pkt = Ether()

        self.assertEqual(extract_metadata(tcp_pkt).protocol, "TCP")
        self.assertEqual(extract_metadata(udp_pkt).protocol, "UDP")
        self.assertEqual(extract_metadata(icmp_pkt).protocol, "ICMP")
        self.assertEqual(extract_metadata(raw_pkt).protocol, "OTHER")

    def test_packet_length_extraction(self):
        """Verify packet byte length matches raw frame length."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=100, dport=200)
        meta = extract_metadata(pkt)
        self.assertEqual(meta.packet_length, len(pkt))
        self.assertGreater(meta.packet_length, 0)


class TestCaptureStatistics(unittest.TestCase):
    """Test suite for thread-safe telemetry statistics."""

    def test_statistics_counters_and_reset(self):
        """Verify counter accuracy across protocols and reset behavior."""
        stats = CaptureStats()
        stats.start_time = time.time()

        stats.record_packet("TCP")
        stats.record_packet("tcp")
        stats.record_packet("UDP")
        stats.record_packet("ICMP")
        stats.record_packet("OTHER")
        stats.record_packet("unknown")

        snapshot = stats.to_dict()
        self.assertEqual(snapshot["total_packets"], 6)
        self.assertEqual(snapshot["tcp_packets"], 2)
        self.assertEqual(snapshot["udp_packets"], 1)
        self.assertEqual(snapshot["icmp_packets"], 1)
        self.assertEqual(snapshot["other_packets"], 2)
        self.assertIsNotNone(snapshot["duration_seconds"])

        stats.reset()
        clean = stats.to_dict()
        self.assertEqual(clean["total_packets"], 0)
        self.assertEqual(clean["tcp_packets"], 0)
        self.assertIsNone(clean["start_time"])

    def test_concurrent_statistics_updates(self):
        """Verify thread-safety when multiple worker threads record packets concurrently."""
        stats = CaptureStats()
        threads = []

        def worker():
            for _ in range(100):
                stats.record_packet("TCP")
                stats.record_packet("UDP")

        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        snapshot = stats.to_dict()
        self.assertEqual(snapshot["total_packets"], 1000)
        self.assertEqual(snapshot["tcp_packets"], 500)
        self.assertEqual(snapshot["udp_packets"], 500)


class TestPacketCaptureEngineLifecycle(unittest.TestCase):
    """Test suite for AsyncSniffer lifecycle, zero-traffic stop, and error handling."""

    def test_initial_state(self):
        """Verify engine begins in IDLE state."""
        engine = PacketCaptureEngine()
        self.assertEqual(engine.status, CaptureStatus.IDLE)
        self.assertIsNone(engine.last_error)

    def test_invalid_interface_handling(self):
        """Verify engine rejects empty or whitespace interface and transitions to ERROR."""
        engine = PacketCaptureEngine()

        for invalid in ["", "   ", None]:
            result = engine.start_capture(interface=invalid)
            self.assertFalse(result)
            self.assertEqual(engine.status, CaptureStatus.ERROR)
            self.assertIn("Explicit interface identifier is required", engine.last_error)

    @patch("scapy.all.AsyncSniffer")
    def test_duplicate_start_prevented(self, mock_sniffer_cls):
        """Verify engine prevents creating duplicate capture sessions while active."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(*args, **kwargs)

        engine = PacketCaptureEngine()
        started1 = engine.start_capture(interface="Wi-Fi")
        self.assertTrue(started1)

        # Attempt duplicate start while running
        started2 = engine.start_capture(interface="Wi-Fi")
        self.assertFalse(started2)

        engine.stop_capture()

    @patch("scapy.all.AsyncSniffer")
    def test_stop_while_packets_arriving(self, mock_sniffer_cls):
        """Verify clean stop while packets are actively arriving (Case 1)."""
        sample_pkts = [
            Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=1000 + i, dport=80)
            for i in range(5)
        ]
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(
            *args, _packets_to_emit=sample_pkts, **kwargs
        )

        received = []
        engine = PacketCaptureEngine(on_packet=lambda m: received.append(m))
        engine.start_capture(interface="eth0")

        time.sleep(0.06)
        self.assertIn(engine.status, (CaptureStatus.RUNNING, CaptureStatus.STARTING))

        stopped = engine.stop_capture(wait_timeout=1.0)
        self.assertTrue(stopped)
        self.assertEqual(engine.status, CaptureStatus.STOPPED)
        self.assertEqual(len(received), 5)
        self.assertFalse(engine._sniffer.thread.is_alive())

    @patch("scapy.all.AsyncSniffer")
    def test_stop_when_no_packets_arriving_idle_interface(self, mock_sniffer_cls):
        """CRITICAL: Verify worker thread terminates on an idle interface within timeout (Case 2)."""
        # No packets emitted - completely idle interface
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(
            *args, _packets_to_emit=[], **kwargs
        )

        engine = PacketCaptureEngine()
        started = engine.start_capture(interface="Loopback")
        self.assertTrue(started)

        time.sleep(0.05)
        self.assertEqual(engine.status, CaptureStatus.RUNNING)
        self.assertTrue(engine._sniffer.thread.is_alive())

        t0 = time.time()
        stopped = engine.stop_capture(wait_timeout=1.0)
        duration = time.time() - t0

        self.assertTrue(stopped)
        self.assertEqual(engine.status, CaptureStatus.STOPPED)
        # PROOF: Verify the underlying worker thread is dead within the timeout
        self.assertFalse(engine._sniffer.thread.is_alive())
        self.assertLess(duration, 1.0)

    @patch("scapy.all.AsyncSniffer")
    def test_stop_immediately_after_starting(self, mock_sniffer_cls):
        """Verify stopping immediately after starting terminates cleanly (Case 3)."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(*args, **kwargs)

        engine = PacketCaptureEngine()
        engine.start_capture(interface="eth0")
        # Immediate stop call without sleep
        stopped = engine.stop_capture(wait_timeout=1.0)

        self.assertTrue(stopped)
        self.assertEqual(engine.status, CaptureStatus.STOPPED)
        self.assertFalse(engine._sniffer.thread.is_alive())

    def test_stop_when_already_stopped(self):
        """Verify calling stop when engine is already in IDLE or STOPPED returns True (Case 4)."""
        engine = PacketCaptureEngine()
        self.assertEqual(engine.status, CaptureStatus.IDLE)
        # Stopping an idle engine returns True cleanly
        self.assertTrue(engine.stop_capture())
        self.assertEqual(engine.status, CaptureStatus.IDLE)

    @patch("scapy.all.AsyncSniffer")
    def test_repeated_stop_requests(self, mock_sniffer_cls):
        """Verify repeated calls to stop_capture do not crash or raise exceptions (Case 5)."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(*args, **kwargs)

        engine = PacketCaptureEngine()
        engine.start_capture(interface="eth0")
        time.sleep(0.02)

        # First stop
        self.assertTrue(engine.stop_capture())
        self.assertEqual(engine.status, CaptureStatus.STOPPED)

        # Repeated stops
        self.assertTrue(engine.stop_capture())
        self.assertTrue(engine.stop_capture())
        self.assertEqual(engine.status, CaptureStatus.STOPPED)

    @patch("scapy.all.AsyncSniffer")
    def test_capture_timeout(self, mock_sniffer_cls):
        """Verify engine stops automatically when duration timeout expires (Case 6)."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(*args, **kwargs)

        engine = PacketCaptureEngine()
        engine.start_capture(interface="eth0", timeout=0.1)

        time.sleep(0.02)
        self.assertEqual(engine.status, CaptureStatus.RUNNING)

        # Wait for timeout timer to fire (0.1s + margin)
        time.sleep(0.15)
        self.assertEqual(engine.status, CaptureStatus.STOPPED)
        self.assertFalse(engine._sniffer.thread.is_alive())

    @patch("scapy.all.AsyncSniffer")
    def test_capture_count_limit_reached(self, mock_sniffer_cls):
        """Verify engine transitions to STOPPED when packet count limit is reached (Case 7)."""
        sample_pkts = [
            Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=5000 + i, dport=53)
            for i in range(3)
        ]
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(
            *args, _packets_to_emit=sample_pkts, **kwargs
        )

        engine = PacketCaptureEngine()
        engine.start_capture(interface="eth0", count=3)

        # Allow watcher thread to detect sniffer completion
        time.sleep(0.1)
        self.assertEqual(engine.status, CaptureStatus.STOPPED)
        self.assertEqual(engine.stats.total_packets, 3)
        self.assertFalse(engine._sniffer.thread.is_alive())

    @patch("scapy.all.AsyncSniffer")
    def test_capture_initialization_failure(self, mock_sniffer_cls):
        """Verify initialization failure transitions engine to ERROR (Case 8)."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(
            *args, _raise_on_start=ValueError("Interface not found"), **kwargs
        )

        engine = PacketCaptureEngine()
        started = engine.start_capture(interface="invalid_adapter")

        self.assertFalse(started)
        self.assertEqual(engine.status, CaptureStatus.ERROR)
        self.assertIn("Capture failed", engine.last_error)

    @patch("scapy.all.AsyncSniffer")
    def test_permission_error_handling(self, mock_sniffer_cls):
        """Verify PermissionError is caught cleanly and provides administrative guidance."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(
            *args, _raise_on_start=PermissionError("Access is denied"), **kwargs
        )

        engine = PacketCaptureEngine()
        started = engine.start_capture(interface="Wi-Fi")

        self.assertFalse(started)
        self.assertEqual(engine.status, CaptureStatus.ERROR)
        self.assertIn("administrator privileges", engine.last_error.lower())

    @patch("scapy.all.AsyncSniffer")
    def test_generic_driver_exception_handling(self, mock_sniffer_cls):
        """Verify generic driver exception does not crash the host application."""
        mock_sniffer_cls.side_effect = lambda *args, **kwargs: MockAsyncSniffer(
            *args, _raise_on_start=OSError("Npcap driver internal error"), **kwargs
        )

        engine = PacketCaptureEngine()
        started = engine.start_capture(interface="BadDevice")

        self.assertFalse(started)
        self.assertEqual(engine.status, CaptureStatus.ERROR)
        self.assertIn("Npcap driver error", engine.last_error)


class TestInterfaceDiscovery(unittest.TestCase):
    """Test suite for network adapter discovery and lookups."""

    def test_get_available_interfaces(self):
        """Verify interface discovery returns non-empty list of NetworkInterface instances."""
        ifaces = get_available_interfaces()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)
        first = ifaces[0]
        self.assertIsInstance(first, NetworkInterface)
        self.assertTrue(bool(first.name))
        self.assertTrue(bool(first.scapy_name))

    def test_find_interface(self):
        """Verify interface lookup by exact name and device identifier."""
        ifaces = get_available_interfaces()
        if ifaces:
            target = ifaces[0]
            found = find_interface(target.name)
            self.assertIsNotNone(found)
            self.assertEqual(found.scapy_name, target.scapy_name)

        # Lookup nonexistent
        self.assertIsNone(find_interface("non_existent_adapter_xyz_9999"))


if __name__ == "__main__":
    unittest.main()
