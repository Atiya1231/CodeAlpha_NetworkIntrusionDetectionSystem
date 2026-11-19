"""Packet Capture Module.

Provides modular network interface discovery, asynchronous non-blocking
packet capture powered by Scapy, thread-safe statistics, and structured
non-sensitive packet metadata extraction.
"""

from nids.capture.engine import CaptureStats, CaptureStatus, PacketCaptureEngine
from nids.capture.interfaces import NetworkInterface, find_interface, get_available_interfaces
from nids.capture.metadata import PacketMetadata, extract_metadata

__all__ = [
    "NetworkInterface",
    "get_available_interfaces",
    "find_interface",
    "PacketMetadata",
    "extract_metadata",
    "PacketCaptureEngine",
    "CaptureStatus",
    "CaptureStats",
]
