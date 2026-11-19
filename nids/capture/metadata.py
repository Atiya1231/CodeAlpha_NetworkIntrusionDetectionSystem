"""Packet Metadata Extraction Module.

Extracts structured, non-sensitive packet telemetry (headers, ports, lengths, TCP flags)
from raw network frames. Strictly avoids capturing, logging, or storing sensitive application payloads.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Mapping of TCP flag characters to readable abbreviations
TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


@dataclass
class PacketMetadata:
    """Structured, sanitized telemetry extracted from a captured network packet.

    Strictly avoids storing raw payloads, credentials, or private user communication.
    Performs header and metadata analysis only.
    """
    timestamp: float
    timestamp_iso: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    packet_length: int
    tcp_flags: Optional[str] = None
    interface_name: str = ""
    layers: Optional[List[str]] = None
    ip_version: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization and logging."""
        return {
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
            "interface_name": self.interface_name,
            "layers": self.layers or [],
            "ip_version": self.ip_version,
        }

    def __str__(self) -> str:
        src = f"{self.source_ip}:{self.source_port}" if self.source_port else str(self.source_ip)
        dst = f"{self.destination_ip}:{self.destination_port}" if self.destination_port else str(self.destination_ip)
        flags_info = f" [{self.tcp_flags}]" if self.tcp_flags else ""
        return f"{self.timestamp_iso} | {self.protocol:<5} | {src} -> {dst} | {self.packet_length} bytes{flags_info}"


def _format_tcp_flags(flags_val: Any) -> Optional[str]:
    """Format TCP flags into comma-separated names (e.g. 'SYN, ACK')."""
    if flags_val is None:
        return None

    # Handle Scapy FlagValue or string representation
    flags_str = str(flags_val)
    expanded = [TCP_FLAG_NAMES[ch] for ch in flags_str if ch in TCP_FLAG_NAMES]
    return ", ".join(expanded) if expanded else (flags_str or None)


def extract_metadata(packet: Any, interface_name: str = "") -> PacketMetadata:
    """Extract non-sensitive header metadata from a Scapy packet.

    Extracts addresses, ports, protocol classification, packet lengths, and TCP flags.
    Never stores or extracts application layer payloads, ensuring safety and compliance.

    Args:
        packet: Scapy packet object.
        interface_name: Friendly name or device ID of the capture interface.

    Returns:
        PacketMetadata: Structured metadata container.
    """
    # 1. Packet timestamp
    ts_val = getattr(packet, "time", None)
    if ts_val is not None:
        try:
            ts = float(ts_val)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc).timestamp()
    else:
        ts = datetime.now(timezone.utc).timestamp()

    iso_str = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    # 2. Total packet length in bytes
    try:
        pkt_len = len(packet)
    except (TypeError, Exception):
        pkt_len = 0

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    tcp_flags: Optional[str] = None
    ip_version: Optional[int] = None

    # 3. Layer 3: Network Layer (IPv4 / IPv6)
    has_ip = False
    try:
        # Check IPv4
        if packet.haslayer("IP"):
            ip_layer = packet.getlayer("IP")
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ip_version = 4
            has_ip = True
        # Check IPv6
        elif packet.haslayer("IPv6"):
            ipv6_layer = packet.getlayer("IPv6")
            src_ip = str(ipv6_layer.src)
            dst_ip = str(ipv6_layer.dst)
            ip_version = 6
            has_ip = True
    except Exception:
        has_ip = False

    # 4. Layer 4: Transport Layer (TCP, UDP, ICMP)
    try:
        if packet.haslayer("TCP"):
            protocol = "TCP"
            tcp_layer = packet.getlayer("TCP")
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = _format_tcp_flags(getattr(tcp_layer, "flags", None))

        elif packet.haslayer("UDP"):
            protocol = "UDP"
            udp_layer = packet.getlayer("UDP")
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        elif packet.haslayer("ICMP") or packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply"):
            protocol = "ICMP"

        else:
            protocol = "OTHER"
    except Exception:
        protocol = "OTHER"

    # 5. Basic Packet Structure Analysis (Header hierarchy; strictly no payload stored)
    layers_detected: List[str] = []
    try:
        curr = packet
        while curr:
            layer_name = curr.__class__.__name__
            if layer_name not in ("NoPayload", "Padding", "Raw"):
                layers_detected.append(layer_name)
            curr = getattr(curr, "payload", None)
            if not curr or curr.__class__.__name__ in ("NoPayload", "Padding", "Raw"):
                break
    except Exception:
        layers_detected = [protocol] if protocol != "OTHER" else []

    return PacketMetadata(
        timestamp=ts,
        timestamp_iso=iso_str,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        packet_length=pkt_len,
        tcp_flags=tcp_flags,
        interface_name=interface_name,
        layers=layers_detected,
        ip_version=ip_version,
    )

