"""Traffic Analysis Domain Models for NIDS.

Defines normalized bidirectional 5-tuple flow keys, thread-safe network flow state,
and aggregated traffic telemetry structures without storing raw packet payloads.
"""

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from nids.capture.metadata import PacketMetadata


class FlowStatus(str, Enum):
    """Lifecycle states of a network flow."""
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class FlowKey:
    """Normalized bidirectional 5-tuple network connection identifier.

    Normalizes endpoints so that traffic flowing A -> B and B -> A produces
    an identical key. Transport ports default to 0 for non-port protocols (e.g. ICMP).
    """
    endpoint_low: Tuple[str, int]
    endpoint_high: Tuple[str, int]
    protocol: str

    @classmethod
    def from_metadata(cls, meta: PacketMetadata) -> Optional["FlowKey"]:
        """Construct a normalized FlowKey from a PacketMetadata object.

        Returns:
            Optional[FlowKey]: Normalized key, or None if packet lacks network addresses.
        """
        src_ip = (meta.source_ip or "").strip().lower()
        dst_ip = (meta.destination_ip or "").strip().lower()

        # Packets without IP addresses (e.g. raw frames or malformed metadata)
        if not src_ip or not dst_ip:
            return None

        src_port = int(meta.source_port) if meta.source_port is not None else 0
        dst_port = int(meta.destination_port) if meta.destination_port is not None else 0
        proto = (meta.protocol or "OTHER").strip().upper()

        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)

        # Lexicographical normalization ensures A -> B and B -> A match
        if ep1 <= ep2:
            return cls(endpoint_low=ep1, endpoint_high=ep2, protocol=proto)
        else:
            return cls(endpoint_low=ep2, endpoint_high=ep1, protocol=proto)

    def __str__(self) -> str:
        ip1, p1 = self.endpoint_low
        ip2, p2 = self.endpoint_high
        p1_str = f":{p1}" if p1 > 0 else ""
        p2_str = f":{p2}" if p2 > 0 else ""
        return f"{self.protocol} {ip1}{p1_str} <-> {ip2}{p2_str}"


@dataclass
class NetworkFlow:
    """Represents an active or completed bidirectional communication session."""
    flow_id: str
    key: FlowKey
    initiator_ip: str
    initiator_port: Optional[int]
    responder_ip: str
    responder_port: Optional[int]
    protocol: str
    first_seen: float
    last_seen: float
    total_packets: int = 0
    total_bytes: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0
    tcp_flags: Set[str] = field(default_factory=set)
    status: FlowStatus = FlowStatus.ACTIVE

    @classmethod
    def create(cls, meta: PacketMetadata, key: FlowKey) -> "NetworkFlow":
        """Instantiate a new NetworkFlow from the initial packet."""
        flow_id = uuid.uuid4().hex[:16]
        ts = meta.timestamp
        flow = cls(
            flow_id=flow_id,
            key=key,
            initiator_ip=meta.source_ip or "",
            initiator_port=meta.source_port,
            responder_ip=meta.destination_ip or "",
            responder_port=meta.destination_port,
            protocol=key.protocol,
            first_seen=ts,
            last_seen=ts,
            status=FlowStatus.ACTIVE,
        )
        flow.add_packet(meta)
        return flow

    @property
    def duration(self) -> float:
        """Calculate flow duration in seconds. Handles out-of-order timestamps safely."""
        return max(0.0, round(self.last_seen - self.first_seen, 4))

    def is_forward_packet(self, meta: PacketMetadata) -> bool:
        """Determine whether packet aligns with the flow's initial direction."""
        src_ip = (meta.source_ip or "").strip().lower()
        init_ip = self.initiator_ip.strip().lower()

        # Match IP
        if src_ip != init_ip:
            return False

        # Match port if applicable
        src_port = meta.source_port or 0
        init_port = self.initiator_port or 0
        return src_port == init_port

    def add_packet(self, meta: PacketMetadata) -> bool:
        """Incorporate packet metadata into flow telemetry.

        Returns:
            bool: True if forward direction, False if reverse direction.
        """
        ts = meta.timestamp
        length = meta.packet_length

        # Handle out-of-order timestamps safely
        self.first_seen = min(self.first_seen, ts)
        self.last_seen = max(self.last_seen, ts)

        is_forward = self.is_forward_packet(meta)
        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += length
        else:
            self.reverse_packets += 1
            self.reverse_bytes += length

        self.total_packets = self.forward_packets + self.reverse_packets
        self.total_bytes = self.forward_bytes + self.reverse_bytes

        # Aggregate unique TCP flags
        if meta.tcp_flags:
            for flag in meta.tcp_flags.split(","):
                cleaned = flag.strip()
                if cleaned:
                    self.tcp_flags.add(cleaned)

        return is_forward

    def close(self) -> None:
        """Transition flow to CLOSED status."""
        self.status = FlowStatus.CLOSED

    def to_dict(self) -> Dict[str, Any]:
        """Serialize flow summary to a JSON-compatible dictionary."""
        first_iso = datetime.fromtimestamp(self.first_seen, tz=timezone.utc).isoformat()
        last_iso = datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat()

        return {
            "flow_id": self.flow_id,
            "key": str(self.key),
            "protocol": self.protocol,
            "status": self.status.value,
            "initiator_ip": self.initiator_ip,
            "initiator_port": self.initiator_port,
            "responder_ip": self.responder_ip,
            "responder_port": self.responder_port,
            "first_seen": self.first_seen,
            "first_seen_iso": first_iso,
            "last_seen": self.last_seen,
            "last_seen_iso": last_iso,
            "duration_seconds": self.duration,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "forward_packets": self.forward_packets,
            "reverse_packets": self.reverse_packets,
            "forward_bytes": self.forward_bytes,
            "reverse_bytes": self.reverse_bytes,
            "tcp_flags": sorted(list(self.tcp_flags)),
        }


class TrafficStats:
    """Thread-safe aggregated network traffic metrics."""

    def __init__(self):
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.active_flows: int = 0
        self.completed_flows: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.icmp_packets: int = 0
        self.other_packets: int = 0
        self.total_forward_packets: int = 0
        self.total_reverse_packets: int = 0
        self._lock = threading.Lock()

    def record_packet(self, protocol: str, byte_count: int, is_forward: bool) -> None:
        """Update packet and byte volume counters thread-safely."""
        with self._lock:
            self.total_packets += 1
            self.total_bytes += byte_count

            if is_forward:
                self.total_forward_packets += 1
            else:
                self.total_reverse_packets += 1

            proto = (protocol or "").upper()
            if proto == "TCP":
                self.tcp_packets += 1
            elif proto == "UDP":
                self.udp_packets += 1
            elif proto in ("ICMP", "ICMPV6"):
                self.icmp_packets += 1
            else:
                self.other_packets += 1

    def update_flow_counts(self, active: int, completed: int) -> None:
        """Update current active and completed flow count snapshots."""
        with self._lock:
            self.active_flows = active
            self.completed_flows = completed

    def reset(self) -> None:
        """Reset all statistical counters."""
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.active_flows = 0
            self.completed_flows = 0
            self.tcp_packets = 0
            self.udp_packets = 0
            self.icmp_packets = 0
            self.other_packets = 0
            self.total_forward_packets = 0
            self.total_reverse_packets = 0

    def to_dict(self) -> Dict[str, Any]:
        """Return a thread-safe snapshot of traffic statistics."""
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "active_flows": self.active_flows,
                "completed_flows": self.completed_flows,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "icmp_packets": self.icmp_packets,
                "other_packets": self.other_packets,
                "total_forward_packets": self.total_forward_packets,
                "total_reverse_packets": self.total_reverse_packets,
            }

