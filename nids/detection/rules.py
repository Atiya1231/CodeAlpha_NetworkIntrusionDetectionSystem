"""Detection Rules for NIDS Intrusion Detection Engine.

Implements explainable heuristic detection rules for Port Scans, SYN Floods,
Traffic Spikes, and Suspicious Flow patterns using non-sensitive metadata only.
"""

import collections
import logging
from abc import ABC, abstractmethod
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from nids.analysis.models import NetworkFlow
from nids.capture.metadata import PacketMetadata
from nids.detection.models import DetectionEvent, Severity

logger = logging.getLogger("nids.detection.rules")


class DetectionRule(ABC):
    """Abstract base class for modular intrusion detection rules."""

    def __init__(self, rule_id: str, name: str, description: str, severity: Severity, enabled: bool = True):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = enabled

    @abstractmethod
    def inspect(
        self,
        meta: PacketMetadata,
        flow: Optional[NetworkFlow] = None,
        timestamp: Optional[float] = None,
    ) -> Optional[DetectionEvent]:
        """Inspect packet and flow metadata against detection criteria.

        Args:
            meta: PacketMetadata from capture engine.
            flow: Optional active NetworkFlow from FlowTracker.
            timestamp: Optional simulated reference timestamp.

        Returns:
            Optional[DetectionEvent]: Event if anomalous activity is identified, else None.
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset internal rule tracking state."""
        pass


class PortScanRule(DetectionRule):
    """Detects horizontal port scanning from a single source to distinct target ports."""

    def __init__(
        self,
        threshold: int = 20,
        window_sec: float = 10.0,
        cooldown_sec: float = 60.0,
        max_tracked_pairs: int = 1000,
        enabled: bool = True,
    ):
        super().__init__(
            rule_id="RULE-PORT-SCAN",
            name="Horizontal Port Scan Indicator",
            description="A single source IP contacted an unusually high count of distinct destination ports on a target.",
            severity=Severity.HIGH,
            enabled=enabled,
        )
        self.threshold = max(2, int(threshold))
        self.window_sec = max(1.0, float(window_sec))
        self.cooldown_sec = max(1.0, float(cooldown_sec))
        self.max_tracked_pairs = max(10, int(max_tracked_pairs))

        # (src_ip, dst_ip) -> Deque of (timestamp, dst_port)
        self._history: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = {}
        # (src_ip, dst_ip) -> last_alert_time
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def inspect(
        self,
        meta: PacketMetadata,
        flow: Optional[NetworkFlow] = None,
        timestamp: Optional[float] = None,
    ) -> Optional[DetectionEvent]:
        if not self.enabled:
            return None

        src_ip = meta.source_ip
        dst_ip = meta.destination_ip
        dst_port = meta.destination_port

        if not src_ip or not dst_ip or dst_port is None:
            return None

        now = timestamp if timestamp is not None else meta.timestamp
        pair_key = (src_ip, dst_ip)

        # Capacity management for tracked host pairs
        if pair_key not in self._history and len(self._history) >= self.max_tracked_pairs:
            oldest_key = min(self._history, key=lambda k: self._history[k][-1][0] if self._history[k] else 0)
            del self._history[oldest_key]

        history = self._history.setdefault(pair_key, collections.deque())
        history.append((now, dst_port))

        # Sliding window pruning
        cutoff = now - self.window_sec
        while history and history[0][0] < cutoff:
            history.popleft()

        distinct_ports = len({port for _, port in history})

        if distinct_ports >= self.threshold:
            last_alert = self._last_alert.get(pair_key, 0.0)
            if (now - last_alert) >= self.cooldown_sec:
                self._last_alert[pair_key] = now
                evidence = {
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "distinct_ports_contacted": distinct_ports,
                    "threshold": self.threshold,
                    "time_window_seconds": self.window_sec,
                    "sample_ports": sorted(list({p for _, p in history}))[:10],
                }
                return DetectionEvent.create(
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    severity=self.severity,
                    description=(
                        f"Heuristic Indicator: Source {src_ip} probed {distinct_ports} distinct ports "
                        f"on target {dst_ip} within {self.window_sec:.1f}s (threshold: {self.threshold})."
                    ),
                    evidence=evidence,
                    threshold_used=self.threshold,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=meta.protocol,
                    timestamp=now,
                    confidence="HEURISTIC_INDICATOR",
                    deduplication_key=f"{self.rule_id}:{src_ip}:{dst_ip}",
                )

        return None

    def reset(self) -> None:
        self._history.clear()
        self._last_alert.clear()


class SynFloodRule(DetectionRule):
    """Detects high-rate TCP SYN packet activity directed at a target or from a source."""

    def __init__(
        self,
        threshold: int = 100,
        window_sec: float = 5.0,
        cooldown_sec: float = 60.0,
        max_tracked_pairs: int = 1000,
        enabled: bool = True,
    ):
        super().__init__(
            rule_id="RULE-SYN-FLOOD",
            name="High-Volume TCP SYN Activity",
            description="Unusually high frequency of TCP SYN requests observed within a short temporal window.",
            severity=Severity.HIGH,
            enabled=enabled,
        )
        self.threshold = max(5, int(threshold))
        self.window_sec = max(1.0, float(window_sec))
        self.cooldown_sec = max(1.0, float(cooldown_sec))
        self.max_tracked_pairs = max(10, int(max_tracked_pairs))

        self._history: Dict[Tuple[str, str], Deque[float]] = {}
        self._last_alert: Dict[Tuple[str, str], float] = {}

    def inspect(
        self,
        meta: PacketMetadata,
        flow: Optional[NetworkFlow] = None,
        timestamp: Optional[float] = None,
    ) -> Optional[DetectionEvent]:
        if not self.enabled:
            return None

        if meta.protocol != "TCP" or not meta.tcp_flags:
            return None

        # Detect SYN packets (SYN flag present, not ACK)
        flags_upper = meta.tcp_flags.upper()
        if "SYN" not in flags_upper or "ACK" in flags_upper:
            return None

        src_ip = meta.source_ip
        dst_ip = meta.destination_ip
        if not src_ip or not dst_ip:
            return None

        now = timestamp if timestamp is not None else meta.timestamp
        pair_key = (src_ip, dst_ip)

        if pair_key not in self._history and len(self._history) >= self.max_tracked_pairs:
            oldest_key = min(self._history, key=lambda k: self._history[k][-1] if self._history[k] else 0)
            del self._history[oldest_key]

        history = self._history.setdefault(pair_key, collections.deque())
        history.append(now)

        cutoff = now - self.window_sec
        while history and history[0] < cutoff:
            history.popleft()

        syn_count = len(history)
        if syn_count >= self.threshold:
            last_alert = self._last_alert.get(pair_key, 0.0)
            if (now - last_alert) >= self.cooldown_sec:
                self._last_alert[pair_key] = now
                evidence = {
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "syn_packet_count": syn_count,
                    "threshold": self.threshold,
                    "time_window_seconds": self.window_sec,
                }
                return DetectionEvent.create(
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    severity=self.severity,
                    description=(
                        f"Heuristic Indicator: Observed {syn_count} TCP SYN packets from {src_ip} "
                        f"to {dst_ip} within {self.window_sec:.1f}s (threshold: {self.threshold})."
                    ),
                    evidence=evidence,
                    threshold_used=self.threshold,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    timestamp=now,
                    confidence="HEURISTIC_INDICATOR",
                    deduplication_key=f"{self.rule_id}:{src_ip}:{dst_ip}",
                )

        return None

    def reset(self) -> None:
        self._history.clear()
        self._last_alert.clear()


class TrafficSpikeRule(DetectionRule):
    """Detects sudden volumetric spikes in packet frequency exceeding baseline limits."""

    def __init__(
        self,
        threshold: int = 500,
        window_sec: float = 5.0,
        cooldown_sec: float = 60.0,
        enabled: bool = True,
    ):
        super().__init__(
            rule_id="RULE-TRAFFIC-SPIKE",
            name="Anomalous Traffic Spike",
            description="Sudden surge in aggregate packet frequency exceeding configured baseline thresholds.",
            severity=Severity.MEDIUM,
            enabled=enabled,
        )
        self.threshold = max(10, int(threshold))
        self.window_sec = max(1.0, float(window_sec))
        self.cooldown_sec = max(1.0, float(cooldown_sec))

        self._history: Deque[Tuple[float, int]] = collections.deque()
        self._last_alert_time: float = 0.0

    def inspect(
        self,
        meta: PacketMetadata,
        flow: Optional[NetworkFlow] = None,
        timestamp: Optional[float] = None,
    ) -> Optional[DetectionEvent]:
        if not self.enabled:
            return None

        now = timestamp if timestamp is not None else meta.timestamp
        length = meta.packet_length or 0
        self._history.append((now, length))

        cutoff = now - self.window_sec
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

        total_pkts = len(self._history)
        if total_pkts >= self.threshold:
            if (now - self._last_alert_time) >= self.cooldown_sec:
                self._last_alert_time = now
                total_bytes = sum(b for _, b in self._history)
                evidence = {
                    "packets_in_window": total_pkts,
                    "bytes_in_window": total_bytes,
                    "threshold_packets": self.threshold,
                    "time_window_seconds": self.window_sec,
                }
                return DetectionEvent.create(
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    severity=self.severity,
                    description=(
                        f"Heuristic Indicator: Traffic spike detected: {total_pkts} packets "
                        f"({total_bytes} bytes) within {self.window_sec:.1f}s (threshold: {self.threshold})."
                    ),
                    evidence=evidence,
                    threshold_used=self.threshold,
                    source_ip=meta.source_ip,
                    destination_ip=meta.destination_ip,
                    protocol=meta.protocol,
                    timestamp=now,
                    confidence="HEURISTIC_INDICATOR",
                    deduplication_key=f"{self.rule_id}:global",
                )

        return None

    def reset(self) -> None:
        self._history.clear()
        self._last_alert_time = 0.0


class SuspiciousFlowRule(DetectionRule):
    """Detects conservative suspicious flow patterns such as reserved Port 0 usage or naked FIN scans."""

    def __init__(
        self,
        cooldown_sec: float = 30.0,
        enabled: bool = True,
    ):
        super().__init__(
            rule_id="RULE-SUSPICIOUS-FLOW",
            name="Suspicious Header / Flow Pattern",
            description="Detected anomalous port or control flag patterns such as reserved Port 0 access or naked FIN.",
            severity=Severity.LOW,
            enabled=enabled,
        )
        self.cooldown_sec = max(1.0, float(cooldown_sec))
        self._last_alerts: Dict[str, float] = {}

    def inspect(
        self,
        meta: PacketMetadata,
        flow: Optional[NetworkFlow] = None,
        timestamp: Optional[float] = None,
    ) -> Optional[DetectionEvent]:
        if not self.enabled:
            return None

        now = timestamp if timestamp is not None else meta.timestamp

        # Case 1: Reserved Port 0 probe
        if meta.source_port == 0 or meta.destination_port == 0:
            dedup = f"{self.rule_id}:port0:{meta.source_ip}:{meta.destination_ip}"
            if (now - self._last_alerts.get(dedup, 0.0)) >= self.cooldown_sec:
                self._last_alerts[dedup] = now
                return DetectionEvent.create(
                    rule_id=self.rule_id,
                    detection_name="Reserved Port 0 Probe",
                    severity=Severity.MEDIUM,
                    description=f"Packet observed targeting reserved port 0 (Source: {meta.source_ip}, Target: {meta.destination_ip}).",
                    evidence={"source_port": meta.source_port, "destination_port": meta.destination_port},
                    threshold_used=0,
                    source_ip=meta.source_ip,
                    destination_ip=meta.destination_ip,
                    protocol=meta.protocol,
                    timestamp=now,
                    confidence="HEURISTIC_INDICATOR",
                    deduplication_key=dedup,
                )

        # Case 2: Naked TCP FIN scan (FIN set without ACK)
        if meta.protocol == "TCP" and meta.tcp_flags:
            flags = [f.strip().upper() for f in meta.tcp_flags.split(",")]
            if flags == ["FIN"]:
                dedup = f"{self.rule_id}:fin_scan:{meta.source_ip}:{meta.destination_ip}"
                if (now - self._last_alerts.get(dedup, 0.0)) >= self.cooldown_sec:
                    self._last_alerts[dedup] = now
                    return DetectionEvent.create(
                        rule_id=self.rule_id,
                        detection_name="Naked TCP FIN Scan Indicator",
                        severity=Severity.LOW,
                        description=f"Observed standalone TCP FIN packet without ACK from {meta.source_ip} to {meta.destination_ip}.",
                        evidence={"tcp_flags": meta.tcp_flags, "destination_port": meta.destination_port},
                        threshold_used="FIN-only",
                        source_ip=meta.source_ip,
                        destination_ip=meta.destination_ip,
                        protocol="TCP",
                        timestamp=now,
                        confidence="HEURISTIC_INDICATOR",
                        deduplication_key=dedup,
                    )

        return None

    def reset(self) -> None:
        self._last_alerts.clear()

