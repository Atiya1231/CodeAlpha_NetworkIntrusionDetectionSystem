"""Domain models for NIDS Intrusion Detection Engine.

Defines severity classifications, structured detection events, and evidence containers
without storing sensitive packet payloads or credentials.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Standardized severity ratings for detection events."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DetectionEvent:
    """Structured, explainable security detection event."""
    event_id: str
    rule_id: str
    detection_name: str
    severity: Severity
    source_ip: Optional[str]
    destination_ip: Optional[str]
    protocol: Optional[str]
    timestamp: float
    timestamp_iso: str
    description: str
    evidence: Dict[str, Any]
    threshold_used: Any
    confidence: str = "HEURISTIC_INDICATOR"
    deduplication_key: str = ""

    @classmethod
    def create(
        cls,
        rule_id: str,
        detection_name: str,
        severity: Severity,
        description: str,
        evidence: Dict[str, Any],
        threshold_used: Any,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        timestamp: Optional[float] = None,
        confidence: str = "HEURISTIC_INDICATOR",
        deduplication_key: str = "",
    ) -> "DetectionEvent":
        """Instantiate a new DetectionEvent with automatic timestamp and unique ID."""
        ts = timestamp if timestamp is not None else datetime.now(timezone.utc).timestamp()
        iso_str = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        uid = uuid.uuid4().hex[:16]

        dedup = deduplication_key or f"{rule_id}:{source_ip}:{destination_ip}"

        return cls(
            event_id=uid,
            rule_id=rule_id,
            detection_name=detection_name,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            timestamp=ts,
            timestamp_iso=iso_str,
            description=description,
            evidence=evidence,
            threshold_used=threshold_used,
            confidence=confidence,
            deduplication_key=dedup,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection event to a JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "rule_id": self.rule_id,
            "detection_name": self.detection_name,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "description": self.description,
            "evidence": self.evidence,
            "threshold_used": self.threshold_used,
            "confidence": self.confidence,
            "deduplication_key": self.deduplication_key,
        }

    def __str__(self) -> str:
        src = self.source_ip or "Unknown"
        dst = self.destination_ip or "Unknown"
        return f"[{self.severity.value}] {self.detection_name} ({src} -> {dst}): {self.description}"

