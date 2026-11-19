"""Data models for Suricata EVE JSON event ingestion.

Defines structured representations for parsed Suricata telemetry events (alert, flow, dns,
http, tls, anomaly) without retaining raw packet frame bytes or sensitive payloads.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class EveEventType(str, Enum):
    """Categorized event types emitted by Suricata EVE log engine."""
    ALERT = "alert"
    FLOW = "flow"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    ANOMALY = "anomaly"
    FILEINFO = "fileinfo"
    STATS = "stats"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, val: str) -> "EveEventType":
        """Safe factory returning matched enum or UNKNOWN."""
        if not val:
            return cls.UNKNOWN
        try:
            return cls(val.lower().strip())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class EveAlertData:
    """Structured fields specific to Suricata 'alert' records."""
    gid: int = 1
    signature_id: int = 0
    rev: int = 0
    signature: str = "Suricata Signature Alert"
    category: str = "Generic Detection"
    severity: int = 3
    action: str = "allowed"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EveAlertData":
        """Safe constructor handling absent or non-integer fields."""
        if not isinstance(data, dict):
            return cls()

        def _safe_int(v: Any, default: int) -> int:
            try:
                return int(v)
            except (TypeError, ValueError):
                return default

        return cls(
            gid=_safe_int(data.get("gid"), 1),
            signature_id=_safe_int(data.get("signature_id"), 0),
            rev=_safe_int(data.get("rev"), 0),
            signature=str(data.get("signature") or "Suricata Signature Alert").strip(),
            category=str(data.get("category") or "Generic Detection").strip(),
            severity=_safe_int(data.get("severity"), 3),
            action=str(data.get("action") or "allowed").strip(),
        )


@dataclass
class EveRecord:
    """Normalized Suricata EVE log event container."""
    timestamp: str
    event_type: EveEventType
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    flow_id: Optional[int] = None
    in_iface: Optional[str] = None
    alert: Optional[EveAlertData] = None
    dns: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    tls: Optional[Dict[str, Any]] = None
    flow: Optional[Dict[str, Any]] = None
    anomaly: Optional[Dict[str, Any]] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def is_alert(self) -> bool:
        """Check if this event is an alert record."""
        return self.event_type == EveEventType.ALERT and self.alert is not None

