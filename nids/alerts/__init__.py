"""Alert Management Module.

Responsibilities:
- Standardized alert data modeling with severity grading.
- Deduplication and rate-limiting to prevent alert fatigue.
- Dispatching alerts to database persistence, UI queues, and logging sinks.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any


class AlertSeverity(str, Enum):
    """Severity ratings for security alerts."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    """Lifecycle statuses for security alerts."""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


@dataclass
class Alert:
    """Standardized Security Alert object."""
    title: str
    severity: AlertSeverity
    source_ip: str
    destination_ip: str
    protocol: str
    description: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    raw_evidence: Optional[str] = None
    status: AlertStatus = AlertStatus.NEW
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert into a dictionary for JSON serialization and DB storage."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "description": self.description,
            "raw_evidence": self.raw_evidence,
        }

