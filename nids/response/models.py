"""Domain models for Incident Response and Intrusion Mitigation.

Defines structured response recommendations, action priorities, and audit-ready
records for safe, manual, and reversible IP containment.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class ResponseAction(str, Enum):
    """Types of response actions an analyst or system can take."""
    ACKNOWLEDGE = "ACKNOWLEDGE"
    RESOLVE = "RESOLVE"
    DISMISS = "DISMISS"
    INVESTIGATE = "INVESTIGATE"
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"


class ActionPriority(str, Enum):
    """Urgency level of recommended incident mitigation."""
    IMMEDIATE = "IMMEDIATE"  # Active compromise or high-volume DDoS
    ELEVATED = "ELEVATED"    # Targeted reconnaissance or policy anomaly
    ROUTINE = "ROUTINE"      # Low-volume spike or informational trigger
    INFO = "INFO"            # Informational notice / baseline observation


class BlockStatus(str, Enum):
    """Lifecycle state of an IP containment rule."""
    ACTIVE = "ACTIVE"
    REMOVED = "REMOVED"


@dataclass
class RecommendedResponse:
    """Contextual, explainable response recommendation for an alert."""
    rule_id: str
    action_type: str
    priority: ActionPriority
    recommended_action: str
    suggested_mitigation: str
    suggested_firewall_rule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert recommendation to JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "action_type": self.action_type,
            "priority": self.priority.value,
            "recommended_action": self.recommended_action,
            "suggested_mitigation": self.suggested_mitigation,
            "suggested_firewall_rule": self.suggested_firewall_rule,
        }


@dataclass
class BlockedIPRecord:
    """Audit record for a manual, reversible IP block."""
    ip_address: str
    reason: str
    status: BlockStatus = BlockStatus.ACTIVE
    alert_id: Optional[int] = None
    analyst: str = "Security Analyst"
    is_simulated: bool = True
    blocked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    unblocked_at: Optional[str] = None
    command_preview: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert blocked IP record to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "status": self.status.value,
            "alert_id": self.alert_id,
            "analyst": self.analyst,
            "is_simulated": self.is_simulated,
            "blocked_at": self.blocked_at,
            "unblocked_at": self.unblocked_at,
            "command_preview": self.command_preview,
        }
