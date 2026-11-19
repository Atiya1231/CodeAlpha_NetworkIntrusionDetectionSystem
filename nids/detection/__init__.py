"""Intrusion Detection Engine Module for NIDS.

Provides passive heuristic rule evaluation, severity grading, and explainable
security anomaly detection using non-sensitive network metadata.
"""

from nids.detection.engine import DetectionEngine
from nids.detection.models import DetectionEvent, Severity
from nids.detection.rules import (
    DetectionRule,
    PortScanRule,
    SuspiciousFlowRule,
    SynFloodRule,
    TrafficSpikeRule,
)

__all__ = [
    "DetectionEngine",
    "DetectionEvent",
    "Severity",
    "DetectionRule",
    "PortScanRule",
    "SynFloodRule",
    "TrafficSpikeRule",
    "SuspiciousFlowRule",
]
