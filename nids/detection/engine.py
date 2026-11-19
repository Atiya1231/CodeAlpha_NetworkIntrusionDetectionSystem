"""Intrusion Detection Engine for NIDS.

Coordinates passive heuristic rule evaluation, enforces memory-bounded event retention,
provides severity aggregation, and exposes explainable security telemetry.
"""

import collections
import logging
import threading
from typing import Any, Callable, Deque, Dict, List, Optional

from nids.analysis.models import NetworkFlow
from nids.capture.metadata import PacketMetadata
from nids.detection.models import DetectionEvent, Severity
from nids.detection.rules import (
    DetectionRule,
    PortScanRule,
    SuspiciousFlowRule,
    SynFloodRule,
    TrafficSpikeRule,
)

logger = logging.getLogger("nids.detection.engine")


class DetectionEngine:
    """Thread-safe, passive intrusion detection engine evaluating rules against packet/flow metadata."""

    def __init__(
        self,
        max_events: int = 1000,
        register_defaults: bool = True,
        on_event: Optional[Callable[[DetectionEvent], None]] = None,
    ):
        """Initialize the DetectionEngine.

        Args:
            max_events: Maximum number of detection events retained in memory buffer.
            register_defaults: Whether to register standard heuristic rules on startup.
            on_event: Optional callback invoked when a new DetectionEvent is triggered.
        """
        self.max_events = max(1, int(max_events))
        self.on_event = on_event
        self._rules: List[DetectionRule] = []
        self._events: Deque[DetectionEvent] = collections.deque(maxlen=self.max_events)
        self._lock = threading.Lock()

        # Telemetry metrics
        self.total_inspections: int = 0
        self.total_events_generated: int = 0
        self.events_by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        self.events_by_rule: Dict[str, int] = {}

        if register_defaults:
            self._register_default_rules()

    def set_event_callback(self, callback: Optional[Callable[[DetectionEvent], None]]) -> None:
        """Register or update the callback for generated detection events."""
        with self._lock:
            self.on_event = callback

    def _register_default_rules(self) -> None:
        """Register default defensive heuristic detection rules."""
        self.register_rule(PortScanRule())
        self.register_rule(SynFloodRule())
        self.register_rule(TrafficSpikeRule())
        self.register_rule(SuspiciousFlowRule())

    def register_rule(self, rule: DetectionRule) -> None:
        """Add a detection rule to the active inspection pipeline."""
        with self._lock:
            # Prevent duplicate rule IDs
            existing = [r for r in self._rules if r.rule_id == rule.rule_id]
            if existing:
                self._rules.remove(existing[0])
            self._rules.append(rule)
            self.events_by_rule.setdefault(rule.rule_id, 0)
        logger.debug("Registered detection rule: %s (%s)", rule.rule_id, rule.name)

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Find a registered rule by its identifier."""
        with self._lock:
            for rule in self._rules:
                if rule.rule_id == rule_id:
                    return rule
            return None

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by its identifier."""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by its identifier."""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def inspect(
        self,
        meta: PacketMetadata,
        flow: Optional[NetworkFlow] = None,
        timestamp: Optional[float] = None,
    ) -> List[DetectionEvent]:
        """Pass packet metadata through all active rules and record any generated events.

        Args:
            meta: PacketMetadata from capture/analysis engine.
            flow: Optional active NetworkFlow context.
            timestamp: Optional simulated timestamp for testing.

        Returns:
            List[DetectionEvent]: List of events triggered by this packet.
        """
        if meta is None:
            return []

        generated_events: List[DetectionEvent] = []

        with self._lock:
            self.total_inspections += 1
            active_rules = [r for r in self._rules if r.enabled]

            for rule in active_rules:
                try:
                    event = rule.inspect(meta, flow=flow, timestamp=timestamp)
                    if event is not None:
                        generated_events.append(event)
                        self._events.append(event)
                        self.total_events_generated += 1
                        self.events_by_severity[event.severity.value] += 1
                        self.events_by_rule[rule.rule_id] = self.events_by_rule.get(rule.rule_id, 0) + 1
                        logger.info("Detection event: %s", event)
                except Exception as rule_err:
                    logger.debug("Error executing rule %s: %s", rule.rule_id, rule_err)

            callback = self.on_event

        # Safely invoke persistence callback outside the lock to avoid contention
        if callback and generated_events:
            for ev in generated_events:
                try:
                    callback(ev)
                except Exception as cb_err:
                    logger.error("Failed to execute event callback for %s: %s", ev.event_id, cb_err)

        return generated_events

    def get_events(self, limit: int = 100, severity: Optional[Severity] = None) -> List[DetectionEvent]:
        """Retrieve recent detection events up to limit, optionally filtered by severity."""
        with self._lock:
            events = list(self._events)
            if severity is not None:
                events = [e for e in events if e.severity == severity]
            return events[-limit:] if limit > 0 else events

    def get_summary(self) -> Dict[str, Any]:
        """Return aggregated summary of detection events and inspection telemetry."""
        with self._lock:
            return {
                "total_inspections": self.total_inspections,
                "total_events_generated": self.total_events_generated,
                "active_event_count": len(self._events),
                "events_by_severity": dict(self.events_by_severity),
                "events_by_rule": dict(self.events_by_rule),
                "active_rules_count": len([r for r in self._rules if r.enabled]),
                "total_rules_count": len(self._rules),
            }

    def clear_events(self) -> None:
        """Clear historical event buffer."""
        with self._lock:
            self._events.clear()

    def reset(self) -> None:
        """Reset all rules, historical buffers, and telemetry statistics."""
        with self._lock:
            self._events.clear()
            self.total_inspections = 0
            self.total_events_generated = 0
            self.events_by_severity = {s.value: 0 for s in Severity}
            self.events_by_rule = {r.rule_id: 0 for r in self._rules}
            for rule in self._rules:
                rule.reset()
