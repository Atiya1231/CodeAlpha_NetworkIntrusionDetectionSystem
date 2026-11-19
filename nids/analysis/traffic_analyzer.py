"""Traffic Analyzer Module for NIDS.

Coordinates flow session tracking with aggregated traffic telemetry.
Serves as the high-level analysis pipeline consumer for PacketMetadata.
"""

import logging
from typing import Any, Dict, List, Optional

from nids.analysis.flow_tracker import FlowTracker
from nids.analysis.models import NetworkFlow, TrafficStats
from nids.capture.metadata import PacketMetadata

logger = logging.getLogger("nids.analysis.traffic_analyzer")


class TrafficAnalyzer:
    """High-level traffic analysis pipeline combining session tracking and volume metrics."""

    def __init__(
        self,
        idle_timeout: float = 30.0,
        max_active_flows: int = 10000,
        max_completed_flows: int = 1000,
        retain_completed_flows: bool = True,
        detection_engine: Optional[Any] = None,
    ):
        """Initialize the TrafficAnalyzer.

        Args:
            idle_timeout: Seconds of inactivity before an active flow expires.
            max_active_flows: Maximum active flows tracked concurrently.
            max_completed_flows: Maximum completed flows retained.
            retain_completed_flows: Whether to buffer completed flows.
            detection_engine: Optional passive DetectionEngine instance.
        """
        self.flow_tracker = FlowTracker(
            idle_timeout=idle_timeout,
            max_active_flows=max_active_flows,
            max_completed_flows=max_completed_flows,
            retain_completed_flows=retain_completed_flows,
        )
        self.stats = TrafficStats()
        self.detection_engine = detection_engine

    def attach_detection_engine(self, engine: Any) -> None:
        """Attach a passive DetectionEngine to the analysis pipeline."""
        self.detection_engine = engine

    def process_packet(self, meta: PacketMetadata) -> Optional[NetworkFlow]:
        """Process incoming packet metadata through the flow tracker and update metrics.

        Args:
            meta: PacketMetadata extracted from the capture engine.

        Returns:
            Optional[NetworkFlow]: The associated NetworkFlow if routable, or None if non-IP.
        """
        if meta is None:
            return None

        result = self.flow_tracker.process_packet(meta)
        if result is not None:
            flow, is_forward = result
            self.stats.record_packet(meta.protocol, meta.packet_length, is_forward=is_forward)
            self.stats.update_flow_counts(
                active=self.flow_tracker.active_flow_count,
                completed=self.flow_tracker.completed_flow_count,
            )
            if self.detection_engine:
                try:
                    self.detection_engine.inspect(meta, flow=flow)
                except Exception as det_err:
                    logger.debug("Error in passive detection inspection: %s", det_err)
            return flow
        else:
            # Handle non-routable / non-IP packets (e.g. ARP, raw frames)
            self.stats.record_packet(meta.protocol or "OTHER", meta.packet_length, is_forward=True)
            self.stats.update_flow_counts(
                active=self.flow_tracker.active_flow_count,
                completed=self.flow_tracker.completed_flow_count,
            )
            if self.detection_engine:
                try:
                    self.detection_engine.inspect(meta, flow=None)
                except Exception as det_err:
                    logger.debug("Error in passive detection inspection: %s", det_err)
            return None

    def expire_idle_flows(self, now: Optional[float] = None) -> List[NetworkFlow]:
        """Trigger idle-flow expiration and update active/completed counters.

        Args:
            now: Optional reference timestamp for testing.

        Returns:
            List[NetworkFlow]: Newly expired flows.
        """
        expired = self.flow_tracker.expire_flows(now=now)
        self.stats.update_flow_counts(
            active=self.flow_tracker.active_flow_count,
            completed=self.flow_tracker.completed_flow_count,
        )
        return expired

    def get_active_flows(self) -> List[NetworkFlow]:
        """Retrieve snapshot of all currently active flows."""
        return self.flow_tracker.get_active_flows()

    def get_completed_flows(self, limit: int = 100) -> List[NetworkFlow]:
        """Retrieve snapshot of recently closed/expired flows."""
        return self.flow_tracker.get_completed_flows(limit=limit)

    def get_summary(self) -> Dict[str, Any]:
        """Return a complete, JSON-serializable telemetry and flow summary."""
        summary = self.stats.to_dict()
        summary["active_flows"] = self.flow_tracker.active_flow_count
        summary["completed_flows"] = self.flow_tracker.completed_flow_count
        if self.detection_engine:
            summary["detection"] = self.detection_engine.get_summary()
        return summary

    def close(self) -> List[NetworkFlow]:
        """Retire all active flows cleanly."""
        closed = self.flow_tracker.close_all_flows()
        self.stats.update_flow_counts(
            active=self.flow_tracker.active_flow_count,
            completed=self.flow_tracker.completed_flow_count,
        )
        return closed

    def reset(self) -> None:
        """Reset flow tracker and telemetry metrics."""
        self.flow_tracker.clear()
        self.stats.reset()

