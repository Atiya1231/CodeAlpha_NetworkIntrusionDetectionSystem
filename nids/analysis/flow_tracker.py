"""Flow Tracker Module for NIDS.

Maintains bidirectional connection state, associates packet telemetry into sessions,
manages idle-flow expiration, and enforces memory retention bounds.
"""

import collections
import logging
import threading
import time
from typing import Deque, Dict, List, Optional, Tuple

from nids.analysis.models import FlowKey, FlowStatus, NetworkFlow
from nids.capture.metadata import PacketMetadata

logger = logging.getLogger("nids.analysis.flow_tracker")


class FlowTracker:
    """Thread-safe bidirectional network session and flow tracking manager."""

    def __init__(
        self,
        idle_timeout: float = 30.0,
        max_active_flows: int = 10000,
        max_completed_flows: int = 1000,
        retain_completed_flows: bool = True,
    ):
        """Initialize the FlowTracker.

        Args:
            idle_timeout: Seconds of inactivity before an active flow expires.
            max_active_flows: Capacity limit for active flow table to prevent memory exhaustion.
            max_completed_flows: Maximum count of closed flows retained in history buffer.
            retain_completed_flows: Whether to retain closed/expired flows for analysis.
        """
        self.idle_timeout = max(0.1, float(idle_timeout))
        self.max_active_flows = max(1, int(max_active_flows))
        self.max_completed_flows = max(1, int(max_completed_flows))
        self.retain_completed_flows = retain_completed_flows

        self._flows: Dict[FlowKey, NetworkFlow] = {}
        self._completed_flows: Deque[NetworkFlow] = collections.deque(maxlen=self.max_completed_flows)
        self._lock = threading.Lock()

    @property
    def active_flow_count(self) -> int:
        """Current number of active flows."""
        with self._lock:
            return len(self._flows)

    @property
    def completed_flow_count(self) -> int:
        """Current number of retained completed flows."""
        with self._lock:
            return len(self._completed_flows)

    def process_packet(self, meta: PacketMetadata) -> Optional[Tuple[NetworkFlow, bool]]:
        """Process incoming packet metadata and update or create its corresponding flow.

        Args:
            meta: Structured packet metadata from the capture engine.

        Returns:
            Optional[Tuple[NetworkFlow, bool]]: Tuple of (NetworkFlow, is_forward),
            or None if the packet could not be mapped to a valid flow key.
        """
        key = FlowKey.from_metadata(meta)
        if key is None:
            # Non-routable or missing IP header (e.g. ARP, raw Ethernet)
            return None

        with self._lock:
            if key in self._flows:
                flow = self._flows[key]
                is_forward = flow.add_packet(meta)
                return flow, is_forward

            # Table capacity limit enforcement
            if len(self._flows) >= self.max_active_flows:
                self._evict_oldest_flow_locked()

            flow = NetworkFlow.create(meta, key)
            self._flows[key] = flow
            return flow, True

    def _evict_oldest_flow_locked(self) -> None:
        """Evict the least recently active flow when table reaches maximum capacity."""
        if not self._flows:
            return

        oldest_key = min(self._flows, key=lambda k: self._flows[k].last_seen)
        evicted = self._flows.pop(oldest_key)
        evicted.close()
        if self.retain_completed_flows:
            self._completed_flows.append(evicted)
        logger.warning(
            "Active flow table capacity reached (%d). Evicted oldest flow: %s",
            self.max_active_flows,
            evicted.flow_id,
        )

    def expire_flows(self, now: Optional[float] = None) -> List[NetworkFlow]:
        """Expire flows that have exceeded the idle inactivity threshold.

        Args:
            now: Optional simulated reference timestamp for deterministic testing.
                 Defaults to time.time() if None.

        Returns:
            List[NetworkFlow]: List of newly expired flows.
        """
        ref_time = now if now is not None else time.time()
        expired: List[NetworkFlow] = []

        with self._lock:
            keys_to_expire = [
                key for key, flow in self._flows.items()
                if (ref_time - flow.last_seen) >= self.idle_timeout
            ]

            for key in keys_to_expire:
                flow = self._flows.pop(key)
                flow.close()
                if self.retain_completed_flows:
                    self._completed_flows.append(flow)
                expired.append(flow)

        return expired

    def get_flow(self, key: FlowKey) -> Optional[NetworkFlow]:
        """Retrieve an active flow by its normalized key."""
        with self._lock:
            return self._flows.get(key)

    def get_active_flows(self) -> List[NetworkFlow]:
        """Return a snapshot of all currently active flows."""
        with self._lock:
            return list(self._flows.values())

    def get_completed_flows(self, limit: int = 100) -> List[NetworkFlow]:
        """Return a snapshot of recently completed/expired flows up to limit."""
        with self._lock:
            flows = list(self._completed_flows)
            return flows[-limit:] if limit > 0 else flows

    def close_all_flows(self) -> List[NetworkFlow]:
        """Close and retire all active flows safely."""
        with self._lock:
            closed_flows: List[NetworkFlow] = []
            for flow in self._flows.values():
                flow.close()
                if self.retain_completed_flows:
                    self._completed_flows.append(flow)
                closed_flows.append(flow)
            self._flows.clear()
            return closed_flows

    def clear(self) -> None:
        """Clear all active and completed flows immediately."""
        with self._lock:
            self._flows.clear()
            self._completed_flows.clear()
