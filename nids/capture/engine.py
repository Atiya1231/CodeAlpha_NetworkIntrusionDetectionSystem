"""Network Packet Capture Engine for NIDS.

Provides asynchronous, non-blocking packet capture using Scapy's native AsyncSniffer,
thread-safe statistics, explicit interface binding, and reliable zero-traffic stop controls.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional

from nids.capture.interfaces import find_interface
from nids.capture.metadata import PacketMetadata, extract_metadata

logger = logging.getLogger("nids.capture.engine")


class CaptureStatus(str, Enum):
    """Lifecycle states of the packet capture engine."""
    IDLE = "IDLE"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


@dataclass
class CaptureStats:
    """Thread-safe telemetry and counters for the capture session."""
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    other_packets: int = 0
    start_time: Optional[float] = None
    stop_time: Optional[float] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def record_packet(self, protocol: str) -> None:
        """Increment protocol counters in a thread-safe manner."""
        with self._lock:
            self.total_packets += 1
            proto_upper = (protocol or "").upper()
            if proto_upper == "TCP":
                self.tcp_packets += 1
            elif proto_upper == "UDP":
                self.udp_packets += 1
            elif proto_upper == "ICMP":
                self.icmp_packets += 1
            else:
                self.other_packets += 1

    def reset(self) -> None:
        """Reset all counters for a new capture session."""
        with self._lock:
            self.total_packets = 0
            self.tcp_packets = 0
            self.udp_packets = 0
            self.icmp_packets = 0
            self.other_packets = 0
            self.start_time = None
            self.stop_time = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a snapshot of current statistics as a dictionary."""
        with self._lock:
            duration = None
            if self.start_time:
                end = self.stop_time or time.time()
                duration = round(end - self.start_time, 2)
            return {
                "total_packets": self.total_packets,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "icmp_packets": self.icmp_packets,
                "other_packets": self.other_packets,
                "start_time": self.start_time,
                "stop_time": self.stop_time,
                "duration_seconds": duration,
            }


class PacketCaptureEngine:
    """Asynchronous Scapy AsyncSniffer-based network packet capture engine."""

    def __init__(self, on_packet: Optional[Callable[[PacketMetadata], None]] = None):
        """Initialize the capture engine.

        Args:
            on_packet: Optional callback invoked for each extracted PacketMetadata.
        """
        self.on_packet = on_packet
        self.stats = CaptureStats()
        self._status = CaptureStatus.IDLE
        self._status_lock = threading.Lock()
        self._sniffer: Optional[Any] = None
        self._watcher_thread: Optional[threading.Thread] = None
        self._timeout_timer: Optional[threading.Timer] = None
        self._last_error: Optional[str] = None
        self._selected_interface: Optional[str] = None

    @property
    def status(self) -> CaptureStatus:
        """Current operational state."""
        with self._status_lock:
            # Synchronize state if background sniffer completed on its own (e.g. count limit reached)
            if self._status == CaptureStatus.RUNNING and self._sniffer:
                sniffer_thread = getattr(self._sniffer, "thread", None)
                if sniffer_thread and not sniffer_thread.is_alive():
                    exc = getattr(self._sniffer, "exception", None)
                    if exc:
                        self._set_error_locked(exc, self._selected_interface or "")
                    else:
                        self._status = CaptureStatus.STOPPED
                        if not self.stats.stop_time:
                            self.stats.stop_time = time.time()
            return self._status

    @property
    def last_error(self) -> Optional[str]:
        """Last encountered error message, if any."""
        return self._last_error

    @property
    def selected_interface(self) -> Optional[str]:
        """Interface currently targeted for capture."""
        return self._selected_interface

    def start_capture(
        self,
        interface: str,
        bpf_filter: str = "",
        count: int = 0,
        timeout: Optional[int] = None,
        promiscuous: bool = False,
    ) -> bool:
        """Start non-blocking packet capture on an explicitly chosen interface.

        Args:
            interface: Name, IP, or device identifier of interface to monitor.
            bpf_filter: Optional BPF filter string (e.g. 'ip', 'tcp port 80').
            count: Number of packets to capture (0 = indefinite).
            timeout: Maximum seconds to capture (None = indefinite).
            promiscuous: Whether to enable promiscuous mode (default False for safety).

        Returns:
            bool: True if capture started successfully, False otherwise.
        """
        with self._status_lock:
            if self._status in (CaptureStatus.RUNNING, CaptureStatus.STARTING):
                sniffer_thread = getattr(self._sniffer, "thread", None)
                if sniffer_thread and sniffer_thread.is_alive():
                    logger.warning("Packet capture is already running or starting.")
                    return False

            if not interface or not str(interface).strip():
                self._last_error = "Explicit interface identifier is required. Silent default capture is prohibited."
                self._status = CaptureStatus.ERROR
                logger.error(self._last_error)
                return False

            # Resolve friendly name to Scapy device identifier if available
            resolved_iface = find_interface(interface)
            target_device = resolved_iface.scapy_name if resolved_iface else interface.strip()
            self._selected_interface = target_device

            # Reset error and initialize state
            self._last_error = None
            self._status = CaptureStatus.STARTING
            self.stats.reset()
            self.stats.start_time = time.time()

        def _packet_handler(packet: Any) -> None:
            """Process individual incoming packet."""
            try:
                meta = extract_metadata(packet, interface_name=target_device)
                self.stats.record_packet(meta.protocol)
                if self.on_packet:
                    self.on_packet(meta)
            except Exception as proc_err:
                logger.debug("Error processing captured packet: %s", proc_err)

        def _on_started() -> None:
            """Callback invoked by Scapy AsyncSniffer when loop begins."""
            with self._status_lock:
                if self._status == CaptureStatus.STARTING:
                    self._status = CaptureStatus.RUNNING

        # Configure Scapy AsyncSniffer
        # Note: Scapy AsyncSniffer does not accept 'timeout' in kwargs; timeout is managed via Timer
        sniff_kwargs: Dict[str, Any] = {
            "iface": target_device,
            "prn": _packet_handler,
            "store": False,
            "promisc": promiscuous,
            "started_callback": _on_started,
        }
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        if count > 0:
            sniff_kwargs["count"] = count

        try:
            import scapy.all as scapy_all
            self._sniffer = scapy_all.AsyncSniffer(**sniff_kwargs)
            self._sniffer.start()
        except PermissionError as perm_err:
            with self._status_lock:
                self._set_error_locked(perm_err, target_device)
            return False
        except Exception as exc:
            with self._status_lock:
                self._set_error_locked(exc, target_device)
            return False

        # Brief delay to detect immediate initialization errors in sniffer worker thread
        time.sleep(0.02)
        if hasattr(self._sniffer, "exception") and self._sniffer.exception:
            with self._status_lock:
                self._set_error_locked(self._sniffer.exception, target_device)
            return False

        with self._status_lock:
            if self._status == CaptureStatus.STARTING and getattr(self._sniffer, "running", False):
                self._status = CaptureStatus.RUNNING

        # Start timeout timer if requested
        if timeout and timeout > 0:
            self._timeout_timer = threading.Timer(float(timeout), self._handle_timeout)
            self._timeout_timer.daemon = True
            self._timeout_timer.start()

        # Start watcher thread to capture completion (e.g., when count limit is reached)
        def _watcher():
            sniffer = self._sniffer
            if sniffer and hasattr(sniffer, "thread") and sniffer.thread:
                sniffer.thread.join()
            self._on_sniffer_terminated(target_device)

        self._watcher_thread = threading.Thread(
            target=_watcher,
            name="NIDS-SnifferWatcher",
            daemon=True,
        )
        self._watcher_thread.start()

        logger.info("Started packet capture on interface: %s (Promiscuous: %s)", target_device, promiscuous)
        return True

    def stop_capture(self, wait_timeout: float = 2.0) -> bool:
        """Gracefully signal the capture engine to terminate and wait.

        Args:
            wait_timeout: Seconds to wait for thread completion.

        Returns:
            bool: True if stopped cleanly, False if thread failed to terminate.
        """
        # Cancel any pending timeout timer
        if self._timeout_timer:
            try:
                self._timeout_timer.cancel()
            except Exception:
                pass
            self._timeout_timer = None

        with self._status_lock:
            if self._status in (CaptureStatus.STOPPED, CaptureStatus.IDLE):
                logger.debug("Stop requested but capture is already inactive (%s).", self._status)
                return True

            if self._status == CaptureStatus.ERROR:
                # Capture is in error state; ensure background sniffer is halted if still running
                if self._sniffer and getattr(self._sniffer, "running", False):
                    try:
                        self._sniffer.stop(join=False)
                    except Exception:
                        pass
                return True

            self._status = CaptureStatus.STOPPING

        logger.info("Signaling packet capture engine to stop...")

        # Stop AsyncSniffer
        if self._sniffer:
            try:
                if getattr(self._sniffer, "running", False):
                    self._sniffer.stop(join=False)
            except Exception as stop_err:
                logger.debug("Exception stopping AsyncSniffer: %s", stop_err)

            sniffer_thread = getattr(self._sniffer, "thread", None)
            if sniffer_thread and sniffer_thread.is_alive():
                sniffer_thread.join(timeout=wait_timeout)

        # Allow watcher thread to finish
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=0.2)

        with self._status_lock:
            sniffer_thread = getattr(self._sniffer, "thread", None) if self._sniffer else None
            # Strict safety check: Do not mark STOPPED if underlying worker thread is still alive!
            if sniffer_thread and sniffer_thread.is_alive():
                self._last_error = f"Capture thread failed to terminate within {wait_timeout}s timeout."
                self._status = CaptureStatus.ERROR
                logger.warning(self._last_error)
                return False

            if self._status != CaptureStatus.ERROR:
                self._status = CaptureStatus.STOPPED
            if not self.stats.stop_time:
                self.stats.stop_time = time.time()

        logger.info("Packet capture engine stopped successfully.")
        return True

    def _handle_timeout(self) -> None:
        """Invoked when the capture duration timer expires."""
        logger.info("Capture duration timeout expired. Stopping capture engine...")
        self.stop_capture()

    def _on_sniffer_terminated(self, device: str) -> None:
        """Invoked by the watcher thread when AsyncSniffer thread terminates naturally."""
        with self._status_lock:
            if self._timeout_timer:
                try:
                    self._timeout_timer.cancel()
                except Exception:
                    pass
                self._timeout_timer = None

            sniffer_exc = getattr(self._sniffer, "exception", None) if self._sniffer else None
            if sniffer_exc:
                self._set_error_locked(sniffer_exc, device)
            elif self._status not in (CaptureStatus.STOPPED, CaptureStatus.ERROR):
                self._status = CaptureStatus.STOPPED
                if not self.stats.stop_time:
                    self.stats.stop_time = time.time()

    def _set_error_locked(self, exc: Exception, device: str) -> None:
        """Format and record error status under lock without throwing uncaught exceptions."""
        self._status = CaptureStatus.ERROR
        if isinstance(exc, PermissionError) or "permission" in str(exc).lower() or "admin" in str(exc).lower():
            self._last_error = (
                f"Permission denied accessing interface '{device}'. "
                "On Windows, administrator privileges are required for physical network adapters."
            )
        else:
            err_str = str(exc)
            if "npcap" in err_str.lower() or "winpcap" in err_str.lower():
                self._last_error = f"Npcap driver error on interface '{device}': {err_str}"
            else:
                self._last_error = f"Capture failed on interface '{device}': {err_str}"
        logger.error(self._last_error)
        if not self.stats.stop_time:
            self.stats.stop_time = time.time()
