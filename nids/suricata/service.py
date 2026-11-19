"""Suricata Integration Service.

Coordinates EVE log tailing, background thread management, event parsing,
alert dispatch to the NIDS storage pipeline, and sample fixture ingestion.
"""

import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from nids.detection.models import DetectionEvent
from nids.suricata.models import EveEventType, EveRecord
from nids.suricata.parser import eve_to_detection_event, parse_eve_line
from nids.suricata.reader import EveLogReader

logger = logging.getLogger("nids.suricata.service")


class SuricataService:
    """High-level coordinator for Suricata EVE log deep inspection ingestion."""

    def __init__(
        self,
        eve_path: str,
        sample_path: Optional[str] = None,
        on_alert: Optional[Callable[[DetectionEvent], None]] = None,
        on_event: Optional[Callable[[EveRecord], None]] = None,
        poll_interval: float = 1.0,
        state_path: Optional[str] = None,
    ):
        """Initialize Suricata service.

        Args:
            eve_path: Filepath to live Suricata eve.json.
            sample_path: Filepath to controlled sample fixture eve.json.
            on_alert: Callback invoked with mapped DetectionEvent for each parsed alert.
            on_event: Optional callback invoked with every parsed EveRecord.
            poll_interval: Polling frequency in seconds for the tailer thread.
            state_path: Optional filepath to persist reader offset.
        """
        self.eve_path = eve_path
        self.sample_path = sample_path
        self.on_alert = on_alert
        self.on_event = on_event
        self.poll_interval = max(0.1, poll_interval)

        self.reader = EveLogReader(file_path=eve_path, state_path=state_path)

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Telemetry statistics
        self._stats: Dict[str, Any] = {
            "total_lines_read": 0,
            "total_events_parsed": 0,
            "alerts_count": 0,
            "dns_count": 0,
            "http_count": 0,
            "tls_count": 0,
            "flow_count": 0,
            "anomaly_count": 0,
            "other_count": 0,
            "parse_errors": 0,
            "sample_ingestions": 0,
            "last_read_timestamp": None,
            "last_error": None,
        }

    @property
    def is_running(self) -> bool:
        """Check whether the background tailer thread is active."""
        return self._worker_thread is not None and self._worker_thread.is_alive()

    def start(self) -> None:
        """Start the background EVE tailing thread."""
        with self._lock:
            if self.is_running:
                logger.warning("SuricataService tailer is already running.")
                return

            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._tail_worker,
                name="SuricataEveTailer",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("SuricataService tailer thread started for %s", self.eve_path)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background EVE tailing thread gracefully."""
        self._stop_event.set()
        thread = self._worker_thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        self._worker_thread = None
        logger.info("SuricataService tailer thread stopped.")

    def poll_once(self) -> List[DetectionEvent]:
        """Execute a single polling pass on the live EVE log.

        Reads newly appended lines, parses events, converts alerts to DetectionEvents,
        and triggers callbacks.

        Returns:
            List of newly created DetectionEvents generated in this pass.
        """
        lines = self.reader.read_new_lines()
        if not lines:
            return []

        generated_events: List[DetectionEvent] = []

        for line in lines:
            with self._lock:
                self._stats["total_lines_read"] += 1

            record = parse_eve_line(line)
            if not record:
                with self._lock:
                    self._stats["parse_errors"] += 1
                continue

            with self._lock:
                self._stats["total_events_parsed"] += 1
                self._update_event_type_stats(record.event_type)

            if record.is_alert():
                det_event = eve_to_detection_event(record)
                if det_event:
                    generated_events.append(det_event)
                    with self._lock:
                        self._stats["alerts_count"] += 1
                    if self.on_alert:
                        try:
                            self.on_alert(det_event)
                        except Exception as exc:
                            logger.error("Error in on_alert callback: %s", exc)
                            with self._lock:
                                self._stats["last_error"] = str(exc)

            if self.on_event:
                try:
                    self.on_event(record)
                except Exception as exc:
                    logger.error("Error in on_event callback: %s", exc)

        if lines:
            with self._lock:
                self._stats["last_read_timestamp"] = time.time()

        return generated_events

    def ingest_file(self, file_path: str, is_fixture: bool = False) -> Dict[str, Any]:
        """Ingest all records from a specified EVE JSON file (one-shot batch).

        Useful for test fixtures, sample demonstrations, or historical log import.

        Args:
            file_path: Path to the EVE log file to read.
            is_fixture: Flag indicating if this is a controlled sample fixture.

        Returns:
            Dictionary summary of ingestion counts and results.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"EVE log file not found: {file_path}")

        lines_read = 0
        events_parsed = 0
        alerts_persisted = 0
        errors = 0
        generated_alerts: List[DetectionEvent] = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                lines_read += 1
                with self._lock:
                    self._stats["total_lines_read"] += 1

                record = parse_eve_line(line)
                if not record:
                    errors += 1
                    with self._lock:
                        self._stats["parse_errors"] += 1
                    continue

                events_parsed += 1
                with self._lock:
                    self._stats["total_events_parsed"] += 1
                    self._update_event_type_stats(record.event_type)

                if record.is_alert():
                    det_event = eve_to_detection_event(record)
                    if det_event:
                        alerts_persisted += 1
                        generated_alerts.append(det_event)
                        with self._lock:
                            self._stats["alerts_count"] += 1
                        if self.on_alert:
                            try:
                                self.on_alert(det_event)
                            except Exception as exc:
                                logger.error("Error persisting alert in ingest_file: %s", exc)
                                with self._lock:
                                    self._stats["last_error"] = str(exc)

                if self.on_event:
                    try:
                        self.on_event(record)
                    except Exception:
                        pass

        with self._lock:
            if is_fixture:
                self._stats["sample_ingestions"] += 1
            self._stats["last_read_timestamp"] = time.time()

        return {
            "status": "success",
            "file_path": file_path,
            "lines_read": lines_read,
            "events_parsed": events_parsed,
            "alerts_persisted": alerts_persisted,
            "parse_errors": errors,
            "is_fixture": is_fixture,
        }

    def ingest_sample_fixture(self) -> Dict[str, Any]:
        """Ingest the configured sample fixture file."""
        if not self.sample_path or not os.path.exists(self.sample_path):
            raise FileNotFoundError(f"Suricata sample fixture file not found at: {self.sample_path}")
        return self.ingest_file(self.sample_path, is_fixture=True)

    def get_status(self) -> Dict[str, Any]:
        """Return operational state and telemetry statistics."""
        live_file_exists = os.path.exists(self.eve_path)
        sample_file_exists = bool(self.sample_path and os.path.exists(self.sample_path))

        with self._lock:
            stats_copy = dict(self._stats)
            offset = self.reader.offset

        mode = "standby"
        if self.is_running:
            mode = "live" if live_file_exists else "waiting_for_log"
        elif stats_copy["sample_ingestions"] > 0:
            mode = "fixture"

        return {
            "is_running": self.is_running,
            "mode": mode,
            "eve_path": self.eve_path,
            "eve_exists": live_file_exists,
            "sample_path": self.sample_path,
            "sample_exists": sample_file_exists,
            "poll_interval": self.poll_interval,
            "file_offset": offset,
            "stats": stats_copy,
        }

    def _tail_worker(self) -> None:
        """Background loop executing poll_once at configured intervals."""
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                logger.error("Unhandled exception in Suricata tail worker: %s", exc)
                with self._lock:
                    self._stats["last_error"] = str(exc)

            self._stop_event.wait(self.poll_interval)

    def _update_event_type_stats(self, event_type: EveEventType) -> None:
        """Internal helper to increment telemetry counter by event type."""
        if event_type == EveEventType.DNS:
            self._stats["dns_count"] += 1
        elif event_type == EveEventType.HTTP:
            self._stats["http_count"] += 1
        elif event_type == EveEventType.TLS:
            self._stats["tls_count"] += 1
        elif event_type == EveEventType.FLOW:
            self._stats["flow_count"] += 1
        elif event_type == EveEventType.ANOMALY:
            self._stats["anomaly_count"] += 1
        elif event_type != EveEventType.ALERT:
            self._stats["other_count"] += 1

