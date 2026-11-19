"""Storage Module for NIDS.

Provides persistent SQLite database connection management, schema migration,
asynchronous/synchronous alert persistence, and security alert repository operations.
"""

from typing import Any, Dict, List, Optional

from nids.detection.models import DetectionEvent
from nids.storage.alert_repository import AlertRepository, AlertStatus
from nids.storage.async_writer import AsyncAlertWriter
from nids.storage.database import Database


class DatabaseManager:
    """Unified database management, asynchronous worker, and alert repository interface.

    Preserves 100% backward compatibility with Phase 1-5 database calls while providing
    full access to Phase 6 alert lifecycle management, filtering, and non-blocking persistence.
    """

    def __init__(self, db_path: str, timeout: float = 15.0, max_queue_size: int = 5000):
        self.db = Database(db_path, timeout=timeout)
        self.repository = AlertRepository(self.db)
        self.async_writer = AsyncAlertWriter(self.repository, max_queue_size=max_queue_size)
        self.db_path = self.db.db_path

    def get_connection(self):
        """Create a connection with row factory configured."""
        return self.db.get_connection()

    def connection(self):
        """Context manager providing a managed SQLite connection with guaranteed closure."""
        return self.db.connection()

    def transaction(self):
        """Context manager providing an atomic transaction with automatic rollback."""
        return self.db.transaction()

    def init_db(self) -> None:
        """Initialize database tables and execute idempotent schema migrations."""
        self.db.init_db()

    def insert_alert(self, alert_data: Dict[str, Any]) -> int:
        """Insert a newly detected alert into SQLite."""
        return self.repository.insert_alert(alert_data)

    def insert_detection_event(self, event: DetectionEvent) -> int:
        """Persist a DetectionEvent directly (synchronously) into SQLite."""
        return self.repository.insert_detection_event(event)

    def enqueue_detection_event(self, event: DetectionEvent) -> bool:
        """Enqueue a DetectionEvent for non-blocking asynchronous persistence."""
        return self.async_writer.enqueue(event)

    def start_worker(self) -> None:
        """Start the background alert persistence thread."""
        self.async_writer.start()

    def stop_worker(self, timeout: float = 5.0) -> None:
        """Stop the background alert persistence thread and flush pending items."""
        self.async_writer.stop(timeout=timeout)

    def get_persistence_stats(self) -> Dict[str, Any]:
        """Return runtime telemetry of the asynchronous persistence worker."""
        return self.async_writer.get_stats()

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single alert by its primary key ID."""
        return self.repository.get_alert_by_id(alert_id)

    def get_alert_by_event_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single alert by unique DetectionEvent ID."""
        return self.repository.get_alert_by_event_id(event_id)

    def count_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> int:
        """Return total count of alerts matching the provided filters."""
        return self.repository.count_alerts(
            severity=severity,
            status=status,
            rule_id=rule_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            start_date=start_date,
            end_date=end_date,
            confidence=confidence,
        )

    def get_recent_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent alerts with optional multi-attribute filtering."""
        return self.repository.get_recent_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            status=status,
            rule_id=rule_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            start_date=start_date,
            end_date=end_date,
            confidence=confidence,
        )

    def update_alert_status(
        self,
        alert_id: int,
        new_status: str,
        timestamp: Optional[str] = None,
        notes: Optional[str] = None,
        responder: Optional[str] = None,
    ) -> bool:
        """Update alert status (NEW, ACKNOWLEDGED, RESOLVED) with optional analyst notes."""
        return self.repository.update_alert_status(
            alert_id, new_status, timestamp=timestamp, notes=notes, responder=responder
        )

    def get_alert_summary(self) -> Dict[str, Any]:
        """Return counts of alerts grouped by severity level and status."""
        return self.repository.get_alert_summary()

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Return dedicated alert statistics grouped by status, severity, and rule."""
        return self.repository.get_alert_statistics()


__all__ = [
    "Database",
    "DatabaseManager",
    "AlertRepository",
    "AlertStatus",
    "AsyncAlertWriter",
]
