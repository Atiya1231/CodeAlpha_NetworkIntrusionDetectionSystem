"""SQLite Database Engine for NIDS.

Provides thread-safe connection pooling, connection PRAGMAs (WAL mode, timeouts),
transaction management, and idempotent schema creation/migration.
"""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List

logger = logging.getLogger("nids.storage.database")

BASE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    rule_id TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    timestamp TEXT NOT NULL,
    description TEXT NOT NULL,
    raw_evidence TEXT,
    evidence TEXT,
    threshold_used TEXT,
    confidence TEXT,
    deduplication_key TEXT,
    status TEXT NOT NULL DEFAULT 'NEW',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    acknowledged_at TEXT,
    resolved_at TEXT,
    recommended_action TEXT,
    response_notes TEXT,
    responder TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT NOT NULL,
    alert_id INTEGER,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    is_simulated INTEGER NOT NULL DEFAULT 1,
    blocked_at TEXT NOT NULL,
    unblocked_at TEXT,
    analyst TEXT NOT NULL DEFAULT 'Security Analyst',
    command_preview TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocked_ip_addr ON blocked_ips (ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_ip_status ON blocked_ips (status);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    tcp_count INTEGER DEFAULT 0,
    udp_count INTEGER DEFAULT 0,
    icmp_count INTEGER DEFAULT 0,
    other_count INTEGER DEFAULT 0
);
"""

# New columns for schema migration on existing databases
MIGRATION_COLUMNS = [
    ("event_id", "TEXT"),
    ("rule_id", "TEXT"),
    ("evidence", "TEXT"),
    ("threshold_used", "TEXT"),
    ("confidence", "TEXT"),
    ("deduplication_key", "TEXT"),
    ("status", "TEXT DEFAULT 'NEW'"),
    ("created_at", "TEXT"),
    ("updated_at", "TEXT"),
    ("acknowledged_at", "TEXT"),
    ("resolved_at", "TEXT"),
    ("recommended_action", "TEXT"),
    ("response_notes", "TEXT"),
    ("responder", "TEXT"),
]


class Database:
    """Manages SQLite connections, pragmas, and schema migrations."""

    def __init__(self, db_path: str, timeout: float = 15.0):
        """Initialize SQLite database engine.

        Args:
            db_path: Path to the SQLite database file.
            timeout: Busy timeout in seconds to prevent OneDrive / Windows lock contention.
        """
        self.db_path = str(db_path)
        self.timeout = float(timeout)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection with configured PRAGMAs and row factory."""
        conn = sqlite3.connect(self.db_path, timeout=self.timeout)
        conn.row_factory = sqlite3.Row

        # Optimize for concurrency and durability
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
        except sqlite3.Error as pragma_err:
            logger.debug("Failed setting SQLite pragmas: %s", pragma_err)

        return conn

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing a managed SQLite connection with guaranteed closure."""
        conn = self.get_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an atomic transaction with automatic rollback on error."""
        conn = self.get_connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Idempotently initialize tables, indices, and execute migrations on existing tables."""
        with self.connection() as conn:
            # 1. Check if alerts table already exists before executing base schema
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
            table_existed = cur.fetchone() is not None

            # 2. Execute base schema
            conn.executescript(BASE_SCHEMA_SQL)

            # 3. Check for missing columns on existing databases (idempotent migration)
            cursor = conn.execute("PRAGMA table_info(alerts)")
            existing_cols = {row["name"].lower() for row in cursor.fetchall()}

            for col_name, col_type in MIGRATION_COLUMNS:
                if col_name.lower() not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type};")
                        logger.info("Migrated alerts table: added column '%s'", col_name)
                    except sqlite3.OperationalError as alter_err:
                        logger.debug("Column migration skipped for '%s': %s", col_name, alter_err)

            # 4. Create indices on columns (safely executed after column checks)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts (event_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts (deduplication_key);")
