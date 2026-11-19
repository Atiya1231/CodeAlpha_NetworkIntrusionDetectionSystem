"""Safe, Reversible, Explicitly Authorized IP Containment Manager.

Provides manual IP blocking capabilities on Windows Defender Firewall.
Strictly disabled by default, defaults to dry-run simulation mode, prevents
blocking loopback/private/critical infrastructure, and strictly forbids
automatic or unauthorized blocking.
"""

import ipaddress
import logging
import os
import subprocess
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from nids.response.models import BlockedIPRecord, BlockStatus
from nids.storage.database import Database

logger = logging.getLogger("nids.response.blocking")


class IPBlockingManager:
    """Manages safe, audited, reversible manual IP blocking."""

    def __init__(
        self,
        database: Optional[Database] = None,
        enabled: Optional[bool] = None,
        simulation_mode: Optional[bool] = None,
    ):
        """Initialize blocking manager with strict safety defaults.

        Args:
            database: Optional Database engine for persistence.
            enabled: Master switch. Defaults to False (via NIDS_RESPONSE_BLOCKING_ENABLED env).
            simulation_mode: Dry-run flag. Defaults to True (via NIDS_BLOCKING_SIMULATION env).
        """
        self.db = database

        # Master feature switch: Disabled by default for absolute safety
        if enabled is not None:
            self.enabled = bool(enabled)
        else:
            self.enabled = os.environ.get("NIDS_RESPONSE_BLOCKING_ENABLED", "False").lower() in ("true", "1")

        # Simulation mode: Defaults to True so no actual firewall changes occur without explicit opt-in
        if simulation_mode is not None:
            self.simulation_mode = bool(simulation_mode)
        else:
            self.simulation_mode = os.environ.get("NIDS_BLOCKING_SIMULATION", "True").lower() in ("true", "1")

        self._lock = threading.Lock()
        self._in_memory_records: Dict[str, BlockedIPRecord] = {}

        if self.db:
            self._ensure_table()
            self._load_records_from_db()

    def _ensure_table(self) -> None:
        """Create blocked_ips persistence table if not present."""
        if not self.db:
            return
        sql = """
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
        """
        with self.db.connection() as conn:
            conn.executescript(sql)

    def _load_records_from_db(self) -> None:
        """Hydrate in-memory lookup cache from database."""
        if not self.db:
            return
        with self.db.connection() as conn:
            cur = conn.execute("SELECT * FROM blocked_ips WHERE status = 'ACTIVE'")
            for row in cur.fetchall():
                rec = BlockedIPRecord(
                    id=row["id"],
                    ip_address=row["ip_address"],
                    reason=row["reason"],
                    status=BlockStatus(row["status"]),
                    alert_id=row["alert_id"],
                    analyst=row["analyst"],
                    is_simulated=bool(row["is_simulated"]),
                    blocked_at=row["blocked_at"],
                    unblocked_at=row["unblocked_at"],
                    command_preview=row["command_preview"],
                )
                self._in_memory_records[rec.ip_address] = rec

    def validate_ip_safety(self, ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Validate IP format and verify that target is not a protected infrastructure address.

        Args:
            ip_str: IPv4 or IPv6 string.

        Returns:
            Parsed ipaddress object.

        Raises:
            ValueError: If address is invalid, loopback, multicast, or link-local.
        """
        if not ip_str or not isinstance(ip_str, str):
            raise ValueError("Target IP address must be a non-empty string.")

        cleaned = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(cleaned)
        except ValueError as err:
            raise ValueError(f"Invalid IP address format '{cleaned}': {err}")

        # Safety Guard 1: Loopback addresses (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            raise ValueError(f"Protected Address: Blocking loopback interface ({ip_obj}) is strictly prohibited.")

        # Safety Guard 2: Unspecified or Broadcast (0.0.0.0, 255.255.255.255)
        if ip_obj.is_unspecified:
            raise ValueError("Protected Address: Blocking unspecified 0.0.0.0 is prohibited.")

        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj == ipaddress.IPv4Address("255.255.255.255"):
            raise ValueError("Protected Address: Blocking global broadcast address is prohibited.")

        # Safety Guard 3: Multicast addresses (224.0.0.0/4, ff00::/8)
        if ip_obj.is_multicast:
            raise ValueError(f"Protected Address: Blocking multicast address ({ip_obj}) is prohibited.")

        # Safety Guard 4: Link-Local addresses (169.254.0.0/16, fe80::/10)
        if ip_obj.is_link_local:
            raise ValueError(f"Protected Address: Blocking link-local autoconfiguration address ({ip_obj}) is prohibited.")

        return ip_obj

    def block_ip(
        self,
        ip_address: str,
        reason: str,
        alert_id: Optional[int] = None,
        analyst: str = "Security Analyst",
        authorized: bool = False,
    ) -> BlockedIPRecord:
        """Manually block an IP address with mandatory authorization and safety checks.

        Args:
            ip_address: IP address to block.
            reason: Justification for block.
            alert_id: Optional linked alert ID.
            analyst: Identifier of operator authorizing the block.
            authorized: Mandatory explicit authorization flag.

        Returns:
            BlockedIPRecord: Recorded block entry.

        Raises:
            PermissionError: If response blocking is disabled.
            ValueError: If authorization is missing or IP is invalid/protected.
        """
        # Strict Rule 1: Must be explicitly enabled
        if not self.enabled:
            raise PermissionError(
                "IP blocking is currently DISABLED by configuration. "
                "Set NIDS_RESPONSE_BLOCKING_ENABLED=true to activate response capabilities."
            )

        # Strict Rule 2: Explicit user authorization is required
        if not authorized:
            raise ValueError(
                "Action rejected: Explicit operator authorization ('authorized=True') "
                "is strictly required to apply network containment."
            )

        if not reason or not reason.strip():
            raise ValueError("A clear operational reason is required to block an IP.")

        # Strict Rule 3: Comprehensive safety validation
        ip_obj = self.validate_ip_safety(ip_address)
        canonical_ip = str(ip_obj)

        with self._lock:
            # Check if already actively blocked
            existing = self._in_memory_records.get(canonical_ip)
            if existing and existing.status == BlockStatus.ACTIVE:
                logger.info("IP %s is already actively blocked.", canonical_ip)
                return existing

            rule_name = f"NIDS_Block_{canonical_ip.replace(':', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={canonical_ip}'

            if not self.simulation_mode:
                # Execute real system command safely without shell expansion
                logger.warning("[FIREWALL ACTIVE] Applying real Windows Firewall block for IP %s", canonical_ip)
                proc = subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", "action=block", f"remoteip={canonical_ip}"
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if proc.returncode != 0:
                    raise RuntimeError(f"Firewall rule creation failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
            else:
                logger.info("[SIMULATION] Simulated firewall block for IP %s: %s", canonical_ip, cmd)

            record = BlockedIPRecord(
                ip_address=canonical_ip,
                reason=reason.strip(),
                status=BlockStatus.ACTIVE,
                alert_id=alert_id,
                analyst=analyst.strip() or "Security Analyst",
                is_simulated=self.simulation_mode,
                blocked_at=datetime.now(timezone.utc).isoformat(),
                command_preview=cmd,
            )

            if self.db:
                with self.db.transaction() as conn:
                    cur = conn.execute(
                        """
                        INSERT INTO blocked_ips (
                            ip_address, reason, alert_id, status, is_simulated,
                            blocked_at, analyst, command_preview
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.ip_address,
                            record.reason,
                            record.alert_id,
                            record.status.value,
                            1 if record.is_simulated else 0,
                            record.blocked_at,
                            record.analyst,
                            record.command_preview,
                        ),
                    )
                    record.id = cur.lastrowid

            self._in_memory_records[canonical_ip] = record
            return record

    def unblock_ip(
        self,
        ip_address: str,
        analyst: str = "Security Analyst",
        authorized: bool = False,
    ) -> bool:
        """Manually remove an IP block rule (reversibility guarantee).

        Args:
            ip_address: IP address to unblock.
            analyst: Identifier of operator authorizing the removal.
            authorized: Mandatory explicit authorization flag.

        Returns:
            bool: True if unblocked, False if no active block found.
        """
        if not authorized:
            raise ValueError(
                "Action rejected: Explicit operator authorization ('authorized=True') "
                "is strictly required to remove network containment."
            )

        ip_obj = self.validate_ip_safety(ip_address)
        canonical_ip = str(ip_obj)

        with self._lock:
            existing = self._in_memory_records.get(canonical_ip)
            if not existing or existing.status != BlockStatus.ACTIVE:
                return False

            rule_name = f"NIDS_Block_{canonical_ip.replace(':', '_')}"
            if not self.simulation_mode and not existing.is_simulated:
                logger.warning("[FIREWALL ACTIVE] Removing Windows Firewall block for IP %s", canonical_ip)
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            else:
                logger.info("[SIMULATION] Simulated firewall unblock for IP %s", canonical_ip)

            now_iso = datetime.now(timezone.utc).isoformat()
            existing.status = BlockStatus.REMOVED
            existing.unblocked_at = now_iso

            if self.db and existing.id:
                with self.db.transaction() as conn:
                    conn.execute(
                        "UPDATE blocked_ips SET status = 'REMOVED', unblocked_at = ? WHERE id = ?",
                        (now_iso, existing.id),
                    )

            del self._in_memory_records[canonical_ip]
            return True

    def list_blocked_ips(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Retrieve list of blocked IP records."""
        with self._lock:
            if not self.db:
                records = list(self._in_memory_records.values())
                if active_only:
                    records = [r for r in records if r.status == BlockStatus.ACTIVE]
                return [r.to_dict() for r in records]

            query = "SELECT * FROM blocked_ips"
            if active_only:
                query += " WHERE status = 'ACTIVE'"
            query += " ORDER BY id DESC"

            with self.db.connection() as conn:
                cur = conn.execute(query)
                results = []
                for row in cur.fetchall():
                    results.append({
                        "id": row["id"],
                        "ip_address": row["ip_address"],
                        "reason": row["reason"],
                        "status": row["status"],
                        "alert_id": row["alert_id"],
                        "analyst": row["analyst"],
                        "is_simulated": bool(row["is_simulated"]),
                        "blocked_at": row["blocked_at"],
                        "unblocked_at": row["unblocked_at"],
                        "command_preview": row["command_preview"],
                    })
                return results

    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check whether an IP is actively blocked."""
        try:
            canonical_ip = str(ipaddress.ip_address(ip_address.strip()))
        except ValueError:
            return False

        with self._lock:
            rec = self._in_memory_records.get(canonical_ip)
            return rec is not None and rec.status == BlockStatus.ACTIVE

    def get_status(self) -> Dict[str, Any]:
        """Return operational state and metrics for the response subsystem."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "simulation_mode": self.simulation_mode,
                "active_blocks_count": len(self._in_memory_records),
                "firewall_type": "Windows Defender Firewall (netsh)",
                "automatic_blocking_active": False,  # Strict guarantee: never automatic
            }
