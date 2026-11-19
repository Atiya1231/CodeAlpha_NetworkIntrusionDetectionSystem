"""Parser and schema mapping for Suricata EVE JSON records.

Translates EVE JSON events into strongly typed EveRecord instances and maps
Suricata alert events into standard NIDS DetectionEvent objects with confidence="SURICATA_SIGNATURE".
Application payloads and credentials are excluded to preserve privacy and safety.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from nids.detection.models import DetectionEvent, Severity
from nids.suricata.models import EveAlertData, EveEventType, EveRecord

logger = logging.getLogger("nids.suricata.parser")


def map_suricata_severity(raw_sev: Any) -> Severity:
    """Map Suricata 1-4 numeric severity to NIDS standardized Severity enum.

    Suricata Standard:
        1: Alert High / Critical (e.g. Exploits, Root compromises)
        2: Alert Medium / High (e.g. Trojans, Scans, User Privilege Gain)
        3: Alert Low / Medium (e.g. Potentially Bad Traffic, Policy Violations)
        4: Informational (e.g. Info, Large ICMP)
    """
    if raw_sev is None:
        return Severity.INFO

    # Numeric mappings
    try:
        sev_int = int(raw_sev)
        if sev_int == 1:
            return Severity.CRITICAL
        elif sev_int == 2:
            return Severity.HIGH
        elif sev_int == 3:
            return Severity.MEDIUM
        elif sev_int == 4:
            return Severity.LOW
        else:
            return Severity.INFO
    except (ValueError, TypeError):
        pass

    # String mappings
    sev_str = str(raw_sev).strip().upper()
    if sev_str in ("1", "CRITICAL", "CRIT"):
        return Severity.CRITICAL
    elif sev_str in ("2", "HIGH"):
        return Severity.HIGH
    elif sev_str in ("3", "MEDIUM", "MED"):
        return Severity.MEDIUM
    elif sev_str in ("4", "LOW"):
        return Severity.LOW
    elif sev_str in ("INFO", "INFORMATIONAL"):
        return Severity.INFO

    return Severity.INFO


def parse_eve_line(line: str) -> Optional[EveRecord]:
    """Parse a single JSON line from an EVE log file.

    Resilient to malformed JSON, empty lines, and comment lines.

    Args:
        line: Raw line string from eve.json.

    Returns:
        EveRecord if parsed successfully, or None if skipped/invalid.
    """
    if not line:
        return None

    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("Skipping malformed Suricata EVE JSON line: %s | Error: %s", cleaned[:100], exc)
        return None

    if not isinstance(data, dict):
        logger.warning("Skipping non-dict Suricata EVE JSON line: %s", cleaned[:100])
        return None

    raw_event_type = data.get("event_type", "")
    event_type = EveEventType.from_string(raw_event_type)

    # Parse ports safely
    def _parse_port(v: Any) -> Optional[int]:
        if v is None:
            return None
        try:
            p = int(v)
            return p if 0 <= p <= 65535 else None
        except (ValueError, TypeError):
            return None

    src_port = _parse_port(data.get("src_port"))
    dest_port = _parse_port(data.get("dest_port"))

    # Parse alert block if present
    alert_obj = None
    if "alert" in data and isinstance(data["alert"], dict):
        alert_obj = EveAlertData.from_dict(data["alert"])
    elif event_type == EveEventType.ALERT:
        alert_obj = EveAlertData()

    # Flow ID safely
    flow_id = None
    if data.get("flow_id") is not None:
        try:
            flow_id = int(data["flow_id"])
        except (ValueError, TypeError):
            pass

    return EveRecord(
        timestamp=str(data.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        event_type=event_type,
        src_ip=str(data["src_ip"]) if data.get("src_ip") else None,
        src_port=src_port,
        dest_ip=str(data["dest_ip"]) if data.get("dest_ip") else None,
        dest_port=dest_port,
        proto=str(data["proto"]).upper() if data.get("proto") else None,
        flow_id=flow_id,
        in_iface=str(data["in_iface"]) if data.get("in_iface") else None,
        alert=alert_obj,
        dns=data.get("dns") if isinstance(data.get("dns"), dict) else None,
        http=data.get("http") if isinstance(data.get("http"), dict) else None,
        tls=data.get("tls") if isinstance(data.get("tls"), dict) else None,
        flow=data.get("flow") if isinstance(data.get("flow"), dict) else None,
        anomaly=data.get("anomaly") if isinstance(data.get("anomaly"), dict) else None,
        raw_data=data,
    )


def eve_to_detection_event(record: EveRecord) -> Optional[DetectionEvent]:
    """Convert an alert-type EveRecord into a standardized DetectionEvent.

    Args:
        record: Parsed EveRecord.

    Returns:
        DetectionEvent with confidence="SURICATA_SIGNATURE", or None if not an alert.
    """
    if not record.is_alert() or not record.alert:
        return None

    alert = record.alert
    severity = map_suricata_severity(alert.severity)
    sig_id = alert.signature_id
    rule_id = f"SURICATA-{sig_id}" if sig_id else "SURICATA-ALERT"
    detection_name = alert.signature or "Suricata Signature Alert"
    description = f"Suricata [{alert.category}]: {detection_name}"

    # Parse ISO timestamp to float epoch
    ts_float: Optional[float] = None
    try:
        # Normalize ISO-8601 string (e.g. +0000 -> +00:00)
        ts_str = record.timestamp
        if ts_str.endswith("+0000"):
            ts_str = ts_str[:-5] + "+00:00"
        elif ts_str.endswith("-0000"):
            ts_str = ts_str[:-5] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        ts_float = dt.timestamp()
    except (ValueError, TypeError):
        ts_float = datetime.now(timezone.utc).timestamp()

    # Build sanitized forensic evidence without raw packet bytes
    evidence: Dict[str, Any] = {
        "suricata_gid": alert.gid,
        "suricata_sid": alert.signature_id,
        "suricata_rev": alert.rev,
        "suricata_category": alert.category,
        "suricata_severity": alert.severity,
        "suricata_action": alert.action,
        "source_port": record.src_port,
        "destination_port": record.dest_port,
        "flow_id": record.flow_id,
        "in_iface": record.in_iface,
    }

    if record.flow:
        evidence["flow_summary"] = {
            "pkts_toserver": record.flow.get("pkts_toserver"),
            "pkts_toclient": record.flow.get("pkts_toclient"),
            "bytes_toserver": record.flow.get("bytes_toserver"),
            "bytes_toclient": record.flow.get("bytes_toclient"),
            "age": record.flow.get("age"),
            "state": record.flow.get("state"),
        }

    if record.http:
        evidence["http_metadata"] = {
            "hostname": record.http.get("hostname"),
            "url": record.http.get("url"),
            "http_method": record.http.get("http_method"),
            "status": record.http.get("status"),
        }

    if record.dns:
        evidence["dns_metadata"] = {
            "type": record.dns.get("type"),
            "rrname": record.dns.get("rrname"),
            "rrtype": record.dns.get("rrtype"),
        }

    if record.tls:
        evidence["tls_metadata"] = {
            "sni": record.tls.get("sni"),
            "subject": record.tls.get("subject"),
            "issuerdn": record.tls.get("issuerdn"),
            "fingerprint": record.tls.get("fingerprint"),
            "version": record.tls.get("version"),
        }

    dedup_key = f"suricata:{sig_id}:{record.src_ip or '*'}:{record.dest_ip or '*'}:{record.timestamp}"
    threshold_str = f"GID:{alert.gid} SID:{alert.signature_id} REV:{alert.rev} ACTION:{alert.action}"

    return DetectionEvent.create(
        rule_id=rule_id,
        detection_name=detection_name,
        severity=severity,
        description=description,
        evidence=evidence,
        threshold_used=threshold_str,
        source_ip=record.src_ip,
        destination_ip=record.dest_ip,
        protocol=record.proto or "UNKNOWN",
        timestamp=ts_float,
        confidence="SURICATA_SIGNATURE",
        deduplication_key=dedup_key,
    )

