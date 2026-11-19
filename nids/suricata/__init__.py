"""Suricata Deep Inspection Integration Module for NIDS.

Provides incremental EVE JSON log tailing, schema parsing, signature alert mapping
into DetectionEvent models, and seamless SQLite persistence.
"""

from nids.suricata.models import (
    EveAlertData,
    EveEventType,
    EveRecord,
)
from nids.suricata.parser import (
    eve_to_detection_event,
    map_suricata_severity,
    parse_eve_line,
)
from nids.suricata.reader import EveLogReader
from nids.suricata.service import SuricataService

__all__ = [
    "EveAlertData",
    "EveEventType",
    "EveLogReader",
    "EveRecord",
    "SuricataService",
    "eve_to_detection_event",
    "map_suricata_severity",
    "parse_eve_line",
]

