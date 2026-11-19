"""Central configuration for NIDS (Network Intrusion Detection System).

Supports environment variable overrides and sensible defaults for Windows 10/11.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"

# Ensure runtime directories exist
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)


class Config:
    """Base application configuration."""

    # Application Info
    APP_NAME = "Network Intrusion Detection System (NIDS)"
    APP_VERSION = "0.1.0-alpha"

    # Security & Flask
    SECRET_KEY = os.environ.get("NIDS_SECRET_KEY", "dev-nids-secret-key-change-in-production")
    FLASK_HOST = os.environ.get("NIDS_FLASK_HOST", "127.0.0.1")
    FLASK_PORT = int(os.environ.get("NIDS_FLASK_PORT", 5000))
    DEBUG = os.environ.get("NIDS_DEBUG", "False").lower() in ("true", "1", "t")

    # Database Settings (SQLite)
    DATABASE_PATH = os.environ.get("NIDS_DB_PATH", str(DATA_DIR / "nids_events.sqlite"))

    # Packet Capture Settings
    # On Windows, None defaults to Scapy's primary interface (conf.iface)
    CAPTURE_INTERFACE = os.environ.get("NIDS_CAPTURE_IFACE", None)
    PROMISCUOUS_MODE = False
    BPF_FILTER = os.environ.get("NIDS_BPF_FILTER", "ip")
    CAPTURE_BUFFER_SIZE = 1000

    # Traffic Analysis & Flow Tracking Settings
    FLOW_IDLE_TIMEOUT = float(os.environ.get("NIDS_FLOW_IDLE_TIMEOUT", 30.0))
    MAX_ACTIVE_FLOWS = int(os.environ.get("NIDS_MAX_ACTIVE_FLOWS", 10000))
    MAX_COMPLETED_FLOWS = int(os.environ.get("NIDS_MAX_COMPLETED_FLOWS", 1000))
    RETAIN_COMPLETED_FLOWS = os.environ.get("NIDS_RETAIN_COMPLETED_FLOWS", "True").lower() in ("true", "1", "t")

    # Detection Thresholds & Cooldowns
    PORT_SCAN_THRESHOLD = int(os.environ.get("NIDS_PORT_SCAN_THRESHOLD", 20))  # ports / time window
    PORT_SCAN_WINDOW_SEC = int(os.environ.get("NIDS_PORT_SCAN_WINDOW", 10))
    PORT_SCAN_COOLDOWN_SEC = int(os.environ.get("NIDS_PORT_SCAN_COOLDOWN", 60))
    SYN_FLOOD_THRESHOLD = int(os.environ.get("NIDS_SYN_FLOOD_THRESHOLD", 100))  # packets / time window
    SYN_FLOOD_WINDOW_SEC = int(os.environ.get("NIDS_SYN_FLOOD_WINDOW", 5))
    SYN_FLOOD_COOLDOWN_SEC = int(os.environ.get("NIDS_SYN_FLOOD_COOLDOWN", 60))
    TRAFFIC_SPIKE_THRESHOLD = int(os.environ.get("NIDS_TRAFFIC_SPIKE_THRESHOLD", 500))  # packets / window
    TRAFFIC_SPIKE_WINDOW_SEC = int(os.environ.get("NIDS_TRAFFIC_SPIKE_WINDOW", 5))
    TRAFFIC_SPIKE_COOLDOWN_SEC = int(os.environ.get("NIDS_TRAFFIC_SPIKE_COOLDOWN", 60))
    MAX_DETECTION_EVENTS = int(os.environ.get("NIDS_MAX_DETECTION_EVENTS", 1000))

    # Suricata Deep Inspection Integration (Phase 8)
    SURICATA_ENABLED = os.environ.get("NIDS_SURICATA_ENABLED", "False").lower() in ("true", "1")
    SURICATA_EVE_PATH = os.environ.get(
        "NIDS_SURICATA_EVE_PATH",
        r"C:\Program Files\Suricata\log\eve.json"
    )
    SURICATA_SAMPLE_PATH = os.environ.get(
        "NIDS_SURICATA_SAMPLE_PATH",
        str(DATA_DIR / "sample_eve.json")
    )
    SURICATA_POLL_INTERVAL = float(os.environ.get("NIDS_SURICATA_POLL_INTERVAL", 1.0))
    SURICATA_OFFSET_FILE = os.environ.get(
        "NIDS_SURICATA_OFFSET_FILE",
        str(DATA_DIR / "suricata_offset.json")
    )

    # Incident Response & Containment (Task 4)
    RESPONSE_BLOCKING_ENABLED = os.environ.get("NIDS_RESPONSE_BLOCKING_ENABLED", "False").lower() in ("true", "1")
    BLOCKING_SIMULATION_MODE = os.environ.get("NIDS_BLOCKING_SIMULATION", "True").lower() in ("true", "1")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}

