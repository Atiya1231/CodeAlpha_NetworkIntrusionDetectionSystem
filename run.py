#!/usr/bin/env python3
"""NIDS - Network Intrusion Detection System Entry Point.

Starts the Flask Web UI and initializes the database.
Packet capture and detection engine background workers will be linked in subsequent phases.
"""

import sys
from config import Config
from nids.web import create_app


def main():
    print("=" * 60)
    print(f" {Config.APP_NAME}")
    print(f" Version: {Config.APP_VERSION}")
    print(" Target Environment: Windows 10/11 | Python 3.13")
    print(" Phase 1: Project Architecture Initialized")
    print("=" * 60)

    app = create_app(Config)
    print(f"[*] SQLite Database verified at: {Config.DATABASE_PATH}")
    print(f"[*] Starting Web Dashboard on http://{Config.FLASK_HOST}:{Config.FLASK_PORT}")
    print("[*] Note: Packet sniffing engine will be activated in Phase 2.")
    print("=" * 60)

    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.DEBUG
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] NIDS server shutting down gracefully.")
        sys.exit(0)

