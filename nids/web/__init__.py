"""Web Module (Flask Backend & REST API).

Provides the web dashboard, real-time alert polling endpoints,
traffic analysis metrics, capture controls, and statistics APIs for Chart.js analytics.
"""

from flask import Flask
from config import Config
from nids.analysis import TrafficAnalyzer
from nids.capture import PacketCaptureEngine
from nids.detection import DetectionEngine
from nids.storage import DatabaseManager


def create_app(config_class=Config) -> Flask:
    """Application factory for the NIDS Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 1. Attach persistent database manager to app extension context
    app.db_manager = DatabaseManager(app.config["DATABASE_PATH"])

    # 2. Attach intrusion detection engine (persisting to db_manager via non-blocking queue)
    app.detection_engine = DetectionEngine(
        max_events=app.config.get("MAX_DETECTION_EVENTS", 1000),
        on_event=app.db_manager.enqueue_detection_event,
    )

    # 3. Attach stateful traffic analyzer and flow tracking coordinator
    app.traffic_analyzer = TrafficAnalyzer(
        idle_timeout=app.config.get("FLOW_IDLE_TIMEOUT", 30.0),
        max_active_flows=app.config.get("MAX_ACTIVE_FLOWS", 10000),
        max_completed_flows=app.config.get("MAX_COMPLETED_FLOWS", 1000),
        detection_engine=app.detection_engine,
    )

    # 4. Attach packet capture engine in safe IDLE state
    app.capture_engine = PacketCaptureEngine(
        on_packet=app.traffic_analyzer.process_packet,
    )

    # 5. Attach Suricata deep inspection integration service (Phase 8)
    from nids.suricata import SuricataService

    def _persist_suricata_alert(event):
        if hasattr(app.db_manager, "async_writer") and app.db_manager.async_writer.is_running:
            app.db_manager.enqueue_detection_event(event)
        else:
            app.db_manager.insert_detection_event(event)

    app.suricata_service = SuricataService(
        eve_path=app.config.get("SURICATA_EVE_PATH"),
        sample_path=app.config.get("SURICATA_SAMPLE_PATH"),
        on_alert=_persist_suricata_alert,
        poll_interval=app.config.get("SURICATA_POLL_INTERVAL", 1.0),
        state_path=app.config.get("SURICATA_OFFSET_FILE"),
    )

    if app.config.get("SURICATA_ENABLED", False):
        app.suricata_service.start()

    # 6. Attach safe, reversible Incident Response & Containment Manager (Task 4)
    from nids.response import IPBlockingManager
    app.blocking_manager = IPBlockingManager(
        database=app.db_manager.db,
        enabled=app.config.get("RESPONSE_BLOCKING_ENABLED", False),
        simulation_mode=app.config.get("BLOCKING_SIMULATION_MODE", True),
    )

    # 7. Defense-in-Depth Security Headers (Task 3 Secure Coding Remediation)
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    # Register routes blueprint
    from nids.web.routes import web_bp
    app.register_blueprint(web_bp)

    return app

