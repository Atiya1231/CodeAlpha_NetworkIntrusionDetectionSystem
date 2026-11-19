"""Web and API routes for NIDS dashboard and alert management."""

from datetime import datetime
from flask import Blueprint, current_app, jsonify, render_template, request

web_bp = Blueprint("web", __name__)

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_STATUSES = {"NEW", "ACKNOWLEDGED", "RESOLVED"}
MAX_PER_PAGE = 100


@web_bp.route("/")
def landing():
    """Render the enterprise cybersecurity landing page."""
    return render_template("landing.html")


@web_bp.route("/dashboard")
def dashboard():
    """Render the main security operations dashboard."""
    return render_template("index.html")



@web_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Retrieve recent alerts with comprehensive filtering, validation, and pagination.

    Supported Query Parameters:
        page (int): 1-based page number (default: 1).
        per_page (int): Page size (default: 50, max: 100).
        limit (int): Backward-compatible alias for per_page.
        offset (int): Backward-compatible offset.
        severity (str): Filter by severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL).
        status (str): Filter by lifecycle state (NEW, ACKNOWLEDGED, RESOLVED).
        rule_id (str): Filter by detection rule identifier.
        source_ip (str): Filter by source IP address.
        destination_ip (str): Filter by destination IP address.
        start_date (str): Filter by minimum timestamp (ISO-8601).
        end_date (str): Filter by maximum timestamp (ISO-8601).
    """
    db_manager = current_app.db_manager

    # 1. Validate pagination parameters
    page_raw = request.args.get("page")
    if page_raw is not None:
        try:
            page = int(page_raw)
            if page < 1:
                return jsonify({"status": "error", "message": "Parameter 'page' must be a positive integer (>= 1)."}), 400
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Parameter 'page' must be a valid integer."}), 400
    else:
        page = 1

    per_page_raw = request.args.get("per_page")
    if per_page_raw is not None:
        try:
            per_page = int(per_page_raw)
            if per_page < 1:
                return jsonify({"status": "error", "message": "Parameter 'per_page' must be a positive integer (>= 1)."}), 400
            per_page = min(per_page, MAX_PER_PAGE)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Parameter 'per_page' must be a valid integer."}), 400
    else:
        per_page = 50

    # Backward compatibility: limit and offset
    limit_raw = request.args.get("limit")
    if limit_raw is not None:
        try:
            limit = int(limit_raw)
            if limit < 1:
                return jsonify({"status": "error", "message": "Parameter 'limit' must be >= 1."}), 400
            per_page = min(limit, MAX_PER_PAGE)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Parameter 'limit' must be an integer."}), 400

    offset_raw = request.args.get("offset")
    if offset_raw is not None:
        try:
            offset = int(offset_raw)
            if offset < 0:
                return jsonify({"status": "error", "message": "Parameter 'offset' must be >= 0."}), 400
            page = (offset // per_page) + 1
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Parameter 'offset' must be an integer."}), 400
    else:
        offset = (page - 1) * per_page

    # 2. Validate filter parameters
    severity = request.args.get("severity")
    if severity:
        sev_clean = severity.strip().upper()
        if sev_clean not in VALID_SEVERITIES:
            return jsonify({
                "status": "error",
                "message": f"Invalid severity: '{severity}'. Allowed: {sorted(VALID_SEVERITIES)}",
            }), 400
        severity = sev_clean

    status = request.args.get("status")
    if status:
        stat_clean = status.strip().upper()
        if stat_clean not in VALID_STATUSES:
            return jsonify({
                "status": "error",
                "message": f"Invalid status: '{status}'. Allowed: {sorted(VALID_STATUSES)}",
            }), 400
        status = stat_clean

    rule_id = request.args.get("rule_id")
    if rule_id:
        rule_id = rule_id.strip()

    source_ip = request.args.get("source_ip")
    if source_ip:
        source_ip = source_ip.strip()

    destination_ip = request.args.get("destination_ip")
    if destination_ip:
        destination_ip = destination_ip.strip()

    confidence = request.args.get("confidence")
    if confidence:
        confidence = confidence.strip()

    start_date = request.args.get("start_date")
    if start_date:
        start_date = start_date.strip()
        try:
            datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except ValueError:
            return jsonify({
                "status": "error",
                "message": f"Invalid start_date: '{start_date}'. Must be a valid ISO-8601 timestamp.",
            }), 400

    end_date = request.args.get("end_date")
    if end_date:
        end_date = end_date.strip()
        try:
            datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        except ValueError:
            return jsonify({
                "status": "error",
                "message": f"Invalid end_date: '{end_date}'. Must be a valid ISO-8601 timestamp.",
            }), 400

    if start_date and end_date and start_date > end_date:
        return jsonify({
            "status": "error",
            "message": "start_date must be earlier than or equal to end_date.",
        }), 400

    # 3. Query total matching count and paginated items
    total = db_manager.count_alerts(
        severity=severity,
        status=status,
        rule_id=rule_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        start_date=start_date,
        end_date=end_date,
        confidence=confidence,
    )

    total_pages = (total + per_page - 1) // per_page if total > 0 else 1

    alerts = db_manager.get_recent_alerts(
        limit=per_page,
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

    return jsonify({
        "status": "success",
        "alerts": alerts,
        "total": total,
        "count": len(alerts),
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "limit": per_page,
        "offset": offset,
    })


@web_bp.route("/api/alerts/<int:alert_id>", methods=["GET"])
def get_alert_detail(alert_id: int):
    """Retrieve a single alert by its primary key ID."""
    db_manager = current_app.db_manager
    alert = db_manager.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": f"Alert with ID {alert_id} not found"}), 404
    return jsonify({"status": "success", "alert": alert})


@web_bp.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST", "PATCH"])
def acknowledge_alert(alert_id: int):
    """Transition an alert's status to ACKNOWLEDGED (supporting POST and PATCH with optional notes)."""
    db_manager = current_app.db_manager
    payload = request.get_json(silent=True) or {}
    notes = payload.get("notes")
    responder = payload.get("responder") or "Security Analyst"

    try:
        updated = db_manager.update_alert_status(
            alert_id, "ACKNOWLEDGED", notes=notes, responder=responder
        )
    except ValueError as val_err:
        return jsonify({"status": "error", "message": str(val_err)}), 400

    if not updated:
        return jsonify({"status": "error", "message": f"Alert with ID {alert_id} not found"}), 404

    alert = db_manager.get_alert_by_id(alert_id)
    return jsonify({
        "status": "success",
        "message": f"Alert {alert_id} acknowledged successfully",
        "alert": alert,
    })


@web_bp.route("/api/alerts/<int:alert_id>/resolve", methods=["POST", "PATCH"])
def resolve_alert(alert_id: int):
    """Transition an alert's status to RESOLVED (supporting POST and PATCH with optional notes)."""
    db_manager = current_app.db_manager
    payload = request.get_json(silent=True) or {}
    notes = payload.get("notes")
    responder = payload.get("responder") or "Security Analyst"

    try:
        updated = db_manager.update_alert_status(
            alert_id, "RESOLVED", notes=notes, responder=responder
        )
    except ValueError as val_err:
        return jsonify({"status": "error", "message": str(val_err)}), 400

    if not updated:
        return jsonify({"status": "error", "message": f"Alert with ID {alert_id} not found"}), 404

    alert = db_manager.get_alert_by_id(alert_id)
    return jsonify({
        "status": "success",
        "message": f"Alert {alert_id} resolved successfully",
        "alert": alert,
    })


@web_bp.route("/api/alerts/<int:alert_id>/recommendation", methods=["GET"])
def get_alert_recommendation(alert_id: int):
    """Retrieve contextual response recommendation and mitigation advice for an alert."""
    db_manager = current_app.db_manager
    alert = db_manager.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": f"Alert with ID {alert_id} not found"}), 404

    from nids.response import get_recommended_response
    rec = get_recommended_response(
        rule_id=alert.get("rule_id"),
        title=alert.get("title"),
        severity=alert.get("severity"),
        evidence=alert.get("evidence_parsed"),
        source_ip=alert.get("source_ip"),
    )
    return jsonify({
        "status": "success",
        "alert_id": alert_id,
        "recommendation": rec.to_dict(),
    })


@web_bp.route("/api/alerts/<int:alert_id>/respond", methods=["POST"])
def respond_to_alert(alert_id: int):
    """Execute analyst incident response workflow (status transition, notes, optional manual IP block)."""
    db_manager = current_app.db_manager
    alert = db_manager.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"status": "error", "message": f"Alert with ID {alert_id} not found"}), 404

    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "ACKNOWLEDGE").strip().upper()
    notes = payload.get("notes")
    responder = payload.get("responder") or "Security Analyst"
    block_ip = bool(payload.get("block_ip", False))
    authorized = bool(payload.get("authorized", False))

    status_map = {
        "ACKNOWLEDGE": "ACKNOWLEDGED",
        "ACKNOWLEDGED": "ACKNOWLEDGED",
        "RESOLVE": "RESOLVED",
        "RESOLVED": "RESOLVED",
    }
    target_status = status_map.get(action, "ACKNOWLEDGED")

    try:
        updated = db_manager.update_alert_status(
            alert_id, target_status, notes=notes, responder=responder
        )
    except ValueError as val_err:
        return jsonify({"status": "error", "message": str(val_err)}), 400

    block_result = None
    if block_ip:
        blocking_mgr = getattr(current_app, "blocking_manager", None)
        target_ip = alert.get("source_ip")
        if not target_ip:
            return jsonify({"status": "error", "message": "Alert has no source IP to block."}), 400

        if not blocking_mgr:
            return jsonify({"status": "error", "message": "IP blocking manager is not available."}), 500

        try:
            block_rec = blocking_mgr.block_ip(
                ip_address=target_ip,
                reason=f"Incident response for alert #{alert_id}: {alert.get('title')}",
                alert_id=alert_id,
                analyst=responder,
                authorized=authorized,
            )
            block_result = block_rec.to_dict()
        except (PermissionError, ValueError, RuntimeError) as blk_err:
            return jsonify({"status": "error", "message": f"IP block failed: {blk_err}"}), 400

    updated_alert = db_manager.get_alert_by_id(alert_id)
    return jsonify({
        "status": "success",
        "message": f"Incident response applied to alert #{alert_id} (Status: {target_status}).",
        "alert": updated_alert,
        "blocked_ip": block_result,
    })


@web_bp.route("/api/alerts/stats", methods=["GET"])
def get_alerts_stats():
    """Return dedicated alert statistics grouped by status, severity, and rule."""
    db_manager = current_app.db_manager
    stats = db_manager.get_alert_statistics()
    return jsonify({
        "status": "success",
        "stats": stats,
    })


@web_bp.route("/api/stats/summary", methods=["GET"])
def get_summary_stats():
    """Return alert aggregation statistics by severity and status for Chart.js."""
    db_manager = current_app.db_manager
    summary = db_manager.get_alert_summary()
    return jsonify({"status": "success", "summary": summary})


@web_bp.route("/api/capture/interfaces", methods=["GET"])
def get_interfaces():
    """Return available network interfaces for explicit capture binding."""
    try:
        from nids.capture.interfaces import get_available_interfaces
        ifaces = get_available_interfaces()
        return jsonify({
            "status": "success",
            "count": len(ifaces),
            "interfaces": [iface.to_dict() for iface in ifaces],
        })
    except Exception as err:
        return jsonify({
            "status": "error",
            "message": f"Failed enumerating network interfaces: {err}",
            "interfaces": [],
        }), 500


@web_bp.route("/api/capture/status", methods=["GET"])
def get_capture_status():
    """Return current packet capture engine status and runtime statistics."""
    capture_engine = getattr(current_app, "capture_engine", None)
    if not capture_engine:
        return jsonify({
            "status": "success",
            "capture_status": "UNAVAILABLE",
            "is_running": False,
            "selected_interface": None,
            "last_error": None,
            "stats": {},
        })

    is_running = capture_engine.status.value == "RUNNING"
    return jsonify({
        "status": "success",
        "capture_status": capture_engine.status.value,
        "is_running": is_running,
        "selected_interface": capture_engine.selected_interface,
        "last_error": capture_engine.last_error,
        "stats": capture_engine.stats.to_dict(),
    })


@web_bp.route("/api/capture/start", methods=["POST"])
def start_capture():
    """Start packet capture on an explicitly specified network interface."""
    capture_engine = getattr(current_app, "capture_engine", None)
    if not capture_engine:
        return jsonify({"status": "error", "message": "Capture engine is not initialized."}), 500

    data = request.get_json(silent=True) or {}
    interface = data.get("interface", "").strip()
    if not interface:
        return jsonify({"status": "error", "message": "Explicit 'interface' is required. Silent default capture is prohibited."}), 400

    bpf_filter = data.get("bpf_filter", "").strip()
    count = data.get("count", 0)
    timeout = data.get("timeout")
    promiscuous = bool(data.get("promiscuous", False))

    # Prevent duplicate start requests
    if capture_engine.status.value in ("RUNNING", "STARTING"):
        return jsonify({"status": "error", "message": "Packet capture is already running."}), 409

    try:
        # Ensure async persistence worker is running
        if hasattr(current_app, "db_manager") and hasattr(current_app.db_manager, "start_worker"):
            current_app.db_manager.start_worker()

        started = capture_engine.start_capture(
            interface=interface,
            bpf_filter=bpf_filter,
            count=int(count) if count else 0,
            timeout=int(timeout) if timeout else None,
            promiscuous=promiscuous,
        )

        if not started:
            err_msg = capture_engine.last_error or "Failed to start packet capture."
            status_code = 403 if "permission" in err_msg.lower() or "administrator" in err_msg.lower() else 500
            return jsonify({"status": "error", "message": err_msg}), status_code

        return jsonify({
            "status": "success",
            "message": f"Packet capture started on interface '{interface}'.",
            "interface": capture_engine.selected_interface,
            "capture_status": capture_engine.status.value,
        })
    except PermissionError as perm_err:
        return jsonify({
            "status": "error",
            "message": f"Permission denied: Administrator privileges required for physical network capture on Windows. ({perm_err})",
        }), 403
    except Exception as exc:
        return jsonify({
            "status": "error",
            "message": f"Error starting capture: {exc}",
        }), 500


@web_bp.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """Stop an active packet capture session cleanly."""
    capture_engine = getattr(current_app, "capture_engine", None)
    if not capture_engine:
        return jsonify({"status": "error", "message": "Capture engine is not initialized."}), 500

    capture_engine.stop_capture()
    return jsonify({
        "status": "success",
        "message": "Packet capture stopped.",
        "capture_status": capture_engine.status.value,
        "stats": capture_engine.stats.to_dict(),
    })


@web_bp.route("/api/traffic/stats", methods=["GET"])
def get_traffic_stats():
    """Return real flow tracking and packet traffic volume statistics."""
    analyzer = getattr(current_app, "traffic_analyzer", None)
    if not analyzer:
        return jsonify({"status": "success", "traffic": {}, "active_flows": 0, "completed_flows": 0})

    stats_dict = analyzer.stats.to_dict()
    active_flows = analyzer.flow_tracker.active_flow_count
    completed_flows = analyzer.flow_tracker.completed_flow_count

    return jsonify({
        "status": "success",
        "traffic": stats_dict,
        "active_flows": active_flows,
        "completed_flows": completed_flows,
    })


@web_bp.route("/api/system/status", methods=["GET"])
def get_system_status():
    """Return current NIDS engine, capture, detection, and storage runtime status."""
    capture_engine = getattr(current_app, "capture_engine", None)
    detection_engine = getattr(current_app, "detection_engine", None)
    db_manager = getattr(current_app, "db_manager", None)

    capture_active = False
    capture_status_str = "IDLE"
    selected_interface = None
    if capture_engine:
        capture_status_str = capture_engine.status.value
        capture_active = capture_status_str == "RUNNING"
        selected_interface = capture_engine.selected_interface

    detection_summary = detection_engine.get_summary() if detection_engine else {}
    storage_stats = db_manager.get_persistence_stats() if db_manager and hasattr(db_manager, "get_persistence_stats") else {}

    suricata_service = getattr(current_app, "suricata_service", None)
    suricata_status = suricata_service.get_status() if suricata_service else {
        "is_running": False,
        "mode": "disabled",
        "eve_exists": False,
    }

    return jsonify({
        "status": "success",
        "engine": "NIDS v0.1.0",
        "phase": "Phase 8 - Suricata Deep Inspection Integration",
        "capture_active": capture_active,
        "capture_status": capture_status_str,
        "selected_interface": selected_interface,
        "detection": detection_summary,
        "storage": storage_stats,
        "suricata_integrated": suricata_service is not None,
        "suricata": suricata_status,
    })


@web_bp.route("/api/suricata/status", methods=["GET"])
def get_suricata_status():
    """Return operational state, metrics, and file status of the Suricata integration."""
    service = getattr(current_app, "suricata_service", None)
    if not service:
        return jsonify({
            "status": "error",
            "message": "Suricata service is not initialized on this application.",
            "is_running": False,
            "mode": "disabled",
        }), 500

    return jsonify({
        "status": "success",
        **service.get_status(),
    })


@web_bp.route("/api/suricata/ingest-sample", methods=["POST"])
def ingest_suricata_sample():
    """Trigger ingestion of sample Suricata EVE JSON fixture for verification or testing."""
    service = getattr(current_app, "suricata_service", None)
    if not service:
        return jsonify({
            "status": "error",
            "message": "Suricata service is not initialized on this application.",
        }), 500

    payload = request.get_json(silent=True) or {}
    requested_path = payload.get("sample_path")
    if requested_path:
        # Security: Prevent path traversal by restricting to verified project data, tests, or logs directories
        from pathlib import Path
        try:
            resolved = Path(requested_path).resolve()
            base_dir = Path(current_app.root_path).parent.resolve()
            allowed_roots = [
                (base_dir / "data").resolve(),
                (base_dir / "tests").resolve(),
                (base_dir / "logs").resolve(),
            ]
            if not any(str(resolved).startswith(str(root)) for root in allowed_roots):
                return jsonify({
                    "status": "error",
                    "message": "Path traversal rejected: sample_path must reside within project data, tests, or logs directory.",
                }), 403
            sample_path = str(resolved)
        except Exception as p_err:
            return jsonify({"status": "error", "message": f"Invalid path parameter: {p_err}"}), 400
    else:
        sample_path = service.sample_path

    if not sample_path:
        return jsonify({
            "status": "error",
            "message": "No sample fixture path configured or provided.",
        }), 400

    try:
        result = service.ingest_file(sample_path, is_fixture=True)
        return jsonify({
            "status": "success",
            "message": f"Successfully ingested {result.get('events_parsed', 0)} events ({result.get('alerts_persisted', 0)} alerts persisted).",
            "ingestion": result,
            "suricata_status": service.get_status(),
        })
    except FileNotFoundError as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
        }), 404
    except Exception as exc:
        return jsonify({
            "status": "error",
            "message": f"Error ingesting sample fixture: {exc}",
        }), 500


# ============================================================================
# Incident Response & Containment Endpoints (Task 4)
# ============================================================================

@web_bp.route("/api/response/status", methods=["GET"])
def get_response_status():
    """Return operational state of incident response and IP containment subsystems."""
    blocking_mgr = getattr(current_app, "blocking_manager", None)
    if not blocking_mgr:
        return jsonify({
            "status": "error",
            "message": "Response subsystem is not initialized on this application.",
        }), 500
    return jsonify({
        "status": "success",
        **blocking_mgr.get_status(),
    })


@web_bp.route("/api/response/blocked-ips", methods=["GET"])
def get_blocked_ips():
    """List actively and historically blocked IP addresses."""
    blocking_mgr = getattr(current_app, "blocking_manager", None)
    if not blocking_mgr:
        return jsonify({
            "status": "error",
            "message": "Response subsystem is not initialized on this application.",
        }), 500

    active_only = request.args.get("active_only", "true").lower() in ("true", "1")
    records = blocking_mgr.list_blocked_ips(active_only=active_only)
    return jsonify({
        "status": "success",
        "count": len(records),
        "blocked_ips": records,
        "is_simulated": blocking_mgr.simulation_mode,
        "enabled": blocking_mgr.enabled,
    })


@web_bp.route("/api/response/block-ip", methods=["POST"])
def manual_block_ip():
    """Manually apply network containment for an IP address with mandatory explicit authorization."""
    blocking_mgr = getattr(current_app, "blocking_manager", None)
    if not blocking_mgr:
        return jsonify({
            "status": "error",
            "message": "Response subsystem is not initialized on this application.",
        }), 500

    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip") or payload.get("ip_address")
    reason = payload.get("reason")
    alert_id = payload.get("alert_id")
    analyst = payload.get("analyst") or "Security Analyst"
    authorized = bool(payload.get("authorized", False))

    if not ip:
        return jsonify({"status": "error", "message": "Parameter 'ip' is required."}), 400
    if not reason:
        return jsonify({"status": "error", "message": "Parameter 'reason' is required."}), 400

    try:
        rec = blocking_mgr.block_ip(
            ip_address=ip,
            reason=reason,
            alert_id=int(alert_id) if alert_id else None,
            analyst=analyst,
            authorized=authorized,
        )
        return jsonify({
            "status": "success",
            "message": f"IP {rec.ip_address} successfully blocked ({'SIMULATED' if rec.is_simulated else 'ACTIVE'}).",
            "record": rec.to_dict(),
        })
    except (PermissionError, ValueError, RuntimeError) as err:
        status_code = 403 if isinstance(err, PermissionError) else 400
        return jsonify({"status": "error", "message": str(err)}), status_code


@web_bp.route("/api/response/unblock-ip", methods=["POST"])
def manual_unblock_ip():
    """Manually remove network containment for an IP address with mandatory explicit authorization."""
    blocking_mgr = getattr(current_app, "blocking_manager", None)
    if not blocking_mgr:
        return jsonify({
            "status": "error",
            "message": "Response subsystem is not initialized on this application.",
        }), 500

    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip") or payload.get("ip_address")
    analyst = payload.get("analyst") or "Security Analyst"
    authorized = bool(payload.get("authorized", False))

    if not ip:
        return jsonify({"status": "error", "message": "Parameter 'ip' is required."}), 400

    try:
        unblocked = blocking_mgr.unblock_ip(ip_address=ip, analyst=analyst, authorized=authorized)
        if not unblocked:
            return jsonify({"status": "error", "message": f"IP {ip} is not currently actively blocked."}), 404
        return jsonify({
            "status": "success",
            "message": f"IP {ip} successfully unblocked.",
        })
    except ValueError as err:
        return jsonify({"status": "error", "message": str(err)}), 400

