"""Incident Response Recommendation Engine.

Generates contextual, actionable mitigation steps and firewall suggestions
based on detection rules, alert severity, and forensic telemetry.
"""

from typing import Any, Dict, Optional

from nids.response.models import ActionPriority, RecommendedResponse


def get_recommended_response(
    rule_id: Optional[str] = None,
    title: Optional[str] = None,
    severity: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
    source_ip: Optional[str] = None,
) -> RecommendedResponse:
    """Generate explainable, actionable response guidance for a security alert.

    Args:
        rule_id: Rule identifier (e.g. 'NIDS_RULE_001', 'SURICATA_2010935').
        title: Alert headline or signature title.
        severity: Severity rating (INFO, LOW, MEDIUM, HIGH, CRITICAL).
        evidence: Forensic evidence dictionary.
        source_ip: Remote source IP associated with the intrusion.

    Returns:
        RecommendedResponse: Structured recommendation with priority and mitigation steps.
    """
    rule_id_clean = (rule_id or "").upper()
    title_clean = (title or "").lower()
    sev_clean = (severity or "INFO").upper()
    evidence_dict = evidence or {}

    src = source_ip or evidence_dict.get("source_ip") or "<source_ip>"
    fw_rule = f'netsh advfirewall firewall add rule name="NIDS_Block_{src}" dir=in action=block remoteip={src}' if src and src != "<source_ip>" else None

    # 1. Rule 001: Port Scan Reconnaissance
    if "NIDS_RULE_001" in rule_id_clean or "port scan" in title_clean:
        port_count = evidence_dict.get("distinct_ports_scanned") or evidence_dict.get("port_count") or "multiple"
        return RecommendedResponse(
            rule_id=rule_id or "NIDS_RULE_001",
            action_type="INVESTIGATE_AND_BLOCK",
            priority=ActionPriority.ELEVATED,
            recommended_action=(
                f"Investigate source IP {src} for unauthorized network reconnaissance ({port_count} distinct ports targeted). "
                "Verify if the host is an authorized vulnerability scanner. If unauthorized, consider a temporary firewall block."
            ),
            suggested_mitigation=(
                "1. Cross-reference source IP against asset inventory and authorized vulnerability scanning schedules.\n"
                "2. Review target ports to identify targeted services (e.g., SSH, RDP, SMB, HTTP).\n"
                "3. If external or unauthorized, manually apply edge/host firewall containment rule.\n"
                "4. Acknowledge and track incident in SOC console until source host is verified."
            ),
            suggested_firewall_rule=fw_rule,
        )

    # 2. Rule 002: SYN Flood DoS
    if "NIDS_RULE_002" in rule_id_clean or "syn flood" in title_clean:
        syn_count = evidence_dict.get("syn_packet_count") or evidence_dict.get("packet_count") or "excessive"
        return RecommendedResponse(
            rule_id=rule_id or "NIDS_RULE_002",
            action_type="THROTTLE_OR_BLOCK",
            priority=ActionPriority.IMMEDIATE,
            recommended_action=(
                f"High-frequency TCP SYN flood detected from {src} ({syn_count} SYN packets). "
                "Enable kernel SYN cookies, rate-limit source host, or manually block offending IP to protect service availability."
            ),
            suggested_mitigation=(
                "1. Verify target server TCP socket table and backlog saturation (e.g., netstat -s).\n"
                "2. Ensure TCP SYN cookies are activated on target web/database services.\n"
                "3. Deploy manual host-level firewall block on source IP if flooding persists.\n"
                "4. Notify upstream network/ISP provider if volumetric DDoS exceeds link capacity."
            ),
            suggested_firewall_rule=fw_rule,
        )

    # 3. Rule 003: Bandwidth / Traffic Spike
    if "NIDS_RULE_003" in rule_id_clean or "spike" in title_clean or "volume" in title_clean:
        bytes_val = evidence_dict.get("window_bytes") or evidence_dict.get("byte_count") or "elevated"
        return RecommendedResponse(
            rule_id=rule_id or "NIDS_RULE_003",
            action_type="INSPECT_FLOW_VOLUME",
            priority=ActionPriority.ROUTINE if sev_clean in ("LOW", "INFO") else ActionPriority.ELEVATED,
            recommended_action=(
                f"Anomalous traffic volume spike detected involving {src}. "
                "Inspect flow telemetry to determine whether activity is a legitimate large file transfer, software update, or unauthorized exfiltration."
            ),
            suggested_mitigation=(
                "1. Check source process on endpoint to identify responsible application.\n"
                "2. Confirm if the activity aligns with scheduled database backup, sync, or patch rollout.\n"
                "3. If unauthorized, isolate host or apply quality-of-service (QoS) throttling."
            ),
            suggested_firewall_rule=fw_rule,
        )

    # 4. Suricata Signature: Malware / Exploit / C2 / Botnet
    if any(k in title_clean for k in ["exploit", "trojan", "malware", "c2", "botnet", "command and control", "backdoor"]):
        return RecommendedResponse(
            rule_id=rule_id or "SURICATA_EXPLOIT",
            action_type="ISOLATE_ENDPOINT",
            priority=ActionPriority.IMMEDIATE,
            recommended_action=(
                f"High-confidence threat signature triggered by {src}: '{title}'. "
                "Immediately isolate the internal endpoint from the network, block remote C2 communication, and initiate forensic triage."
            ),
            suggested_mitigation=(
                "1. Disconnect endpoint from network or place into quarantine VLAN.\n"
                "2. Capture volatile memory dump before rebooting host.\n"
                "3. Block external destination IP and domain at edge firewall and recursive DNS.\n"
                "4. Execute deep antivirus/EDR scan and audit user authentication logs."
            ),
            suggested_firewall_rule=fw_rule,
        )

    # 5. Suricata Signature: Protocol Anomalies (TLS, HTTP, DNS)
    if any(k in title_clean for k in ["tls", "certificate", "http", "dns", "anomaly", "suspicious"]):
        return RecommendedResponse(
            rule_id=rule_id or "SURICATA_ANOMALY",
            action_type="INSPECT_PROTOCOL_HEADERS",
            priority=ActionPriority.ELEVATED if sev_clean in ("HIGH", "CRITICAL") else ActionPriority.ROUTINE,
            recommended_action=(
                f"Protocol anomaly or evasion indicator detected: '{title}'. "
                "Review protocol metadata headers, inspect certificate validation status, and verify destination domain reputation."
            ),
            suggested_mitigation=(
                "1. Inspect decoded application layer headers (SNI, HTTP User-Agent, DNS query record).\n"
                "2. Verify whether domain is newly registered or associated with known phishing/phoning home.\n"
                "3. If certificate is self-signed or revoked, block untrusted TLS negotiation."
            ),
            suggested_firewall_rule=fw_rule,
        )

    # 6. Default Fallback based on severity
    if sev_clean in ("CRITICAL", "HIGH"):
        priority = ActionPriority.IMMEDIATE
        action = f"High-severity intrusion alert '{title}'. Triage affected host {src} immediately."
        mitigation = "1. Verify alert validity against forensic evidence.\n2. Isolate compromised endpoint if confirmed.\n3. Block hostile IP at firewall if external."
    elif sev_clean == "MEDIUM":
        priority = ActionPriority.ELEVATED
        action = f"Medium-severity security event '{title}'. Monitor connection flows and verify host reputation."
        mitigation = "1. Review surrounding network flows.\n2. Confirm endpoint authorization.\n3. Acknowledge and resolve if false positive."
    else:
        priority = ActionPriority.ROUTINE
        action = f"Informational or low-risk trigger '{title}'. Log for baseline analysis."
        mitigation = "1. Verify normal network service baseline.\n2. No urgent containment required unless clustered with higher severity alerts."

    return RecommendedResponse(
        rule_id=rule_id or "NIDS_RULE_GENERIC",
        action_type="MONITOR_AND_TRIAGE",
        priority=priority,
        recommended_action=action,
        suggested_mitigation=mitigation,
        suggested_firewall_rule=fw_rule,
    )
