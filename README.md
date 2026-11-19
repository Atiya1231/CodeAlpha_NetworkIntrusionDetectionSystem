# 🛡️ NIDS – Network Intrusion Detection System

[![Python Version](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask_3.1-black.svg)](https://palletsprojects.com/p/flask/)
[![Network Engine](https://img.shields.io/badge/Engine-Scapy-red.svg)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D6.svg)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-ready, modular Network Intrusion Detection System (NIDS) built for Windows environments. The system captures live network traffic, decodes protocols, performs real-time heuristic anomaly detection and signature matching, logs alerts into a resilient SQLite database, and presents threat analytics through an interactive security operations dashboard powered by Chart.js.

Designed with an extensible architecture to support enterprise deep packet inspection engines such as **Suricata**.

---

## ⚠️ Legal & Ethical Disclaimer

> **IMPORTANT:** This software is designed strictly for defensive cybersecurity monitoring, educational research, and network diagnostics on systems and networks **where you possess explicit written authorization** from the network owner. Unauthorized packet sniffing, traffic interception, or port scanning against networks you do not own or administer is illegal under laws including the U.S. Computer Fraud and Abuse Act (CFAA) and international cybersecurity statutes.

---

## 🏛️ System Architecture

The project follows a clean decoupled pipeline architecture where data flows from low-level network drivers up to persistent storage and web visualization:

```
                      +-----------------------------+
                      |   Network Adapter (Npcap)   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |    Packet Capture Engine    |  (Scapy Thread / Promiscuous Sniffing)
                      |       [nids.capture]        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       Traffic Analysis      |  (Protocol Decoding & Flow 5-Tuple Tracking)
                      |       [nids.analysis]       |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       Detection Engine      |  (Heuristics, Thresholds & Signatures)
                      |      [nids.detection]       |
                      +--------------+--------------+
                                     ^
                                     |
                      +--------------+--------------+
                      |  Suricata Deep Inspection   |  (EVE JSON Incremental Tailing & Parsing)
                      |       [nids.suricata]       |  <--- Live eve.json / Controlled Fixture
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       Alert Management      |  (Severity Grading & Deduplication)
                      |        [nids.alerts]        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |      SQLite Persistence     |  (WAL Mode, Thread-Safe Storage)
                      |       [nids.storage]        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Flask API & Web Console   |  (REST Endpoints & Chart.js Telemetry)
                      |         [nids.web]          |
                      +-----------------------------+
```

---

## 🧰 Technology Stack

| Layer | Technology | Details |
| :--- | :--- | :--- |
| **Runtime Environment** | Python 3.13 | High-performance modern Python runtime |
| **Driver / Packet Sniffer** | Scapy 2.8+ / Npcap | Raw packet sniffing, promiscuous mode, BPF filtering |
| **Deep Packet Inspection** | Suricata / EVE JSON | High-fidelity signature detection, application protocol parsing |
| **Web Server & REST API** | Flask 3.1+ | Lightweight asynchronous-friendly REST backend |
| **Database** | SQLite3 | Zero-configuration ACID persistent alert store with WAL mode |
| **Frontend UI** | HTML5 / CSS3 / JavaScript | Responsive cybersecurity dark-mode operations console |
| **Analytics & Visuals** | Chart.js 4.4 | Doughnut severity distribution & threat category breakdown |
| **IDS Integration** | Suricata (Phase 8) | EVE JSON parser, incremental tailer, and signature alert mapper |

---

## 📂 Project Directory Structure

```text
NIDS-Project/
├── .gitignore                    # Ignores bytecode, venv, databases, PCAP dumps, secrets
├── README.md                     # Comprehensive architecture and setup documentation
├── requirements.txt              # Production and development dependencies
├── config.py                     # Centralized settings (capture limits, DB paths, thresholds)
├── run.py                        # Top-level executable entry point
├── data/                         # SQLite database storage directory (git-ignored)
├── logs/                         # Runtime diagnostic logs (git-ignored)
└── nids/                         # Core NIDS Python package
    ├── __init__.py               # Package metadata and versioning
    ├── capture/                  # Module 1: Packet Capture Engine (Phase 3 - AsyncSniffer)
    │   ├── __init__.py           # Package public exports
    │   ├── engine.py             # Native Scapy AsyncSniffer capture engine, thread-safe lifecycle
    │   ├── interfaces.py         # Network adapter discovery & lookup (Npcap / Scapy)
    │   └── metadata.py           # Sanitized telemetry extraction (TCP/UDP/ICMP/Other)
    ├── analysis/                 # Module 2: Traffic Analysis & Flow Tracking (Phase 4)
    │   ├── __init__.py           # Package public exports
    │   ├── flow_tracker.py       # Bidirectional session tracker, capacity bounds & expiration
    │   ├── models.py             # FlowKey, NetworkFlow, FlowStatus, TrafficStats models
    │   └── traffic_analyzer.py   # High-level pipeline coordinator & telemetry aggregation
    ├── detection/                # Module 3: Detection Engine & Rules (Phase 5)
    │   ├── __init__.py           # Package public exports
    │   ├── engine.py             # DetectionEngine coordinator & event history buffer
    │   ├── models.py             # DetectionEvent, Severity models
    │   └── rules.py              # Heuristic detection rules (Port Scan, SYN Flood, Spike, etc.)
    ├── alerts/                   # Module 4: Alert Management (Severity classification & models)
    │   └── __init__.py
    ├── storage/                  # Module 5: Persistent Storage Engine (Phase 6)
    │   ├── __init__.py           # DatabaseManager unified facade & exports
    │   ├── alert_repository.py   # Alert CRUD, status lifecycle, filtering & aggregations
    │   ├── async_writer.py       # Bounded asynchronous persistence worker & queue
    │   └── database.py           # SQLite connection pool, WAL mode, migrations, transactions
    ├── suricata/                 # Module 6: Suricata Deep Inspection Integration (Phase 8)
    │   ├── __init__.py           # Public exports & facades
    │   ├── models.py             # EveRecord, EveAlertData, EveEventType dataclasses
    │   ├── parser.py             # EVE JSON line parser & DetectionEvent mapper
    │   ├── reader.py             # Incremental EveLogReader with byte-offset tracking
    │   └── service.py            # SuricataService coordinator & worker lifecycle
    └── web/                      # Module 7: Flask Backend & Frontend Dashboard
        ├── __init__.py           # Flask application factory
        ├── routes.py             # REST API endpoints & HTML view controller
        ├── templates/
        │   └── index.html        # Operations dashboard interface
        └── static/
            ├── css/
            │   └── style.css     # Cybersecurity SOC dark theme styling
            └── js/
                └── dashboard.js  # Live polling controller and Chart.js graphics
tests/
├── test_capture.py               # Unit test suite for packet capture & metadata extraction (23 tests)
├── test_flow_tracker.py          # Unit test suite for traffic analysis & flow tracking (20 tests)
├── test_detection.py             # Unit test suite for intrusion detection rules (20 tests)
├── test_storage.py               # Unit & integration test suite for storage, async writer, and REST APIs (30 tests)
├── test_capture_routes.py        # Integration test suite for web capture controls and traffic endpoints (10 tests)
└── test_suricata.py              # Unit & integration test suite for Suricata deep inspection (17 tests)
```

---

## 🖥️ Security Operations Center Dashboard (Phase 7)

The frontend operations dashboard ([nids/web](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/nids/web)) provides a modern, dark-themed SOC interface built with vanilla HTML5, CSS3, and JavaScript, connected directly to real backend telemetry.

### Key Capabilities
- **Real-Time SOC KPI Overview:** Live metrics for total alerts, new pending alerts, high/critical priority incidents, active bidirectional flow sessions, and cumulative packet counts.
- **Dynamic Chart.js Telemetry:**
  - *Severity Distribution:* Interactive doughnut chart displaying counts across `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
  - *Heuristic Rules Breakdown:* Horizontal bar chart depicting frequency across detection rules (`RULE-PORT-SCAN`, `RULE-SYN-FLOOD`, `RULE-TRAFFIC-SPIKE`, `RULE-SUSPICIOUS-FLOW`).
  - *Protocol Breakdown:* Live distribution of captured transport protocols (`TCP`, `UDP`, `ICMP`, `Other`).
- **Comprehensive Alert Log & Triage Console:**
  - Full-text search across titles, rules, descriptions, and IP addresses.
  - Multi-field filters: severity level, lifecycle status, rule identifier, and date ranges (`start_date`, `end_date`).
  - Server-side pagination with configurable page size (10, 25, 50, 100).
  - Quick-action buttons in every row for instant `Acknowledge` and `Resolve` state transitions via `PATCH`.
- **Forensic Alert Detail Inspector:** Accessible modal inspector providing full event telemetry, network 5-tuple, confidence rating, threshold applied, and formatted JSON evidence payload.
- **Safe DOM Rendering:** Avoids unsafe `innerHTML` for untrusted server data, constructing DOM elements via `document.createElement` and `textContent`.
- **Interactive Capture Controls:**
  - Explicit network adapter selector populated via `GET /api/capture/interfaces`.
  - Optional BPF filter input (e.g. `tcp port 80`, `ip`) and packet limit count.
  - Safe start/stop controls with visual pulse indicators and duplicate request prevention.
  - Clear guidance for Windows elevation requirements if administrative privileges are needed.

### REST API Endpoints Reference

| Method | Endpoint | Description | Query / Body Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Renders the primary SOC operations dashboard | None |
| `GET` | `/api/alerts` | Paginated and filtered security alert records | `page`, `per_page`, `severity`, `status`, `rule_id`, `confidence`, `source_ip`, `destination_ip`, `start_date`, `end_date` |
| `GET` | `/api/alerts/<id>` | Full alert detail & parsed forensic evidence | Path parameter `id` (int) |
| `POST` / `PATCH` | `/api/alerts/<id>/acknowledge`| Transitions alert to `ACKNOWLEDGED` | Path parameter `id` (int) |
| `POST` / `PATCH` | `/api/alerts/<id>/resolve` | Transitions alert to `RESOLVED` | Path parameter `id` (int) |
| `GET` | `/api/alerts/stats` | Dedicated alert metrics grouped by status, severity, and rule | None |
| `GET` | `/api/stats/summary` | Backward-compatible severity summary dictionary for Chart.js | None |
| `GET` | `/api/capture/interfaces` | Discovers available host network adapters | None |
| `GET` | `/api/capture/status` | Inspects live packet capture status and telemetry | None |
| `POST` | `/api/capture/start` | Starts non-blocking packet capture session | `{"interface": "...", "bpf_filter": "...", "count": 0, "promiscuous": false}` |
| `POST` | `/api/capture/stop` | Stops active packet capture session | None |
| `GET` | `/api/traffic/stats` | Returns real session flow and directional packet statistics | None |
| `GET` | `/api/system/status` | Runtime health of capture, detection, storage, and Suricata | None |
| `GET` | `/api/suricata/status` | Runtime status, offset, and telemetry of Suricata engine | None |
| `POST` | `/api/suricata/ingest-sample` | Triggers batch ingestion of sample Suricata EVE JSON fixture | `{"sample_path": "..."}` (optional) |

---

## 💾 Persistent SQLite Alert Management & REST APIs (Phase 6)

The storage module ([nids/storage](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/nids/storage/__init__.py)) provides reliable SQLite persistence, WAL concurrency, schema migrations, non-blocking asynchronous writing, and REST APIs for security alerts and detection events.

### Architecture & Capabilities
- **Resilient Concurrency (WAL Mode & Busy Timeouts):** Enables `PRAGMA journal_mode = WAL;` and `busy_timeout = 15.0s`, allowing concurrent read and write operations without SQLite database locks, even on OneDrive or Windows filesystems.
- **Idempotent Schema Migration:** On startup, `Database.init_db()` inspects existing tables using `PRAGMA table_info` and safely executes non-destructive `ALTER TABLE` statements for any missing columns, preserving existing historical alerts.
- **Explainable Event Persistence:** Persists `DetectionEvent` objects with JSON-serialized forensic evidence, rule identifiers, confidence scores, and deduplication keys.
- **Alert Lifecycle State Transitions:** Enforces valid unidirectional state transitions (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `RESOLVED`), supports idempotent repeat requests, and strictly prohibits invalid transitions (e.g. from `RESOLVED` back to `ACKNOWLEDGED` or `NEW`).
- **Bounded Non-Blocking Asynchronous Persistence (`AsyncAlertWriter`):** Provides a dedicated background worker with a bounded memory queue (default: 5,000 events) and graceful shutdown flushing. This prevents disk I/O serialization from stalling real-time packet capture on high-volume networks.

### REST API Endpoints

| Method | Endpoint | Description | Query / Body Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/alerts` | Paginated and filtered list of security alerts with metadata | `page`, `per_page` (max: 100), `severity`, `status`, `rule_id`, `source_ip`, `destination_ip`, `start_date`, `end_date`, `limit`, `offset` |
| `GET` | `/api/alerts/<id>` | Full alert detail & parsed evidence JSON | None |
| `POST` / `PATCH` | `/api/alerts/<id>/acknowledge`| Transition alert status to `ACKNOWLEDGED` | None |
| `POST` / `PATCH` | `/api/alerts/<id>/resolve` | Transition alert status to `RESOLVED` | None |
| `GET` | `/api/alerts/stats` | Dedicated alert metrics grouped by status, severity, and rule | None |
| `GET` | `/api/stats/summary` | Backward-compatible severity and status summary for Chart.js | None |
| `GET` | `/api/system/status` | Runtime engine health & phase info | None |

### Python Integration Example

```python
from nids.detection import DetectionEngine
from nids.storage import DatabaseManager

# 1. Initialize persistent storage layer with async persistence worker
db_manager = DatabaseManager("data/nids_events.sqlite", max_queue_size=5000)
db_manager.start_worker()

# 2. Attach non-blocking SQLite enqueue callback to detection engine
detection_engine = DetectionEngine(on_event=db_manager.enqueue_detection_event)

# 3. Query alerts with filtering and pagination
page_alerts = db_manager.get_recent_alerts(
    limit=20,
    offset=0,
    severity="HIGH",
    status="NEW",
    rule_id="RULE-PORT-SCAN",
)

# 4. Triage and update alert lifecycle status
for alert in page_alerts:
    print(f"Alert [{alert['id']}]: {alert['title']} from {alert['source_ip']}")
    db_manager.update_alert_status(alert["id"], "ACKNOWLEDGED")

# 5. Fetch comprehensive alert metrics
stats = db_manager.get_alert_statistics()
print("Total Alerts:", stats["total_alerts"])
print("Rule Counts:", stats["rule_counts"])

# 6. Flush pending queue and stop worker cleanly on shutdown
db_manager.stop_worker()
```

---

## 🎯 Intrusion Detection Engine (Phase 5)

The detection engine module ([nids/detection](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/nids/detection/__init__.py)) provides modular, passive, and explainable heuristic threat detection, evaluating rules against packet metadata and flow telemetry.

### Implemented Detection Rules

| Rule Identifier | Detection Name | Severity | Default Trigger Threshold | Description |
| :--- | :--- | :---: | :--- | :--- |
| **`RULE-PORT-SCAN`** | Horizontal Port Scan Indicator | `HIGH` | $\ge 20$ distinct ports in 10s | Identifies a single source attempting to probe multiple ports on a target. |
| **`RULE-SYN-FLOOD`** | High-Volume TCP SYN Activity | `HIGH` | $\ge 100$ SYN packets in 5s | Flags volumetric bursts of unacknowledged TCP SYN initiation frames. |
| **`RULE-TRAFFIC-SPIKE`**| Anomalous Traffic Spike | `MEDIUM` | $\ge 500$ packets in 5s | Flags aggregate throughput surges exceeding rolling baselines. |
| **`RULE-SUSPICIOUS-FLOW`**| Suspicious Header / Flow Pattern | `LOW` / `MEDIUM` | Immediate (Port 0 / Naked FIN) | Flags reserved Port 0 usage or naked standalone TCP FIN probe frames. |

### Deduplication, Cooldown, and False-Positive Considerations

- **Heuristic Indicators:** Detections are labeled with confidence `HEURISTIC_INDICATOR`. High traffic volumes or rapid port access can occur during benign network benchmarking, heavy web browsing, or P2P operations. These rules represent potential indicators rather than definitive proof of malicious activity.
- **Cooldown Rate-Limiting:** Continuous anomalous activity does not flood the event queue. Each rule enforces a per-pair cooldown window (default: 60 seconds) during which duplicate alerts are suppressed.
- **Bounded Retention:** Events are buffered in a thread-safe `collections.deque(maxlen=MAX_DETECTION_EVENTS)` to strictly bound memory consumption.

### Python Integration Example

```python
from nids.capture import PacketCaptureEngine
from nids.analysis import TrafficAnalyzer
from nids.detection import DetectionEngine, Severity

# 1. Initialize DetectionEngine and TrafficAnalyzer
detection_engine = DetectionEngine(max_events=1000)
analyzer = TrafficAnalyzer(detection_engine=detection_engine)

# 2. Attach analyzer callback to capture engine
engine = PacketCaptureEngine(on_packet=analyzer.process_packet)
engine.start_capture(interface="Wi-Fi", count=100)

# 3. Query security detection events
events = detection_engine.get_events(limit=10, severity=Severity.HIGH)
for event in events:
    print(f"[{event.severity.value}] {event.detection_name}: {event.description}")
    print(f"  Evidence: {event.evidence}")

# 4. Inspect overall detection telemetry summary
summary = detection_engine.get_summary()
print("Detection Summary:", summary)
```

---

## 🔄 Traffic Analysis & Flow Tracking (Phase 4)

The traffic analysis module ([nids/analysis](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/nids/analysis/__init__.py)) provides real-time stateful connection tracking and network volume telemetry, consuming sanitized packet metadata from the capture layer.

### Features Implemented
- **Bidirectional 5-Tuple Normalization (`FlowKey`):** Packets flowing $A \rightarrow B$ and $B \rightarrow A$ are mapped to an identical normalized key (`endpoint_low`, `endpoint_high`, `protocol`).
- **Directional Traffic Accounting:** Identifies communication initiator and tracks forward vs. reverse packet and byte volumes independently.
- **Session Duration & Timestamp Integrity:** Calculates active flow duration (`max(0.0, last_seen - first_seen)`) and handles out-of-order packets safely.
- **TCP Flag Aggregation:** Maintains an accumulated set of unique control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`) observed during the session.
- **Deterministic Idle-Flow Expiration:** Configurable timeout (`FLOW_IDLE_TIMEOUT`) retires inactive flows to a completed flow buffer.
- **Strict Memory Bounds:** `MAX_ACTIVE_FLOWS` and `MAX_COMPLETED_FLOWS` prevent unbounded memory growth or state exhaustion.
- **Aggregated Telemetry (`TrafficStats`):** Thread-safe metrics track total packets, total bytes, active/completed flow counts, and directional protocol breakdowns.

### Python Integration Example

```python
from nids.capture import PacketCaptureEngine
from nids.analysis import TrafficAnalyzer

# 1. Initialize TrafficAnalyzer
analyzer = TrafficAnalyzer(idle_timeout=30.0, max_active_flows=10000)

# 2. Attach analyzer's process_packet directly to the capture engine's callback
engine = PacketCaptureEngine(on_packet=analyzer.process_packet)

# 3. Start non-blocking capture on selected interface
engine.start_capture(interface="Wi-Fi", count=50)

# 4. Query real-time active flows and telemetry summary
active_flows = analyzer.get_active_flows()
for flow in active_flows:
    print(f"Flow {flow.flow_id}: {flow.initiator_ip}:{flow.initiator_port} -> "
          f"{flow.responder_ip}:{flow.responder_port} [{flow.protocol}] "
          f"({flow.forward_packets} fwd / {flow.reverse_packets} rev packets, {flow.duration}s)")

# 5. Expire idle flows and inspect summary
expired = analyzer.expire_idle_flows()
print("Traffic Summary:", analyzer.get_summary())

# 6. Stop cleanly
engine.stop_capture()
analyzer.close()
```

---

## 🛰️ Packet Capture Engine (Phase 3)

The network packet capture module ([nids/capture](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/nids/capture/__init__.py)) provides modular, non-blocking packet ingestion designed for Windows 10/11 using Scapy and Npcap.

### Features Implemented
- **Explicit Interface Selection:** Requires intentional target adapter specification; silent default captures are strictly prohibited.
- **Asynchronous Execution:** Background daemon thread isolates packet capture from web services and user interaction.
- **Sanitized Metadata Extraction:** Extracts timestamp, IP 5-tuple, protocol, packet length, and TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`). Never extracts, captures, or logs application payloads or credentials.
- **Thread-Safe Telemetry:** Thread-locked counters track total packets, TCP, UDP, ICMP, and other packets in real time.
- **Safe Lifecycle Control:** Responsive `start_capture()` and `stop_capture()` controls with graceful thread joining.
- **Defensive Defaults:** Promiscuous mode defaults to `False` (`promiscuous=False`).

### Quick Python Usage Example

```python
from nids.capture import PacketCaptureEngine, get_available_interfaces

# 1. Enumerate available network interfaces
interfaces = get_available_interfaces()
for iface in interfaces:
    print(f"[{iface.name}] {iface.description} -> {iface.scapy_name} (IPs: {iface.ips})")

# 2. Callback for real-time metadata consumption
def handle_packet(metadata):
    print(f"[PACKET] {metadata.protocol} {metadata.source_ip}:{metadata.source_port} -> "
          f"{metadata.destination_ip}:{metadata.destination_port} ({metadata.packet_length} bytes)")

# 3. Instantiate and start non-blocking capture
engine = PacketCaptureEngine(on_packet=handle_packet)
engine.start_capture(interface="Wi-Fi", count=100)  # or specific Scapy device

# 4. Inspect runtime statistics
print("Telemetry:", engine.stats.to_dict())

# 5. Stop capture cleanly
engine.stop_capture()
```

### Running Automated Tests
The capture test suite tests all metadata extraction, protocol classifications, lifecycle transitions, and exception scenarios using mock synthetic packets without live network traffic:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

---

## ⚡ Prerequisites & Windows Compatibility Notes

1. **Operating System:** Windows 10 or Windows 11 (64-bit).
2. **Python:** Python 3.13.x (Ensure Python is in system `PATH`).
3. **Npcap Packet Capture Driver (Mandatory for Windows):**
   - Scapy requires Npcap on Windows to access the network card in promiscuous mode.
   - Download from [https://npcap.com/](https://npcap.com/).
   - **Crucial:** During installation, select the checkbox: **"Install Npcap in WinPcap API-compatible Mode"**.
4. **Administrator Privileges:**
   - Raw packet capturing requires elevation. You must run the command prompt / PowerShell as **Administrator** when executing network capture phases.
5. **OneDrive Path Precaution:**
   - If hosting the project inside an active Microsoft OneDrive folder, avoid OneDrive synchronization conflicts on SQLite database files by setting `NIDS_DB_PATH` to a local non-synced directory if locks occur.

---

## 🚀 Getting Started (Phase 1 Verification)

### 1. Virtual Environment
The virtual environment is already established in `.venv`:
```powershell
# In PowerShell (Run as Administrator):
.\.venv\Scripts\Activate.ps1
```

### 2. Verify Dependencies
Dependencies are detailed in `requirements.txt`:
```powershell
pip install -r requirements.txt
```

### 3. Launch the Phase 1 Web Console
You can launch the dashboard to verify that the Flask backend, SQLite database schema, and frontend UI are properly connected:
```powershell
python run.py
```
Open your browser to: **`http://127.0.0.1:5000`**

---

## 🛡️ Suricata Deep Inspection Integration (Phase 8)

The Suricata Integration engine ([nids/suricata](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/nids/suricata)) provides deep packet inspection and signature-based threat detection alongside the heuristic engine. It operates in **dual mode**: live continuous tailing of Suricata's `eve.json` log or controlled simulation with verified sample fixtures.

### Key Capabilities

1. **Incremental Log Tailing & Offset Tracking (`EveLogReader`):**
   - Reads `eve.json` in binary mode (`"rb"`), tracking exact byte offsets across restarts.
   - Detects log rotation and file truncation (resets offset if `file_size < offset`).
   - Partial line protection: incomplete lines lacking terminating newlines remain buffered until complete, preventing corrupted JSON decoding.
   - Optional persistent offset tracking in `data/suricata_offset.json`.

2. **Multi-Protocol Telemetry & Signature Mapping (`EveEventParser`):**
   - Parses telemetry types: `alert`, `dns`, `http`, `tls`, `flow`, `anomaly`.
   - Maps Suricata alert severity (1: `CRITICAL`, 2: `HIGH`, 3: `MEDIUM`, 4: `LOW`).
   - Converts alerts to `DetectionEvent` with `confidence="SURICATA_SIGNATURE"`.
   - Strict privacy & safety: zero raw packet frame or payload retention; retains sanitized forensic metadata (network 5-tuple, signature ID, revision, category, flow stats).
   - Generates deterministic deduplication keys: `suricata:{sig_id}:{src_ip}:{dest_ip}:{timestamp}`.

3. **Asynchronous Non-Blocking Persistence (`SuricataService`):**
   - Background tailing thread (`SuricataEveTailer`) polling at configurable intervals (default: 1.0s).
   - Enqueues detected alerts into `AsyncAlertWriter` for SQLite persistence with zero capture worker blocking.
   - Thread-safe statistics tracking (`total_lines_read`, `total_events_parsed`, `alerts_count`, protocol breakdown).

4. **SOC Dashboard & REST API Controls:**
   - Real-time Suricata status card showing mode, target file, parsed events, and ingested alerts.
   - Interactive **"📥 Ingest Sample EVE Fixture"** button for instant signature detection demonstration without requiring a live Suricata process.
   - Alert triage table distinguishes signature alerts with dedicated purple badge (`🛡️ SURICATA`).
   - Confidence filter dropdown: filter by `All`, `Suricata Signatures`, or `Heuristic Indicators`.

### Suricata Installation & Setup Guide

#### Option A: Native Windows Installation
1. **Download Suricata for Windows:**
   - Obtain the official Windows MSI installer from [https://suricata.io/download/](https://suricata.io/download/).
2. **Install Npcap:**
   - Ensure Npcap is installed with **WinPcap API-compatible Mode** enabled.
3. **Configure `suricata.yaml`:**
   - Locate `C:\Program Files\Suricata\suricata.yaml`.
   - Ensure `eve-log` is enabled with JSON output:
     ```yaml
     outputs:
       - eve-log:
           enabled: yes
           filetype: regular
           filename: eve.json
           types:
             - alert:
                 payload: no
                 metadata: yes
             - http
             - dns
             - tls
             - flow
     ```
4. **Identify Adapter GUID:**
   - Run `suricata.exe --pcap` to list adapter GUIDs.
   - Bind Suricata: `suricata.exe -c "C:\Program Files\Suricata\suricata.yaml" -i "\Device\NPF_{...}"`
5. **Connect NIDS:**
   - Set environment variable: `$env:NIDS_SURICATA_ENABLED = "true"`
   - Set log path: `$env:NIDS_SURICATA_EVE_PATH = "C:\Program Files\Suricata\log\eve.json"`

#### Option B: Windows Subsystem for Linux (WSL2 Ubuntu)
1. **Install Suricata in WSL2:**
   ```bash
   sudo apt update
   sudo apt install -y suricata
   sudo suricata-update
   ```
2. **Start Suricata on WSL2 interface:**
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
   ```
3. **Connect NIDS from Windows Host:**
   - Set environment variable in PowerShell:
     ```powershell
     $env:NIDS_SURICATA_ENABLED = "true"
     $env:NIDS_SURICATA_EVE_PATH = "\\wsl$\Ubuntu\var\log\suricata\eve.json"
     ```

#### Option C: Controlled Sample Fixture Mode (Default / Testing)
- Ideal when native Suricata is not installed on the system.
- Includes pre-verified synthetic telemetry in [data/sample_eve.json](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/data/sample_eve.json).
- Ingest on-demand via the Web Dashboard or API:
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/suricata/ingest-sample" -Method POST
  ```

---

## 🗺️ Implementation Roadmap

- [x] **Phase 1: Project Initialization & Architecture**
  - Modular directory scaffold
  - SQLite database schema & connection manager
  - Flask REST API endpoints
  - Chart.js cybersecurity dashboard UI
  - Requirements, .gitignore, and documentation
- [x] **Phase 2: Environment Verification**
  - Python 3.13 and Windows compatibility validation
  - Npcap driver availability & interface enumeration testing
  - Dependency integrity audit with zero-modification preservation
- [x] **Phase 3: Network Packet Capture Engine** *(Completed & Verified)*
  - Windows & Scapy network interface discovery with friendly naming
  - Scapy `AsyncSniffer` non-blocking capture with IPC control-socket unblocking
  - Sanitized packet metadata extraction (`PacketMetadata`, no payload retention)
  - Thread-safe statistics tracking (`CaptureStats`)
  - Automated mock test suite (23 passing tests)
- [x] **Phase 4: Traffic Analysis & Flow Tracking** *(Completed & Verified)*
  - Bidirectional 5-tuple normalized flow identification (`FlowKey`)
  - Forward and reverse packet/byte accounting and timestamp tracking (`NetworkFlow`)
  - Deterministic idle-flow expiration and table capacity bounds (`FlowTracker`)
  - Aggregated traffic telemetry and capture callback integration (`TrafficAnalyzer`)
  - Automated mock test suite (20 passing tests)
- [x] **Phase 5: Detection Engine & Rules** *(Completed & Verified)*
  - Modular heuristic detection engine architecture (`DetectionEngine`)
  - Four defensive detection rules: Port Scan, SYN Flood, Traffic Spike, Suspicious Flow Patterns
  - Explainable `DetectionEvent` model with JSON serialization and metadata-only evidence
  - Sliding time-window calculation and per-target cooldown rate-limiting
  - Automated mock test suite (20 passing tests; 63 total project tests)
- [x] **Phase 6: Persistent SQLite Alert Management** *(Completed, Remediated & Verified)*
  - Resilient SQLite database engine with WAL mode and busy timeouts
  - Idempotent schema migration for historical alerts
  - Complete alert triage lifecycle (`NEW`, `ACKNOWLEDGED`, `RESOLVED`) with invalid transition blocking
  - Bounded asynchronous persistence queue (`AsyncAlertWriter`) preventing capture worker stall
  - Enhanced Flask REST API endpoints with comprehensive parameter validation, pagination, and multi-field filtering
  - Support for both POST and PATCH lifecycle transition endpoints
  - Dedicated alert statistics endpoint (`GET /api/alerts/stats`)
  - Automated mock test suite (30 passing tests; 93 total project tests)
- [x] **Phase 7: Frontend Operations Dashboard & Live Integration** *(Completed & Verified)*
  - Modern dark-themed cybersecurity SOC dashboard
  - Real-time KPI metrics, severity doughnut, rule bar chart, and protocol breakdown
  - Live alert triage console with search, multi-attribute filtering, and pagination
  - Safe DOM rendering strictly avoiding unsafe innerHTML for untrusted alert data
  - Forensic detail inspector modal with formatted JSON evidence viewer
  - Live alert lifecycle transitions (`Acknowledge` and `Resolve` via PATCH)
  - Safe network packet capture controls with adapter enumeration, BPF filters, and permission handling
  - Automated mock test suite (10 passing tests; 103 total project tests)
- [x] **Phase 8: Suricata Deep Inspection Integration** *(Completed & Verified)*
  - Modular EVE JSON log tailer with byte-offset tracking and rotation recovery (`EveLogReader`)
  - Multi-protocol telemetry parsing: `alert`, `dns`, `http`, `tls`, `flow`, `anomaly`
  - Standardized `DetectionEvent` mapping with `confidence="SURICATA_SIGNATURE"`
  - Asynchronous SQLite alert persistence integration via `AsyncAlertWriter`
  - Controlled sample fixture mode ([data/sample_eve.json](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/data/sample_eve.json)) for offline evaluation
  - REST API endpoints (`GET /api/suricata/status`, `POST /api/suricata/ingest-sample`, `confidence` filter)
  - Frontend dashboard Suricata status card, fixture ingestion action, and signature badges
  - Comprehensive unit and integration test suite (17 dedicated passing tests; 120 total project tests)
- [x] **Phase 9: Incident Response, Secure Coding Audit & Final Internship Compliance** *(Completed & Verified)*
  - Contextual Incident Response Recommendation Engine (`nids/response/recommendations.py`)
  - Safe, reversible, explicitly authorized manual IP containment (`nids/response/blocking.py`)
  - Incident response tracking with analyst notes and responder identity
  - Basic packet structure analysis (`layers`, `ip_version`) in `PacketMetadata`
  - Path traversal remediation on sample ingestion
  - Global defense-in-depth HTTP security headers (`nosniff`, `SAMEORIGIN`, `CSP`)
  - Full internship compliance checklist (`docs/INTERNSHIP_REQUIREMENTS_CHECKLIST.md`)
  - Comprehensive formal security audit report (`docs/SECURE_CODING_REVIEW.md`)
  - 137 automated tests passing (100% pass rate)

---

## 🛡️ Incident Response & Containment Subsystem (Task 4)

The NIDS incorporates a disciplined, defensive incident response workflow that equips security analysts to triage, annotate, and contain threats safely without operational self-denial.

### 1. Contextual Response Recommendations
Every detection alert—whether generated by heuristic rules or Suricata signatures—is automatically evaluated by the **Response Recommendation Engine** (`nids.response.recommendations`). The engine outputs explainable, step-by-step guidance:
* **Port Scans (`NIDS_RULE_001`):** Advises cross-referencing authorized vulnerability scanning schedules, inspecting target port distributions, and considering temporary edge containment.
* **SYN Floods (`NIDS_RULE_002`):** Recommends verifying TCP backlog saturation, enabling kernel SYN cookies, and throttling hostile source IPs.
* **Traffic Spikes (`NIDS_RULE_003`):** Prompts analysis of high-volume transfer processes to differentiate scheduled database backups or updates from data exfiltration.
* **Suricata Malware & C2 Signatures:** Recommends immediate host network isolation, memory forensics prior to reboot, and blocking external command-and-control domains.
* **Protocol Anomalies:** Directs review of decoded HTTP/TLS headers, certificate chains, and domain reputation.

### 2. Safe, Reversible, Authorized IP Containment
The **IP Blocking Manager** (`nids.response.blocking`) provides manual, audited host containment via Windows Defender Firewall (`netsh advfirewall`):
* **Strictly Disabled by Default:** `RESPONSE_BLOCKING_ENABLED = False` (activated only via `$env:NIDS_RESPONSE_BLOCKING_ENABLED="true"`).
* **Simulation Mode by Default:** `BLOCKING_SIMULATION_MODE = True`. In simulation mode, the exact Windows firewall command is generated and logged, but no host firewall alterations take place.
* **Zero Automatic Blocking:** Automatic containment is strictly prohibited; all blocks require explicit human analyst interaction.
* **Mandatory Explicit Authorization:** All containment calls require `authorized=True`. Calls lacking this flag are immediately rejected.
* **Protected Address Safeguards:** Using Python's `ipaddress` module, the manager strictly forbids blocking loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`), broadcast (`255.255.255.255`), multicast (`224.0.0.0/4`), or link-local autoconfiguration (`169.254.0.0/16`) addresses.
* **Reversibility Guarantee:** All containment rules can be undone cleanly at any time through the REST API or SOC dashboard.

---

## 🔍 Basic Network Sniffer Features (Task 1)

The packet sniffing engine provides comprehensive, privacy-preserving Layer 3/4 network analysis:
* **Capture Engine:** Built on Scapy and Windows Npcap kernel drivers with promiscuous mode support and BPF filtering (`ip`, `tcp port 80`, etc.).
* **Telemetry Fields Extracted:**
  - Source and Destination IPv4/IPv6 addresses
  - Source and Destination TCP/UDP transport ports
  - Protocol classification (`TCP`, `UDP`, `ICMP`, `OTHER`)
  - Total frame length in bytes
  - Formatted TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`)
  - Basic packet structure analysis (`layers` list and `ip_version`)
* **Strict Privacy & Zero Payload Storage:**
  - Raw packet payloads (`Raw`, `Padding`, application data) are **never** stored in memory queues or written to SQLite.
  - Passwords, credentials, session tokens, and personal communications are strictly excluded from ingestion.
  - The system is architecturally designed exclusively for metadata-based security monitoring.

---

## 🔒 Security Audit & Secure Coding (Task 3)

A rigorous security review was performed across the entire application stack. Full documentation is available in [docs/SECURE_CODING_REVIEW.md](file:///c:/Users/atiya/OneDrive/Desktop/NIDS-Project/docs/SECURE_CODING_REVIEW.md):
* **Path Traversal Remediated:** Fixed unrestricted `sample_path` input in `/api/suricata/ingest-sample` by enforcing canonical path resolution within approved project roots.
* **Defense-in-Depth HTTP Headers:** Automated injection of `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection`, `Referrer-Policy`, and `Content-Security-Policy`.
* **SQL Injection Immunity:** 100% of SQLite database queries employ parameterized SQL placeholders (`?`).
* **Cross-Site Scripting (XSS) Immunity:** Frontend dashboard strictly uses safe DOM APIs (`textContent`, `createElement`) with zero dynamic `innerHTML` usage.
* **Dependency Health:** Verified clean via `python -m pip check` with zero broken requirements.

---

## 🚀 Installation & Windows Setup Guide

### Prerequisites
* Windows 10 or 11 (64-bit)
* Python 3.13 (or 3.11+)
* **Npcap Driver:** Download and install from [https://npcap.com/](https://npcap.com/) (Ensure "Install Npcap in WinPcap API-compatible Mode" is checked).
* **Suricata 8.0.8 (Optional for live DPI):** Installed at `C:\Program Files\Suricata`.

### Setup Instructions
1. **Clone or Navigate to Project:**
   ```powershell
   cd "C:\Users\atiya\OneDrive\Desktop\NIDS-Project"
   ```

2. **Activate Virtual Environment:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

3. **Verify Dependencies:**
   ```powershell
   python -m pip check
   ```

4. **Launch NIDS Flask Dashboard:**
   ```powershell
   # Optional: Configure custom ports or enable live Suricata EVE monitoring
   $env:NIDS_SURICATA_ENABLED = "true"
   $env:NIDS_SURICATA_EVE_PATH = "C:\Users\atiya\OneDrive\Desktop\NIDS-Project\logs\eve.json"

   # Launch server
   python run.py
   ```
   Open your browser to: **`http://127.0.0.1:5000`**

5. **Starting Authorized Live Capture:**
   - In the SOC Dashboard, navigate to **Live Capture Controls**.
   - Select your active physical network adapter (e.g., `Wi-Fi` or `\Device\NPF_{...}`).
   - Click **Start Packet Capture**. (Note: On Windows, physical network sniffing requires running the terminal as Administrator).
   - Real-time packet throughput, protocol counters, and flow graphs will update live.

6. **Running the Full Automated Test Suite:**
   ```powershell
   python -m unittest discover -s tests -v
   ```
   Expected result: **137 tests passing (OK)**.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /api/system/status` | GET | System version, phase metadata, Suricata telemetry, and capture status |
| `GET /api/alerts` | GET | Paginated alerts with filtering (`severity`, `status`, `rule_id`, `source_ip`) |
| `GET /api/alerts/<id>` | GET | Detailed alert telemetry including evidence and recommended response |
| `GET /api/alerts/<id>/recommendation` | GET | Contextual response recommendations and mitigation guidance |
| `POST /api/alerts/<id>/acknowledge` | POST/PATCH | Acknowledge alert with optional analyst notes (`notes`, `responder`) |
| `POST /api/alerts/<id>/resolve` | POST/PATCH | Resolve alert with optional resolution justification notes |
| `POST /api/alerts/<id>/respond` | POST | Unified response workflow (status transition, notes, optional IP block) |
| `GET /api/response/status` | GET | Operational state of response subsystem and simulation mode |
| `GET /api/response/blocked-ips` | GET | List actively and historically contained IP addresses |
| `POST /api/response/block-ip` | POST | Manually contain an IP (`ip`, `reason`, `authorized: true`) |
| `POST /api/response/unblock-ip` | POST | Manually remove containment rule (`ip`, `authorized: true`) |
| `GET /api/capture/interfaces` | GET | Enumerate available Windows adapters with friendly names |
| `POST /api/capture/start` | POST | Start packet capture session (`interface`, `bpf_filter`, `count`) |
| `POST /api/capture/stop` | POST | Stop active packet capture session |
| `GET /api/traffic/stats` | GET | Live packet counters, throughput, and active/completed flows |
| `GET /api/suricata/status` | GET | Suricata integration state, offset tracking, and parsed counts |
| `POST /api/suricata/ingest-sample` | POST | Ingest controlled EVE JSON fixture for verification |

---

## 📸 SOC Dashboard Previews

*(Screenshots will be captured during live demonstration on the operational workstation.)*

```text
+---------------------------------------------------------------------------------------+
|  🛡️ NIDS SOC DEFENSE CONSOLE                                                          |
|  [Overview] [Live Alerts] [Traffic Analytics] [Capture Controls] [System Status]     |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|   +-------------------+  +-------------------+  +-------------------+  +-----------+  |
|   | CRITICAL ALERTS   |  | HIGH SEVERITY     |  | ACTIVE FLOWS      |  | SURICATA  |  |
|   |         2         |  |         7         |  |        142        |  |  ONLINE   |  |
|   +-------------------+  +-------------------+  +-------------------+  +-----------+  |
|                                                                                       |
|   [ Severity Distribution ]           [ Live Threat Feed & Triage Table ]             |
|   ( Doughnut Chart:       )           ID | Time     | Severity | Title        | Action|
|   ( Critical: 15%         )           01 | 12:45:01 | CRITICAL | CobaltStrike | View  |
|   ( High:     35%         )           02 | 12:45:10 | HIGH     | Port Scan    | View  |
|   ( Medium:   30%         )           03 | 12:45:22 | MEDIUM   | SYN Flood    | View  |
|                                                                                       |
|   [ Forensic Inspector Modal ]                                                        |
|   Title: Port Scan Detected (#02)                                                     |
|   Source: 198.51.100.77 -> Target: 10.0.0.1:80                                       |
|   🛡️ Recommended Response: Investigate unauthorized reconnaissance.                   |
|   Analyst Notes: [ Authorized security audit verified                         ]       |
|   [ 🛡️ Acknowledge ]   [ ✅ Resolve Alert ]   [ 🚫 Block Source IP ]                   |
+---------------------------------------------------------------------------------------+
```

---

## ⚖️ Limitations & Operational Boundaries

1. **Host-Level Permissions:** Physical packet capture on Windows requires an elevated (Administrator) command prompt due to Npcap kernel driver security boundaries.
2. **Intranet Desktop Architecture:** The application is built for single-operator desktop SOC analysis. It does not provide multi-tenant user authentication (RBAC); deploy behind a secure reverse proxy if shared across corporate networks.
3. **Passive Sniffing Focus:** Operates as a passive detection system. Active IP blocking is strictly manual, reversible, and requires human authorization to prevent network self-denial.
4. **Scope Exclusions:** In accordance with internship requirements, **Task 2 is explicitly not claimed and excluded from this project scope**.


