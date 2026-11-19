/**
 * NIDS Security Operations Center (SOC) Dashboard Controller
 * Plain Vanilla JavaScript, Safe DOM Manipulation, Real Backend Telemetry.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    SOCApp.init();
});

const SOCApp = {
    // State
    state: {
        activeSection: "overview",
        currentPage: 1,
        perPage: 50,
        totalAlerts: 0,
        totalPages: 1,
        filters: {
            search: "",
            severity: "",
            status: "",
            rule_id: "",
            confidence: "",
            start_date: "",
            end_date: "",
        },
        autoRefreshInterval: 10000,
        refreshTimer: null,
        currentModalAlert: null,
        captureRunning: false,
    },

    // Chart instances
    charts: {
        severity: null,
        rules: null,
        protocols: null,
    },

    /** Initialize application */
    init() {
        this.initNavigation();
        this.initCharts();
        this.initEventListeners();
        this.initModalEvents();

        // Initial Data Fetch
        this.fetchAllData();
        this.fetchInterfaces();
        this.startAutoRefresh();
    },

    // =========================================================================
    // NAVIGATION & VIEW SWITCHING
    // =========================================================================

    initNavigation() {
        // Only bind intra-page section switching to items with explicit data-section attributes
        const navItems = document.querySelectorAll(".nav-item[data-section]");
        navItems.forEach(item => {
            item.addEventListener("click", (e) => {
                e.preventDefault();
                const section = item.getAttribute("data-section");
                this.switchSection(section);

                // Close mobile sidebar if open
                const sidebar = document.getElementById("sidebar");
                if (sidebar) sidebar.classList.remove("open");
            });
        });

        // Ensure external / portal links navigate directly to their target URL
        const portalLinks = document.querySelectorAll("#public-portal-link, .nav-item-portal, #btn-back-home");
        portalLinks.forEach(link => {
            link.addEventListener("click", (e) => {
                const targetUrl = link.getAttribute("href") || "/";
                window.location.href = targetUrl;
            });
        });

        // Mobile drawer toggle
        const menuBtn = document.getElementById("mobile-menu-btn");
        const closeBtn = document.getElementById("sidebar-close-btn");
        const sidebar = document.getElementById("sidebar");

        if (menuBtn && sidebar) {
            menuBtn.addEventListener("click", () => sidebar.classList.add("open"));
        }
        if (closeBtn && sidebar) {
            closeBtn.addEventListener("click", () => sidebar.classList.remove("open"));
        }

        // Handle URL hash if provided
        const hash = window.location.hash.replace("#", "");
        if (hash && ["overview", "alerts", "traffic", "capture", "status"].includes(hash)) {
            this.switchSection(hash);
        }
    },

    switchSection(sectionId) {
        if (!sectionId) return;
        this.state.activeSection = sectionId;

        // Update nav items
        document.querySelectorAll(".nav-item").forEach(item => {
            if (item.getAttribute("data-section") === sectionId) {
                item.classList.add("active");
            } else {
                item.classList.remove("active");
            }
        });

        // Update dashboard sections
        document.querySelectorAll(".dashboard-section").forEach(sec => {
            if (sec.id === `section-${sectionId}`) {
                sec.classList.remove("hidden");
                sec.classList.add("active");
            } else {
                sec.classList.remove("active");
                sec.classList.add("hidden");
            }
        });

        // Update top heading
        const headingMap = {
            overview: "Operations Overview",
            alerts: "Intrusion Detection Events",
            traffic: "Network Traffic & Session Tracking",
            capture: "Packet Capture Engine Controls",
            status: "System Components & Runtime Status",
        };
        const pageHeading = document.getElementById("page-heading");
        if (pageHeading) {
            pageHeading.textContent = headingMap[sectionId] || "Security Operations";
        }

        window.location.hash = sectionId;

        // Specific section reload
        if (sectionId === "alerts") {
            this.fetchAlerts();
        } else if (sectionId === "traffic") {
            this.fetchTrafficStats();
        } else if (sectionId === "capture") {
            this.fetchCaptureStatus();
        } else if (sectionId === "status") {
            this.fetchSystemStatus();
        }
    },

    // =========================================================================
    // EVENT LISTENERS & FILTER CONTROLS
    // =========================================================================

    initEventListeners() {
        // Manual refresh button
        const refreshBtn = document.getElementById("manual-refresh-btn");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                this.fetchAllData();
                this.showNotification("Dashboard data refreshed.", "success");
            });
        }

        // Auto refresh select dropdown
        const autoRefreshSelect = document.getElementById("auto-refresh-select");
        if (autoRefreshSelect) {
            autoRefreshSelect.addEventListener("change", (e) => {
                this.state.autoRefreshInterval = parseInt(e.target.value, 10);
                this.startAutoRefresh();
            });
        }

        // Alert Filters
        const searchInput = document.getElementById("alert-search-input");
        let searchDebounce = null;
        if (searchInput) {
            searchInput.addEventListener("input", (e) => {
                clearTimeout(searchDebounce);
                searchDebounce = setTimeout(() => {
                    this.state.filters.search = e.target.value.trim();
                    this.state.currentPage = 1;
                    this.fetchAlerts();
                }, 300);
            });
        }

        const sevFilter = document.getElementById("filter-severity");
        if (sevFilter) {
            sevFilter.addEventListener("change", (e) => {
                this.state.filters.severity = e.target.value;
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        const statFilter = document.getElementById("filter-status");
        if (statFilter) {
            statFilter.addEventListener("change", (e) => {
                this.state.filters.status = e.target.value;
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        const ruleFilter = document.getElementById("filter-rule");
        if (ruleFilter) {
            ruleFilter.addEventListener("change", (e) => {
                this.state.filters.rule_id = e.target.value;
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        const confFilter = document.getElementById("filter-confidence");
        if (confFilter) {
            confFilter.addEventListener("change", (e) => {
                this.state.filters.confidence = e.target.value;
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        const startDateInput = document.getElementById("filter-start-date");
        if (startDateInput) {
            startDateInput.addEventListener("change", (e) => {
                this.state.filters.start_date = e.target.value;
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        const endDateInput = document.getElementById("filter-end-date");
        if (endDateInput) {
            endDateInput.addEventListener("change", (e) => {
                this.state.filters.end_date = e.target.value;
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        const resetBtn = document.getElementById("filter-reset-btn");
        if (resetBtn) {
            resetBtn.addEventListener("click", () => {
                this.resetFilters();
            });
        }

        // Pagination buttons
        const prevBtn = document.getElementById("btn-page-prev");
        if (prevBtn) {
            prevBtn.addEventListener("click", () => {
                if (this.state.currentPage > 1) {
                    this.state.currentPage--;
                    this.fetchAlerts();
                }
            });
        }

        const nextBtn = document.getElementById("btn-page-next");
        if (nextBtn) {
            nextBtn.addEventListener("click", () => {
                if (this.state.currentPage < this.state.totalPages) {
                    this.state.currentPage++;
                    this.fetchAlerts();
                }
            });
        }

        const perPageSelect = document.getElementById("table-per-page-select");
        if (perPageSelect) {
            perPageSelect.addEventListener("change", (e) => {
                this.state.perPage = parseInt(e.target.value, 10);
                this.state.currentPage = 1;
                this.fetchAlerts();
            });
        }

        // Capture Controls
        const startCapBtn = document.getElementById("btn-start-capture");
        if (startCapBtn) {
            startCapBtn.addEventListener("click", () => this.handleStartCapture());
        }

        const stopCapBtn = document.getElementById("btn-stop-capture");
        if (stopCapBtn) {
            stopCapBtn.addEventListener("click", () => this.handleStopCapture());
        }

        // Suricata Sample Fixture Ingestion
        const ingestSampleBtn = document.getElementById("btn-ingest-sample");
        if (ingestSampleBtn) {
            ingestSampleBtn.addEventListener("click", () => this.handleIngestSample());
        }

        // Notification close button
        const notifClose = document.getElementById("notification-close-btn");
        if (notifClose) {
            notifClose.addEventListener("click", () => this.hideNotification());
        }
    },

    resetFilters() {
        this.state.filters = {
            search: "",
            severity: "",
            status: "",
            rule_id: "",
            confidence: "",
            start_date: "",
            end_date: "",
        };
        this.state.currentPage = 1;

        const ids = [
            "alert-search-input",
            "filter-severity",
            "filter-status",
            "filter-rule",
            "filter-confidence",
            "filter-start-date",
            "filter-end-date"
        ];
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = "";
        });

        this.fetchAlerts();
    },

    startAutoRefresh() {
        if (this.state.refreshTimer) {
            clearInterval(this.state.refreshTimer);
            this.state.refreshTimer = null;
        }

        if (this.state.autoRefreshInterval > 0) {
            this.state.refreshTimer = setInterval(() => {
                this.fetchAllData(true);
            }, this.state.autoRefreshInterval);
        }
    },

    fetchAllData(silent = false) {
        this.fetchAlertStats();
        this.fetchCaptureStatus();
        this.fetchSystemStatus();

        if (this.state.activeSection === "alerts") {
            this.fetchAlerts();
        } else if (this.state.activeSection === "traffic") {
            this.fetchTrafficStats();
        }

        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];
        const lastUpdatedEl = document.getElementById("last-updated-text");
        if (lastUpdatedEl) {
            lastUpdatedEl.textContent = `Updated: ${timeStr}`;
        }
    },

    // =========================================================================
    // CHART.JS ANALYTICS INITIALIZATION
    // =========================================================================

    initCharts() {
        if (typeof Chart === "undefined") {
            console.warn("Chart.js is not loaded.");
            return;
        }

        // Chart.js default dark theme typography
        Chart.defaults.color = "#94a3b8";
        Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

        // 1. Severity Doughnut
        const ctxSev = document.getElementById("severityDoughnutChart");
        if (ctxSev) {
            this.charts.severity = new Chart(ctxSev, {
                type: "doughnut",
                data: {
                    labels: ["Critical", "High", "Medium", "Low", "Info"],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            "#ef4444", // Critical
                            "#f97316", // High
                            "#eab308", // Medium
                            "#3b82f6", // Low
                            "#06b6d4", // Info
                        ],
                        borderColor: "#131c31",
                        borderWidth: 2,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                boxWidth: 12,
                                padding: 12,
                            }
                        }
                    },
                    cutout: "70%",
                }
            });
        }

        // 2. Detection Rules Horizontal Bar
        const ctxRules = document.getElementById("ruleBarChart");
        if (ctxRules) {
            this.charts.rules = new Chart(ctxRules, {
                type: "bar",
                data: {
                    labels: [],
                    datasets: [{
                        label: "Alert Count",
                        data: [],
                        backgroundColor: "#0ea5e9",
                        borderRadius: 4,
                    }]
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            beginAtZero: true,
                            grid: { color: "#1e293b" },
                            ticks: { precision: 0 }
                        },
                        y: {
                            grid: { display: false }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        // 3. Protocol Distribution Doughnut
        const ctxProto = document.getElementById("protocolDoughnutChart");
        if (ctxProto) {
            this.charts.protocols = new Chart(ctxProto, {
                type: "doughnut",
                data: {
                    labels: ["TCP", "UDP", "ICMP", "Other"],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            "#0ea5e9", // TCP
                            "#10b981", // UDP
                            "#f59e0b", // ICMP
                            "#8b5cf6", // Other
                        ],
                        borderColor: "#131c31",
                        borderWidth: 2,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                boxWidth: 12,
                                padding: 12,
                            }
                        }
                    },
                    cutout: "65%",
                }
            });
        }
    },

    // =========================================================================
    // API CONSUMPTION: ALERTS & STATS
    // =========================================================================

    async fetchAlertStats() {
        try {
            const res = await fetch("/api/alerts/stats");
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            const stats = data.stats || {};

            // Update KPI cards
            const total = stats.total_alerts || 0;
            const newCount = stats.new_alerts || 0;
            const sevCounts = stats.severity_counts || {};
            const criticalHigh = (sevCounts.CRITICAL || 0) + (sevCounts.HIGH || 0);

            this.setText("kpi-total-alerts", total.toLocaleString());
            this.setText("kpi-new-alerts", newCount.toLocaleString());
            this.setText("kpi-critical-high-alerts", criticalHigh.toLocaleString());
            this.setText("nav-alerts-badge", newCount.toLocaleString());
            this.setText("chart-severity-total", `${total} Total`);

            // Update Severity Chart
            if (this.charts.severity) {
                this.charts.severity.data.datasets[0].data = [
                    sevCounts.CRITICAL || 0,
                    sevCounts.HIGH || 0,
                    sevCounts.MEDIUM || 0,
                    sevCounts.LOW || 0,
                    sevCounts.INFO || 0,
                ];
                this.charts.severity.update();
            }

            // Update Rules Bar Chart
            if (this.charts.rules) {
                const ruleCounts = stats.rule_counts || {};
                const labels = Object.keys(ruleCounts);
                const values = Object.values(ruleCounts);

                if (labels.length === 0) {
                    this.charts.rules.data.labels = ["No Detections Yet"];
                    this.charts.rules.data.datasets[0].data = [0];
                } else {
                    this.charts.rules.data.labels = labels;
                    this.charts.rules.data.datasets[0].data = values;
                }
                this.charts.rules.update();
            }
        } catch (err) {
            console.error("Failed fetching alert statistics:", err);
        }
    },

    async fetchAlerts() {
        const tbody = document.getElementById("alerts-table-body");
        if (!tbody) return;

        // Construct query parameters
        const params = new URLSearchParams();
        params.set("page", this.state.currentPage);
        params.set("per_page", this.state.perPage);

        if (this.state.filters.severity) params.set("severity", this.state.filters.severity);
        if (this.state.filters.status) params.set("status", this.state.filters.status);
        if (this.state.filters.rule_id) params.set("rule_id", this.state.filters.rule_id);
        if (this.state.filters.confidence) params.set("confidence", this.state.filters.confidence);
        if (this.state.filters.start_date) params.set("start_date", this.state.filters.start_date);
        if (this.state.filters.end_date) params.set("end_date", this.state.filters.end_date);

        try {
            const res = await fetch(`/api/alerts?${params.toString()}`);
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.message || `HTTP ${res.status}`);
            }

            const data = await res.json();
            const alerts = data.alerts || [];
            this.state.totalAlerts = data.total || 0;
            this.state.totalPages = data.total_pages || 1;
            this.state.currentPage = data.page || 1;

            this.updatePaginationUI();

            // Client-side search filtering (if search box has text)
            let displayAlerts = alerts;
            const searchQ = this.state.filters.search.toLowerCase();
            if (searchQ) {
                displayAlerts = alerts.filter(a => {
                    return (
                        (a.title && a.title.toLowerCase().includes(searchQ)) ||
                        (a.rule_id && a.rule_id.toLowerCase().includes(searchQ)) ||
                        (a.source_ip && a.source_ip.toLowerCase().includes(searchQ)) ||
                        (a.destination_ip && a.destination_ip.toLowerCase().includes(searchQ)) ||
                        (a.description && a.description.toLowerCase().includes(searchQ))
                    );
                });
            }

            this.renderAlertsTable(displayAlerts);
        } catch (err) {
            this.renderTableError(err.message);
        }
    },

    /** Safe DOM Table Rendering (Strictly Avoids Unsafe innerHTML for dynamic data) */
    renderAlertsTable(alerts) {
        const tbody = document.getElementById("alerts-table-body");
        if (!tbody) return;

        // Clear existing rows
        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }

        if (!alerts || alerts.length === 0) {
            const tr = document.createElement("tr");
            tr.className = "table-state-row";
            const td = document.createElement("td");
            td.colSpan = 8;
            td.textContent = "No intrusion alerts found matching current filter parameters.";
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        alerts.forEach(alert => {
            const tr = document.createElement("tr");

            // 1. ID
            const tdId = document.createElement("td");
            tdId.textContent = alert.id;
            tr.appendChild(tdId);

            // 2. Timestamp
            const tdTime = document.createElement("td");
            tdTime.className = "text-sm text-muted";
            tdTime.textContent = this.formatTimestamp(alert.timestamp);
            tr.appendChild(tdTime);

            // 3. Severity Badge
            const tdSev = document.createElement("td");
            const badge = document.createElement("span");
            const sevUpper = (alert.severity || "INFO").toUpperCase();
            badge.className = `badge badge-${sevUpper.toLowerCase()}`;
            badge.textContent = sevUpper;
            tdSev.appendChild(badge);
            tr.appendChild(tdSev);

            // 4. Alert Title & Rule ID + Confidence Badge
            const tdTitle = document.createElement("td");
            const titleRow = document.createElement("div");
            titleRow.style.display = "flex";
            titleRow.style.alignItems = "center";
            titleRow.style.gap = "0.4rem";

            const titleBold = document.createElement("span");
            titleBold.style.fontWeight = "600";
            titleBold.textContent = alert.title || "Security Alert";
            titleRow.appendChild(titleBold);

            if (alert.confidence === "SURICATA_SIGNATURE") {
                const confBadge = document.createElement("span");
                confBadge.className = "badge-suricata";
                confBadge.textContent = "🛡️ SURICATA";
                titleRow.appendChild(confBadge);
            }

            const ruleSmall = document.createElement("div");
            ruleSmall.className = "text-sm text-muted";
            ruleSmall.textContent = alert.rule_id || "";
            tdTitle.appendChild(titleRow);
            if (alert.rule_id) tdTitle.appendChild(ruleSmall);
            tr.appendChild(tdTitle);

            // 5. Source -> Destination
            const tdEndpoints = document.createElement("td");
            const srcCode = document.createElement("span");
            srcCode.className = "endpoint-code";
            srcCode.textContent = `${alert.source_ip || "*"}${alert.source_port ? ":" + alert.source_port : ""}`;
            const arrow = document.createElement("span");
            arrow.textContent = " → ";
            arrow.style.color = "var(--text-muted)";
            const dstCode = document.createElement("span");
            dstCode.className = "endpoint-code";
            dstCode.textContent = `${alert.destination_ip || "*"}${alert.destination_port ? ":" + alert.destination_port : ""}`;
            tdEndpoints.appendChild(srcCode);
            tdEndpoints.appendChild(arrow);
            tdEndpoints.appendChild(dstCode);
            tr.appendChild(tdEndpoints);

            // 6. Protocol
            const tdProto = document.createElement("td");
            tdProto.textContent = alert.protocol || "IP";
            tr.appendChild(tdProto);

            // 7. Status Badge
            const tdStatus = document.createElement("td");
            const statPill = document.createElement("span");
            const st = (alert.status || "NEW").toUpperCase();
            statPill.className = `badge-status badge-status-${st === "ACKNOWLEDGED" ? "ack" : (st === "RESOLVED" ? "res" : "new")}`;
            statPill.textContent = st;
            tdStatus.appendChild(statPill);
            tr.appendChild(tdStatus);

            // 8. Actions
            const tdActions = document.createElement("td");
            const rowActions = document.createElement("div");
            rowActions.className = "row-actions";

            // View Detail Button
            const btnView = document.createElement("button");
            btnView.className = "btn btn-secondary btn-xs";
            btnView.textContent = "View";
            btnView.title = "View forensic alert details";
            btnView.addEventListener("click", () => this.openAlertModal(alert.id));
            rowActions.appendChild(btnView);

            // Acknowledge Button (if NEW)
            if (st === "NEW") {
                const btnAck = document.createElement("button");
                btnAck.className = "btn btn-warning btn-xs";
                btnAck.textContent = "Ack";
                btnAck.title = "Acknowledge alert";
                btnAck.addEventListener("click", () => this.handleUpdateStatus(alert.id, "ACKNOWLEDGED"));
                rowActions.appendChild(btnAck);
            }

            // Resolve Button (if NEW or ACKNOWLEDGED)
            if (st !== "RESOLVED") {
                const btnRes = document.createElement("button");
                btnRes.className = "btn btn-success btn-xs";
                btnRes.textContent = "Resolve";
                btnRes.title = "Resolve alert";
                btnRes.addEventListener("click", () => this.handleUpdateStatus(alert.id, "RESOLVED"));
                rowActions.appendChild(btnRes);
            }

            tdActions.appendChild(rowActions);
            tr.appendChild(tdActions);

            tbody.appendChild(tr);
        });
    },

    renderTableError(errorMsg) {
        const tbody = document.getElementById("alerts-table-body");
        if (!tbody) return;
        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

        const tr = document.createElement("tr");
        tr.className = "table-state-row";
        const td = document.createElement("td");
        td.colSpan = 8;
        td.style.color = "var(--color-critical)";
        td.textContent = `Failed loading alerts from database: ${errorMsg}`;
        tr.appendChild(td);
        tbody.appendChild(tr);
    },

    updatePaginationUI() {
        const total = this.state.totalAlerts;
        const page = this.state.currentPage;
        const perPage = this.state.perPage;
        const totalPages = this.state.totalPages;

        const start = total === 0 ? 0 : (page - 1) * perPage + 1;
        const end = Math.min(page * perPage, total);

        this.setText("table-record-count-text", `Showing ${start}–${end} of ${total} alerts`);
        this.setText("pagination-info-text", `Page ${page} of ${totalPages}`);
        this.setText("current-page-indicator", String(page));

        const prevBtn = document.getElementById("btn-page-prev");
        const nextBtn = document.getElementById("btn-page-next");
        if (prevBtn) prevBtn.disabled = (page <= 1);
        if (nextBtn) nextBtn.disabled = (page >= totalPages);
    },

    // =========================================================================
    // ALERT LIFECYCLE ACTIONS (ACKNOWLEDGE & RESOLVE)
    // =========================================================================

    async handleUpdateStatus(alertId, newStatus) {
        const endpoint = newStatus === "ACKNOWLEDGED"
            ? `/api/alerts/${alertId}/acknowledge`
            : `/api/alerts/${alertId}/resolve`;

        const notesInput = document.getElementById("modal-analyst-notes");
        const notesVal = notesInput ? notesInput.value.trim() : "";

        try {
            // Using PATCH as specified in lifecycle requirements
            const res = await fetch(endpoint, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    notes: notesVal || undefined,
                    responder: "Security Analyst",
                }),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.message || `Failed to update alert ${alertId}`);
            }

            this.showNotification(`Alert ${alertId} updated to ${newStatus}.`, "success");
            this.fetchAlertStats();
            this.fetchAlerts();

            // Refresh modal if active
            if (this.state.currentModalAlert && this.state.currentModalAlert.id === alertId) {
                this.openAlertModal(alertId);
            }
        } catch (err) {
            this.showNotification(err.message, "error");
        }
    },

    // =========================================================================
    // MODAL INSPECTOR (SAFE DOM RENDERING)
    // =========================================================================

    initModalEvents() {
        const modal = document.getElementById("alert-modal");
        const closeBtn = document.getElementById("modal-close-btn");
        const footerCloseBtn = document.getElementById("modal-footer-close-btn");

        const closeModal = () => {
            if (modal) modal.classList.add("hidden");
            this.state.currentModalAlert = null;
        };

        if (closeBtn) closeBtn.addEventListener("click", closeModal);
        if (footerCloseBtn) footerCloseBtn.addEventListener("click", closeModal);

        if (modal) {
            modal.addEventListener("click", (e) => {
                if (e.target === modal) closeModal();
            });
        }

        window.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && modal && !modal.classList.contains("hidden")) {
                closeModal();
            }
        });

        // Modal Action Buttons
        const modalAckBtn = document.getElementById("modal-ack-btn");
        if (modalAckBtn) {
            modalAckBtn.addEventListener("click", () => {
                if (this.state.currentModalAlert) {
                    this.handleUpdateStatus(this.state.currentModalAlert.id, "ACKNOWLEDGED");
                }
            });
        }

        const modalResolveBtn = document.getElementById("modal-resolve-btn");
        if (modalResolveBtn) {
            modalResolveBtn.addEventListener("click", () => {
                if (this.state.currentModalAlert) {
                    this.handleUpdateStatus(this.state.currentModalAlert.id, "RESOLVED");
                }
            });
        }

        // Manual Reversible IP Containment Button
        const modalBlockBtn = document.getElementById("modal-block-ip-btn");
        if (modalBlockBtn) {
            modalBlockBtn.addEventListener("click", async () => {
                const alert = this.state.currentModalAlert;
                if (!alert || !alert.source_ip) {
                    this.showNotification("Cannot block: Alert has no associated source IP.", "error");
                    return;
                }
                const ip = alert.source_ip;
                const confirmed = confirm(
                    `[MANUAL INCIDENT CONTAINMENT ACTION]\n\n` +
                    `Target IP: ${ip}\n` +
                    `Alert: #${alert.id} (${alert.title || "Intrusion"})\n\n` +
                    `Strict Safety Notice:\n` +
                    `• Automatic blocking is DISABLED.\n` +
                    `• By default, containment runs in safe Simulation Mode (no actual firewall disruption).\n` +
                    `• This action is completely reversible.\n` +
                    `• Do you authorize manual IP containment for this host?`
                );
                if (!confirmed) return;

                try {
                    const res = await fetch("/api/response/block-ip", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            ip: ip,
                            reason: `Manual containment for alert #${alert.id}: ${alert.title || "Intrusion"}`,
                            alert_id: alert.id,
                            authorized: true,
                            analyst: "Security Analyst",
                        }),
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.message || "Failed to block IP");
                    this.showNotification(`[CONTAINMENT] ${data.message}`, "success");
                    this.openAlertModal(alert.id);
                } catch (err) {
                    this.showNotification(`Containment rejected: ${err.message}`, "error");
                }
            });
        }
    },

    async openAlertModal(alertId) {
        const modal = document.getElementById("alert-modal");
        if (!modal) return;

        try {
            const res = await fetch(`/api/alerts/${alertId}`);
            if (!res.ok) throw new Error(`Alert with ID ${alertId} not found.`);
            const data = await res.json();
            const alert = data.alert;
            this.state.currentModalAlert = alert;

            // Populate Modal Text Content Safely
            this.setText("modal-alert-title", alert.title || "Intrusion Detection Alert");
            this.setText("modal-alert-id", alert.id);
            this.setText("modal-rule-id", alert.rule_id || "-");
            this.setText("modal-timestamp", alert.timestamp || "-");
            this.setText("modal-protocol", alert.protocol || "UNKNOWN");
            this.setText("modal-src-endpoint", `${alert.source_ip || "*"}${alert.source_port ? ":" + alert.source_port : ""}`);
            this.setText("modal-dst-endpoint", `${alert.destination_ip || "*"}${alert.destination_port ? ":" + alert.destination_port : ""}`);
            const confText = alert.confidence === "SURICATA_SIGNATURE"
                ? "🛡️ SURICATA_SIGNATURE (Deep Packet Inspection)"
                : "🎯 HEURISTIC_INDICATOR (Traffic Heuristics)";
            this.setText("modal-confidence", confText);
            this.setText("modal-threshold", alert.threshold_used || "Default");
            this.setText("modal-description", alert.description || "No description provided.");

            // Recommended Incident Response & Mitigation
            const recAction = alert.recommended_action || alert.recommended_response?.recommended_action || "Investigate alert telemetry and verify host integrity.";
            this.setText("modal-recommended-action", recAction);
            const sugMit = alert.recommended_response?.suggested_mitigation || "";
            this.setText("modal-suggested-mitigation", sugMit);

            // Analyst Notes
            const notesEl = document.getElementById("modal-analyst-notes");
            if (notesEl) {
                notesEl.value = alert.response_notes || "";
            }

            // Badges
            const sevBadge = document.getElementById("modal-severity-badge");
            if (sevBadge) {
                const s = (alert.severity || "INFO").toUpperCase();
                sevBadge.className = `badge badge-${s.toLowerCase()}`;
                sevBadge.textContent = s;
            }

            const statBadge = document.getElementById("modal-status-badge");
            if (statBadge) {
                const st = (alert.status || "NEW").toUpperCase();
                statBadge.className = `badge-status badge-status-${st === "ACKNOWLEDGED" ? "ack" : (st === "RESOLVED" ? "res" : "new")}`;
                statBadge.textContent = st;
            }

            // Evidence JSON
            const evidenceCode = document.getElementById("modal-evidence-json");
            if (evidenceCode) {
                if (alert.evidence_parsed) {
                    evidenceCode.textContent = JSON.stringify(alert.evidence_parsed, null, 2);
                } else if (alert.evidence) {
                    try {
                        const parsed = JSON.parse(alert.evidence);
                        evidenceCode.textContent = JSON.stringify(parsed, null, 2);
                    } catch {
                        evidenceCode.textContent = alert.evidence;
                    }
                } else {
                    evidenceCode.textContent = "No additional evidence payload attached.";
                }
            }

            // Modal Button States
            const ackBtn = document.getElementById("modal-ack-btn");
            const resBtn = document.getElementById("modal-resolve-btn");
            const blockBtn = document.getElementById("modal-block-ip-btn");

            if (ackBtn) ackBtn.disabled = (alert.status !== "NEW");
            if (resBtn) resBtn.disabled = (alert.status === "RESOLVED");
            if (blockBtn) {
                if (alert.source_ip && alert.source_ip !== "*" && alert.source_ip !== "127.0.0.1") {
                    blockBtn.disabled = false;
                    blockBtn.textContent = `🚫 Block ${alert.source_ip}`;
                } else {
                    blockBtn.disabled = true;
                    blockBtn.textContent = "🚫 Block Source IP";
                }
            }

            modal.classList.remove("hidden");
        } catch (err) {
            this.showNotification(err.message, "error");
        }
    },

    // =========================================================================
    // TRAFFIC ANALYSIS TELEMETRY
    // =========================================================================

    async fetchTrafficStats() {
        try {
            const res = await fetch("/api/traffic/stats");
            if (!res.ok) return;
            const data = await res.json();
            const traffic = data.traffic || {};

            const activeFlows = data.active_flows || 0;
            const completedFlows = data.completed_flows || 0;

            this.setText("traffic-active-flows", activeFlows.toLocaleString());
            this.setText("traffic-completed-flows", completedFlows.toLocaleString());
            this.setText("kpi-active-flows", activeFlows.toLocaleString());

            const fwdPackets = traffic.forward_packets || 0;
            const revPackets = traffic.reverse_packets || 0;
            this.setText("traffic-forward-packets", fwdPackets.toLocaleString());
            this.setText("traffic-reverse-packets", revPackets.toLocaleString());

            this.setText("traffic-forward-bytes", this.formatBytes(traffic.forward_bytes || 0));
            this.setText("traffic-reverse-bytes", this.formatBytes(traffic.reverse_bytes || 0));

            // Update Protocol Chart
            if (this.charts.protocols) {
                const protoCounts = traffic.protocol_packets || {};
                const tcp = protoCounts.TCP || 0;
                const udp = protoCounts.UDP || 0;
                const icmp = protoCounts.ICMP || 0;
                const other = protoCounts.OTHER || 0;

                this.charts.protocols.data.datasets[0].data = [tcp, udp, icmp, other];
                this.charts.protocols.update();
            }
        } catch (err) {
            console.error("Failed fetching traffic stats:", err);
        }
    },

    // =========================================================================
    // CAPTURE CONTROLS & LIFECYCLE
    // =========================================================================

    async fetchInterfaces() {
        const select = document.getElementById("capture-interface-select");
        if (!select) return;

        try {
            const res = await fetch("/api/capture/interfaces");
            if (!res.ok) throw new Error("Failed fetching network adapters.");
            const data = await res.json();
            const ifaces = data.interfaces || [];

            while (select.firstChild) select.removeChild(select.firstChild);

            if (ifaces.length === 0) {
                const opt = document.createElement("option");
                opt.value = "";
                opt.textContent = "No network adapters detected (Check Npcap driver)";
                select.appendChild(opt);
                return;
            }

            const defOpt = document.createElement("option");
            defOpt.value = "";
            defOpt.textContent = "-- Select Network Adapter --";
            select.appendChild(defOpt);

            ifaces.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface.name;
                const ipStr = (iface.ips && iface.ips.length > 0) ? ` [${iface.ips.join(", ")}]` : "";
                opt.textContent = `${iface.description || iface.name}${ipStr}`;
                select.appendChild(opt);
            });
        } catch (err) {
            while (select.firstChild) select.removeChild(select.firstChild);
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = `Adapter enumeration failed: ${err.message}`;
            select.appendChild(opt);
        }
    },

    async fetchCaptureStatus() {
        try {
            const res = await fetch("/api/capture/status");
            if (!res.ok) return;
            const data = await res.json();

            const isRunning = Boolean(data.is_running);
            const statusStr = (data.capture_status || "IDLE").toUpperCase();
            this.state.captureRunning = isRunning;

            // Update topbar badge
            this.setText("header-capture-status-text", `Capture: ${statusStr}`);
            const pulseDot = document.getElementById("header-pulse-dot");
            if (pulseDot) {
                if (isRunning) pulseDot.classList.add("running");
                else pulseDot.classList.remove("running");
            }

            // Update sidebar indicator
            const sideDot = document.getElementById("sidebar-capture-dot");
            if (sideDot) {
                if (isRunning) sideDot.className = "status-indicator-dot running";
                else if (statusStr === "ERROR") sideDot.className = "status-indicator-dot error";
                else sideDot.className = "status-indicator-dot";
            }
            this.setText("sidebar-capture-text", `Capture: ${statusStr}`);

            // Update capture section elements
            this.setText("capture-panel-state", `Engine: ${statusStr}`);
            this.setText("capture-stats-status", statusStr);

            const startBtn = document.getElementById("btn-start-capture");
            const stopBtn = document.getElementById("btn-stop-capture");
            if (startBtn) startBtn.disabled = isRunning;
            if (stopBtn) stopBtn.disabled = !isRunning;

            // Update live telemetry counters
            const stats = data.stats || {};
            const totalPackets = stats.total_packets || 0;
            this.setText("kpi-packet-count", totalPackets.toLocaleString());
            this.setText("cs-total-packets", totalPackets.toLocaleString());
            this.setText("cs-tcp-packets", (stats.tcp_packets || 0).toLocaleString());
            this.setText("cs-udp-packets", (stats.udp_packets || 0).toLocaleString());
            this.setText("cs-icmp-packets", (stats.icmp_packets || 0).toLocaleString());
            this.setText("cs-duration", `${stats.duration_seconds || 0.0}s`);
            this.setText("cs-adapter", data.selected_interface || "None");

            if (data.selected_interface) {
                this.setText("kpi-capture-adapter", `Adapter: ${data.selected_interface}`);
            } else {
                this.setText("kpi-capture-adapter", `Engine ${statusStr}`);
            }
        } catch (err) {
            console.error("Failed fetching capture status:", err);
        }
    },

    async handleStartCapture() {
        const ifaceSelect = document.getElementById("capture-interface-select");
        const bpfInput = document.getElementById("capture-bpf-input");
        const countInput = document.getElementById("capture-count-input");
        const promiscCheck = document.getElementById("capture-promiscuous-check");

        const selectedIface = ifaceSelect ? ifaceSelect.value : "";
        if (!selectedIface) {
            this.showNotification("Please select an explicit network adapter before starting capture.", "error");
            return;
        }

        const payload = {
            interface: selectedIface,
            bpf_filter: bpfInput ? bpfInput.value.trim() : "",
            count: countInput ? parseInt(countInput.value, 10) || 0 : 0,
            promiscuous: promiscCheck ? promiscCheck.checked : false,
        };

        const startBtn = document.getElementById("btn-start-capture");
        if (startBtn) startBtn.disabled = true;

        try {
            const res = await fetch("/api/capture/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.message || "Failed to start capture session.");
            }

            this.showNotification(data.message, "success");
            this.fetchCaptureStatus();
        } catch (err) {
            this.showNotification(err.message, "error");
            if (startBtn) startBtn.disabled = false;
        }
    },

    async handleStopCapture() {
        const stopBtn = document.getElementById("btn-stop-capture");
        if (stopBtn) stopBtn.disabled = true;

        try {
            const res = await fetch("/api/capture/stop", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
            });

            const data = await res.json();
            if (!res.ok) throw new Error(data.message || "Failed to stop capture.");

            this.showNotification("Packet capture stopped successfully.", "success");
            this.fetchCaptureStatus();
            this.fetchAlertStats();
        } catch (err) {
            this.showNotification(err.message, "error");
            if (stopBtn) stopBtn.disabled = false;
        }
    },

    // =========================================================================
    // SYSTEM STATUS
    // =========================================================================

    async fetchSystemStatus() {
        try {
            const res = await fetch("/api/system/status");
            if (!res.ok) return;
            const data = await res.json();

            this.setText("sys-engine-version", data.engine || "NIDS v0.1.0");
            this.setText("sys-phase", data.phase || "Phase 7");
            this.setText("sys-capture-status", data.capture_status || "IDLE");
            this.setText("sys-capture-iface", data.selected_interface || "None");

            const detection = data.detection || {};
            this.setText("sys-active-rules", `${detection.active_rules_count || 4} Active Rules`);
            this.setText("sys-inspections", (detection.total_inspections || 0).toLocaleString());
            this.setText("sys-events-gen", (detection.total_events_generated || 0).toLocaleString());

            const storage = data.storage || {};
            const queueCap = storage.max_queue_size || 5000;
            const dropped = storage.total_dropped || 0;
            this.setText("sys-queue-stats", `${queueCap} / ${dropped} dropped`);
            this.setText("sys-async-worker", storage.is_running ? "Running (Non-blocking)" : "Standby");

            // Suricata Deep Inspection Status
            const suricata = data.suricata || {};
            const suriStats = suricata.stats || {};
            const suriMode = suricata.mode || "disabled";
            const modeLabels = {
                live: "Live EVE Tailing",
                fixture: "Fixture Simulation",
                standby: "Standby (Waiting for EVE)",
                disabled: "Disabled",
            };
            this.setText("sys-suricata", data.suricata_integrated ? "Active (Phase 8)" : "Not Integrated");
            this.setText("sys-suricata-mode", modeLabels[suriMode] || suriMode);
            this.setText("sys-suricata-path", suricata.eve_path ? suricata.eve_path.split(/[\\/]/).pop() : "None");
            const parsedEvents = (suriStats.total_events_parsed || 0).toLocaleString();
            const offsetKb = Math.round((suricata.file_offset || 0) / 1024);
            this.setText("sys-suricata-events", `${parsedEvents} events (${offsetKb} KB)`);
            this.setText("sys-suricata-alerts", (suriStats.alerts_count || 0).toLocaleString());
        } catch (err) {
            console.error("Failed fetching system status:", err);
        }
    },

    async handleIngestSample() {
        const btn = document.getElementById("btn-ingest-sample");
        if (btn) {
            btn.disabled = true;
            btn.textContent = "⏳ Ingesting...";
        }

        try {
            const res = await fetch("/api/suricata/ingest-sample", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.message || `HTTP ${res.status}`);
            }

            this.showNotification(
                data.message || "Suricata sample fixture ingested successfully!",
                "success"
            );
            this.fetchAllData();
            if (this.state.activeSection === "alerts") {
                this.fetchAlerts();
            }
        } catch (err) {
            console.error("Failed to ingest sample fixture:", err);
            this.showNotification(`Ingestion failed: ${err.message}`, "error");
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = "📥 Ingest Sample EVE Fixture";
            }
        }
    },

    // =========================================================================
    // HELPERS & NOTIFICATIONS
    // =========================================================================

    setText(elementId, text) {
        const el = document.getElementById(elementId);
        if (el) el.textContent = (text !== undefined && text !== null) ? text : "";
    },

    showNotification(message, type = "success") {
        const banner = document.getElementById("notification-banner");
        const text = document.getElementById("notification-text");
        if (!banner || !text) return;

        text.textContent = message;
        banner.className = `notification-banner ${type}`;
        banner.classList.remove("hidden");

        setTimeout(() => {
            this.hideNotification();
        }, 6000);
    },

    hideNotification() {
        const banner = document.getElementById("notification-banner");
        if (banner) banner.classList.add("hidden");
    },

    formatTimestamp(isoString) {
        if (!isoString) return "-";
        try {
            const d = new Date(isoString);
            if (isNaN(d.getTime())) return isoString;
            return d.toISOString().replace("T", " ").substring(0, 19);
        } catch {
            return isoString;
        }
    },

    formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }
};
