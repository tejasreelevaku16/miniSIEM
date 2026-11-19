/**
 * Mini-SIEM SOC Dashboard JavaScript Controller
 * Connects frontend UI to real FastAPI backend endpoints.
 */

// State variables
let currentEventsOffset = 0;
const EVENTS_PAGE_SIZE = 25;
let charts = {};
let activeIncidentId = null;

// DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initClock();
  initTabs();
  initUpload();
  initFilters();
  initCharts();
  refreshAll();

  // Polling every 30 seconds for live updates
  setInterval(refreshAll, 30000);

  // Manual actions
  document.getElementById("btn-refresh-all").addEventListener("click", refreshAll);
  document.getElementById("btn-run-detection").addEventListener("click", triggerDetection);
  document.getElementById("btn-close-modal").addEventListener("click", closeInvestigationModal);
  document.getElementById("btn-modal-save-status").addEventListener("click", saveModalIncidentStatus);

  // Pagination
  document.getElementById("btn-events-prev").addEventListener("click", () => {
    if (currentEventsOffset >= EVENTS_PAGE_SIZE) {
      currentEventsOffset -= EVENTS_PAGE_SIZE;
      loadSecurityEvents();
    }
  });

  document.getElementById("btn-events-next").addEventListener("click", () => {
    currentEventsOffset += EVENTS_PAGE_SIZE;
    loadSecurityEvents();
  });
});

/* ==========================================================
   TIME & TABS
   ========================================================== */
function initClock() {
  const timeEl = document.getElementById("server-time");
  function update() {
    const now = new Date();
    timeEl.textContent = now.toUTCString().split(" ")[4] + " UTC";
  }
  update();
  setInterval(update, 1000);
}

function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));

      tab.classList.add("active");
      const targetId = tab.getAttribute("data-tab");
      const targetEl = document.getElementById(targetId);
      if (targetEl) targetEl.classList.add("active");
    });
  });
}

function showBanner(message, type = "info", duration = 5000) {
  const banner = document.getElementById("soc-alert-banner");
  banner.className = `alert-banner ${type}`;
  banner.innerHTML = `<span>${message}</span><button class="btn-close" onclick="this.parentElement.classList.add('hidden')">&times;</button>`;
  banner.classList.remove("hidden");
  if (duration > 0) {
    setTimeout(() => banner.classList.add("hidden"), duration);
  }
}

/* ==========================================================
   REFRESH ALL DATA
   ========================================================== */
async function refreshAll() {
  await Promise.allSettled([
    loadDashboardStats(),
    loadIncidents(),
    loadAlerts(),
    loadSecurityEvents(),
  ]);
}

/* ==========================================================
   1. DASHBOARD STATS & CHARTS
   ========================================================== */
async function loadDashboardStats() {
  try {
    const res = await fetch("/api/dashboard/stats");
    if (!res.ok) throw new Error("Failed to load dashboard metrics");
    const data = await res.json();

    // Update KPI numbers
    document.getElementById("val-total-events").textContent = data.total_events.toLocaleString();
    document.getElementById("val-total-alerts").textContent = data.total_alerts.toLocaleString();
    document.getElementById("val-total-incidents").textContent = data.total_incidents.toLocaleString();
    document.getElementById("val-open-incidents").textContent = data.open_incidents.toLocaleString();
    document.getElementById("val-critical-incidents").textContent = data.high_critical_incidents.toLocaleString();

    // Tab badges
    document.getElementById("badge-open-incidents").textContent = data.open_incidents;
    document.getElementById("badge-total-alerts").textContent = data.total_alerts;

    // Update Top Suspicious IPs table
    renderTopIps(data.top_suspicious_ips || []);

    // Update Charts
    updateCharts(data);
  } catch (err) {
    console.error("Dashboard metrics error:", err);
  }
}

function renderTopIps(topIps) {
  const tbody = document.getElementById("tbody-top-ips");
  if (!topIps || topIps.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center">No malicious telemetry detected.</td></tr>`;
    return;
  }

  tbody.innerHTML = topIps.map((item, index) => {
    let risk = "MEDIUM";
    let badgeClass = "badge-medium";
    let rec = "Monitor authentication logs";

    if (item.failures >= 10) {
      risk = "CRITICAL";
      badgeClass = "badge-critical";
      rec = "Block IP permanently at perimeter firewall";
    } else if (item.failures >= 5) {
      risk = "HIGH";
      badgeClass = "badge-high";
      rec = "Temporarily rate-limit IP at firewall";
    }

    return `
      <tr>
        <td>#${index + 1}</td>
        <td><span class="mono"><strong>${escapeHtml(item.ip)}</strong></span></td>
        <td><span class="badge ${badgeClass}">${item.failures}</span></td>
        <td><span class="badge ${badgeClass}">${risk}</span></td>
        <td>${rec}</td>
      </tr>
    `;
  }).join("");
}

function initCharts() {
  // 1. Activity Timeline (Line)
  const ctxTimeline = document.getElementById("chart-timeline").getContext("2d");
  charts.timeline = new Chart(ctxTimeline, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Security Events",
        data: [],
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.1)",
        fill: true,
        tension: 0.3,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9ca3af", font: { size: 10 } }, grid: { color: "#1f293d" } },
        y: { ticks: { color: "#9ca3af", stepSize: 1 }, grid: { color: "#1f293d" } }
      }
    }
  });

  // 2. Outcomes (Doughnut)
  const ctxOutcomes = document.getElementById("chart-outcomes").getContext("2d");
  charts.outcomes = new Chart(ctxOutcomes, {
    type: "doughnut",
    data: {
      labels: ["Success", "Failure", "Blocked", "Other"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ["#10b981", "#ef4444", "#f59e0b", "#6b7280"],
        borderColor: "#111827",
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "right", labels: { color: "#f3f4f6", font: { size: 11 } } } }
    }
  });

  // 3. Alerts by Severity (Bar)
  const ctxSeverity = document.getElementById("chart-severity").getContext("2d");
  charts.severity = new Chart(ctxSeverity, {
    type: "bar",
    data: {
      labels: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ["#10b981", "#f59e0b", "#f97316", "#ef4444"],
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9ca3af" }, grid: { display: false } },
        y: { ticks: { color: "#9ca3af", stepSize: 1 }, grid: { color: "#1f293d" } }
      }
    }
  });

  // 4. Incidents by Status (Bar)
  const ctxStatus = document.getElementById("chart-status").getContext("2d");
  charts.status = new Chart(ctxStatus, {
    type: "bar",
    data: {
      labels: ["Open", "Investigating", "Resolved", "False Positive"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ["#3b82f6", "#f59e0b", "#10b981", "#6b7280"],
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9ca3af" }, grid: { display: false } },
        y: { ticks: { color: "#9ca3af", stepSize: 1 }, grid: { color: "#1f293d" } }
      }
    }
  });

  // 5. Sources (Bar)
  const ctxSources = document.getElementById("chart-sources").getContext("2d");
  charts.sources = new Chart(ctxSources, {
    type: "bar",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: "#06b6d4",
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9ca3af" }, grid: { display: false } },
        y: { ticks: { color: "#9ca3af", stepSize: 1 }, grid: { color: "#1f293d" } }
      }
    }
  });
}

function updateCharts(data) {
  // 1. Timeline
  if (charts.timeline && data.events_timeline) {
    charts.timeline.data.labels = data.events_timeline.map(e => e.time);
    charts.timeline.data.datasets[0].data = data.events_timeline.map(e => e.count);
    charts.timeline.update();
  }

  // 2. Outcomes
  if (charts.outcomes && data.outcomes) {
    const oc = data.outcomes;
    charts.outcomes.data.datasets[0].data = [
      oc.success || 0,
      oc.failure || 0,
      oc.blocked || 0,
      oc.unknown || 0,
    ];
    charts.outcomes.update();
  }

  // 3. Alerts Severity
  if (charts.severity && data.alerts_by_severity) {
    const sev = data.alerts_by_severity;
    charts.severity.data.datasets[0].data = [
      sev.LOW || 0,
      sev.MEDIUM || 0,
      sev.HIGH || 0,
      sev.CRITICAL || 0,
    ];
    charts.severity.update();
  }

  // 4. Incidents Status
  if (charts.status && data.incidents_by_status) {
    const st = data.incidents_by_status;
    charts.status.data.datasets[0].data = [
      st.Open || 0,
      st.Investigating || 0,
      st.Resolved || 0,
      st["False Positive"] || 0,
    ];
    charts.status.update();
  }

  // 5. Telemetry Sources
  if (charts.sources && data.events_by_source) {
    charts.sources.data.labels = Object.keys(data.events_by_source);
    charts.sources.data.datasets[0].data = Object.values(data.events_by_source);
    charts.sources.update();
  }
}

/* ==========================================================
   2. INCIDENTS MANAGEMENT
   ========================================================== */
function initFilters() {
  document.getElementById("filter-incident-status").addEventListener("change", loadIncidents);
  document.getElementById("filter-incident-severity").addEventListener("change", loadIncidents);
  document.getElementById("filter-alert-rule").addEventListener("change", loadAlerts);
  document.getElementById("filter-alert-severity").addEventListener("change", loadAlerts);
}

async function loadIncidents() {
  const statusFilter = document.getElementById("filter-incident-status").value;
  const severityFilter = document.getElementById("filter-incident-severity").value;

  const params = new URLSearchParams();
  if (statusFilter) params.append("status", statusFilter);
  if (severityFilter) params.append("severity", severityFilter);

  try {
    const res = await fetch(`/api/incidents?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load incidents");
    const data = await res.json();
    renderIncidents(data.incidents || []);
  } catch (err) {
    console.error("Load incidents error:", err);
    document.getElementById("tbody-incidents").innerHTML =
      `<tr><td colspan="9" class="text-center">Failed to load incidents.</td></tr>`;
  }
}

function renderIncidents(incidents) {
  const tbody = document.getElementById("tbody-incidents");
  if (!incidents || incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center">No security incidents found matching filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sevBadge = getSeverityBadge(inc.severity);
    const statusBadge = getStatusBadge(inc.status);
    const mitreTech = inc.mitre_technique || "T1110";

    return `
      <tr>
        <td><strong>#${inc.id}</strong></td>
        <td>${sevBadge}</td>
        <td>
          <select onchange="updateIncidentStatusInline(${inc.id}, this.value)" class="status-select">
            <option value="Open" ${inc.status === "Open" ? "selected" : ""}>Open</option>
            <option value="Investigating" ${inc.status === "Investigating" ? "selected" : ""}>Investigating</option>
            <option value="Resolved" ${inc.status === "Resolved" ? "selected" : ""}>Resolved</option>
            <option value="False Positive" ${inc.status === "False Positive" ? "selected" : ""}>False Positive</option>
          </select>
        </td>
        <td><span class="mono">${escapeHtml(inc.source_ip)}</span></td>
        <td>${escapeHtml(inc.targeted_usernames || "none")}</td>
        <td><span class="mono">${escapeHtml(inc.rule_id || "AUTH-001")}</span></td>
        <td><span class="mitre-tag">${escapeHtml(mitreTech)}</span></td>
        <td><small class="mono">${escapeHtml(inc.window_start)}<br>→ ${escapeHtml(inc.window_end)}</small></td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="openInvestigationModal(${inc.id})">
            🔍 Investigate
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

async function updateIncidentStatusInline(incidentId, newStatus) {
  try {
    const res = await fetch(`/api/incidents/${incidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });

    if (!res.ok) throw new Error("Failed to update status");
    showBanner(`Incident #${incidentId} status updated to '${newStatus}'.`, "success");
    loadDashboardStats();
  } catch (err) {
    showBanner(`Failed to update status: ${err.message}`, "warning");
    loadIncidents();
  }
}

/* ==========================================================
   3. INVESTIGATION DRAWER / MODAL
   ========================================================== */
async function openInvestigationModal(incidentId) {
  activeIncidentId = incidentId;
  const modal = document.getElementById("investigation-modal");
  modal.classList.remove("hidden");

  document.getElementById("inv-id").textContent = incidentId;
  document.getElementById("inv-description").textContent = "Loading incident telemetry...";
  document.getElementById("tbody-inv-timeline").innerHTML = `<tr><td colspan="6" class="text-center">Loading timeline...</td></tr>`;

  try {
    const res = await fetch(`/api/incidents/${incidentId}`);
    if (!res.ok) throw new Error("Failed to retrieve incident details");
    const inc = await res.json();

    document.getElementById("inv-id").textContent = inc.id;
    document.getElementById("inv-badge-container").innerHTML = getSeverityBadge(inc.severity) + " " + getStatusBadge(inc.status);
    document.getElementById("inv-description").textContent = inc.description;
    document.getElementById("inv-ip").textContent = inc.source_ip;
    document.getElementById("inv-users").textContent = inc.targeted_usernames || "N/A";
    document.getElementById("inv-window").textContent = `${inc.window_start} -> ${inc.window_end}`;
    document.getElementById("inv-count").textContent = `${inc.failure_count} event(s)`;
    document.getElementById("inv-rule").textContent = inc.rule_id || "AUTH-001";
    document.getElementById("modal-status-select").value = inc.status || "Open";

    // Playbook
    document.getElementById("inv-action").textContent = inc.recommended_action || "Investigate source IP telemetry.";

    // MITRE Mapping
    const mitreTech = inc.mitre_technique || "T1110";
    document.getElementById("inv-mitre-badge").textContent = mitreTech;
    document.getElementById("inv-mitre-name").textContent = getMitreName(mitreTech);
    document.getElementById("inv-mitre-desc").textContent = getMitreDescription(mitreTech);

    // Timeline Events
    renderIncidentTimeline(inc.events || []);
  } catch (err) {
    document.getElementById("inv-description").textContent = `Error: ${err.message}`;
  }
}

function renderIncidentTimeline(events) {
  const tbody = document.getElementById("tbody-inv-timeline");
  document.getElementById("inv-events-count").textContent = events.length;

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center">No raw events recorded in this time window.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(e => `
    <tr>
      <td><span class="mono">${escapeHtml(e.timestamp)}</span></td>
      <td><span class="mono">${escapeHtml(e.source_ip)}</span></td>
      <td><strong>${escapeHtml(e.username || "none")}</strong></td>
      <td><span class="mono">${escapeHtml(e.event_type)}</span></td>
      <td><span class="badge ${e.outcome === 'success' ? 'badge-low' : 'badge-high'}">${escapeHtml(e.outcome || "unknown")}</span></td>
      <td><small class="mono">${escapeHtml(e.user_agent || "N/A")}</small></td>
    </tr>
  `).join("");
}

function closeInvestigationModal() {
  document.getElementById("investigation-modal").classList.add("hidden");
  activeIncidentId = null;
}

async function saveModalIncidentStatus() {
  if (!activeIncidentId) return;
  const newStatus = document.getElementById("modal-status-select").value;
  await updateIncidentStatusInline(activeIncidentId, newStatus);
  openInvestigationModal(activeIncidentId);
  loadIncidents();
}

/* ==========================================================
   4. ALERTS FEED
   ========================================================== */
async function loadAlerts() {
  const ruleFilter = document.getElementById("filter-alert-rule").value;
  const severityFilter = document.getElementById("filter-alert-severity").value;

  const params = new URLSearchParams();
  if (ruleFilter) params.append("rule_id", ruleFilter);
  if (severityFilter) params.append("severity", severityFilter);

  try {
    const res = await fetch(`/api/alerts?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load alerts");
    const data = await res.json();
    renderAlerts(data.alerts || []);
  } catch (err) {
    console.error("Load alerts error:", err);
    document.getElementById("tbody-alerts").innerHTML =
      `<tr><td colspan="9" class="text-center">Failed to load alerts feed.</td></tr>`;
  }
}

function renderAlerts(alerts) {
  const tbody = document.getElementById("tbody-alerts");
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center">No alerts triggered yet. Click 'Run Detections' or upload logs.</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td>#${a.id}</td>
      <td><span class="mono"><strong>${escapeHtml(a.rule_id)}</strong></span></td>
      <td>${getSeverityBadge(a.severity)}</td>
      <td><span class="mono">${escapeHtml(a.source_ip)}</span></td>
      <td>${escapeHtml(a.username || "various")}</td>
      <td><span class="badge badge-soc">${a.event_count}</span></td>
      <td><small class="mono">${escapeHtml(a.first_observed)}</small></td>
      <td><span class="mitre-tag">${escapeHtml(a.mitre_technique_id || "T1110")}</span></td>
      <td><small>${escapeHtml(a.description)}</small></td>
    </tr>
  `).join("");
}

/* ==========================================================
   5. SECURITY EVENTS EXPLORER
   ========================================================== */
async function loadSecurityEvents() {
  try {
    const res = await fetch(`/api/logs?limit=${EVENTS_PAGE_SIZE}&offset=${currentEventsOffset}`);
    if (!res.ok) throw new Error("Failed to load security events");
    const data = await res.json();

    const total = data.total || 0;
    const start = Math.min(total, currentEventsOffset + 1);
    const end = Math.min(total, currentEventsOffset + data.events.length);
    document.getElementById("events-page-info").textContent = `Showing ${start}-${end} of ${total}`;

    document.getElementById("btn-events-prev").disabled = (currentEventsOffset === 0);
    document.getElementById("btn-events-next").disabled = (end >= total);

    renderSecurityEvents(data.events || []);
  } catch (err) {
    console.error("Load events error:", err);
    document.getElementById("tbody-events").innerHTML =
      `<tr><td colspan="8" class="text-center">Failed to load security events.</td></tr>`;
  }
}

function renderSecurityEvents(events) {
  const tbody = document.getElementById("tbody-events");
  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center">No telemetry events found. Upload a CSV log file.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(e => {
    let outcomeBadge = `<span class="badge badge-soc">${escapeHtml(e.outcome || "unknown")}</span>`;
    if (e.outcome === "success") outcomeBadge = `<span class="badge badge-low">SUCCESS</span>`;
    else if (e.outcome === "failure") outcomeBadge = `<span class="badge badge-high">FAILURE</span>`;
    else if (e.outcome === "blocked") outcomeBadge = `<span class="badge badge-critical">BLOCKED</span>`;

    let extraTelemetry = e.user_agent || "";
    if (e.dest_port) extraTelemetry += ` | Port:${e.dest_port}`;
    if (e.request_path) extraTelemetry += ` | Path:${e.request_path}`;

    return `
      <tr>
        <td>#${e.id}</td>
        <td><span class="mono">${escapeHtml(e.timestamp)}</span></td>
        <td><span class="mono">${escapeHtml(e.source || "legacy")}</span></td>
        <td><span class="mono">${escapeHtml(e.source_ip)}</span></td>
        <td><strong>${escapeHtml(e.username || "none")}</strong></td>
        <td><span class="mono">${escapeHtml(e.event_type)}</span></td>
        <td>${outcomeBadge}</td>
        <td><small class="mono text-muted">${escapeHtml(extraTelemetry || "N/A")}</small></td>
      </tr>
    `;
  }).join("");
}

/* ==========================================================
   6. LOG UPLOAD INGESTION
   ========================================================== */
function initUpload() {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  const submitBtn = document.getElementById("btn-submit-upload");
  const fileNameDisplay = document.getElementById("selected-file-name");

  let selectedFile = null;

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      selectedFile = e.target.files[0];
      fileNameDisplay.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      submitBtn.disabled = false;
    }
  });

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      selectedFile = e.dataTransfer.files[0];
      fileNameDisplay.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      submitBtn.disabled = false;
    }
  });

  submitBtn.addEventListener("click", async () => {
    if (!selectedFile) return;

    submitBtn.disabled = true;
    submitBtn.textContent = "Uploading & Ingesting...";

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const res = await fetch("/api/logs/upload", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      displayUploadResult(data, res.status);
      refreshAll();
    } catch (err) {
      displayUploadResult({ status: "error", message: err.message }, 500);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "🚀 Upload & Ingest";
    }
  });
}

function displayUploadResult(data, statusCode) {
  const card = document.getElementById("upload-result-card");
  const title = document.getElementById("upload-result-title");
  const details = document.getElementById("upload-result-details");
  const rejectedBox = document.getElementById("rejected-rows-box");
  const pillsContainer = document.getElementById("rejected-row-pills");

  card.classList.remove("hidden");

  if (data.status === "duplicate") {
    title.innerHTML = `⚠️ <span style="color:#f59e0b">Duplicate File Detected</span>`;
    details.innerHTML = `
      <p><strong>${escapeHtml(data.message)}</strong></p>
      <p>Existing Upload Record ID: <span class="mono">#${data.existing_raw_log_id}</span></p>
      <p>To avoid polluting SOC audit logs, identical files are safely skipped by cryptographic SHA-256 fingerprinting.</p>
    `;
    rejectedBox.classList.add("hidden");
    showBanner("Duplicate file detected: this exact CSV file has already been ingested.", "warning");
    return;
  }

  if (statusCode === 200 && data.status === "success") {
    title.innerHTML = `✅ <span style="color:#10b981">${escapeHtml(data.message)}</span>`;
    details.innerHTML = `
      <p>Filename: <span class="mono"><strong>${escapeHtml(data.filename)}</strong></span> (Upload ID: #${data.upload_id})</p>
      <p>Total Data Rows: <strong>${data.total_rows}</strong> &bull;
         Valid Processed Events: <strong>${data.processed_events}</strong> &bull;
         Stored to DB: <strong>${data.summary ? data.summary.stored_events : data.processed_events}</strong> &bull;
         Duplicate Events Skipped: <strong>${data.summary ? data.summary.duplicate_events_skipped : 0}</strong></p>
    `;

    if (data.rejected_rows > 0 && data.rejected_row_numbers) {
      rejectedBox.classList.remove("hidden");
      document.getElementById("rejected-rows-count").textContent = data.rejected_rows;
      pillsContainer.innerHTML = data.rejected_row_numbers.map(num => `
        <span class="pill" title="Physical CSV row ${num} was skipped due to malformed timestamp, invalid outcome, or missing fields.">Row #${num}</span>
      `).join("");
    } else {
      rejectedBox.classList.add("hidden");
    }

    showBanner(`Successfully ingested ${data.processed_events} security event(s). Detection rules executed.`, "success");
    return;
  }

  // Error case
  title.innerHTML = `❌ <span style="color:#ef4444">Upload Failed</span>`;
  details.innerHTML = `<p>${escapeHtml(data.detail || data.message || "An unexpected error occurred.")}</p>`;
  rejectedBox.classList.add("hidden");
  showBanner(`Upload failed: ${data.detail || data.message}`, "warning");
}

/* ==========================================================
   7. BATCH DETECTION RUNNER
   ========================================================== */
async function triggerDetection() {
  const btn = document.getElementById("btn-run-detection");
  btn.disabled = true;
  btn.textContent = "⚡ Running...";

  try {
    const res = await fetch("/api/alerts/run-detection", { method: "POST" });
    const data = await res.json();
    showBanner(
      `Detection Engine Complete: Analyzed ${data.analyzed_events} event(s), generated ${data.generated_alerts} alert(s), created ${data.saved_incidents} incident(s).`,
      "success"
    );
    refreshAll();
  } catch (err) {
    showBanner(`Detection error: ${err.message}`, "warning");
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ Run Detections";
  }
}

/* ==========================================================
   HELPERS & BADGES
   ========================================================== */
function getSeverityBadge(sev) {
  const s = (sev || "LOW").toUpperCase();
  if (s === "CRITICAL") return `<span class="badge badge-critical">CRITICAL</span>`;
  if (s === "HIGH") return `<span class="badge badge-high">HIGH</span>`;
  if (s === "MEDIUM") return `<span class="badge badge-medium">MEDIUM</span>`;
  return `<span class="badge badge-low">LOW</span>`;
}

function getStatusBadge(status) {
  const st = (status || "Open").toLowerCase().replace(" ", "-");
  return `<span class="status-badge status-${st}">${escapeHtml(status || "Open")}</span>`;
}

function getMitreName(techId) {
  const map = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1046": "Network Service Discovery",
    "T1499": "Endpoint Denial of Service",
  };
  return map[techId] || "Credential Access Technique";
}

function getMitreDescription(techId) {
  const map = {
    "T1110": "Adversaries may use brute force techniques to attempt authentication by guessing passwords through automated attempts.",
    "T1078": "Adversaries may obtain and use credentials of existing accounts following successful brute force or guessing.",
    "T1046": "Adversaries may attempt to get a listing of services running on remote hosts by conducting port scans.",
    "T1499": "Adversaries may perform service exhausting attacks, such as HTTP floods or heavy request volume, to degrade endpoint availability.",
  };
  return map[techId] || "Security anomaly mapped to MITRE ATT&CK framework.";
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
