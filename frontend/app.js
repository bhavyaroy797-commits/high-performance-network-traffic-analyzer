const BASE_URL = "http://localhost:3000";
const socket = io(BASE_URL);

let isCapturing = true;
let displayFilter = "";
let totalPackets = 0;
let anomalyCount = 0;

const btnStart = document.getElementById("btn-start");
const btnStop = document.getElementById("btn-stop");
const btnClear = document.getElementById("btn-clear");
const bpfInput = document.getElementById("bpf-input");
const btnApplyFilter = document.getElementById("btn-apply-filter");
const activeFilterText = document.getElementById("active-filter-text");
const compileBanner = document.getElementById("compile-banner");

const liveStatus = document.getElementById("live-status");
const statusText = document.getElementById("status-text");

const metricPps = document.getElementById("metric-pps");
const metricTcp = document.getElementById("metric-tcp");
const metricAnomalies = document.getElementById("metric-anomalies");
const cardAnomalies = document.getElementById("card-anomalies");
const anomaliesBadge = document.getElementById("anomalies-badge");

const consoleScroll = document.getElementById("console-scroll");
const emptyState = document.getElementById("empty-state");
const capturedCount = document.getElementById("captured-count");
const filterChips = document.querySelectorAll(".filter-chip");

const PROTOCOL_CLASS = {
  TCP: "p-tcp",
  UDP: "p-udp",
  ICMP: "p-icmp",
  HTTP: "p-http",
  TLS: "p-tls",
  DNS: "p-dns",
};

function formatTimestamp(isoString) {
  const d = new Date(isoString);
  const hrs = String(d.getHours()).padStart(2, "0");
  const mins = String(d.getMinutes()).padStart(2, "0");
  const secs = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hrs}:${mins}:${secs}.${ms}`;
}

function matchesFilter(row) {
  if (!displayFilter) return true;
  const f = displayFilter.toLowerCase().trim();

  if (f === "tcp" && row.protocol.toUpperCase().includes("TCP")) return true;
  if (f === "udp" && row.protocol.toUpperCase() === "UDP") return true;
  if (f === "icmp" && row.protocol.toUpperCase() === "ICMP") return true;
  if (f === "port 80" && (row.source_port === 80 || row.dest_port === 80))
    return true;
  if (f === "port 53" && (row.source_port === 53 || row.dest_port === 53))
    return true;
  if (row.source_ip.includes(f) || row.dest_ip.includes(f)) return true;

  return false;
}

function buildPacketRowElement(row) {
  const protoClass = PROTOCOL_CLASS[row.protocol.toUpperCase()] || "p-icmp";
  const el = document.createElement("div");
  el.className = "packet-row anomaly";
  el.title = row.threat_type;
  el.innerHTML = `
    <div class="col-time">${formatTimestamp(row.event_timestamp)}</div>
    <div class="col-ip">${row.source_ip}</div>
    <div class="col-ip">${row.dest_ip}</div>
    <div><span class="col-proto ${protoClass}">${row.protocol}</span></div>
    <div class="col-len">${row.packet_length} B</div>
  `;
  return el;
}

function renderAnomalyRow(row) {
  if (!matchesFilter(row)) return;

  if (emptyState) {
    emptyState.style.display = "none";
  }

  const el = buildPacketRowElement(row);
  consoleScroll.appendChild(el);
  totalPackets++;
  capturedCount.textContent = totalPackets;

  anomalyCount++;
  metricAnomalies.textContent = anomalyCount;
  anomaliesBadge.style.display = "flex";

  cardAnomalies.classList.add("shake");
  setTimeout(() => cardAnomalies.classList.remove("shake"), 500);

  consoleScroll.scrollTop = consoleScroll.scrollHeight;

  if (consoleScroll.children.length > 150) {
    consoleScroll.removeChild(consoleScroll.children[1]);
  }
}

function setCaptureUI(active) {
  isCapturing = active;
  if (active) {
    liveStatus.className = "status-indicator active";
    statusText.textContent = "Live Capture: Active";
    btnStart.classList.add("pressed");
    btnStop.classList.remove("pressed");
  } else {
    liveStatus.className = "status-indicator paused";
    statusText.textContent = "Live Capture: Paused";
    btnStop.classList.add("pressed");
    btnStart.classList.remove("pressed");
    metricPps.textContent = "0";
  }
}

async function loadInitialState() {
  try {
    const summaryRes = await fetch(`${BASE_URL}/api/stats/summary`);
    const summary = await summaryRes.json();

    anomalyCount = summary.anomalyCount;
    metricAnomalies.textContent = anomalyCount;
    if (anomalyCount > 0) anomaliesBadge.style.display = "flex";

    metricPps.textContent = summary.packetsPerSec;
    metricTcp.textContent = summary.activeTcpConnections;
    setCaptureUI(summary.isActive);

    const recentRes = await fetch(`${BASE_URL}/api/anomalies/recent?limit=150`);
    const recentRows = await recentRes.json();

    if (recentRows.length > 0 && emptyState) {
      emptyState.style.display = "none";
    }

    recentRows.forEach((row) => {
      if (!matchesFilter(row)) return;
      consoleScroll.appendChild(buildPacketRowElement(row));
      totalPackets++;
    });

    capturedCount.textContent = totalPackets;
    consoleScroll.scrollTop = consoleScroll.scrollHeight;
  } catch (err) {
    console.error("Failed to load initial state:", err);
  }
}

socket.on("anomaly:new", renderAnomalyRow);

socket.on("stats:update", (stats) => {
  if (!isCapturing) return;
  metricPps.textContent = stats.packets_per_sec;
  metricTcp.textContent = stats.active_tcp_connections;
});

socket.on("capture:state", (state) => {
  setCaptureUI(state.isActive);
});

btnStart.addEventListener("click", async () => {
  try {
    await fetch(`${BASE_URL}/api/capture/start`, { method: "POST" });
    setCaptureUI(true);
  } catch (err) {
    console.error("Failed to start capture:", err);
  }
});

btnStop.addEventListener("click", async () => {
  try {
    await fetch(`${BASE_URL}/api/capture/stop`, { method: "POST" });
    setCaptureUI(false);
  } catch (err) {
    console.error("Failed to stop capture:", err);
  }
});

btnClear.addEventListener("click", () => {
  btnClear.classList.add("pressed");
  setTimeout(() => btnClear.classList.remove("pressed"), 200);

  consoleScroll.innerHTML = "";
  emptyState.style.display = "flex";
  consoleScroll.appendChild(emptyState);

  totalPackets = 0;
  anomalyCount = 0;
  capturedCount.textContent = "0";
  metricAnomalies.textContent = "0";
  anomaliesBadge.style.display = "none";
});

function compileAndApplyFilter(expression) {
  displayFilter = expression;

  compileBanner.style.display = "block";
  setTimeout(() => {
    compileBanner.style.display = "none";
  }, 2500);

  activeFilterText.textContent = expression.trim() ? expression : "none";
  bpfInput.value = expression;

  filterChips.forEach((chip) => {
    const val = chip.getAttribute("data-filter");
    if (val === expression || (val === "all" && !expression)) {
      chip.classList.add("active");
    } else {
      chip.classList.remove("active");
    }
  });
}

btnApplyFilter.addEventListener("click", () => {
  compileAndApplyFilter(bpfInput.value);
});

bpfInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    compileAndApplyFilter(bpfInput.value);
  }
});

filterChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    filterChips.forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");

    const val = chip.getAttribute("data-filter");
    compileAndApplyFilter(val === "all" ? "" : val);
  });
});

loadInitialState();
