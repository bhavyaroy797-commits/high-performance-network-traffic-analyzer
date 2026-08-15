require("dotenv").config();

const path = require("path");
const fs = require("fs");
const readline = require("readline");
const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const mysql = require("mysql2/promise");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || "analyzer",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "network_analyzer",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const ANOMALY_POLL_INTERVAL_MS =
  Number(process.env.ANOMALY_POLL_INTERVAL_MS) || 500;
const STATS_POLL_INTERVAL_MS =
  Number(process.env.STATS_POLL_INTERVAL_MS) || 1000;
const ANOMALY_LOG_FILE = "C:\\hpnta\\anomalies.jsonl";

let lastSeenAnomalyId = 0;
let lastProcessedLineCount = 0;

async function initWatermark() {
  const [rows] = await pool.query(
    "SELECT COALESCE(MAX(id), 0) AS max_id FROM network_anomalies",
  );
  lastSeenAnomalyId = rows[0].max_id;
}

async function pollAnomaliesFromFile() {
  if (!fs.existsSync(ANOMALY_LOG_FILE)) {
    return;
  }

  const fileStream = fs.createReadStream(ANOMALY_LOG_FILE);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  let lineCount = 0;
  for await (const line of rl) {
    lineCount++;

    if (lineCount <= lastProcessedLineCount) {
      continue;
    }

    try {
      const anomaly = JSON.parse(line);

      const [result] = await pool.query(
        `INSERT INTO network_anomalies
        (event_timestamp, source_ip, source_port, dest_ip, dest_port, protocol, packet_length, threat_type, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          anomaly.timestamp,
          anomaly.source_ip,
          anomaly.source_port,
          anomaly.dest_ip,
          anomaly.dest_port,
          anomaly.protocol,
          anomaly.packet_length,
          anomaly.threat_type,
          anomaly.severity || "high",
        ],
      );

      const insertedId = result.insertId;
      lastSeenAnomalyId = insertedId;

      io.emit("anomaly:new", {
        id: insertedId,
        event_timestamp: anomaly.timestamp,
        source_ip: anomaly.source_ip,
        source_port: anomaly.source_port,
        dest_ip: anomaly.dest_ip,
        dest_port: anomaly.dest_port,
        protocol: anomaly.protocol,
        packet_length: anomaly.packet_length,
        threat_type: anomaly.threat_type,
        severity: anomaly.severity || "high",
      });
    } catch (err) {
      console.error("Error processing anomaly line:", err.message);
    }
  }

  lastProcessedLineCount = lineCount;
}

async function pollAnomalies() {
  try {
    await pollAnomaliesFromFile();
  } catch (err) {
    console.error("Anomaly poll failed:", err.message);
  }
}

async function pollStats() {
  try {
    const [rows] = await pool.query(
      "SELECT packets_per_sec, active_tcp_connections, updated_at FROM capture_stats WHERE id = 1",
    );
    if (rows.length === 0) return;
    io.emit("stats:update", rows[0]);
  } catch (err) {
    console.error("Stats poll failed:", err.message);
  }
}

app.get("/api/anomalies/recent", async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 150, 500);
  try {
    const [rows] = await pool.query(
      `SELECT id, event_timestamp, source_ip, source_port, dest_ip, dest_port,
              protocol, packet_length, threat_type, severity
       FROM network_anomalies
       ORDER BY id DESC
       LIMIT ?`,
      [limit],
    );
    res.json(rows.reverse());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/stats/summary", async (req, res) => {
  try {
    const [[anomalyCountRow]] = await pool.query(
      "SELECT COUNT(*) AS anomaly_count FROM network_anomalies",
    );
    const [[statsRow]] = await pool.query(
      "SELECT packets_per_sec, active_tcp_connections FROM capture_stats WHERE id = 1",
    );
    const [[controlRow]] = await pool.query(
      "SELECT is_active FROM capture_control WHERE id = 1",
    );
    res.json({
      anomalyCount: anomalyCountRow.anomaly_count,
      packetsPerSec: statsRow ? statsRow.packets_per_sec : 0,
      activeTcpConnections: statsRow ? statsRow.active_tcp_connections : 0,
      isActive: controlRow ? !!controlRow.is_active : true,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/capture/start", async (req, res) => {
  try {
    await pool.query("UPDATE capture_control SET is_active = 1 WHERE id = 1");
    io.emit("capture:state", { isActive: true });
    res.json({ isActive: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/capture/stop", async (req, res) => {
  try {
    await pool.query("UPDATE capture_control SET is_active = 0 WHERE id = 1");
    io.emit("capture:state", { isActive: false });
    res.json({ isActive: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

const PORT = process.env.SERVER_PORT || 3000;

async function start() {
  try {
    await initWatermark();
    setInterval(pollAnomalies, ANOMALY_POLL_INTERVAL_MS);
    setInterval(pollStats, STATS_POLL_INTERVAL_MS);
    server.listen(PORT, () => {
      console.log(`Network Traffic Analyzer backend running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

start();
