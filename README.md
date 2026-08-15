# High-Performance Network Traffic Analyzer

A real-time network traffic analyzer built with C++ (Npcap), Node.js, MySQL, and Socket.io. Detects suspicious network activity and displays anomalies on a beautiful neumorphic dashboard.

## 🚀 Live Deployment

**Access the dashboard here:** https://blame-lake-silver.ngrok-free.dev

> Note: The deployment uses ngrok for public tunneling. The URL changes if the service restarts. Keep ngrok running locally for persistent access.

## ✨ Features

- **Real-time anomaly detection** — C++ engine captures packets and flags suspicious activity
- **Live dashboard** — Neumorphic UI with real-time anomaly feed via Socket.io
- **Network metrics** — Packets/sec, active TCP connections, anomaly count
- **Filtering** — BPF filter expressions and quick preset filters (TCP, UDP, ICMP, ports)
- **Start/Stop controls** — Control capture state from the dashboard
- **Cross-platform accessibility** — Access from any browser via ngrok tunnel

## 🏗 Architecture

```
┌─────────────────────┐
│  PacketAnalyzer.exe │  (C++ with Npcap)
│   - Captures packets │
│   - Detects anomalies│
│   - Writes to file   │
└──────────┬───────────┘
           │ anomalies.jsonl
           │
┌──────────▼──────────┐
│   Node.js Backend   │  (Express + Socket.io)
│  - Polls anomalies  │
│  - Stores in MySQL  │
│  - Broadcasts live  │
└──────────┬──────────┘
           │ Socket.io
           │
┌──────────▼──────────┐
│   Web Dashboard     │  (HTML/CSS/JS)
│  - Real-time feed   │
│  - Neumorphic UI    │
│  - Control panel    │
└─────────────────────┘
```

## 📋 Prerequisites

- **Windows 10+** (for C++ engine and Npcap)
- **Visual Studio 2022** (or Build Tools for C++ compilation)
- **MySQL 8.0+** (local or remote)
- **Node.js 16+** and npm
- **Npcap 1.88+** (for network packet capture)
- **Npcap SDK 1.16+** (for compilation)
- **ngrok** (for public access via tunnel)

## 🔧 Installation

### 1. Clone the repository

```bash
git clone https://github.com/bhavyaroy797-commits/high-performance-network-traffic-analyzer.git
cd high-performance-network-traffic-analyzer
```

### 2. Set up MySQL database

```bash
mysql -u root -p < database/schema.sql
```

### 3. Install Node.js dependencies

```bash
npm install
```

### 4. Configure environment variables

Create `.env` in the project root:

```dotenv
DB_HOST=localhost
DB_PORT=3306
DB_USER=analyzer
DB_PASSWORD=AnalyzerPass123!
DB_NAME=network_analyzer

SERVER_PORT=3000

ANOMALY_POLL_INTERVAL_MS=500
STATS_POLL_INTERVAL_MS=1000
```

### 5. Compile C++ engine

In x64 Native Tools Command Prompt:

```bash
cd C:\path\to\project
cl.exe /EHsc /Fe:PacketAnalyzer.exe backend\PacketAnalyzer.cpp /I C:\npcap-sdk-1.16\Include /link /LIBPATH:C:\npcap-sdk-1.16\Lib\x64 wpcap.lib Packet.lib ws2_32.lib
```

## ▶️ Running the Application

### Terminal 1: Start MySQL

```bash
net start MySQL80
```

### Terminal 2: Start Node.js backend

```bash
npm start
```

You should see:

```
Network Traffic Analyzer backend running on port 3000
```

### Terminal 3: Start C++ capture engine

```bash
PacketAnalyzer.exe
```

You should see:

```
Engine active. Listening for traffic... (Press Ctrl+C to stop)
```

### Terminal 4: Expose via ngrok (for public access)

```bash
ngrok http 3000
```

You'll get a public URL like:

```
Forwarding  https://abc123.ngrok-free.dev -> http://localhost:3000
```

### Access the dashboard

- **Locally:** http://localhost:3000
- **Publicly:** https://abc123.ngrok-free.dev (via ngrok)

## 📁 Project Structure

```
high-performance-network-traffic-analyzer/
├── backend/
│   └── PacketAnalyzer.cpp       # C++ Npcap engine
├── database/
│   └── schema.sql               # MySQL schema
├── frontend/
│   ├── index.html              # Dashboard UI
│   ├── app.js                  # Frontend logic (Socket.io)
│   └── style.css               # Neumorphic styling
├── .env                         # Environment variables
├── .gitignore                   # Git ignore rules
├── package.json                 # Node.js dependencies
├── server.js                    # Express backend
└── README.md                    # This file
```

## 🎯 How It Works

1. **Packet Capture** — `PacketAnalyzer.exe` (C++) uses Npcap to capture network packets on your Wi-Fi adapter
2. **Anomaly Detection** — Engine flags TCP traffic to ports 22 (SSH) and 3389 (RDP) as suspicious
3. **File Bridge** — Anomalies written to `anomalies.jsonl` (one JSON object per line)
4. **Backend Polling** — Node.js polls the file every 500ms
5. **Database Storage** — New anomalies inserted into MySQL `network_anomalies` table
6. **Real-time Broadcasting** — Socket.io emits `anomaly:new` events to all connected clients
7. **Dashboard Display** — Frontend renders live anomaly rows with timestamps, IPs, protocols, and packet sizes

## 🌐 Public Deployment Notes

**ngrok (Current Setup)**

- ✅ Free, simple, no configuration needed
- ✅ Your local machine stays as the capture engine
- ❌ URL changes on restart
- ❌ 50+ second cold startup on free tier after 15 min inactivity

**Future Improvements**

- Deploy Node.js backend to Railway/Render while keeping C++ locally
- Use static ngrok URL (requires paid plan)
- Add Docker containerization for easier deployment

## 🛠 Troubleshooting

**PacketAnalyzer.exe crashes immediately**

- Ensure you're running in x64 Native Tools Command Prompt
- Verify Npcap is installed and the Wi-Fi adapter GUID is correct
- Check your network adapter GUID: `Get-NetAdapter | Format-Table Name, InterfaceGuid`

**No anomalies appearing on dashboard**

- Verify all three services are running (MySQL, Node.js, PacketAnalyzer.exe)
- Trigger test traffic: `Test-NetConnection -ComputerName github.com -Port 22`
- Check `C:\hpnta\anomalies.jsonl` exists and has content

**ngrok URL not loading**

- Ensure `npm start` is still running
- Confirm ngrok tunnel is active (check ngrok terminal window)
- Refresh the browser (might need to wait for cold start)

---

**Built with:** C++ • Npcap • Node.js • Express • Socket.io • MySQL • ngrok
