# Cyber Sentinel XDR — Run Commands Reference

## STARTUP ORDER
```
Terminal 1 → MongoDB       (database)
Terminal 2 → Backend       (FastAPI + ML pipeline)
Terminal 3 → Frontend      (React SOC dashboard)
```
> **Suricata and Winlogbeat are launched automatically** when you open
> `http://localhost:8000/start-monitoring` (or click Start Monitoring in the dashboard).
> Run as Administrator so the backend can spawn them with elevated privileges.
> Manual fallback: `start_capture.ps1` at the project root.

---

## 1. SURICATA + WINLOGBEAT — Auto-started by dashboard

Both are launched automatically when you visit `http://localhost:8000/start-monitoring`
(the backend must be running as Administrator for this to work).

**Manual fallback** (run as Administrator from project root):
```powershell
.\start_capture.ps1
```

**Verify Suricata is capturing:**
```powershell
Get-Content "C:\SuricataLogs\eve.json" -Wait -Tail 5
```

**Verify Winlogbeat is writing logs:**
```powershell
ls "C:\XDR_Logs\"
```

> Winlogbeat writes Windows Security + Sysmon events as `.ndjson` files to `C:\XDR_Logs\`.

---

## 2. MONGODB  (Terminal 1 — keep open)

```powershell
& "C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe" `
  --dbpath "D:\Cyber Sentinal\mongodb\data" `
  --port 27017
```

> Replace `8.0` with your installed version if different.  
> Check version: `ls "C:\Program Files\MongoDB\Server\"`

---

## 4. BACKEND — FastAPI + Socket.IO  (Terminal 4)

```powershell
cd "D:\Cyber Sentinal\Backend"
venv\Scripts\activate
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload
```

**Start monitoring after backend is running:**
```
GET http://localhost:8000/start-monitoring
```
Open that URL in your browser once the backend is up.

**Health check:**
```
GET http://localhost:8000/health
```

---

## 5. FRONTEND — React (CRA)  (Terminal 5)

```powershell
cd "D:\Cyber Sentinal\Cyber Sentinal XDR Frontend"
npm start
```

Opens at: **http://localhost:3000**

---

## 5. ATTACK SIMULATION — Zenmap / Nmap

> IMPORTANT: Always target your ROUTER or another device on the network.
> DO NOT target 127.0.0.1 (loopback) or 192.168.1.8 (your own IP from your own machine).
> Both bypass Wi-Fi and Suricata will not see the packets.

### Trigger PORT_SCAN_HORIZONTAL (≥15 unique dst ports from one source)
```
nmap -sS -p 1-1000 --min-rate 500 192.168.1.1
```

### Trigger HOST_SWEEP (≥10 unique dst IPs)
```
nmap -sn 192.168.1.1-50
```

### Aggressive scan (port scan + service detection + scripts)
```
nmap -A --min-rate 300 192.168.1.1
```

### SYN flood simulation (high SYN count, low ACK ratio)
```
nmap -sS --min-rate 1000 -p 80,443,8000 192.168.1.1
```

### Discover all live hosts on subnet first
```
nmap -sn 192.168.1.0/24
```

### Brute-force simulation
```
nmap -sV --script ssh-brute,ftp-brute 192.168.1.1
```

---

## 6. STARTUP ORDER

Run in this exact order to avoid connection errors:

```
1. Suricata       (must be capturing before backend reads eve.json)
2. MongoDB        (optional — backend degrades gracefully without it)
3. Backend        (uvicorn)
4. Browser        → http://localhost:8000/start-monitoring
5. Frontend       (npm start)
6. Browser        → http://localhost:3000
7. Nmap attacks   (target router or other LAN device)
```

---

## 7. MISSING MODEL FILES (one-time setup)

These need to be generated before ML detection works:

```powershell
cd "D:\Cyber Sentinal\Backend"
venv\Scripts\activate

# Step 1 — collect 30 min of your normal traffic (keep doing normal activity)
python collect_baseline.py

# Step 2 — train personal baseline (Gate 1)
python train_personal_model.py

# Step 3 — train CIC IsolationForest (Gate 2 — needs CIC-IDS2017 dataset)
python train_model.py

# Step 4 — train RandomForest attack classifier
python train_classifier.py
```

---

## 8. QUICK DIAGNOSTICS

```powershell
# Is Suricata running?
tasklist | findstr suricata

# Is MongoDB running?
Get-Service MongoDB

# Is port 8000 open?
netstat -an | findstr 8000

# Check Suricata error log
Get-Content "C:\SuricataLogs\suricata.log" -Tail 20

# Count new flow events in eve.json
(Get-Content "C:\SuricataLogs\eve.json" | Select-String '"event_type":"flow"').Count
```
