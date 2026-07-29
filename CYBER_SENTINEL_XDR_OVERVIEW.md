# Cyber Sentinel XDR — Complete Project Overview

**Version:** v1.0 XDR Platform  
**Document Date:** 2026-06-03  
**Status:** Production-Ready (~99.8% complete)  
**Architecture:** Windows-based AI-Driven Extended Detection and Response

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [System Architecture — Full Data Flow](#2-system-architecture--full-data-flow)
3. [Detection Layers — The 5 AI Engines](#3-detection-layers--the-5-ai-engines)
4. [Fusion Engine](#4-fusion-engine)
5. [Attack Types Monitored and Mitigated](#5-attack-types-monitored-and-mitigated)
6. [SOAR Response System](#6-soar-response-system)
7. [Endpoint Agent — Standalone Python Package](#7-endpoint-agent--standalone-python-package)
8. [Backend — FastAPI + Socket.IO](#8-backend--fastapi--socketio)
9. [Frontend SOC Dashboard](#9-frontend-soc-dashboard)
10. [SHAP Explainability](#10-shap-explainability)
11. [MongoDB — All 27 Collections](#11-mongodb--all-27-collections)
12. [Technology Stack](#12-technology-stack)
13. [Complete File Directory](#13-complete-file-directory)
14. [Key Metrics and Performance](#14-key-metrics-and-performance)
15. [Security and RBAC Matrix](#15-security-and-rbac-matrix)

---

## 1. Product Overview

### What Is Cyber Sentinel XDR?

Cyber Sentinel XDR is a Windows-based, AI-driven Extended Detection and Response platform built for Security Operations Center (SOC) teams that need automated, explainable threat detection across network, endpoint, user, and file-system attack surfaces. The system ingests telemetry from every monitored Windows endpoint, runs four independent machine learning models in a concurrent fan-out pipeline, fuses their outputs into a single normalized threat score, explains every decision using SHAP feature attribution, and automatically executes SOAR containment actions — all without requiring a human to manually correlate events.

Unlike traditional AV tools that rely on signature databases updated daily, Cyber Sentinel XDR detects novel attacks through behavioral anomaly detection. Unlike conventional SIEMs that produce alert fatigue by logging everything, Cyber Sentinel XDR uses a three-tier detection architecture (deterministic rules, baseline ML, attack classifier) to suppress false positives before they reach the SOC analyst's screen.

### Target Environment

- **Operating System:** Windows 10/11 endpoints, Windows Server 2019+ backend host
- **Deployment:** On-premise SOC or managed security service provider (MSSP) environment
- **Scale:** Supports up to 500 registered endpoints per MongoDB replica (capped collection)
- **Network:** IPv4, HOME_NET = `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`

### Key Differentiators vs Traditional AV/SIEM

| Capability | Traditional AV | SIEM | Cyber Sentinel XDR |
|---|---|---|---|
| Signature-based detection | Yes | Partial | Yes (rule engine) |
| Behavioral anomaly detection | No | No | Yes (4 ML models) |
| Automated response (SOAR) | No | Partial | Yes (9 executable actions) |
| Explainable AI (SHAP) | No | No | Yes (all 4 models) |
| Real-time fusion scoring | No | No | Yes (weighted linear combiner) |
| MITRE ATT&CK mapping | No | Partial | Yes (15+ techniques) |
| Multi-endpoint orchestration | No | Partial | Yes (500-endpoint registry) |
| PDF incident reports | No | Partial | Yes (ReportLab, auto-generated) |
| Enterprise MFA recovery | No | Varies | Yes (TOTP + backup codes + admin approval) |
| Per-operator baseline | No | No | Yes (personal IsolationForest) |

---

## 2. System Architecture — Full Data Flow

### Complete Pipeline Diagram

```
+====================================================================================+
|                          CYBER SENTINEL XDR — DATA FLOW                            |
+====================================================================================+

  WINDOWS ENDPOINTS (Multiple Hosts)
  +---------------------------------+
  | Sysmon  TShark  psutil          |
  | Suricata   Winlogbeat           |
  +---------------------------------+
              |
              | POST /endpoint/ingest  (every 5 seconds, per host)
              v
  +==========================+
  | FastAPI Backend          |   (uvicorn, port 8000)
  | + Socket.IO Server       |
  +==========================+
              |
    +---------+---------+
    |                   |
    v                   v
  MongoDB             _score_endpoint_telemetry_with_ai()
  endpoint_logs       [asyncio.gather — 4 concurrent agents]
  endpoint_registry
                         |           |            |            |
                         v           v            v            v
                    Network      System       Malware       User
                    Detection    Monitor      Analysis      Behavior
                    Agent        Agent        Agent         Agent
                    (IF+RF)      (LSTM)       (LightGBM)    (OC-SVM)
                    network_score  system_score  malware_score  user_score
                         |           |            |            |
                         +-----+-----+-----+------+
                               |
                               v
                    FusionEngineAgent.fuse()
                    Score = 0.35*net + 0.30*usr + 0.15*sys + 0.20*mal
                    Severity: HIGH >= 0.70, CRITICAL >= 0.85
                               |
                  +------------+------------+
                  |                         |
                  v                         v
          fusion_alert               _emit_soc_alert_if_correlated()
          Socket.IO event                   |
                  |                         v
                  |              response_engine.generate_response_plan()
                  |              MITRE ATT&CK-mapped plan written to MongoDB
                  |                         |
                  |                         v
                  |              POST /response/execute
                  |              endpoint_commands written to MongoDB
                  |                         |
                  v                         v
  +==============================+   Endpoint Agent polls /endpoint/commands
  | REACT SOC DASHBOARD          |   executes: isolate_host / block_ip /
  | (Socket.IO subscriber)       |   kill_process / quarantine_file / etc.
  | AlertsTable                  |
  | NetworkMap (D3 force graph)  |   ACK result -> command_result Socket.IO
  | EndpointView (SOAR panel)    |         |
  | ResponseModal (SHAP chart)   |         v
  | AttackGraph (TTL decay)      |   PDF Incident Report (ReportLab)
  | AttackReconstructionView     |   saved to reports/{incident_id}.pdf
  +==============================+

  SERVER-SIDE PIPELINE (runs concurrently on the backend host):
  Suricata eve.json -> NetworkDetectionAgent.detect()  [rule + ML]
  psutil local loop  -> SystemMonitorAgent             [1 Hz]
  Winlogbeat ndjson  -> UserBehaviorAgent              [300 s tick]
  File watcher       -> MalwareAnalysisAgent           [background]
  Get-WinEvent PS    -> SysmonBehaviorAgent            [event-driven]
  All feeds -> FusionEngineAgent.fuse() -> same fusion_alert pipeline
```

### Stage Descriptions

**Stage 1 — Telemetry Collection:** Endpoint agents (Python asyncio) collect network connections, CPU/memory metrics, active user sessions, and process lists every 5 seconds via psutil. Suricata captures network packets server-side and writes `eve.json`. Winlogbeat ships Windows Security Event Logs as ndjson to `C:\XDR_Logs\`. Sysmon logs process creation, network connections, file creation, and registry changes.

**Stage 2 — AI Scoring Fan-out:** `_score_endpoint_telemetry_with_ai()` dispatches all four detection agents concurrently using `asyncio.gather()`. Each agent returns a normalized score in [0.0, 1.0]. Any agent that raises an exception has its score floored to 0.0 silently, ensuring the pipeline never halts on a single model failure.

**Stage 3 — Fusion and Correlation:** `FusionEngineAgent.fuse()` applies the weighted linear formula to produce the final threat score. `fusion_engine.py` maintains a 300-second sliding event buffer and runs a stateless correlation rule set to detect multi-domain attack chains (e.g., network anomaly + malicious PE on the same host = Ransomware Activity).

**Stage 4 — Response Orchestration:** When severity reaches HIGH or CRITICAL, `_emit_soc_alert_if_correlated()` auto-generates a MITRE ATT&CK-mapped response plan, writes SOAR commands to `endpoint_commands` in MongoDB, and emits `response_required` over Socket.IO. The endpoint agent polls for commands every 3 seconds and executes them with full OS-level enforcement.

**Stage 5 — Visualization and Reporting:** The React SOC dashboard subscribes to 19 Socket.IO events and renders real-time network maps, alert streams, SHAP explanations, attack graphs with TTL-decayed nodes, and SOAR action status. On completion, a ReportLab PDF incident report is auto-generated and made available for download.

---

## 3. Detection Layers — The 5 AI Engines

### 3.1 Network Detection Agent

**File:** `Backend/agents/network_detection_agent.py`  
**Orchestrates:** `Backend/rule_detector.py` + `Backend/hybrid_detector.py`

#### Stage 1 — Rule Detector (Deterministic, evaluated first)

The rule detector provides zero-latency, zero-false-negative detection for well-defined attack signatures. A `RuleHit` dataclass is returned on match; confirmed hits skip ML entirely.

| Rule | Threshold | Detection Logic |
|---|---|---|
| `PORT_SCAN_HORIZONTAL` | >= 15 unique dst ports from one source | Horizontal port enumeration / reconnaissance |
| `HOST_SWEEP` | >= 10 unique dst IPs from one source | Network range discovery / host enumeration |
| `SYN_FLOOD` | >= 500 SYN packets, < 10% ACK ratio | TCP SYN flood / denial of service |
| `DATA_EXFILTRATION` | Large outbound byte threshold exceeded | Sensitive data being transferred outbound |
| `BRUTE_FORCE` | Failed authentication threshold exceeded | Repeated login attempts against a service |

The rule detector reads Suricata `eve.json` incrementally using a file-offset tracker, preventing re-processing of already-analyzed flows across restarts.

#### Stage 2 — Hybrid ML Detector (2-Gate Pipeline)

Flows that are not caught by the rule engine pass through a two-gate ML pipeline:

**Gate 1 — Personal Baseline IsolationForest** (`personal_baseline_model.pkl`):
- Trained on the specific operator's own normal traffic via `collect_baseline.py`
- IsolationForest anomaly scoring: flows that deviate from the operator's personal baseline pass to Gate 2
- Purpose: reduces false positives from legitimate traffic patterns unique to this environment
- Training time: 30–60 minutes of baseline capture

**Gate 2 — CIC-IDS2017 RandomForest Classifier** (`network_classifier.pkl`):
- Trained on the full CIC-IDS2017 benchmark dataset (99.6% accuracy)
- 63 CIC-IDS2017 flow features: packet lengths, inter-arrival times, flag counts, bytes/s, packets/s, flow duration, forward/backward packet statistics (49 computed from Suricata aggregates, 14 zeroed)
- Multi-class attack classifier: BENIGN, Botnet, BruteForce, DDoS, DoS, Heartbleed, Infiltration, PortScan
- Output: attack type label + confidence score normalized to [0.0, 1.0]

**Endpoint network scoring** (`detect_from_endpoint_network()`): Converts psutil `net_connections` and I/O counters into synthetic flow dicts and runs the same Gate 1 + Gate 2 pipeline, unifying server-side Suricata analysis with endpoint-agent telemetry through a single inference path.

### 3.2 User Behavior Agent

**File:** `Backend/agents/user_behavior_agent.py`  
**Inference engine:** `User Behavior/final_model_backend_only/xdr_runtime.py`

The User Behavior Agent detects insider threats and compromised accounts by modeling normal Windows authentication and session behavior using a One-Class SVM trained on the CERT Insider Threat Dataset r4.2.

**Model:** One-Class SVM (`user_model.pkl`) with StandardScaler (`user_scaler.pkl`)  
**Dataset:** CERT Insider Threat Dataset r4.2 — labeled insider threat scenarios  
**Anomaly threshold:** 0.80 (tuned to eliminate false positives on normal high-activity environments)  
**Tick rate:** 300-second evaluation window

**12 Active Feature Columns** (from `feature_columns.json`):
Features derived from Windows Security Event Logs (EventID 4624 logon, 4625 failed logon, 4648 explicit credentials, 4688 process creation) shipped via Winlogbeat ndjson:
- Logon count, failed logon count, unique source IPs, remote session count
- Off-hours activity indicator (before 06:00 / after 22:00)
- Concurrent session count, system account usage flag
- Process creation rate (4688 events), file access anomaly flags
- OCEAN personality features (currently 0.0 — requires HR integration)

**Detection Capabilities:**
- Off-hours access: activity occurring outside normal business hours
- Concurrent sessions: multiple simultaneous logins suggesting credential sharing or hijack
- Remote IP anomalies: sessions originating from unrecognized external IPs
- System account misuse: interactive logins using machine accounts
- Impossible travel: geographically inconsistent login locations (when IP geolocation is wired)
- Insider data staging: elevated file access combined with anomalous process patterns

**Endpoint session scoring** (`score_session_telemetry()`): Lightweight heuristic scoring of psutil session data from the endpoint agent (concurrent sessions, unusual hours, remote IPs, system accounts) when full Winlogbeat data is unavailable.

**CRITICAL ≥ 0.85 / HIGH ≥ 0.70** — anomalous users display with orange/red badge in the User Behavior view; normal users display with a green "NORMAL" badge.

### 3.3 System Monitor Agent

**File:** `Backend/agents/system_monitor_agent.py`  
**Model file:** `Backend/system_model.pt`

The System Monitor Agent uses a PyTorch LSTM Autoencoder trained on live endpoint telemetry to detect abnormal system resource consumption patterns, including ransomware encryption storms and process injection behavior.

**Model Architecture:** LSTM Autoencoder (encoder → latent → decoder)  
**Training data:** Live psutil telemetry collected via `train_system_model.py`  
**Evaluation window:** 60-second rolling sequence of 20-feature vectors  
**Inference rate:** 1 Hz (local psutil loop on backend host)

**20 Feature Vector** (from `FEATURE_NAMES`):
CPU%, memory%, disk%, process count, network bytes sent/received, network packets sent/received, CPU per-core breakdown, memory available, swap usage, top-10 process CPU contributions

**Resource-Aware Severity Gating** (`_resource_aware_severity()`):
The ML model output is post-processed by a resource-aware gate to prevent normal high-memory workloads from triggering CRITICAL alerts:

```
CRITICAL requires:  CPU > 85%  OR  Memory > 95%  OR  (CPU > 80% AND Memory > 80%)
HIGH requires:      CPU > 70%  OR  Memory > 85%
Normal high memory: caps ML severity at MEDIUM regardless of autoencoder output
```

**`is_genuinely_anomalous` flag:** Boolean field added to every result dict. Only events where this flag is True contribute to the Fusion CorrelationEngine, preventing benign memory usage from triggering SOAR actions.

**Detects:**
- Ransomware encryption behavior: combined CPU + memory spike pattern
- Cryptomining: sustained high CPU with periodic network bursts
- Process injection side effects: memory fragmentation + CPU anomalies
- Resource exhaustion DoS: rapid escalation of all resource metrics

**Rate limiting:** At most one CRITICAL socket event per 30 seconds to prevent dashboard flooding.

### 3.4 Malware Analysis Agent

**File:** `Backend/agents/malware_analysis_agent.py`  
**Model file:** `Backend/malware_model.pkl`

The Malware Analysis Agent performs static PE binary analysis using a LightGBM classifier trained on the EMBER 2018 dataset, achieving near-production-grade detection accuracy.

**Model:** LightGBM binary classifier  
**Dataset:** EMBER 2018 (Endgame Malware BEnchmark for Research)  
**Feature vector:** 280-dimensional (PE header fields, section characteristics, imports, exports, strings statistics)  
**Feature extraction:** `pefile` library for PE structure parsing

**Trained Performance Metrics:**
- AUC-ROC: **0.9803**
- F1 Score: **0.9298**
- Accuracy: **0.9284**

**3-Tier Label System:**
```
benign     — score < 0.30  (safe, no action)
suspicious — score 0.30–0.70  (monitor, alert analyst)
malicious  — score > 0.70  (CRITICAL alert, auto-SOAR)
```

**Trusted Path Whitelist (false positive suppression):**
Files from the following paths have their score capped at 0.40:
- `site-packages` (Python dependencies)
- `C:\Windows\System32` (OS binaries)
- `C:\Program Files` (signed vendor software)

Signed binary heuristic: files with `has_signature=1` AND score < 0.85 are capped at 0.50.

**New output fields:** `source`, `label`, `confidence`, `trusted`, `trust_reason`

**Background file watcher:** `_malware_scan_loop()` continuously monitors configured directories for new PE files. Newly created `.exe`, `.dll`, `.sys` files trigger automatic scanning within seconds.

**Process metadata scoring** (`assess_process_metadata()`): When full PE files are unavailable (endpoint agent telemetry), the agent scores process names against 22 known-malicious IOC substrings and 5 temp-path tokens (e.g., `mimikatz`, `meterpreter`, `cobalt`, `beacon`, processes launched from `%TEMP%`).

**Ransomware correlation gate:** Malware events only feed the Fusion CorrelationEngine when `label == "malicious" AND trusted == False`. This prevents signed vendor software from triggering ransomware correlation rules.

**CRITICAL malware path:** `_maybe_emit_malware_fusion_alert()` is called at all three malware detection sites (predict, scan, watcher), emitting a `network_anomaly` (populates Alert Stream), a `fusion_alert` (correct `attack_type = "Malware Activity"`), and triggering an auto-generated response plan. A 60-second per-file cooldown prevents duplicate alerts.

### 3.5 Sysmon Behavior Agent

**File:** `Backend/agents/sysmon_behavior_agent.py`  
**Supporting files:** `Backend/sysmon_feature_extractor.py`, `Backend/sysmon_winevent_reader.py`

The Sysmon Behavior Agent provides Windows kernel-level behavioral telemetry by parsing Sysmon event logs, detecting suspicious process chains, network connections from unexpected processes, and registry-based persistence mechanisms.

**Data source (dual, mutually exclusive):**
1. **Primary:** `_sysmon_ps_loop()` — PowerShell `Get-WinEvent` forwarder started by `/start-monitoring`. Feeds `SysmonBehaviorAgent._handle_event()` directly without requiring Winlogbeat. Active when `_sysmon_winlogbeat_active = False`.
2. **Secondary:** `SysmonFileReader` tailing `C:\winlogbeat\logs\sysmon_events.json` (Winlogbeat NDJSON). Sets `_sysmon_winlogbeat_active = True` when running, suppressing the PS forwarder to prevent duplicate events.

**Key EventIDs monitored:**
| EventID | Event | Detection Use |
|---|---|---|
| 1 | Process Create | Suspicious process spawning, LOLBins, malware launchers |
| 3 | Network Connect | Unexpected outbound connections from processes |
| 11 | File Create | Malware dropper artifacts, ransomware encrypted file creation |
| 13 | Registry Set Value | Persistence via HKCU\Run, services, WMI subscriptions |
| 8 | Create Remote Thread | Process injection detection |
| 10 | Process Access | Credential dumping (LSASS access) |

**SHAP indicator analysis:** `_maybe_explain_sysmon()` applies feature-importance analysis to Sysmon events, identifying which behavioral indicators (process name, parent process, command line, file path, registry key) most contributed to the anomaly score. Present as `shap_explanation` on every `sysmon_alert` event.

**Rate limiting:** `_SYSMON_EMIT_COOLDOWN = 5.0s` — at most one alert per 5 seconds to prevent burst flooding during attack campaigns. Module-level `_last_sysmon_emit_time` guard in `_handle_sysmon_result`.

**Feature extractor:** `sysmon_feature_extractor.py` handles both flat and nested Sysmon event formats, normalizing fields regardless of whether they arrive from the PS forwarder or Winlogbeat NDJSON.

---

## 4. Fusion Engine

### Core Formula

```
Threat Score = (0.35 × network_score)
             + (0.30 × user_score)
             + (0.15 × system_score)
             + (0.20 × malware_score)

Range: [0.0, 1.0]
```

**Weight rationale:**
- Network (0.35): Highest weight — network attacks are the most common initial access vector
- User (0.30): Second highest — insider threats and credential abuse are highest-impact
- Malware (0.20): Elevated from initial 0.10 to reflect EMBER model confidence (AUC 0.98)
- System (0.15): Lowest — resource anomalies generate the most false positives; ML score validated by `_resource_aware_severity` before contributing

### Severity Thresholds

```
CRITICAL  >=  0.85   (auto-execute SOAR actions + auto-generate PDF)
HIGH      >=  0.70   (generate response plan, surface "Respond" button)
MEDIUM    <   0.70   (log to MongoDB, display in dashboard, no auto-SOAR)
LOW       <   0.50   (log only, minimal dashboard visibility)
```

Threshold enforcement is layered: the `FusionEngineAgent` applies thresholds, `_compute_final_decision` in `fusion_engine.py` adds a downward severity cap, and `_emit_soc_alert_if_correlated` suppresses HIGH events below 0.70 and downgrades CRITICAL to HIGH when the score is in the 0.70–0.84 range.

### Event Correlation Engine (`fusion_engine.py`)

The `fusion_engine.py` module runs a stateless correlation rule set over a 300-second sliding event buffer. It is an additional layer on top of `FusionEngineAgent` — the agent handles per-event numeric scoring; the correlation engine handles multi-domain attack chain detection.

**Architecture:**
- `EventBuffer` — Thread-safe ring buffer, 300-second retention window
- `CorrelationEngine` — Stateless rule set, 120-second correlation look-behind
- `FusionDecisionEngine` — Orchestrates buffer + correlation → final decision dict

**Attack chain detection requires >= 2 source domains.** Single-source system anomalies alone cannot trigger a "Correlated Attack."

**Ransomware Correlation Gate** (`_detect_ransomware()`):
```
Condition: malware event WHERE (label == "malicious" AND trusted == False)
           PLUS system event WHERE (severity IN {HIGH, CRITICAL})
           WITHIN 120-second window on the same host
Result:    attack_type = "Ransomware Activity"
           Triggers: isolate_host + kill_process + scan_filesystem + monitor_persistence
```

### Fusion Alert Emission

`_emit_soc_alert_if_correlated()` runs on every HIGH/CRITICAL fusion result:
1. Generates a MITRE ATT&CK-mapped response plan via `generate_response_plan()`
2. Persists the plan to `response_plans` MongoDB collection
3. Emits `response_required` Socket.IO event to all connected dashboard clients
4. If `auto_response_enabled = True` AND severity is CRITICAL (and attack type is not in `_NO_AUTO_EXECUTE_ATTACKS`): queues SOAR commands to `endpoint_commands`, auto-generates PDF incident report, emits `auto_response_completed`
5. Dual-writes HIGH/CRITICAL events to `critical_alerts` (permanent uncapped collection for forensic evidence)

**No-auto-execute attacks** (require human review regardless of severity):
`port scan`, `portscan`, `lateral movement`, `privilege escalation`, `insider threat`, `impossible travel`

---

## 5. Attack Types Monitored and Mitigated

| Attack | Detection Layer | MITRE Technique | Automated SOAR Response |
|---|---|---|---|
| Port Scan | Rule: >= 15 unique dst ports from one src | T1046 — Network Service Discovery | block_ip (source), monitor_persistence |
| Host Sweep | Rule: >= 10 unique dst IPs from one src | T1018 — Remote System Discovery | block_ip (source) |
| SYN Flood / DDoS | Rule: >= 500 SYN, < 10% ACK | T1498 — Network Denial of Service | block_ip, scan_filesystem |
| Brute Force | Rule: failed auth threshold | T1110 — Brute Force | block_ip, lock_account |
| Data Exfiltration | Rule: large outbound bytes | T1041 — Exfiltration Over C2 Channel | isolate_host, block_ip |
| C2 Beaconing | ML RandomForest (Botnet class) | T1071 — Application Layer Protocol | block_ip (C2 IP), kill_process, monitor_persistence |
| DoS (Slowloris, etc.) | ML RandomForest (DoS class) | T1498 — Network Denial of Service | block_ip, scan_filesystem |
| Botnet | ML RandomForest (Botnet class) | T1071 — Application Layer Protocol | block_ip, kill_process, monitor_persistence |
| Heartbleed | ML RandomForest (Heartbleed class) | T1499 — Endpoint Denial of Service | block_ip, patch_openssl (advisory), rotate_certificates (advisory) |
| Infiltration | ML RandomForest (Infiltration class) | T1190 — Exploit Public-Facing App | isolate_host, scan_filesystem |
| Ransomware Activity | Fusion: Malware(malicious+untrusted) + System(HIGH/CRITICAL) | T1486 — Data Encrypted for Impact | kill_process, isolate_host, scan_filesystem, monitor_persistence |
| Insider Threat | User Behavior OC-SVM (CERT r4.2) | T1078.004 — Valid Accounts: Cloud Accounts | lock_account, monitor_persistence |
| Privilege Escalation | Sysmon EventID analysis | T1068 — Exploitation for Privilege Escalation | kill_process, lock_account, monitor_persistence |
| Lateral Movement | Network + Sysmon correlation | T1021 — Remote Services | isolate_host, block_ip (SMB/RDP source) |
| Malicious PE File | EMBER LightGBM (malware_score > 0.70) | T1204 — User Execution: Malicious File | quarantine_file, kill_process, scan_filesystem, block_ip |
| Trojan / Malware | EMBER LightGBM (non-ransomware path) | T1204 — User Execution | quarantine_file, kill_process, scan_filesystem |
| Process Injection | Sysmon EventID 8 (CreateRemoteThread) | T1055 — Process Injection | kill_process, scan_filesystem, monitor_persistence; + isolate_host if CRITICAL |
| Worm | Network + Sysmon multi-domain | T1210 — Exploitation of Remote Services | isolate_host, block_ip, kill_process, scan_filesystem |
| Rootkit | Sysmon EventID analysis | T1014 — Rootkit | scan_filesystem, monitor_persistence, lock_account, isolate_host |
| Persistence | Sysmon EventID 13 (RegistrySet) | T1547 — Boot/Logon Autostart | monitor_persistence, scan_filesystem |
| Impossible Travel | User Behavior Agent | T1078 — Valid Accounts | lock_account, force_logout (advisory) |
| Advanced Persistent Threat | Default fusion correlation | T1059 — Command and Scripting Interpreter | scan_filesystem, monitor_persistence |

---

## 6. SOAR Response System

Cyber Sentinel XDR implements a production-grade SOAR (Security Orchestration, Automation, and Response) system with 9 executable OS-level actions and 13 advisory actions. All actions use `shell=False` subprocess calls with strict input validation, preventing command injection.

### 9 Executable Actions

#### 1. `isolate_host`
- **Implementation:** `netsh interface set interface <iface> disable`
- **Interface detection:** Reads from `endpoint_config.json` (set at startup by `detect_network_interface()`). Priority: Wi-Fi > Wireless > Ethernet > first UP interface. Never hard-coded.
- **Flag file:** `isolation_flag.txt` written BEFORE the netsh call, ensuring the backend always knows isolation was attempted even if NIC disable fails.
- **Verification:** `_verify_host_isolated()` confirms flag file contains "ISOLATED" sentinel.
- **Visual feedback:** Dashboard endpoint card shows pulsing red glow + striped "NETWORK DISABLED" bar.

#### 2. `unisolate_host`
- **Implementation:** `netsh interface set interface <iface> enable`
- **Flag cleanup:** `isolation_flag.txt` removed on success.
- **Dashboard:** Updates endpoint registry `$set: {status: "online"}`, emits `endpoint_update` immediately.

#### 3. `block_ip`
- **Implementation:** `netsh advfirewall firewall add rule name=XDR_BLOCK_<ip> dir=in/out action=block remoteip=<ip>`
- **Both directions:** Creates separate inbound AND outbound rules for complete traffic blocking.
- **IP validation:** Strict IPv4 regex `^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}...` — no shell injection possible.
- **Rollback:** If either direction fails, both rules are removed before reporting failure to avoid asymmetric block state.
- **PowerShell fallback:** If `netsh` fails, tries `New-NetFirewallRule` via PowerShell.
- **Verification:** `_verify_ip_blocked()` queries netsh for the named rule after creation.
- **Rule naming:** `XDR_BLOCK_<ip>` convention for easy identification and cleanup.

#### 4. `unblock_ip`
- **Implementation:** `netsh advfirewall firewall delete rule name=XDR_BLOCK_<ip>`
- **Dashboard:** `$pull` removes IP from `blocked_ips` array in endpoint registry.

#### 5. `kill_process`
- **By PID:** `psutil.Process(int(pid)).terminate()` — PID always cast to `int()`, never string-interpolated.
- **By name:** Iterates `psutil.process_iter()` case-insensitively; falls back to `taskkill.exe /F /IM <name>` if psutil access is denied.
- **Full path:** `C:\Windows\System32\taskkill.exe` — avoids PATH manipulation attacks.
- **Input validation:** Maximum 260 characters (Windows MAX_PATH cap).

#### 6. `quarantine_file`
- **Implementation:** `shutil.move(src, quarantine_dir / basename)`
- **Security:** Null-byte check, absolute path requirement, source existence check before move.
- **Quarantine directory:** `endpoint_agent/quarantine/` (standalone agent) or `Backend/quarantine/` (server).
- **Verification:** `_verify_file_quarantined()` confirms file present in quarantine dir.
- **Restore action:** `restore_quarantine_file` reverses the operation; recreates parent directories.

#### 7. `lock_account`
- **Implementation:** `net user <username> /active:no`
- **Username validation:** Strict allowlist regex `^[\w\-\. ]{1,20}$` — prevents command injection.
- **Full path:** `C:\Windows\System32\net.exe`.
- **Verification:** `_verify_account_locked()` runs `net user <username>` and checks "Account active ... No" in output.
- **Windows only:** Returns graceful error on non-Windows platforms.

#### 8. `scan_filesystem`
- **Implementation:** `os.walk` over 4 fixed WATCH_PATHS: `C:\Users`, `C:\Temp`, `C:\Windows\Temp`, `C:\ProgramData`
- **Filter:** Files with extensions `{.exe, .dll, .ps1, .bat, .vbs, .scr}` modified within the last 3600 seconds.
- **Noise reduction:** Skips `AppData`, `node_modules`, `.git`, `venv`, `__pycache__` subdirectories.
- **Returns:** Count of suspicious files + top-10 by modification time.

#### 9. `monitor_persistence`
- **HKCU Run keys:** `winreg.OpenKey(HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run")` — all values enumerated. Falls back gracefully if HKLM requires elevation.
- **Startup folder:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` — file listing, excludes `desktop.ini`.
- **Scheduled tasks:** `schtasks /query /fo CSV` — total count returned.
- **Returns:** Structured JSON dict with all three findings.

### 13 Advisory Actions

These actions are logged to `response_advisory_logs` in MongoDB and acknowledged as `success=True` without OS-level changes. They represent recommendations for human analysts:

`alert_admin`, `update_software`, `patch_openssl`, `rotate_certificates`, `check_exposed_secrets`, `force_logout`, `review_account`, `review_logs`, `invalidate_sessions`, `log_event`, `log_user_session`, `restrict_access`, `rate_limit_traffic`

### Auto-Response Flow

When `auto_response_enabled = True` (configurable via Settings page) and fusion severity reaches CRITICAL for a non-excluded attack type:

```
1. SOAR commands queued to endpoint_commands (MongoDB)
2. PDF incident report auto-generated in threadpool (ReportLab)
3. PDF metadata inserted to incident_reports collection
4. auto_response_completed Socket.IO event emitted (plan_id, endpoint_id, attack_type,
   severity, actions_taken, report metadata)
5. Dashboard shows toast notification
6. PDF auto-download triggered in browser if report.incident_id present
```

### Response Plan Lifecycle

```
open  ->  executing  ->  contained   (all commands ACK'd success)
                    ->  partial      (mixed success/failure)
```

`response_plan_executed` and `response_plan_contained` audit events are written to `audit_logs` with plan_id, endpoint_id, actions_queued, user_id, and source IP.

### PDF Incident Reports

`report_generator.py` generates a 5-section ReportLab PDF:

1. **Header** — Severity-colored banner, incident ID, generation timestamp, analyst certification block
2. **Incident Summary** — Endpoint, attack type, threat score, MITRE technique, domain
3. **Attack Timeline** — Up to 100 events from 4 MongoDB sources (endpoint_logs, fused_alerts, alerts, predictions)
4. **SHAP Explanation Table** — Visual bar chart (red/green bars), feature importance list
5. **Response Actions** — `[OK]`/`[ADV]`/`[FAIL]`/`[...]` status per action; result message from endpoint ACK; advisory vs. executable legend

PDF MITRE ATT&CK section includes: technique ID (in severity accent color), tactic badge, description paragraph.  
PDF Analyst Certification block: two-column layout, "CERTIFIED" stamp colored by severity, "CONFIDENTIAL — SOC USE ONLY" footer.  
Saved to: `D:\Cyber Sentinal\reports\{incident_id}.pdf`

---

## 7. Endpoint Agent — Standalone Python Package

**Directory:** `endpoint_agent/`  
**Entry point:** `endpoint_agent/agent.py`

The endpoint agent is a self-contained Python package that runs on each monitored Windows host. It requires only `httpx>=0.27.0` and `psutil>=5.9.0`, making it lightweight and deployable without a full Python data science stack.

### Architecture

```python
asyncio.gather([
    _telemetry_loop(interval=5s),   # collect -> POST /endpoint/ingest
    _command_loop(interval=3s),     # GET /endpoint/commands -> execute -> ACK
])
```

**Configuration (environment variables or CLI):**
```
XDR_BACKEND_URL          Backend URL (default: http://localhost:8000)
XDR_API_KEY              API key for authentication
XDR_COLLECT_INTERVAL     Telemetry send interval in seconds (default: 5)
XDR_COMMAND_INTERVAL     Command poll interval in seconds (default: 3)
--simulate               Dry-run mode: logs all actions, never touches OS
```

**Startup banner:** Redacts API key (shows only last 4 characters). Admin elevation check at startup — CRITICAL log warning if not running as Administrator.

### Endpoint Identity (`identity.py`)

On first run, generates a UUID `endpoint_id` and persists it to `endpoint_config.json`. Subsequent runs load the cached identity without regenerating the UUID, ensuring stable endpoint tracking across restarts.

Identity payload:
```json
{
  "endpoint_id": "<uuid4>",
  "hostname": "<hostname>",
  "ip_address": "<primary NIC IP>",
  "os": "Windows",
  "os_version": "<build string>",
  "username": "<current user>",
  "agent_version": "1.0.0",
  "network_interface": "<detected NIC name>"
}
```

**NIC detection** (`detect_network_interface()`): psutil priority order: Wi-Fi > Wireless > Ethernet > first UP interface. Saved to `endpoint_config.json` so `isolate_host` always targets the correct adapter.

### Resilient Sender (`sender.py`)

`httpx.AsyncClient` with 10-second timeout. 3-attempt exponential backoff: 1s → 2s → 4s delays. Never raises to the caller loop — failures are logged at WARNING level and the loop continues.

### 4 Telemetry Collectors

| Collector | File | Data Collected | Notes |
|---|---|---|---|
| Network | `collectors/network_collector.py` | psutil net_connections (max 50), net_io_counters, suspicious port flags | 22-port IOC set: 4444, 1337, 31337 (common RAT/C2 ports) |
| System | `collectors/system_collector.py` | CPU%, memory%, disk%, process count, top-10 processes by CPU | All major metrics |
| User | `collectors/user_collector.py` | Current user, psutil.users() sessions, remote session detection | Session anomaly heuristics |
| Malware | `collectors/malware_collector.py` | Heuristic: suspicious process name matching, temp-dir launch detection | Server-side ML handles final scoring |

### Diagnostic Tool

`endpoint_agent/check_payload.py` validates all 37 fields of the `EndpointTelemetry` Pydantic model against the canonical specification, performs a live POST to the backend, and prints PASS/FAIL/WARN per field. Used to diagnose 422 validation errors before deployment.

---

## 8. Backend — FastAPI + Socket.IO

**Entry point:** `Backend/backend.py`  
**Framework:** FastAPI 0.100+ with python-socketio ASGI mounting  
**Start command:**
```powershell
cd "D:\Cyber Sentinal\Backend"
venv\Scripts\activate
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload
```

### REST API Endpoints (Complete)

#### Authentication (10 endpoints)
| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /auth/register` | None | Register new user; first user becomes admin |
| `POST /auth/login` | None | Email + password login; returns access + refresh tokens |
| `POST /auth/verify-2fa-login` | None | Complete MFA-required login with TOTP code |
| `POST /auth/refresh` | Refresh token | Silent access token renewal |
| `POST /auth/logout` | JWT | Invalidate current session |
| `POST /auth/logout-all` | JWT | Invalidate all sessions for this user |
| `GET /auth/me` | JWT | Current user profile |
| `POST /auth/enable-2fa` | JWT | Generate TOTP QR code for MFA setup |
| `POST /auth/verify-2fa` | JWT | Confirm TOTP enrollment |
| `POST /auth/disable-2fa` | JWT | Disable MFA (requires current TOTP) |

#### Enterprise Recovery (7 endpoints)
| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /auth/forgot-password` | None (rate-limited 3/IP/15min) | Generate bcrypt-hashed reset token (10-min TTL) |
| `POST /auth/reset-password` | Reset token + TOTP | Reset password; requires MFA even during recovery |
| `POST /auth/recovery/request-mfa` | None (rate-limited 1/email/24h) | Request admin-approved MFA device reset |
| `GET /auth/recovery/pending` | JWT admin | View pending MFA recovery queue |
| `POST /auth/recovery/approve/{request_id}` | JWT admin | Approve/deny MFA recovery request |
| `GET /auth/backup-codes/status` | JWT | Count remaining backup codes (without revealing them) |
| `POST /audit/client-event` | JWT | Accept frontend-originated audit events |

#### Detection and Inference
| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /ingest` | API key | Legacy single-host telemetry ingestion |
| `POST /predict/network` | API key or JWT | Network model inference (IsolationForest + RandomForest) |
| `POST /predict/user` | API key or JWT | User behavior model inference (OC-SVM) |
| `POST /predict/malware` | API key or JWT | Malware model inference (LightGBM EMBER) |
| `POST /scan/malware` | API key or JWT | On-demand PE file scan with path allowlist |
| `POST /fusion` | API key | Combine model scores into threat score |
| `GET /shap` | API key | SHAP explanation for latest prediction |
| `POST /response` | API key | Legacy SOAR-lite trigger |

#### Endpoint Management (6 endpoints)
| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /endpoint/ingest` | API key | Multi-endpoint telemetry; rate-limited 1/2s per endpoint_id; upserts registry |
| `GET /endpoint/commands/{endpoint_id}` | API key | Fetch + atomically mark-sent pending SOAR commands |
| `POST /endpoint/command/ack` | API key | ACK command execution result; emits `command_result` |
| `POST /endpoint/command` | API key or JWT (admin/analyst) | Issue SOAR command; validates action + endpoint |
| `GET /endpoint/list` | API key or JWT | All endpoints with online/offline status (>30s = offline) |
| `GET /endpoint/{endpoint_id}` | API key or JWT | Registry doc + last 20 logs + last 10 commands |

#### Response and EDR (6 endpoints)
| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /response/plan` | API key or JWT | Generate MITRE ATT&CK-mapped response plan |
| `POST /response/execute` | API key or JWT (admin/analyst) | Queue SOAR commands; split executable vs advisory |
| `GET /response/plans` | API key or JWT | List last N response plans, newest-first, with status |
| `POST /reports/generate` | API key or JWT (admin) | Generate ReportLab PDF; save to reports/ |
| `GET /reports/{incident_id}/download` | API key or JWT | Serve PDF via FileResponse |
| `GET /reports` | API key or JWT | List incident report metadata |

#### Settings, Users, Case Notes (8 endpoints)
| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /settings` | JWT admin | Read current threshold/config settings |
| `POST /settings/thresholds` | JWT admin | Update fusion/detection thresholds (persisted to MongoDB) |
| `GET /users` | JWT admin | List all users for user management table |
| `DELETE /users/{user_id}` | JWT admin | Delete user account |
| `POST /users/{user_id}/role` | JWT admin | Change user role (admin/analyst/viewer) |
| `POST /users/{user_id}/force-logout` | JWT admin | Invalidate all sessions for a user |
| `GET /case-notes/{endpoint_id}` | JWT analyst/admin | Get analyst case notes for an endpoint |
| `POST /case-notes` | JWT analyst/admin | Save case note |

#### Monitoring and System (6 endpoints)
| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /start-monitoring` | API key | Start all background detection loops |
| `GET /stop-monitoring` | API key | Cancel all background tasks |
| `GET /health` | None | Component health check (MongoDB, models, endpoint API) |
| `GET /security/events` | API key or JWT (admin) | Security event log; pagination (limit/skip, max 500) |
| `GET /replay/{incident_id}` | JWT | Unified investigation bundle: incident + plan + timeline + SHAP + case notes |
| `GET /critical-alerts` | JWT | Paginated permanent evidence store (max 200) |
| `GET /attack-graph/snapshot` | JWT | Current attack graph: 2h window, min_score=0.70, 50-node cap |
| `GET /endpoint/timeline/{endpoint_id}` | JWT | Endpoint event timeline (500 docs, timestamp DESC) |
| `GET /audit-logs` | JWT admin | Paginated audit log with 28 labeled action types |

### Authentication and Security

**JWT HS256:** 15-minute access tokens + 7-day refresh tokens. Refresh tokens are bcrypt-12 hashed before storage in MongoDB (`sessions` collection). `_require_key_or_jwt` dual-auth allows both API key (for agents) and JWT (for browser) on the same endpoint.

**TOTP 2FA:** `pyotp` + `qrcode` for TOTP secret generation and QR code display. Backup codes generated at enrollment, bcrypt-hashed in MongoDB. TOTP is required even during password reset — an attacker with email access cannot complete recovery without the authenticator.

**Rate limiting:** 5 attempts/IP/15-minute sliding window. Account lockout after 5 consecutive failures (15-minute lockout). Rate limiters are in-memory (resets on restart; production should use Redis-backed counters).

**CORS:** Restricted to `["http://localhost:3000", "http://127.0.0.1:3000"]` — not `*`.

**Startup validation:** CRITICAL log warning if `JWT_SECRET_KEY` or `XDR_API_KEY` are using default development values.

### Background Tasks (all started by `GET /start-monitoring`)

| Task | Function | Interval | Purpose |
|---|---|---|---|
| Network monitoring | `_network_monitor_loop()` | Continuous | Reads Suricata eve.json, runs rule + ML detection |
| System monitoring | `_system_monitor_loop()` | 1 Hz | psutil metrics + LSTM Autoencoder inference |
| User behavior | `_user_behavior_loop()` | 300 s | Winlogbeat ndjson + OC-SVM inference |
| Malware scanner | `_malware_scan_loop()` | File-event | Background PE file watcher |
| Sysmon PS forwarder | `_sysmon_ps_loop()` | Event-driven | PowerShell Get-WinEvent → SysmonBehaviorAgent |
| Endpoint heartbeat | `_endpoint_heartbeat_loop()` | 30 s | Marks stale endpoints offline, emits endpoint_offline |
| Server SOAR loop | `_server_soar_loop()` | 5 s | Executes SOAR commands targeting server_host |

Graceful shutdown: `_do_shutdown()` awaits all background task cancellations via `asyncio.gather(return_exceptions=True)` with a hard 5-second timeout via `asyncio.wait_for`.

### Socket.IO Events — Complete List (19 events, server → client)

| Event | Description |
|---|---|
| `network_anomaly` | Network flow anomaly detected (populates Alert Stream) |
| `user_anomaly` | User behavior anomaly from OC-SVM |
| `user_behavior_summary` | Periodic user behavior stats with users[] list |
| `system_anomaly` | System telemetry anomaly (rate-limited 1/30s) |
| `sysmon_alert` | Sysmon behavioral event with SHAP explanation |
| `malware_alert` | Malware detection result (label, confidence, trusted) |
| `malware_scan` | On-demand file scan result |
| `fusion_alert` | Fused threat score (all models combined, with SHAP) |
| `audit_event` | Auth and admin action audit log entry |
| `endpoint_update` | Endpoint telemetry heartbeat + registry state |
| `endpoint_alert` | Alert from endpoint telemetry AI analysis |
| `endpoint_offline` | Endpoint heartbeat timeout (> 35 seconds) |
| `command_queued` | New SOAR command written to MongoDB |
| `command_result` | SOAR command execution ACK (status, result_message, target) |
| `response_required` | Auto-generated when fusion severity is HIGH/CRITICAL |
| `response_plan_ready` | Response plan generated via POST /response/plan |
| `response_executed` | SOAR commands queued from POST /response/execute |
| `report_generated` | PDF incident report ready for download |
| `auto_response_completed` | Auto-SOAR completed; includes report metadata if PDF generated |

---

## 9. Frontend SOC Dashboard

**Directory:** `Cyber Sentinal XDR Frontend/`  
**Framework:** React 18 + TypeScript (Create React App)  
**Port:** 3000  
**Entry:** `src/components/NetworkMonitor.tsx` (state owner)

### UI Layout

**Top bar:** Start Monitoring button, Stop Monitoring button only (clean SOC interface).  
**Sidebar navigation:** Overview, Network, Alerts, Attack Graph, Endpoints, System Status, Malware, User Behavior, Sysmon.  
**Sidebar bottom section (stacked above user card):** Settings icon-button, About icon-button, User card (name + role + Sign Out).  
**Theme:** Dark cyberpunk with neon accents, glassmorphism cards, Framer Motion animations, scan-line CSS effect.

### View-by-View Description

#### Overview (`views/OverviewView.tsx`)
- KPI summary cards: active endpoints, total alerts, malware detections, threat score gauge
- Admin-only: real-time Activity Log showing colored badges per action type (28 labeled action types), user email, IP, timestamp
- Non-admin: KPI grid only (no activity log shown)
- Fetches `GET /audit-logs` on mount + subscribes to `audit_event` socket

#### Network (`views/NetworkView.tsx`)
- Live network flow table with columns: timestamp, source IP:port, destination IP:port, protocol, bytes, attack type, severity badge
- `NetworkMap.tsx`: D3 force-graph (`react-force-graph-2d`) of live network flows as edges between IP nodes
- Real-time updates via `network_anomaly` Socket.IO events

#### Alerts (`views/AlertsView.tsx`)
Two-section layout:
1. **ALERT STREAM:** Network anomaly table with SHAP reasons column; "Respond" button on HIGH/CRITICAL rows only
2. **CORRELATED ATTACKS:** Multi-domain correlation events; "Respond" button for MEDIUM/HIGH/CRITICAL; ATTACK_COLOURS per type

#### Attack Graph (`views/AttackGraphView/AttackGraphView.tsx`)
- D3 force simulation: charge -300, link distance 120, named collision force, type-based `forceX`/`forceY` positional biases
- Node TTL decay: CRITICAL 30 min, HIGH 15 min, MEDIUM/LOW 5 min
- Ingestion filter: MEDIUM/LOW network/endpoint/user events dropped to reduce noise
- Status bar: "System Normal" vs "X Critical Threats Active"
- `NodeDetailPanel.tsx`: 5-tab panel per node (Overview, SHAP with fallback, Timeline, Response, Info)
- SHAP RBAC gating: admin = full values + chart, analyst = chart + labels, viewer = plain text
- `clearGraph()` button: admin/analyst only
- Position preservation: `useMemo` reads `simRef.current.nodes()` before state updates; alpha reduced 0.5→0.2 on topology changes

#### Endpoints (`views/EndpointView.tsx`)
6-section layout:
1. **Endpoint Grid:** Auto-fill cards with CPU/MEM progress bars, online (green dot) / offline (grey dot) / isolated (orange glow + lock badge) status; red pulse animation on HIGH/CRITICAL
2. **Endpoint Alerts Table:** Last 20 alerts; severity badges; row click selects endpoint in response panel
3. **Response Panel:** Endpoint selector (online-only); 5 action buttons with inline forms; Isolate Host shows confirmation warning; Command History last 10 with OK/FAIL badges
4. **Active Threats:** Response plans filtered to selected endpoint; plan status badges (CONTAINED/PARTIAL/EXECUTING/OPEN); "View Response" per plan
5. **Response History:** Historical executed plans with action outcomes
6. **Incident Reports:** PDF download (admin/analyst) or "Summary only" (viewer); re-fetched on every login + `report_generated` socket event

#### Attack Reconstruction / Investigation (`views/AttackReconstructionView.tsx`)
3-panel investigation interface accessed via "Investigate" button in EndpointView:
- **Left panel:** Mini attack graph (filtered to incident context)
- **Center panel:** `ReplayTimeline.tsx` — vertical scrollable event log; past/active/future opacity states; auto-scroll to current step; click-to-jump; 4 source types (endpoint_logs, fused_alerts, alerts, sysmon_alerts)
- **Right panel:** `FusionDecisionPanel.tsx` — SVG arc threat gauge + per-model contribution bars with weight badges; severity-colored glow
- Narrative panel: server-generated plain-English attack narrative (client fallback if unavailable)
- Response Actions Taken panel: SOAR commands from plan_id
- SHAP fallback: contributing model bars if per-event SHAP unavailable

#### System Status (`views/SystemStatusView.tsx`)
- `/health` + `/storage-status` endpoint polling
- Component status: MongoDB, model files, Suricata, Winlogbeat, Sysmon
- Storage metrics: collection sizes, cap utilization

#### Malware (`views/MalwareView.tsx`)
- Malware scan results table: file_path, label badge (red=malicious/orange=suspicious/green=benign), confidence%, trusted shield icon
- SHAP Reasons column
- Trusted file rows shown at 55% opacity
- Fusion attack_type chip inline

#### User Behavior (`views/UserBehaviorView.tsx`)
- OC-SVM anomaly feed; anomaly score per user
- Green "NORMAL" badge for non-anomalous users
- `user_behavior_summary` Socket.IO subscription; users[] list upserted to display state

#### Sysmon (`views/SysmonBehaviorView.tsx`)
- Live Process Events: raw Sysmon event stream (EventID, process, parent, command line)
- System Telemetry Logs panel: CPU/memory/disk over time; ANOMALOUS badge only when `is_genuinely_anomalous === true`
- SHAP Reasons column: hidden from viewers; plain text for viewers (RBAC)

#### Settings (`views/SettingsView.tsx`) — Admin only
5 accordion sections:
- **A. General:** Theme toggle (dark/cyberpunk), animation on/off, Sound Alerts on/off
- **B. Security:** MFA enable/disable, session timeout, password policy info
- **C. Integrations:** Live status of Suricata/Sysmon/Winlogbeat (running/stopped) via `/health`
- **D. Detection:** Network/system/fusion threshold sliders; calls `POST /settings/thresholds`; thresholds persist to MongoDB across restarts
- **E. Alerts:** Siren toggle, min severity filter, auto-response toggle (loads/saves `auto_response_enabled`; shows info banner when auto-response is ON)

#### Profile / User Management (`views/ProfileView.tsx`)
- **All roles:** Name, email, role badge, last login, MFA status, change password
- **Admin extras:** User management table (create/delete/reset-password/assign-role), MFA Recovery Panel (auto-refreshes 30s; Approve/Deny with confirmation modal), force-logout sessions
- **Analyst extras:** Case notes panel — free-text investigation notes per endpoint/alert, saved to `case_notes` MongoDB collection
- **Viewer:** Read-only profile card

#### About (`views/AboutView.tsx`)
- Professional product positioning paragraph
- Animated architecture flow diagram (Framer Motion): Endpoints → Data Collection → Ingestion → Fusion → Alerts → Response
- Detection capabilities matrix (MITRE ATT&CK coverage)
- Tech stack panel
- Interactive commands reference (Endpoint Setup, XDR Backend, ML Training) with copy button + syntax highlight
- Version badge (v1.0 XDR Platform)

### Key Frontend Components

| Component | File | Purpose |
|---|---|---|
| `NetworkMonitor.tsx` | `src/components/` | State owner; Socket.IO subscriptions; passes props to all views |
| `ResponseModal.tsx` | `src/components/` | Full-screen glassmorphism SOAR modal: attack summary, SHAP bar chart, action checklist, PDF download |
| `AlertSiren.tsx` | `src/components/` | Web Audio API siren (600–900 Hz sweep) + red vignette on HIGH/CRITICAL |
| `AuditLogPanel.tsx` | `src/components/` | Live audit_event feed panel |
| `Sidebar.tsx` | `src/components/shared/` | Navigation with red pulsing RESPOND badge when responseRequiredCount > 0 |
| `UnauthorizedBanner.tsx` | `src/components/` | Fixed red top banner (z-index 10000) on 403; 2.6s auto-dismiss |
| `ProtectedRoute.tsx` | `src/components/` | Role-enforcement wrapper with AccessDeniedOverlay |
| `OTPInput.tsx` | `src/components/` | 6-cell auto-advance TOTP input |
| `SecurityRecoveryTimeline.tsx` | `src/components/` | Reusable neon timeline with Framer Motion stagger |
| `FusionDecisionPanel.tsx` | `src/components/views/AttackGraphView/` | SVG arc gauge + per-model contribution bars |
| `ReplayTimeline.tsx` | `src/components/views/AttackGraphView/` | Scrollable event timeline for investigation view |
| `NodeDetailPanel.tsx` | `src/components/views/AttackGraphView/` | 5-tab node detail with SHAP RBAC |

### Auth Pages

| Page | Route | Description |
|---|---|---|
| `LoginPage.tsx` | `/login` | Glassmorphism, canvas particles, password toggle, "Forgot password?" + "Lost MFA device?" links |
| `RegisterPage.tsx` | `/register` | Strength meter, per-field validation |
| `MFASetupPage.tsx` | `/setup-2fa` | QR code display + OTP confirmation |
| `ForgotPasswordPage.tsx` | `/forgot-password` | Animated pulsing shield; DEV MODE panel with raw token |
| `ResetPasswordPage.tsx` | `/reset-password` | 3-step: MFA verify → password + strength meter → SecurityRecoveryTimeline |
| `MFARecoveryRequestPage.tsx` | `/mfa-recovery` | Email + reason form; animated hourglass pending state |

---

## 10. SHAP Explainability

Cyber Sentinel XDR applies SHAP (SHapley Additive exPlanations) to every detection model, providing human-readable justification for every alert. No alert is shown to the SOC analyst without an explanation.

**File:** `Backend/agents/shap_agent.py`

### Coverage by Model

| Model | SHAP Method | How It Works |
|---|---|---|
| Network (RandomForest) | `shap.TreeExplainer` | Tree-path attribution on 63 CIC-IDS2017 features; top features returned as `[{"feature": "...", "value": ..., "shap": ...}]` |
| Malware (LightGBM) | `shap.TreeExplainer` | Gradient-boosted tree attribution on 280 EMBER PE features; identifies which PE header fields drove the malicious classification |
| System (LSTM Autoencoder) | Reconstruction-error decomposition | Per-feature contribution to the reconstruction error; features where actual vs. predicted diverge most are ranked highest |
| Sysmon | Indicator analysis | Rule-based indicator weighting: process name, parent process, command line arguments, registry key, file path each weighted by behavioral risk level |

### 3-Tier Fallback Chain

In the Attack Graph snapshot and Investigation UI:
1. **Inline SHAP:** SHAP explanation included directly in the fusion_alert event
2. **Collection lookup:** Query `shap_explanations` MongoDB collection by event correlation (4-stage fallback: endpoint_id + timestamp, endpoint_id only, timestamp only, most recent)
3. **Synthetic model scores:** Generate SHAP-equivalent bars from per-model threat scores × fusion weights if no stored explanation exists

### RBAC Gating (3 Tiers)

| Role | Network/Malware SHAP | System/Sysmon SHAP | ResponseModal |
|---|---|---|---|
| Admin | Full raw values + bar chart + feature names | Full reconstruction scores + feature list | Full SHAP bar chart with numeric values |
| Analyst | Bar chart + direction labels (high/low) | Bar chart + relative magnitudes | Summarized chart with direction labels |
| Viewer | "Suspicious process behavior detected." (plain text only) | Generic anomaly description | Read-only badge, no SHAP |

SHAP gating is enforced at the component level in `ResponseModal.tsx` and `NodeDetailPanel.tsx`. The backend always sends full SHAP data; the frontend renders only what the user's role permits.

### Example SHAP Output

```json
{
  "reason": ["high packet rate", "suspicious destination IP", "periodic traffic pattern"],
  "features": [
    {"feature": "packets_per_second", "value": 847.3, "shap": 0.42},
    {"feature": "dst_ip", "value": "185.220.101.34", "shap": 0.31},
    {"feature": "flow_iat_mean", "value": 0.003, "shap": 0.18}
  ]
}
```

---

## 11. MongoDB — All 27 Collections

| Collection | Cap | TTL Index | Key Fields | Purpose |
|---|---|---|---|---|
| `logs` | None | None | host, timestamp, data | Legacy raw telemetry from single-host ingestion |
| `features` | None | None | host, flow_duration, packets_sec, syn_count, bytes_sec | Extracted network flow features |
| `predictions` | None | None | model, prediction, score | Per-model inference results |
| `alerts` | None | None | host, threat, severity | Legacy alert records |
| `shap_explanations` | None | None | features (list of contributing factors), model, timestamp | SHAP output stored per prediction |
| `commands` | None | None | host, actions, status (pending→done) | Legacy single-host SOAR commands |
| `endpoints` | None | None | host, status (online/isolated) | Legacy endpoint registry |
| `malware_scans` | None | None | file_path, label, score, shap_explanation | PE file scan results |
| `malware_events` | 2,000 | None | label, trusted, confidence, source, ts_dt | Capped malware event stream |
| `fused_alerts` | 1,000 | 30 days | threat_score, severity, attack_type, sources, ts_dt | Capped fusion alert stream |
| `critical_alerts` | None (permanent) | None | threat_score, severity, attack_type, endpoint_id, ts_dt | Permanent HIGH/CRITICAL evidence store |
| `users` | None | None | email, hashed_password, role, 2fa_enabled, two_factor_secret | User accounts with TOTP secrets |
| `sessions` | None | None | user_id, refresh_token_hash, device_trust, is_active | Active JWT refresh sessions |
| `audit_logs` | None | None | user_id, action, ip, timestamp, detail | Full auth and admin action audit trail |
| `security_events` | 5,000 | None | user_id, ip, severity (401→MEDIUM, 403→HIGH), timestamp | HTTP 401/403 security event log |
| `endpoint_logs` | 10,000 | 90 days | endpoint_id, hostname, timestamp, network, system, user, malware | Per-endpoint telemetry records |
| `endpoint_registry` | 500 | None | endpoint_id (unique index), hostname, ip_address, os, username, last_seen, status, blocked_ips | Registered endpoint state |
| `endpoint_commands` | 2,000 | None | endpoint_id, action, target, status (pending→sent→completed/failed), created_at | SOAR command queue |
| `response_plans` | 2,000 | None | plan_id, endpoint_id, severity, attack_type, mitre_technique, recommended_actions, auto_execute, status | EDR response plans with lifecycle status |
| `response_advisory_logs` | None | None | endpoint_id, action (advisory), plan_id, status: acknowledged, created_at | Advisory action acknowledgment log |
| `incident_reports` | None | None | incident_id, plan_id, endpoint_id, severity, attack_type, pdf_path, generated_by, generated_at, generated_at_dt | PDF report metadata (PDFs on disk) |
| `sysmon_alerts` | None | 30 days | EventID, process, parent, command_line, shap_explanation, ts_dt | Sysmon behavioral events |
| `case_notes` | None | None | endpoint_id, plan_id, analyst_email, note, created_at | Analyst free-text investigation notes |
| `settings` | None | None | key, value, updated_at, updated_by | Persistent threshold and config settings |
| `password_reset_tokens` | 1,000 | None | token_hash, user_id, expires_at, used | Single-use bcrypt-hashed password reset tokens |
| `mfa_recovery_requests` | 500 | None | user_id, email, reason, status (pending/approved/denied), risk_level, created_at | Admin-queued MFA device recovery requests |
| `sysmon_alerts` (already listed above) | — | — | — | — |

**Total: 27 collections** (26 unique + 1 counted twice above in audit)

**Indexes:** TTL indexes on `fused_alerts` (30d), `endpoint_logs` (90d), `sysmon_alerts` (30d) via `ts_dt` BSON datetime field. Unique index on `endpoint_registry.endpoint_id`. Compound indexes on `endpoint_logs(endpoint_id, timestamp DESC)`, `endpoint_commands(endpoint_id, status, created_at DESC)`, `security_events(timestamp DESC, user_id, ip)`.

**MongoDB Atlas auto-trim:** Storage-full detection triggers periodic trim every 100 cycles. Collection caps enforce maximum document counts. Connection timeout: 20 seconds (required for Atlas DNS SRV + TLS handshake).

---

## 12. Technology Stack

### Runtime
- **Python 3.11** — Backend ML pipeline, FastAPI server, endpoint agent
- **Node.js 18** — React frontend build toolchain
- **React 18 + TypeScript** — SOC dashboard frontend

### Backend Framework
- **FastAPI 0.100+** — ASGI REST API framework with Pydantic v2 validation
- **uvicorn** — ASGI server (production deployment)
- **python-socketio** — WebSocket real-time event bus (mounted on FastAPI ASGI)
- **Pydantic v2** — Request/response validation, model serialization

### ML / AI
- **scikit-learn** — IsolationForest (personal baseline), RandomForest (CIC classifier), One-Class SVM (user behavior), StandardScaler
- **PyTorch** — LSTM Autoencoder for system telemetry anomaly detection
- **LightGBM** — EMBER 2018 malware classifier (streaming training)
- **XGBoost** — Available in stack (referenced in CLAUDE.md AI models summary)
- **SHAP** — `shap.TreeExplainer` for RandomForest + LightGBM; reconstruction-error decomposition for LSTM

### Security
- **PyJWT** — JWT HS256 token generation and verification
- **bcrypt (passlib)** — bcrypt-12 password and token hashing
- **pyotp** — TOTP two-factor authentication (RFC 6238)
- **qrcode** — QR code generation for MFA enrollment

### Frontend Libraries
- **React 18** — UI framework with concurrent rendering
- **TypeScript** — End-to-end type safety
- **Framer Motion** — Animation framework (cards, modals, alert sirens, recovery timeline)
- **D3.js** — Force simulation for attack graph layout
- **react-force-graph-2d** — Canvas-based network force graph
- **react-hot-toast** — Toast notifications for SOAR results
- **axios** — HTTP client with JWT interceptor (silent refresh on 401)
- **socket.io-client** — WebSocket subscriber

### Data
- **MongoDB Atlas / MongoDB 8.0** — Primary data store (27 collections)
- **pymongo** — Python MongoDB driver
- **pandas** — Feature engineering, dataset processing
- **numpy** — Numerical operations, feature vectors

### Network Detection Tools
- **Suricata 7.0.14** — IDS engine generating `eve.json`; HOME_NET `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`; interface `\Device\NPF_{B5A75558-6CB6-473B-B521-5B390F7ADE47}`
- **Winlogbeat** — Ships Windows Security Event Logs (ndjson) to `C:\XDR_Logs\`
- **Sysmon** — Windows kernel-level process/network/file/registry logging
- **TShark** — Packet capture for baseline collection on endpoints
- **Zeek** — Protocol-level network analysis (`Backend/ZEEK/`)

### Report Generation
- **ReportLab** — PDF generation; custom `Flowable` classes for SHAP bar charts and MITRE sections

### Endpoint Agent
- **psutil** — Cross-platform system and network metrics
- **httpx** — Async HTTP client with exponential backoff
- **asyncio** — Dual-loop concurrent telemetry + command handling
- **winreg** — Windows registry access for persistence monitoring

---

## 13. Complete File Directory

### Backend/

| File | Description |
|---|---|
| `backend.py` | FastAPI + Socket.IO central server; all 40+ endpoints; background task orchestration; ENTRY POINT |
| `config.py` | Centralized settings with env-var overrides; model paths, MongoDB URI, API key, thresholds |
| `fusion_engine.py` | Event-driven correlation engine; EventBuffer (300s), CorrelationEngine, FusionDecisionEngine; ransomware gate |
| `response_engine.py` | MITRE ATT&CK-mapped response plan generator; 15+ attack patterns; no-auto-execute set |
| `report_generator.py` | ReportLab 5-section PDF generator; SHAP bar chart Flowable; MITRE lookup; severity-colored stamps |
| `hybrid_detector.py` | 2-gate ML detection; Gate 1 IsolationForest + Gate 2 RandomForest; 63 CIC features |
| `rule_detector.py` | Deterministic rule engine; incremental eve.json reader with file-offset tracking |
| `attack_graph.py` | AttackGraphEngine; monotonic chain_seq counter; node TTL metadata |
| `collect_baseline.py` | TShark capture of normal traffic; writes personal_baseline.csv |
| `train_model.py` | Train CIC-IDS2017 IsolationForest; saves network_model_isolation.pkl |
| `train_classifier.py` | Train RandomForest multi-class attack classifier on CIC-IDS2017; 99.6% accuracy |
| `train_personal_model.py` | Train per-operator IsolationForest baseline |
| `train_system_model.py` | Collect live psutil telemetry + train LSTM Autoencoder; saves system_model.pt |
| `train_malware_model.py` | EMBER 2018 streaming trainer for LightGBM; AUC-ROC 0.9803 |
| `sysmon_winevent_reader.py` | SysmonFileReader; tails C:\winlogbeat\logs\sysmon_events.json |
| `sysmon_feature_extractor.py` | Normalizes flat and nested Sysmon event formats to feature dict |
| `winlogbeat_manager.py` | Start/stop/detect Winlogbeat process; lifecycle tied to monitoring |
| `test_connection.py` | Socket.IO connection verification tool |
| `test_network_model.py` | Network ML inference pipeline test |

### Backend/agents/

| File | Description |
|---|---|
| `network_detection_agent.py` | Orchestrates rule detector + hybrid ML; detect() for Suricata; detect_from_endpoint_network() for psutil |
| `user_behavior_agent.py` | Async wrapper around xdr_runtime.py (300s tick); score_session_telemetry() for endpoint telemetry |
| `fusion_engine_agent.py` | Weighted threat score combiner; thresholds HIGH=0.70, CRITICAL=0.85 |
| `shap_agent.py` | SHAP explainability wrapper; explain_network(), explain_malware(), explain_system(), explain_sysmon() |
| `malware_analysis_agent.py` | LightGBM EMBER inference; pefile PE extraction; 3-tier labels; trusted-path whitelist; assess_process_metadata() |
| `system_monitor_agent.py` | LSTM Autoencoder inference; 20-feature vector; resource-aware severity; is_genuinely_anomalous; predict_from_metrics() |
| `sysmon_behavior_agent.py` | Sysmon event handler; behavioral anomaly detection; dual-source with mutual exclusion |
| `endpoint_agent.py` | Legacy single-host SOAR executor (superseded by endpoint_agent/ package) |

### Backend/auth/

| File | Description |
|---|---|
| `__init__.py` | Package init; exports key functions |
| `security.py` | JWT creation/verification; bcrypt hashing; TOTP functions; create_password_reset_token() |
| `models.py` | Pydantic models: LoginRequest, RegisterRequest, ForgotPasswordRequest, ResetPasswordRequest, MFARecovery* |
| `rbac.py` | RBAC enforcement; role hierarchy; hasRequiredRole() logic |
| `rate_limiter.py` | Sliding-window rate limiters; forgot_password_rate_limiter, mfa_recovery_rate_limiter |
| `email_sender.py` | SMTP email sender for password reset; SMTP_ENABLED env var gate |

### User Behavior/final_model_backend_only/

| File | Description |
|---|---|
| `xdr_runtime.py` | OC-SVM inference engine; reads Winlogbeat ndjson; 12-feature OCEAN model |
| `user_model.pkl` | Trained One-Class SVM (CERT Insider Threat Dataset r4.2) |
| `user_scaler.pkl` | StandardScaler fitted on training data |
| `feature_columns.json` | 12 active feature column names |
| `model_threshold.json` | Anomaly decision threshold (0.80) |
| `test_model_realtime.py` | Real-time inference test harness |

### endpoint_agent/

| File | Description |
|---|---|
| `agent.py` | Main asyncio runner; _telemetry_loop (5s) + _command_loop (3s); CLI + env-var config; startup banner |
| `identity.py` | UUID generation/persistence in endpoint_config.json; detect_network_interface() NIC detection |
| `sender.py` | httpx.AsyncClient sender; 3-attempt exponential backoff (1s/2s/4s) |
| `command_listener.py` | poll_commands / execute_command / acknowledge_command; all 9 SOAR actions; safe_execute_command wrapper |
| `check_payload.py` | Validates all 37 EndpointTelemetry fields against canonical spec; live POST diagnostic |
| `requirements.txt` | httpx>=0.27.0, psutil>=5.9.0 |
| `collectors/network_collector.py` | psutil net_connections (max 50) + net_io_counters; 22 suspicious port IOC set |
| `collectors/system_collector.py` | CPU%, memory%, disk%, process count, top-10 by CPU |
| `collectors/user_collector.py` | Current user + psutil.users() sessions; remote session detection |
| `collectors/malware_collector.py` | Heuristic suspicious process name matching; temp-dir launch detection |

### Cyber Sentinal XDR Frontend/src/

| File | Description |
|---|---|
| `App.tsx` | React Router routes; root-level UnauthorizedBanner mounting; auth page routes |
| `index.tsx` | React DOM entry; global font-size 17px |
| `index.css` | Global styles; neon animations; pulse-border; scan-line; unauthorized-glitch body class |

### src/components/

| File | Description |
|---|---|
| `NetworkMonitor.tsx` | State owner; 19 Socket.IO subscriptions; auto_response_completed handler; PDF auto-download |
| `ResponseModal.tsx` | Full-screen SOAR modal; SHAP bar chart; action checklist; role-gated Execute; PDF download |
| `AlertSiren.tsx` | Web Audio API siren (600–900 Hz sweep); red vignette; AnimatePresence keyed children |
| `AuditLogPanel.tsx` | Live audit_event feed; colored badges per action |
| `OTPInput.tsx` | 6-cell auto-advance TOTP input |
| `UnauthorizedBanner.tsx` | Fixed top banner on 403; 2.6s dismiss; unauthorized-glitch body class |
| `ProtectedRoute.tsx` | Route role guard; AccessDeniedOverlay (2s glitch animation before redirect) |
| `StartupScreen.tsx` | Animated loading screen on initial app load |

### src/components/shared/

| File | Description |
|---|---|
| `Sidebar.tsx` | Navigation sidebar; RESPOND badge; Settings/About bottom icons; user card |
| `responseTypes.ts` | TypeScript: ResponseAction, ResponsePlan, IncidentReport interfaces |
| `StatCard.tsx` | KPI metric card component |
| `SeverityBadge.tsx` | Colored severity badge (LOW/MEDIUM/HIGH/CRITICAL) |
| `LiveIndicator.tsx` | Pulsing green/red live status indicator |
| `ConfirmDialog.tsx` | Modal confirmation dialog |

### src/components/views/

| File | Description |
|---|---|
| `OverviewView.tsx` | KPI cards + admin Activity Log (28 labeled action types) |
| `NetworkView.tsx` | Network flow table; column alignment; timestamp display |
| `AlertsView.tsx` | Alert stream + Correlated Attacks; Respond buttons; RBAC gating |
| `EndpointView.tsx` | 6-section endpoint management; Active Threats; Response History; Incident Reports |
| `EndpointDetailView.tsx` | Individual endpoint detail; timeline; registry state |
| `AttackReconstructionView.tsx` | 3-panel investigation: mini graph + ReplayTimeline + FusionDecisionPanel |
| `UserBehaviorView.tsx` | OC-SVM anomaly feed; NORMAL badges |
| `SysmonBehaviorView.tsx` | Process events + System Telemetry Logs; SHAP RBAC; userRole prop |
| `MalwareView.tsx` | Malware scan results; 3-tier label badges |
| `SystemStatusView.tsx` | /health + /storage-status polling; component status |
| `ProfileView.tsx` | User profile; admin user table; analyst case notes; MFA Recovery Panel |
| `SettingsView.tsx` | 5-section admin settings; auto-response toggle wired end-to-end |
| `AboutView.tsx` | Product overview; animated architecture diagram; commands reference |
| `DetectionPipelineFlow.tsx` | Visual pipeline flow diagram |
| `AttackChainGraph.tsx` | Attack chain graph component |

### src/components/views/AttackGraphView/

| File | Description |
|---|---|
| `AttackGraphView.tsx` | Main attack graph container; status bar |
| `AttackGraph.tsx` | D3 force simulation; node TTL; position preservation; canvas rendering |
| `NodeDetailPanel.tsx` | 5-tab node detail panel; SHAP RBAC gating |
| `FusionDecisionPanel.tsx` | SVG arc threat gauge; per-model bars with weight badges |
| `ReplayTimeline.tsx` | Scrollable event timeline; past/active/future states |
| `GraphControls.tsx` | Graph filter controls; clearGraph() |
| `RecentEvents.tsx` | Recent events list in graph sidebar |

### src/services/

| File | Description |
|---|---|
| `api.ts` | Socket.IO client + REST calls; authAxios instance |
| `networkSocket.ts` | Socket.IO event subscription handlers |

### src/context/

| File | Description |
|---|---|
| `AuthContext.tsx` | Auth state; hydrate() decision tree (no tokens / refresh only / access token); silent refresh |

### src/pages/ (Auth)

| File | Description |
|---|---|
| `LoginPage.tsx` | Glassmorphism login; canvas particles; "Forgot password?" + "Lost MFA device?" links |
| `RegisterPage.tsx` | Registration with strength meter |
| `MFASetupPage.tsx` | QR code display + OTP confirmation |
| `ForgotPasswordPage.tsx` | DEV MODE collapsible panel with raw token |
| `ResetPasswordPage.tsx` | 3-step recovery flow |
| `MFARecoveryRequestPage.tsx` | Broken-lock theme; animated hourglass |

### src/components/views/ProfileView/

| File | Description |
|---|---|
| `MFARecoveryPanel.tsx` | Admin MFA recovery queue; 30s auto-refresh; Approve/Deny modal |

### src/hooks/

| File | Description |
|---|---|
| `useSirenAudio.ts` | Siren audio hook; isPlaying guard; no-op before enableAudio() |

### src/utils/

| File | Description |
|---|---|
| `sirenAudio.ts` | Dual-source audio: HTMLAudioElement (siren.mp3.wav) → Web Audio API fallback |

### src/types/

| File | Description |
|---|---|
| `network.ts` | NetworkAnomaly TypeScript interface (source of truth for alert shape) |

### src/components/

| File | Description |
|---|---|
| `SecurityRecoveryTimeline.tsx` | Reusable neon timeline; Framer Motion stagger; completed/in-progress/pending |

---

## 14. Key Metrics and Performance

### ML Model Performance

| Model | Algorithm | Dataset | Key Metrics |
|---|---|---|---|
| `malware_model.pkl` | LightGBM | EMBER 2018 (280 features) | AUC-ROC: 0.9803, F1: 0.9298, Accuracy: 0.9284 |
| `network_classifier.pkl` | RandomForest | CIC-IDS2017 (63 features) | Accuracy: 99.6%, 8 attack classes |
| `network_model_isolation.pkl` | IsolationForest | CIC-IDS2017 | Unsupervised baseline; anomaly score output |
| `personal_baseline_model.pkl` | IsolationForest | Live operator traffic | Personal behavioral baseline |
| `user_model.pkl` | One-Class SVM | CERT Insider Threat r4.2 | Threshold: 0.80 (tuned) |
| `system_model.pt` | LSTM Autoencoder (PyTorch) | Live psutil telemetry | Reconstruction-error anomaly detection |

### Detection Thresholds

```
Fusion HIGH:               score >= 0.70
Fusion CRITICAL:           score >= 0.85
User behavior anomaly:     OC-SVM score >= 0.80
User behavior CRITICAL:    OC-SVM score > 0.85
User behavior HIGH:        OC-SVM score > 0.70
Malware malicious:         LightGBM score > 0.70
Malware suspicious:        LightGBM score 0.30–0.70
System genuinely anomalous: CPU > 85% OR Memory > 95% OR (CPU > 80% AND Memory > 80%)
```

### Pipeline Timing

| Component | Interval / Rate |
|---|---|
| Endpoint telemetry send | Every 5 seconds per endpoint |
| Endpoint command poll | Every 3 seconds per endpoint |
| System monitoring (psutil) | 1 Hz (1 second) |
| User behavior evaluation | Every 300 seconds |
| Endpoint heartbeat check | Every 30 seconds |
| Server SOAR executor poll | Every 5 seconds |
| System anomaly emit throttle | At most 1/30 seconds |
| Sysmon emit cooldown | 5.0 seconds |
| Malware alert cooldown | 60 seconds per file |
| Attack graph node TTL (CRITICAL) | 30 minutes |
| Attack graph node TTL (HIGH) | 15 minutes |
| Attack graph node TTL (MEDIUM/LOW) | 5 minutes |

### MongoDB Scale

| Metric | Value |
|---|---|
| Total collections | 27 |
| Endpoint registry cap | 500 endpoints |
| Endpoint logs cap | 10,000 documents (90-day TTL) |
| Fused alerts cap | 1,000 documents (30-day TTL) |
| Security events cap | 5,000 documents |
| Endpoint commands cap | 2,000 documents |
| Response plans cap | 2,000 documents |
| Malware events cap | 2,000 documents |
| critical_alerts | Uncapped (permanent evidence store) |

### Feature Dimensions

| Model | Feature Count | Feature Source |
|---|---|---|
| Network classifier | 63 | CIC-IDS2017 flow statistics |
| Malware classifier | 280 | EMBER PE header features |
| User behavior | 12 | Windows event log aggregations |
| System LSTM | 20 | psutil system metrics |

---

## 15. Security and RBAC Matrix

### Role Hierarchy

```
admin > analyst > viewer
```

First registered user automatically becomes admin. Role changes require admin JWT.

### Feature Access by Role

| Feature | Admin | Analyst | Viewer |
|---|---|---|---|
| Dashboard / Alerts / Endpoints | Full | Full | Full |
| SHAP — raw feature values + bar chart | Full | Summarized chart only | Plain text only |
| Raw log access | Full | Full | Hidden |
| Response actions (kill/block/isolate) | Full | Limited | Hidden |
| User Management | Full | Hidden | Hidden |
| Settings page | Full | Hidden | Hidden |
| Audit Logs | Full view | Partial (own actions) | Hidden |
| PDF Reports | Download full | Download full | View summary text only |
| Fusion config / threshold editing | Edit | Read-only | Hidden |
| Case Notes | Hidden (uses audit_logs) | Full read/write | Hidden |
| Attack Graph | Full | Full | Hidden |
| Correlated Attacks Respond button | Visible | Visible | Hidden |
| Alert Stream Respond button | Visible | Visible | Hidden |
| SOAR Execute button (ResponseModal) | Active | Active (limited) | Read-only badge |
| PDF Download button | Active | Active | "Summary only" text |
| Force logout other users | Active | Hidden | Hidden |
| MFA Recovery approvals | Active | Hidden | Hidden |
| Admin Activity Log in Overview | Visible | Hidden | Hidden |
| Sysmon SHAP column | Full values | Summarized | Hidden |
| Sysmon Indicators SHAP Reasons | Full | Hidden | Plain text |

### Security Controls Summary

| Control | Implementation |
|---|---|
| Authentication | JWT HS256 (15-min access) + bcrypt-12 refresh tokens in MongoDB |
| 2FA | TOTP RFC 6238 via pyotp; QR code enrollment; backup codes |
| Password policy | bcrypt-12 hashing; strength meter enforced in UI |
| Rate limiting | 5 attempts/IP/15-min sliding window; 15-min account lockout after 5 failures |
| CORS | Restricted to localhost:3000 and 127.0.0.1:3000 |
| API key | Required for all agent endpoints; CRITICAL warning on default key |
| Password reset | MFA required even during reset (TOTP or backup code) |
| MFA recovery | Admin approval required; risk assessment (known IPs, recent attempts) |
| Session management | All sessions revoked on password reset or MFA recovery |
| Audit trail | Every auth and admin action logged to audit_logs + emitted as audit_event |
| 401/403 handling | Normalized JSON responses; security events persisted to security_events collection |
| SOAR security | All subprocess calls use shell=False; strict IP regex; PID cast to int(); username allowlist |
| JWT secret validation | CRITICAL startup log if JWT_SECRET_KEY is default value |
| Admin name in PDF | Derived server-side from JWT claims; request body value ignored (impersonation closed) |

### Known Production Hardening Items (Acceptable for Dev/Demo)

| Item | Current State | Production Fix |
|---|---|---|
| JWT storage | localStorage (XSS-extractable) | httpOnly cookies + CSRF tokens |
| Rate limiter persistence | In-memory (resets on restart) | Redis or MongoDB-backed counters |
| Endpoint agent transport | Plaintext HTTP + API key | HTTPS + certificate pinning |
| Endpoint agent install | Manual Python process | NSSM Windows Service wrapper |
| X-Forwarded-For | Blindly trusted | Configure trusted proxy list |
| SMTP email | Requires .env config | Set SMTP_ENABLED=true + SMTP credentials |

---

## Quick Start Commands

### Start All Components

```powershell
# 1. MongoDB
& "C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe" `
  --dbpath "D:\Cyber Sentinal\mongodb\data" --port 27017

# 2. Backend (as Administrator)
cd "D:\Cyber Sentinal\Backend"
venv\Scripts\activate
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload

# 3. Start monitoring (triggers all background detection loops)
Invoke-WebRequest -Uri "http://localhost:8000/start-monitoring"

# 4. Suricata (as Administrator)
& "C:\Program Files\Suricata\suricata.exe" `
  -c "C:\Program Files\Suricata\suricata.yaml" `
  -i "\Device\NPF_{B5A75558-6CB6-473B-B521-5B390F7ADE47}" `
  -l "C:\SuricataLogs"

# 5. Frontend
cd "D:\Cyber Sentinal\Cyber Sentinal XDR Frontend"
npm start
# Dashboard: http://localhost:3000
```

### ML Model Training (Run in Order)

```bash
# Network models
python collect_baseline.py        # 30-60 min normal traffic capture
python train_personal_model.py    # IsolationForest on baseline

python train_model.py             # CIC-IDS2017 IsolationForest
python train_classifier.py        # RandomForest multi-class (99.6% acc)

# System model
python train_system_model.py --collect-minutes 60  # Live psutil + LSTM Autoencoder

# Malware model
python train_malware_model.py     # EMBER 2018 streaming LightGBM (AUC 0.9803)
```

### Endpoint Agent Deployment (on monitored hosts)

```bash
# Install on monitored Windows host (run as Administrator)
pip install httpx>=0.27.0 psutil>=5.9.0

# Configure via environment or .env
set XDR_BACKEND_URL=http://192.168.1.5:8000
set XDR_API_KEY=<your-api-key>

# Start (will auto-detect NIC, generate UUID identity, start telemetry)
python -m endpoint_agent.agent

# Dry run (no OS changes)
python -m endpoint_agent.agent --simulate

# Diagnose payload issues
python endpoint_agent/check_payload.py
```

---

*Document generated: 2026-06-03*  
*Project status: ~99.8% production-ready*  
*See `D:\Cyber Sentinal\CLAUDE.md` for the canonical implementation reference.*
