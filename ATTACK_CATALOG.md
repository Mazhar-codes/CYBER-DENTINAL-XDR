# Cyber Sentinel XDR — Attack & Intrusion Detection Catalog

> Complete reference of every threat, anomaly, and intrusion pattern detected across all four detection layers plus the fusion engine, including verified SOAR mitigation steps and their rollbacks.
> Updated from source code as of 2026-05-18.

---

## Endpoint Agent Execution Model (NSSM)

The endpoint agent (`endpoint_agent/agent.py`) runs as a **Windows Service via NSSM** on every monitored host. This means:

- The service starts automatically at boot with **LocalSystem (Administrator)** privileges.
- All SOAR actions executed on the **endpoint** go through the command polling loop: `GET /endpoint/commands/{endpoint_id}` every 3 seconds.
- All SOAR actions executed on the **server host** go through `_server_soar_loop()` in `backend.py`, polling `endpoint_commands` for `endpoint_id = "server_host"` every 5 seconds.
- Both paths share the same action implementations — `command_listener.py` for endpoints, `_server_soar_executor()` in `backend.py` for the server.
- `shell=False` is enforced on all subprocess calls. Full absolute paths (`C:\Windows\System32\netsh.exe`, etc.) are used so actions succeed even when PATH is restricted by the service context.
- **Simulate mode** (`--simulate` flag) logs every action but never touches the OS — safe for testing.

**Auto-execute rules (Fusion Engine gate):**

| Severity | Auto-Execute | Condition |
|----------|-------------|-----------|
| CRITICAL (≥ 0.85) | ✅ Yes | Fires immediately without analyst approval |
| HIGH (0.70–0.84) | ❌ No | Queued, waits for analyst approval via ResponseModal |
| MEDIUM / LOW | ❌ No | Response plan generated but not queued |

**Attacks that never auto-execute regardless of severity:**
`port scan`, `portscan`, `lateral movement`, `privilege escalation`, `insider threat`, `impossible travel`

---

## Table of Contents

1. [Network Detection Layer](#1-network-detection-layer)
   - 1.1 [Rule-Based Detections (Deterministic)](#11-rule-based-detections-deterministic)
   - 1.2 [ML-Based Detections (CIC-IDS2017 RandomForest)](#12-ml-based-detections-cic-ids2017-randomforest)
2. [User Behavior Layer](#2-user-behavior-layer)
   - 2.1 [Session Heuristic Rules (Endpoint Agent)](#21-session-heuristic-rules-endpoint-agent)
   - 2.2 [OC-SVM Model Detections (Winlogbeat / Windows Event Logs)](#22-oc-svm-model-detections-winlogbeat--windows-event-logs)
   - 2.3 [Fast-Path Rule Overrides](#23-fast-path-rule-overrides)
3. [System Monitor Layer](#3-system-monitor-layer)
   - 3.1 [LSTM Autoencoder Detections](#31-lstm-autoencoder-detections)
   - 3.2 [Resource-Aware Severity Overrides](#32-resource-aware-severity-overrides)
   - 3.3 [Heuristic Rules (Degraded / Warmup Mode)](#33-heuristic-rules-degraded--warmup-mode)
4. [Malware Analysis Layer](#4-malware-analysis-layer)
   - 4.1 [Static PE File Analysis (EMBER / LightGBM)](#41-static-pe-file-analysis-ember--lightgbm)
   - 4.2 [Process Metadata Heuristics (Endpoint Agent)](#42-process-metadata-heuristics-endpoint-agent)
   - 4.3 [Suspicious Launch Path Detection](#43-suspicious-launch-path-detection)
   - 4.4 [Watched File Extensions](#44-watched-file-extensions)
5. [Fusion Engine — Cross-Layer Correlations](#5-fusion-engine--cross-layer-correlations)
6. [MITRE ATT&CK Technique Mapping](#6-mitre-attck-technique-mapping)
7. [Severity & Scoring Reference](#7-severity--scoring-reference)
8. [SOAR Action Reference with Rollbacks](#8-soar-action-reference-with-rollbacks)

---

## 1. Network Detection Layer

Source files: `Backend/rule_detector.py`, `Backend/hybrid_detector.py`, `Backend/agents/network_detection_agent.py`

The network layer runs in two sequential stages. Rule detections always fire first and skip the ML pipeline entirely. Flows not flagged by rules are forwarded to the two-gate ML detector.

---

### 1.1 Rule-Based Detections (Deterministic)

These are 100% deterministic, zero false-positive rules based on flow aggregation from Suricata `eve.json`.

| Rule Name | Attack Type | Severity | Trigger Condition | Evidence Reported | Confidence |
|-----------|-------------|----------|-------------------|-------------------|------------|
| `PORT_SCAN_HORIZONTAL` | PortScan | HIGH | ≥ 15 unique destination ports from one source IP in a single capture window | `"{N} unique ports scanned in one window"` | 70–99% (scales with port count) |
| `HOST_SWEEP` | PortScan | HIGH | ≥ 10 unique destination IPs from one source, using ≤ 3 ports (excludes broadcast/multicast) | `"{N} unique hosts probed on {M} port(s)"` | 90% |
| `SYN_FLOOD` | DoS | CRITICAL | ≥ 500 SYN packets sent AND ACK completion ratio < 10% | `"{N} SYNs sent, {X}% ACK completion rate"` | 97% |
| `DOS_FLOOD` | DoS | CRITICAL | ≥ 1,000 packets per second from one source | `"{N} packets/sec from this host"` | 96% |
| `BRUTE_FORCE` | BruteForce | HIGH | ≥ 20 connections to any of the brute-force target ports from one source | `"{N} repeated connections to {SERVICE} (port {P})"` | 75–99% (scales with connection count) |
| `DATA_EXFIL` | Infiltration | CRITICAL | ≥ 50 MB uploaded AND upload-to-download ratio ≥ 5× | `"{N}MB uploaded, {R}x more sent than received"` | 88% |

**Brute-Force Target Ports:**

| Port | Service |
|------|---------|
| 22   | SSH |
| 3389 | RDP |
| 21   | FTP |
| 5900 | VNC |
| 1433 | MSSQL |
| 3306 | MySQL |
| 23   | Telnet |

**Additional behaviors of the Rule Detector:**
- Reads `eve.json` incrementally (byte-offset tracking); only new lines since last call are processed.
- Detects Suricata log rotation (file shrink) and resets offset automatically.
- Applies a 2-minute recency filter — flows older than 120 seconds are discarded to prevent stale detections after log rotation.
- Skips IPv6 link-local (`fe80::`) and multicast (`ff02::`) source addresses.

#### 1.1 Response & Mitigation per Rule

---

##### PORT_SCAN_HORIZONTAL / HOST_SWEEP → PortScan

**MITRE:** T1046 — Network Service Discovery | **Auto-Execute:** ❌ No (never auto-executes for PortScan)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `block_ip` | Scanning source IP | Endpoint NSSM service OR Server host | Adds `XDR_BLOCK_<ip>` inbound + outbound firewall deny rule via `netsh advfirewall` — stops further reconnaissance | `unblock_ip <same IP>` — deletes the `XDR_BLOCK_<ip>` rule |
| 2 | `monitor_persistence` | Endpoint | Endpoint NSSM service OR Server host | Read-only audit: checks HKCU Run keys, Startup folder, scheduled tasks — detects implants possibly dropped during reconnaissance | No rollback needed (read-only) |

**Notes:** Source IP must resolve to a valid IPv4 address (validated by strict regex before any firewall call). If IP cannot be determined, `block_ip` is skipped entirely — no placeholder rules are ever created.

---

##### SYN_FLOOD / DOS_FLOOD → DoS

**MITRE:** T1498/T1499 — Network/Endpoint DoS | **Auto-Execute:** ✅ Yes (CRITICAL severity)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `block_ip` | Flood source IP | Endpoint NSSM service OR Server host | Adds `XDR_BLOCK_<ip>` inbound + outbound deny rule — stops the flood at the firewall before it exhausts kernel resources | `unblock_ip <same IP>` |
| 2 | `scan_filesystem` | Endpoint | Endpoint NSSM service OR Server host | Walk `C:\Users`, `C:\Temp`, `C:\Windows\Temp`, `C:\ProgramData` for `.exe/.dll/.ps1/.bat/.vbs/.scr` modified in last 60 min — checks whether a DDoS agent was planted | No rollback needed (read-only) |

**Notes:** SYN_FLOOD requires both packet count AND ACK ratio conditions to eliminate false positives from high-traffic legitimate servers.

---

##### BRUTE_FORCE → BruteForce

**MITRE:** T1110 — Brute Force | **Auto-Execute:** ✅ Yes (CRITICAL) / ❌ No (HIGH)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `block_ip` | Attacking source IP | Endpoint NSSM service OR Server host | Adds `XDR_BLOCK_<ip>` deny rule — stops further authentication attempts | `unblock_ip <same IP>` |
| 2 | `lock_account` | Username targeted | Endpoint NSSM service OR Server host | `net user <username> /active:no` — disables the account, preventing credential use even if password is guessed | `unlock_account <same username>` — `net user <username> /active:yes` |

**Notes:** Username is validated with strict allowlist regex `^[\w\-\. ]{1,20}$` before being passed to `net.exe` — prevents command injection. Services: SSH (22), RDP (3389), FTP (21), VNC (5900), MSSQL (1433), MySQL (3306), Telnet (23).

---

##### DATA_EXFIL → Infiltration

**MITRE:** T1190 — Exploit Public-Facing Application | **Auto-Execute:** ✅ Yes (CRITICAL severity)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `isolate_host` | Compromised endpoint | Endpoint NSSM service OR Server host | Writes `isolation_flag.txt` + `netsh interface set interface <NIC> disable` — cuts all network connectivity to stop ongoing data exfiltration | `unisolate_host` — deletes flag + `netsh interface set interface <NIC> enable` |
| 2 | `scan_filesystem` | Endpoint | Endpoint NSSM service OR Server host | Scans for recently dropped web shells, staged data archives, and exfiltration tools | No rollback needed (read-only) |

**Notes:** The NIC name is read from `endpoint_config.json` (auto-detected by `identity.py` at startup using psutil — prefers Wi-Fi → Wireless → Ethernet → first UP adapter). The isolation flag is always written even if `netsh` fails — the backend and agent both check this file.

---

### 1.2 ML-Based Detections (CIC-IDS2017 RandomForest)

Two-gate pipeline applied to flows not caught by rules.

**Gate 1 — Personal Baseline IsolationForest** (`personal_baseline_model.pkl`)
- Trained on the operator's own normal traffic.
- If the flow looks like the operator's normal → classified BENIGN, skip Gate 2.
- If anomalous → passed to Gate 2.

**Gate 2 — CIC-IDS2017 RandomForest Classifier** (`network_classifier.pkl`)
- Feature set: 63 CIC-IDS2017 flow features (packet lengths, IAT, flags, bytes/s, packets/s, flow duration); 49 computed from Suricata eve.json aggregates, 14 zeroed due to missing per-packet data.
- Trained accuracy: 99.6%.
- Outputs attack class probabilities with top-3 breakdown.

| Attack Class | Severity | Auto-Execute | Notes |
|---|---|---|---|
| `BENIGN` | LOW | ❌ | Normal traffic — no alert |
| `PortScan` | HIGH (confidence > 70%) / MEDIUM | ❌ Never | Reconnaissance scanning |
| `BruteForce` | HIGH (confidence > 70%) / MEDIUM | ❌ (HIGH) / ✅ (CRITICAL post-fusion) | Credential brute-force |
| `WebAttack` | HIGH (confidence > 70%) / MEDIUM | ❌ (HIGH) / ✅ (CRITICAL) | Web application attacks |
| `DoS` | CRITICAL | ✅ | Denial of service |
| `DDoS` | CRITICAL | ✅ | Distributed denial of service |
| `Botnet` | CRITICAL | ✅ | Botnet / C2 communication |
| `Heartbleed` | CRITICAL | ✅ | CVE-2014-0160 OpenSSL memory disclosure |
| `Infiltration` | CRITICAL | ✅ | Active exploitation / exfiltration |
| Unknown (IsolationForest fallback) | MEDIUM | ❌ | Gate 2 model unavailable |

**Fallback path:** When `network_classifier.pkl` is absent, a standalone CIC IsolationForest (`network_model_isolation.pkl`) is used. Anomaly detected → `attack_type="Unknown"`, severity=MEDIUM.

#### 1.2 Response & Mitigation per ML Class

---

##### PortScan (ML)

**MITRE:** T1046 | **Auto-Execute:** ❌ Never

Same actions as rule-based PortScan above:
1. `block_ip` scanning source IP → rollback: `unblock_ip`
2. `monitor_persistence` (read-only audit) → no rollback

---

##### BruteForce (ML)

**MITRE:** T1110 | **Auto-Execute:** ❌ (HIGH) / ✅ (CRITICAL post-fusion)

Same actions as rule-based BRUTE_FORCE:
1. `block_ip` source IP → rollback: `unblock_ip`
2. `lock_account` targeted account → rollback: `unlock_account`

---

##### WebAttack (ML)

**MITRE:** T1190 — Exploit Public-Facing Application | **Auto-Execute:** ❌ (HIGH) / ✅ (CRITICAL)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `block_ip` | Attack source IP | Endpoint NSSM / Server | Block the IP conducting web attack (SQLi, XSS, path traversal, etc.) | `unblock_ip <same IP>` |
| 2 | `scan_filesystem` | Endpoint | Endpoint NSSM / Server | Scan for web shells or dropped payloads from successful exploitation | No rollback (read-only) |
| 3 | `monitor_persistence` | Endpoint | Endpoint NSSM / Server | Check for backdoor persistence installed post-exploitation | No rollback (read-only) |

---

##### DoS / DDoS (ML)

**MITRE:** T1498/T1499 | **Auto-Execute:** ✅ Yes (CRITICAL)

Same actions as rule-based SYN_FLOOD/DOS_FLOOD:
1. `block_ip` flood source → rollback: `unblock_ip`
2. `scan_filesystem` check for DDoS agent → no rollback

---

##### Botnet / C2 Beaconing (ML)

**MITRE:** T1071 — Application Layer Protocol | **Auto-Execute:** ✅ Yes (CRITICAL)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `block_ip` | C2 server IP | Endpoint NSSM / Server | Severs the command-and-control channel — extracted from `src_ip` field or SHAP IP features | `unblock_ip <C2 IP>` |
| 2 | `kill_process` | Beaconing process name | Endpoint NSSM / Server | `psutil.process.terminate()` by PID or name — terminates the process maintaining the C2 connection | Manual restart if process was legitimate (unlikely for confirmed C2) |
| 3 | `monitor_persistence` | Endpoint | Endpoint NSSM / Server | Enumerate HKCU Run keys, Startup folder, scheduled tasks — bots routinely install persistence | No rollback (read-only) |

**Notes:** If no valid C2 IP can be extracted from the fusion alert or SHAP explanation, `block_ip` is skipped entirely. `kill_process` is only issued when the process name is available in the fusion alert data.

---

##### Heartbleed (ML) — CVE-2014-0160

**MITRE:** T1499 — Endpoint Denial of Service | **Auto-Execute:** ✅ Yes (CRITICAL)

| # | SOAR Action | Target | Execution | Advisory? | Purpose | Rollback |
|---|------------|--------|-----------|-----------|---------|---------|
| 1 | `block_ip` | Exploiting source IP | Endpoint NSSM / Server | ❌ Executable | Firewall deny rule stops further OpenSSL heap read attempts | `unblock_ip <IP>` |
| 2 | `patch_openssl` | Endpoint | Advisory only (logged) | ✅ Advisory | Reminder to upgrade OpenSSL to ≥ 1.0.1g / ≥ 1.0.2 | N/A |
| 3 | `rotate_certificates` | Endpoint | Advisory only (logged) | ✅ Advisory | Revoke and reissue all TLS certificates — private keys may have been read from heap | N/A |
| 4 | `check_exposed_secrets` | Endpoint | Advisory only (logged) | ✅ Advisory | Audit for API keys, passwords, session tokens potentially leaked from OpenSSL memory | N/A |

**Notes:** Advisory actions (2–4) are logged in `response_advisory_logs` and shown in the ResponseModal but are never forwarded to the endpoint agent or server SOAR executor — they require manual human action.

---

##### Infiltration (ML)

**MITRE:** T1190 | **Auto-Execute:** ✅ Yes (CRITICAL)

Same actions as DATA_EXFIL rule:
1. `isolate_host` → rollback: `unisolate_host`
2. `scan_filesystem` → no rollback

---

## 2. User Behavior Layer

Source files: `Backend/agents/user_behavior_agent.py`, `User Behavior/final_model_backend_only/xdr_runtime.py`

The user behavior layer runs two separate scoring paths that are both active concurrently.

---

### 2.1 Session Heuristic Rules (Endpoint Agent)

Applied in real-time to every endpoint telemetry snapshot. No ML model required. Anomaly threshold: score ≥ 0.70.

| Indicator | Score Added | Flag | Trigger Condition |
|-----------|-------------|------|-------------------|
| System account interactive session | +0.60 | `system_account_session` | `current_user` matches `SYSTEM`, `NT AUTHORITY\SYSTEM`, `LOCAL SERVICE`, or `NETWORK SERVICE` |
| Excessive concurrent sessions | +0.30 | `excess_sessions` | ≥ 4 simultaneous sessions |
| Elevated concurrent sessions | +0.15 | _(none)_ | Exactly 3 simultaneous sessions |
| Multiple remote sessions after hours | +0.50 | `multiple_remote_after_hours` | ≥ 2 remote IP sessions + login time before 05:00 or after 23:00 |
| Remote session after hours | +0.30 | `remote_after_hours` | 1 remote IP session + unusual hours |
| Excessive remote sessions (daytime) | +0.30 | `excess_remote_sessions` | ≥ 3 remote IP sessions during normal hours |

**Scoring design invariants:**

| Scenario | Score | Classification |
|----------|-------|----------------|
| 1 remote session + business hours | 0.00 | NORMAL (RDP admin) |
| 1 remote session + 1am | 0.30 | NORMAL (borderline) |
| 2 remote sessions + 1am | 0.50 | NORMAL (needs additional signal) |
| SYSTEM account alone | 0.60 | NORMAL (borderline) |
| SYSTEM account + remote at 1am | 0.90 | **ANOMALY** |
| 4+ sessions | 0.30 | NORMAL (needs second factor) |

#### 2.1 Response & Mitigation — Insider Threat (Session Heuristics)

**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts | **Auto-Execute:** ❌ Never (Insider Threat is on the no-auto-execute list)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `lock_account` | Anomalous username | Endpoint NSSM / Server | `net user <username> /active:no` — prevents further logins while investigation proceeds | `unlock_account <same username>` |
| 2 | `monitor_persistence` | Endpoint | Endpoint NSSM / Server | Audit HKCU Run keys, Startup folder, scheduled tasks — insider actors often install staging tools | No rollback (read-only) |

---

### 2.2 OC-SVM Model Detections (Winlogbeat / Windows Event Logs)

Runs every 300 seconds. Reads Winlogbeat NDJSON logs from `C:\XDR_Logs\` (2-hour lookback by default). Model: One-Class SVM trained on CERT Insider Threat Dataset r4.2.

**Feature set (19 dimensions):**

| Feature | Description |
|---------|-------------|
| `file_ops_count` | Total file operations (Sysmon events 11, 15, 23) |
| `file_write_count` | File write/create operations |
| `file_read_count` | File read/stream operations |
| `unique_files_accessed` | Count of distinct file paths touched |
| `file_ops_rate` | File operations per second over active window |
| `logon_count` | Successful logons (Event 4624) |
| `logoff_count` | Logoffs (Event 4634, 4647) |
| `failed_logon_count` | Failed logons (Event 4625) |
| `after_hours_activity` | Events outside 09:00–18:00 |
| `device_connects` | USB device connect events |
| `device_disconnects` | USB device disconnect events |
| `device_events` | Total USB/removable media events |
| `emails_sent` | Email send events (SMTP / Outlook) |
| `unique_recipients` | Distinct email recipients |
| `O` (Openness) | Event-source provider diversity ratio |
| `C` (Conscientiousness) | Login-time regularity (inverted std-dev of logon hours) |
| `E` (Extraversion) | Proportion of network (Type-3) logons |
| `A` (Agreeableness) | Inverse of failed-auth ratio |
| `N` (Neuroticism) | After-hours event ratio |

**Anomaly reasons emitted when the model flags a user:**

| Reason | Trigger |
|--------|---------|
| `Fast-path rule: file_ops_count exceeded {threshold}` | Fast-path override fired (see §2.3) |
| `Elevated after-hours activity` | `after_hours_activity > 5` |
| `USB burst` | `device_events >= 10` |
| `High file activity ({N} ops)` | `file_ops_count >= 100` |
| `Repeated failed logons ({N})` | `failed_logon_count >= 5` |
| `Model score {S} >= threshold {T}` | OC-SVM decision function exceeds threshold |

**Windows Event IDs monitored:**

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Account logoff |
| 4647 | User-initiated logoff |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4720 | User account created |
| 4726 | User account deleted |
| 4740 | User account locked out |
| 11 (Sysmon) | FileCreate |
| 15 (Sysmon) | FileCreateStreamHash |
| 23 (Sysmon) | FileDelete |

#### 2.2 Response & Mitigation — OC-SVM Insider Threat

**MITRE:** T1078.004 | **Auto-Execute:** ❌ Never

Same response as session heuristics:
1. `lock_account` targeted username → rollback: `unlock_account`
2. `monitor_persistence` audit → no rollback

---

### 2.3 Fast-Path Rule Overrides

These bypass the OC-SVM model and force `ANOMALY` label immediately regardless of ML score.

| Rule | Threshold | Anomaly Score |
|------|-----------|---------------|
| Bulk file operations | `file_ops_count ≥ 300` | Boosted to 1.0 |
| Mass directory scan | `_unique_dirs ≥ 50` | Boosted to 1.0 |
| USB burst override | `device_events ≥ 10` (configurable via `XDR_FAST_PATH_FILE_OPS`) | Forced ANOMALY |

**Fast-path mitigation:** Same Insider Threat response plan — `lock_account` + `monitor_persistence` with analyst approval required.

---

## 3. System Monitor Layer

Source file: `Backend/agents/system_monitor_agent.py`

Collects 20 psutil features at 1 Hz. Maintains a 60-second rolling window. LSTM Autoencoder produces a reconstruction error score normalized to [0.0, 1.0].

---

### 3.1 LSTM Autoencoder Detections

**Architecture:** Encoder LSTM (20→64) → Bottleneck Linear (64→32) → Decoder LSTM (32→64) → Output Linear (64→20). Trained on live endpoint telemetry.

**20 monitored features:**

| Feature | Description |
|---------|-------------|
| `cpu_percent` | CPU utilization (0–100) |
| `mem_percent` | RAM utilization (0–100) |
| `disk_read_bytes_norm` | Disk read delta per tick (MB) |
| `disk_write_bytes_norm` | Disk write delta per tick (MB) |
| `net_bytes_sent_norm` | Network send delta per tick (MB) |
| `net_bytes_recv_norm` | Network receive delta per tick (MB) |
| `num_processes` | Total running process count |
| `num_threads` | Total thread count across all processes |
| `cpu_freq_current` | CPU frequency (normalized ~1.0) |
| `swap_percent` | Swap/page file usage |
| `open_files_count` | Open file handles for the agent process |
| `ctx_switches_norm` | Context switch delta / 1000 |
| `interrupts_norm` | Hardware interrupt delta / 1000 |
| `disk_read_count_norm` | Disk read operation count delta / 100 |
| `disk_write_count_norm` | Disk write operation count delta / 100 |
| `net_packets_sent_norm` | Network packets sent delta / 100 |
| `net_packets_recv_norm` | Network packets received delta / 100 |
| `net_errin_norm` | Network receive error delta / 10 |
| `net_errout_norm` | Network send error delta / 10 |
| `mem_available_norm` | Available physical RAM (GB) |

**Anomaly detection:** Reconstruction MSE of the 60-second window is normalized against a 99th-percentile adaptive threshold (re-calibrated every 60 windows, ×1.5 headroom). Outputs `anomaly_score` in [0.0, 1.0].

**Attack patterns detected via unusual telemetry patterns:**

| Behavior | Observable Signal | Typical Attack | MITRE | Response Triggered |
|----------|------------------|----------------|-------|--------------------|
| CPU spike sustained over window | High `cpu_percent` reconstruction error | Cryptominer, ransomware encryption loop | T1496 / T1486 | Ransomware or System Anomaly plan |
| Memory exhaustion | High `mem_percent`, low `mem_available_norm` | Memory-based DoS, process injection | T1499 / T1055 | System Anomaly plan |
| Disk I/O storm | Spike in `disk_write_bytes_norm` + `disk_write_count_norm` | Ransomware mass file encryption | T1486 | Ransomware response plan (if fusion confirms) |
| Network I/O burst | Spike in `net_bytes_sent_norm` + `net_packets_sent_norm` | Data exfiltration, DDoS participation | T1048 / T1498 | System Anomaly + network correlation |
| Process count anomaly | Unusual `num_processes` or `num_threads` delta | Process injection, spawning malicious child chains | T1055 | System Anomaly plan |
| Context switch explosion | High `ctx_switches_norm` + `interrupts_norm` | Rootkit activity, kernel-level manipulation | T1014 | Rootkit response plan |
| Network errors | Spike in `net_errin_norm` / `net_errout_norm` | Network stack abuse, flooding | T1499 | System Anomaly plan |

#### 3.1 Response & Mitigation — System Anomalies

Only triggers when `is_genuinely_anomalous = True` (final severity HIGH or CRITICAL after resource-aware check).

**Ransomware Activity (corroborated by fusion — malware + system):**

**MITRE:** T1486 | **Auto-Execute:** ✅ Yes (CRITICAL)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `kill_process` | Encrypting process name | Endpoint NSSM / Server | Terminates the process responsible for CPU/disk spike encryption loop | Manual restart if false positive |
| 2 | `isolate_host` | Endpoint | Endpoint NSSM / Server | Disables NIC to stop ransomware spreading to network shares | `unisolate_host` |
| 3 | `scan_filesystem` | Endpoint | Endpoint NSSM / Server | Find encrypted files and dropper artifacts in watch paths | No rollback (read-only) |
| 4 | `monitor_persistence` | Endpoint | Endpoint NSSM / Server | Check for autorun keys installed by ransomware dropper | No rollback (read-only) |

**System Anomaly (standalone — no malware corroboration):**

**MITRE:** T1496 | **Auto-Execute:** ❌ (HIGH) / ✅ (CRITICAL)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `scan_filesystem` | Endpoint | Endpoint NSSM / Server | Check for suspicious binaries recently modified | No rollback (read-only) |
| 2 | `monitor_persistence` | Endpoint | Endpoint NSSM / Server | Enumerate persistence mechanisms | No rollback (read-only) |

---

### 3.2 Resource-Aware Severity Overrides

Applied after ML scoring to prevent false CRITICAL alerts during normal heavy workloads.

| CPU % | Memory % | ML Score | Final Severity |
|-------|----------|----------|----------------|
| > 85 OR mem > 95 | — | ≥ 0.65 | **CRITICAL** |
| > 85 OR mem > 95 | — | ≥ 0.35 | **HIGH** |
| > 85 OR mem > 95 | — | < 0.35 | MEDIUM |
| > 80 | > 80 | ≥ 0.35 | **HIGH** |
| > 80 | > 80 | < 0.35 | MEDIUM |
| > 70 OR mem > 90 | — | ≥ 0.35 | MEDIUM |
| Below all thresholds | — | ML=CRITICAL | Capped at MEDIUM |
| Below all thresholds | — | ML=HIGH | Capped at MEDIUM |

The `is_genuinely_anomalous` flag is `true` only when final severity is HIGH or CRITICAL. Only genuine anomalies trigger SOAR isolation actions.

---

### 3.3 Heuristic Rules (Degraded / Warmup Mode)

Used when LSTM model is not yet loaded or the 60-second buffer is not yet full (fires every 5 seconds during warmup).

| CPU % | CPU Score | Memory % | Memory Score |
|-------|-----------|----------|--------------|
| > 95 | 1.0 | > 95 | 0.85 |
| > 85 | 0.80 | > 90 | 0.60 |
| > 75 | 0.60 | > 85 | 0.40 |
| > 65 | 0.40 | ≤ 85 | 0.0 |
| ≤ 65 | 0.0 | — | — |

Final heuristic score = `max(cpu_score, mem_score)`.

---

## 4. Malware Analysis Layer

Source file: `Backend/agents/malware_analysis_agent.py`

Two complementary methods: static PE file analysis (server-initiated) and process metadata heuristics (from endpoint agent telemetry).

---

### 4.1 Static PE File Analysis (EMBER / LightGBM)

Model: LightGBM classifier trained on EMBER 2018 dataset. **AUC-ROC: 0.9803, F1: 0.9298, Accuracy: 0.9284.**

Feature vector: **280 dimensions** covering:
- Byte histogram (256 values)
- Shannon entropy (1 value)
- PE header features: file size, virtual size, debug/exports/imports/resources/signature/TLS/symbols/architecture/timestamp/sections/subsystem (13 values)
- Section statistics: max entropy, avg entropy, avg size, executable sections, writable sections (5 values)
- Import/export counts (3 values)
- Printable string entropy and count (2 values)

**3-Tier Output Labels:**

| Score Range | Label | Prediction | Meaning |
|-------------|-------|------------|---------|
| < 0.30 | `benign` | `BENIGN` | No malware indicators |
| 0.30 – 0.69 | `suspicious` | `SUSPICIOUS` | Partial malware indicators; investigate |
| ≥ 0.70 | `malicious` | `MALICIOUS` | High-confidence malware — triggers SOAR `quarantine_file` when score ≥ 0.85 |

**Trust Caps (applied before labeling):**

| Condition | Score Cap | `trusted` | `trust_reason` |
|-----------|-----------|-----------|----------------|
| Path matches known-safe directories | 0.40 | true | `known_safe_path` |
| Digitally signed binary (`has_signature=1`) AND score < 0.85 | 0.50 | true | `signed_binary` |

**Known-Safe Path Patterns (score capped at 0.40):**
- `site-packages` (Python packages)
- `\Python3\`, `\Python{N}\`
- `C:\Windows\System32`
- `C:\Windows\SysWOW64`
- `C:\Program Files\`
- `C:\Program Files (x86)\`

**Watched Directories (background file watcher):**
- `C:\Users`
- `C:\Temp`
- `C:\Windows\Temp`
- `C:\ProgramData`
- `C:\Downloads`

#### 4.1 Response & Mitigation — Malware (PE Static Analysis)

**MITRE:** T1204 — User Execution | **Auto-Execute:** ✅ Yes when score ≥ 0.85 AND `trusted = False`

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `quarantine_file` | Absolute path of malicious file | Endpoint NSSM / Server | `shutil.move(src, endpoint_agent/quarantine/<basename>)` — removes file from execution path without deleting evidence | `restore_quarantine_file <original_absolute_path>` — moves file back to original location |
| 2 | `kill_process` | Process name running the file | Endpoint NSSM / Server | Terminate the malicious process by name or PID | Manual restart if confirmed false positive |
| 3 | `scan_filesystem` | Endpoint | Endpoint NSSM / Server | Full scan of watch paths for additional dropped payloads | No rollback (read-only) |
| 4 | `block_ip` | C2 IP (if extracted) | Endpoint NSSM / Server | Block suspected C2 communication channel | `unblock_ip <same IP>` |

**Escalation path:** When `malware_score ≥ 0.85` the Fusion Engine hard-overrides the threat score floor to **0.93 (CRITICAL)** via Rule A regardless of other model scores.

**SUSPICIOUS files (0.30–0.69):** No auto-execute. Response plan generated for analyst review only.

---

### 4.2 Process Metadata Heuristics (Endpoint Agent)

Used when PE file bytes are unavailable (endpoint telemetry only reports process names). Scores against 22 known-malicious process name substrings.

| Tool / Process Name | Category | Score Added |
|--------------------|----------|-------------|
| `mimikatz` | Credential Dumping | +0.40 |
| `meterpreter` | Metasploit Payload / RAT | +0.40 |
| `cobaltstrike`, `cobalt_strike` | C2 Framework | +0.40 |
| `bloodhound`, `sharphound` | Active Directory Enumeration | +0.40 |
| `rubeus` | Kerberos Attack (TGT/ST abuse) | +0.40 |
| `certify` | AD Certificate Services Abuse | +0.40 |
| `powersploit` | PowerShell Attack Framework | +0.40 |
| `invoke-mimikatz` | PowerShell Credential Dumping | +0.40 |
| `empire` | Post-Exploitation Framework | +0.40 |
| `ncat`, `netcat`, `nc.exe` | Reverse Shell / Tunneling | +0.40 |
| `psexec` | Remote Execution | +0.40 |
| `wmiexec` | WMI-based Remote Execution | +0.40 |
| `smbexec` | SMB-based Remote Execution | +0.40 |
| `xmrig`, `monero` | Cryptocurrency Miner | +0.40 |
| `cryptonight` | Cryptocurrency Miner | +0.40 |
| `beacon.exe` | C2 Beacon (Cobalt Strike) | +0.40 |
| `metasploit` | Exploitation Framework | +0.40 |

Maximum score from name matching: 0.90 (capped). Multiple matches accumulate additively up to the cap.

#### 4.2 Response & Mitigation — Process Heuristics

**MITRE:** T1059 — Command and Scripting Interpreter | **Auto-Execute:** ✅ (CRITICAL) / ❌ (HIGH)

| # | SOAR Action | Target | Execution | Purpose | Rollback |
|---|------------|--------|-----------|---------|---------|
| 1 | `kill_process` | Detected process name | Endpoint NSSM / Server | Terminates the IOC-matched process (e.g., `mimikatz.exe`, `xmrig.exe`, `beacon.exe`) | Manual restart only if false positive confirmed by analyst |
| 2 | `scan_filesystem` | Endpoint | Endpoint NSSM / Server | Find the binary on disk and any related dropped files | No rollback (read-only) |
| 3 | `block_ip` | C2 IP if available | Endpoint NSSM / Server | Block outbound C2 channel (relevant for meterpreter, empire, cobaltstrike) | `unblock_ip <C2 IP>` |

---

### 4.3 Suspicious Launch Path Detection

Applied on top of name matching. Processes launched from these path fragments receive an additional +0.15 per match (max +0.30 total).

| Path Fragment | Risk Reason |
|---------------|-------------|
| `\temp\` | Malware staging common in temp directories |
| `\tmp\` | Temporary execution area |
| `%appdata%` | Persistence location for many malware families |
| `\downloads\` | Drive-by download execution |
| `\$recycle` | Recycle Bin — common for hiding malware |

---

### 4.4 Watched File Extensions

The background file watcher monitors new files with these extensions in the watched directories:

`.exe` `.dll` `.sys` `.scr` `.bat` `.ps1` `.vbs`

---

## 5. Fusion Engine — Cross-Layer Correlations

Source file: `Backend/agents/fusion_engine_agent.py`, `Backend/fusion_engine.py`

The fusion engine combines all four model scores into a single weighted threat score and applies escalation rules when multiple models corroborate each other.

**Base formula:**
```
threat_score = (network × 0.35) + (user × 0.30) + (system × 0.15) + (malware × 0.20)
```

### Corroboration Bonuses

| Active Models (score > 0.30) | Bonus |
|-----------------------------|-------|
| 3 or more | × 1.20 (+20%) |
| 2 | × 1.10 (+10%) |
| 1 | None |

### Escalation Hard-Overrides

These override the weighted score floor regardless of individual model values:

| Rule | Condition | Score Floor | Reason Emitted |
|------|-----------|-------------|----------------|
| **Rule A — Confirmed Malware** | `malware_score ≥ 0.85` | 0.93 (CRITICAL) | `"Confirmed malware detection — CRITICAL escalation"` |
| **Rule B — Synchronized Attack + System Impact** | `network_score ≥ 0.80` AND `system_score ≥ 0.50` | 0.82 (HIGH) | `"Synchronized network attack + system impact — HIGH escalation"` |
| **Rule C — Critical Insider Threat** | `user_score ≥ 0.80` | 0.75 (HIGH) | `"Critical insider threat indicator"` |
| **Rule D — Malware + Network Correlation** | `malware_score ≥ 0.60` AND `network_score ≥ 0.50` | 0.75 (HIGH) | `"Malware + network activity correlation — HIGH escalation"` |

### Correlated Attack Patterns (from `fusion_engine.py`)

| Correlated Sources | Detected Attack | Condition | Response Plan |
|--------------------|-----------------|-----------|---------------|
| `network` + `system` | Ransomware Activity | `malware label == "malicious"` AND `trusted == False` AND `system severity in {HIGH, CRITICAL}` | Ransomware plan: `kill_process` + `isolate_host` + `scan_filesystem` + `monitor_persistence` |
| `network` + `user` | Insider + Network | High user + network scores | Insider Threat plan: `lock_account` + `monitor_persistence` |
| `malware` + `network` | C2 Activity | Malware ≥ 0.60 + Network ≥ 0.50 | C2 plan: `block_ip` + `kill_process` + `monitor_persistence` |
| 3+ sources | Multi-Domain Attack | Any 3+ models exceeding 0.30 threshold | Most severe matching plan based on `attack_type` |

### Score → Severity Mapping

| Threat Score | Severity | `should_respond` | Auto-Execute SOAR |
|-------------|----------|-----------------|-------------------|
| ≥ 0.85 | **CRITICAL** | ✅ Yes | ✅ Yes |
| 0.70 – 0.84 | **HIGH** | ✅ Yes | ❌ No (analyst approval) |
| 0.35 – 0.69 | MEDIUM | ❌ No | ❌ No |
| < 0.35 | LOW | ❌ No | ❌ No |

---

## 6. MITRE ATT&CK Technique Mapping

Source file: `Backend/response_engine.py`

Every detected attack type is mapped to a MITRE ATT&CK technique. Response plans include the technique ID.

| Attack Type | MITRE Technique | Tactic | Executable SOAR Actions | Advisory Actions |
|-------------|-----------------|--------|-------------------------|-----------------|
| Ransomware | **T1486** — Data Encrypted for Impact | Impact | `kill_process`, `isolate_host`, `scan_filesystem`, `monitor_persistence` | — |
| C2 Beaconing / Botnet | **T1071** — Application Layer Protocol | Command and Control | `block_ip`, `kill_process`, `monitor_persistence` | — |
| Privilege Escalation | **T1068** — Exploitation for Privilege Escalation | Privilege Escalation | `kill_process`, `lock_account`, `monitor_persistence` | `log_user_session`, `restrict_access` |
| Lateral Movement | **T1021** — Remote Services | Lateral Movement | `isolate_host`, `block_ip` | `alert_admin` |
| PortScan / Port Scan | **T1046** — Network Service Discovery | Discovery | `block_ip`, `monitor_persistence` | — |
| DDoS / DoS | **T1498 / T1499** — Network / Endpoint DoS | Impact | `block_ip`, `scan_filesystem` | `rate_limit_traffic` |
| Brute Force | **T1110** — Brute Force | Credential Access | `block_ip`, `lock_account` | — |
| Heartbleed (CVE-2014-0160) | **T1499** — Endpoint Denial of Service | Impact | `block_ip` | `patch_openssl`, `rotate_certificates`, `check_exposed_secrets` |
| Infiltration | **T1190** — Exploit Public-Facing Application | Initial Access | `isolate_host`, `scan_filesystem` | — |
| Advanced Persistent / Unknown | **T1059** — Command and Scripting Interpreter | Execution | `scan_filesystem`, `monitor_persistence` | — |
| Insider Threat | **T1078.004** — Valid Accounts | Defense Evasion / Persistence | `lock_account`, `monitor_persistence` | `log_user_session` |
| Malware | **T1204** — User Execution | Execution | `quarantine_file`, `kill_process`, `scan_filesystem` | — |
| System Anomaly | **T1496** — Resource Hijacking | Impact | `scan_filesystem`, `monitor_persistence` | — |
| Suspicious Process | **T1059** — Command and Scripting Interpreter | Execution | `kill_process`, `scan_filesystem` | — |
| Process Injection | **T1055** — Process Injection | Defense Evasion | `kill_process`, `scan_filesystem`, `monitor_persistence`, `isolate_host` (CRITICAL) | — |
| Persistence | **T1547** — Boot or Logon Autostart Execution | Persistence | `monitor_persistence`, `scan_filesystem` | — |
| Impossible Travel | **T1078** — Valid Accounts | Defense Evasion | `lock_account` | `force_logout` |
| Worm | **T1210** — Exploitation of Remote Services | Lateral Movement | `isolate_host`, `block_ip`, `kill_process`, `scan_filesystem` | — |
| Rootkit | **T1014** — Rootkit | Defense Evasion | `scan_filesystem`, `monitor_persistence`, `lock_account`, `isolate_host` | — |
| Trojan | **T1204** — User Execution | Execution | `quarantine_file`, `kill_process`, `scan_filesystem`, `block_ip` | — |
| WebAttack | **T1190** — Exploit Public-Facing Application | Initial Access | `block_ip`, `scan_filesystem`, `monitor_persistence` | — |

---

## 7. Severity & Scoring Reference

### Network Rule Confidence Levels

| Rule | Base Confidence | Scaling |
|------|----------------|---------|
| `PORT_SCAN_HORIZONTAL` | 70% | +0.5% per extra port above threshold (max 99%) |
| `HOST_SWEEP` | 90% | Fixed |
| `SYN_FLOOD` | 97% | Fixed |
| `DOS_FLOOD` | 96% | Fixed |
| `BRUTE_FORCE` | 75% | +0.5% per extra connection above 20 (max 99%) |
| `DATA_EXFIL` | 88% | Fixed |

### Fusion Score Thresholds

| Threshold | Value | Meaning |
|-----------|-------|---------|
| LOW→MEDIUM | 0.35 | Low-risk anomaly, informational only |
| MEDIUM→HIGH | 0.70 | Actionable threat — response plan generated |
| HIGH→CRITICAL | 0.85 | Immediate response — SOAR auto-executes |
| Malware escalation | 0.85 | Forces threat score floor to 0.93 (CRITICAL) |

### Malware Score Tiers

| Score | Label | Dashboard Color | Trust Override |
|-------|-------|-----------------|----------------|
| < 0.30 | benign | Green | — |
| 0.30–0.69 | suspicious | Orange | — |
| ≥ 0.70 | malicious | Red | None (unless trusted path / signed) |
| ≥ 0.85 | malicious | Red (CRITICAL) | `quarantine_file` SOAR fires automatically |

### System Monitor Score Thresholds

| ML Score | Base Severity |
|----------|--------------|
| ≥ 0.85 | CRITICAL (overridden by resource-aware check) |
| ≥ 0.65 | HIGH |
| ≥ 0.35 | MEDIUM |
| < 0.35 | LOW |

---

## 8. SOAR Action Reference with Rollbacks

This section documents every executable SOAR action available in Cyber Sentinel XDR, how it executes on both the endpoint (NSSM service) and the server host, and the exact rollback procedure to reverse it.

### 8.1 Execution Architecture

```
SOC Analyst / Auto-Execute
        │
        ▼
POST /response/execute
        │
        ├─ endpoint_id = "server_host"
        │        └──► backend.py: _server_soar_loop()
        │                    └──► _server_soar_executor(action, target)
        │                              └──► Same logic as command_listener.py
        │
        └─ endpoint_id = "<any other endpoint>"
                 └──► MongoDB: endpoint_commands collection
                          └──► NSSM Service polls GET /endpoint/commands/{id} every 3s
                                    └──► command_listener.py: execute_command()
                                              └──► ACK via POST /endpoint/command/ack
```

**NSSM Service context:**
- Runs as `LocalSystem` account — has Administrator privileges on Windows.
- `CREATE_NO_WINDOW` flag suppresses all console/UAC popups.
- Full absolute paths prevent PATH-hijacking attacks in service context.
- If an action fails (non-zero exit code), the failure is logged, ACK'd, and the command loop continues — no crash.

---

### 8.2 Complete Action Reference

---

#### `block_ip`

| Property | Value |
|----------|-------|
| **Purpose** | Create Windows Firewall deny rules for a specific IPv4 address |
| **Execution** | `netsh advfirewall firewall add rule name=XDR_BLOCK_<ip> dir=in action=block remoteip=<ip>` + same for `dir=out` |
| **Runs on** | Endpoint (NSSM service) or Server host (backend SOAR loop) |
| **Security** | IP validated by strict regex `^(\d{1,3}\.){3}\d{1,3}$` before any subprocess call. `shell=False`. Never a placeholder target. |
| **Timeout** | 15 seconds per netsh call |
| **Effect** | Both inbound and outbound traffic to/from the IP is dropped at kernel level |
| **Rule naming** | `XDR_BLOCK_<ip>` — consistent prefix allows easy bulk cleanup |
| **Rollback action** | `unblock_ip` |
| **Rollback detail** | `netsh advfirewall firewall delete rule name=XDR_BLOCK_<ip>` — deletes both directions in one command |
| **Manual rollback** | `netsh advfirewall firewall delete rule name=XDR_BLOCK_<ip>` (run as Administrator) |

---

#### `unblock_ip`

| Property | Value |
|----------|-------|
| **Purpose** | Remove firewall deny rules previously created by `block_ip` |
| **Execution** | `netsh advfirewall firewall delete rule name=XDR_BLOCK_<ip>` |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Rollback** | N/A — this is itself a rollback action. Restores full connectivity to the IP. |

---

#### `isolate_host`

| Property | Value |
|----------|-------|
| **Purpose** | Completely cut a host's network connectivity to contain active threats |
| **Execution** | (1) Write `endpoint_agent/isolation_flag.txt` (always, even if NIC disable fails) → (2) `netsh interface set interface "<NIC>" disable` |
| **NIC detection** | Read from `endpoint_config.json` (auto-detected at NSSM service startup via psutil: Wi-Fi → Wireless → Ethernet → first UP adapter) |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Security** | `shell=False`. NIC name from trusted config file, not user input. |
| **Effect** | All network communication severed. Agent loop continues running locally — can still receive commands from a management-out-of-band channel if one exists. |
| **Flag file** | `isolation_flag.txt` written with content `"ISOLATED"` — both agent and backend check this file |
| **Rollback action** | `unisolate_host` |
| **Rollback detail** | Deletes `isolation_flag.txt` + `netsh interface set interface "<NIC>" enable` |
| **Manual rollback** | Physical console access or IPMI/iDRAC → run `netsh interface set interface "<NIC>" enable` as Administrator |

---

#### `unisolate_host`

| Property | Value |
|----------|-------|
| **Purpose** | Re-enable a previously isolated host's network interface |
| **Execution** | (1) Delete `isolation_flag.txt` → (2) `netsh interface set interface "<NIC>" enable` |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Rollback** | N/A — this is itself a rollback action. Restores full network connectivity. |

---

#### `kill_process`

| Property | Value |
|----------|-------|
| **Purpose** | Terminate a malicious or suspicious running process |
| **Execution by PID** | `psutil.Process(int(pid)).terminate()` — PID cast to `int()`, never interpolated as string |
| **Execution by name** | Iterates `psutil.process_iter()`, case-insensitive name match, calls `.terminate()` on all matches |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Security** | PID always cast to `int()`. No shell subprocess. psutil used directly. |
| **Effect** | `SIGTERM` sent to process (graceful termination). If process ignores SIGTERM, escalate manually with Task Manager. |
| **Rollback** | No automatic rollback. Processes terminated by SOAR are assumed malicious. If confirmed false positive: manually restart the process or service. |
| **Manual rollback** | Restart the application/service manually. For Windows services: `sc start <service_name>` |

---

#### `quarantine_file`

| Property | Value |
|----------|-------|
| **Purpose** | Remove a malicious file from its execution path without permanently deleting it |
| **Execution** | `shutil.move(src_path, endpoint_agent/quarantine/<basename>)` |
| **Validation** | Source path must be absolute. File must exist. No shell subprocess. |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Storage** | `endpoint_agent/quarantine/` subdirectory — survives agent restarts |
| **Effect** | File moved out of watched/execution path. Original location empty. File preserved for forensic analysis. |
| **Rollback action** | `restore_quarantine_file <original_absolute_path>` |
| **Rollback detail** | `shutil.move(quarantine/<basename>, original_absolute_path)` — recreates parent dirs if needed |
| **Manual rollback** | Move `endpoint_agent/quarantine/<filename>` back to its original location manually |

---

#### `restore_quarantine_file`

| Property | Value |
|----------|-------|
| **Purpose** | Restore a previously quarantined file back to its original location (false positive recovery) |
| **Execution** | `shutil.move(quarantine/<basename>, original_path)` — creates parent directories if missing |
| **Target** | Original absolute path (not the quarantine path) — basename is derived automatically |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Rollback** | N/A — this is itself a rollback action |

---

#### `lock_account`

| Property | Value |
|----------|-------|
| **Purpose** | Disable a Windows local user account to prevent further logins |
| **Execution** | `net user <username> /active:no` |
| **Validation** | Username validated against `^[\w\-\. ]{1,20}$` — strict allowlist prevents command injection |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Security** | `shell=False`. Full path `C:\Windows\System32\net.exe`. No string interpolation. |
| **Effect** | Account disabled in SAM database. Existing sessions remain until session timeout. New logins rejected. |
| **Rollback action** | `unlock_account <same username>` |
| **Rollback detail** | `net user <username> /active:yes` — re-enables the account |
| **Manual rollback** | Run `net user <username> /active:yes` as Administrator |

---

#### `unlock_account`

| Property | Value |
|----------|-------|
| **Purpose** | Re-enable a previously disabled Windows local user account |
| **Execution** | `net user <username> /active:yes` |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **Rollback** | N/A — this is itself a rollback action. Restores login capability. |

---

#### `scan_filesystem`

| Property | Value |
|----------|-------|
| **Purpose** | Enumerate recently modified suspicious files across watched directories |
| **Execution** | `os.walk()` over `C:\Users`, `C:\Temp`, `C:\Windows\Temp`, `C:\ProgramData` |
| **Filter** | Extensions: `.exe .dll .ps1 .bat .vbs .scr` modified within the last 3600 seconds |
| **Excluded dirs** | `AppData`, `node_modules`, `.git`, `venv`, `__pycache__` |
| **Returns** | `count` of matching files + `files` list of top-10 by modification time |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **System changes** | None — purely read-only filesystem walk |
| **Rollback** | None needed — no system state changed |

---

#### `monitor_persistence`

| Property | Value |
|----------|-------|
| **Purpose** | Audit three common Windows persistence mechanisms |
| **Checks performed** | (1) `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` values via `winreg` → (2) `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` folder listing → (3) `schtasks /query /fo CSV` count via `C:\Windows\System32\schtasks.exe` |
| **Returns** | `registry_run_keys[]`, `startup_files[]`, `scheduled_tasks` count |
| **Runs on** | Endpoint (NSSM service) or Server host |
| **System changes** | None — purely read-only audit |
| **Rollback** | None needed — no system state changed |

---

### 8.3 Advisory Actions (Logged Only — Not Auto-Executed)

These actions appear in response plans and are logged to `response_advisory_logs` in MongoDB, but are **never forwarded to the endpoint agent or server SOAR executor**. They require manual human action.

| Advisory Action | Meaning | How to Execute Manually |
|-----------------|---------|------------------------|
| `log_user_session` | Log the user session details for investigation | Review Windows Event Log 4624/4648 in Event Viewer |
| `restrict_access` | Reduce permissions for the flagged account | Active Directory: remove from privileged groups; local: edit group memberships |
| `rate_limit_traffic` | Apply traffic shaping or rate limiting to a source | Configure via router/firewall QoS or `netsh qos` policy |
| `log_event` | Log the security event for audit trail | Automated — event already stored in `security_events` MongoDB collection |
| `patch_openssl` | Upgrade OpenSSL to ≥ 1.0.1g (Heartbleed fix) | `winget upgrade openssl` or vendor patch; verify with `openssl version` |
| `rotate_certificates` | Revoke and reissue all TLS certificates | Use your PKI/CA (Let's Encrypt, internal CA) to revoke and reissue |
| `check_exposed_secrets` | Audit for API keys, tokens leaked from memory | Review secrets vaults; rotate all credentials; use `git secrets` scan |
| `update_software` | Update vulnerable software packages | `winget upgrade --all` or vendor-specific patch process |
| `force_logout` | Force logout all active sessions for an account | `query session` + `logoff <session_id>` as Administrator |
| `review_account` | Review the account's recent activity and permissions | Review `security_events` collection + Windows Security Event Log |
| `review_logs` | Review system and application logs for indicators | Windows Event Viewer + `C:\XDR_Logs\` Winlogbeat output |
| `invalidate_sessions` | Invalidate all JWT/auth sessions for a user | Admin → Profile → Force Logout All Sessions in the SOC dashboard |

---

### 8.4 Quick Rollback Reference Table

| Action Executed | Rollback Action | SOAR Command | Manual Alternative |
|-----------------|----------------|-------------|-------------------|
| `block_ip <IP>` | `unblock_ip <IP>` | Issue via ResponseModal or `POST /endpoint/command` | `netsh advfirewall firewall delete rule name=XDR_BLOCK_<IP>` |
| `isolate_host` | `unisolate_host` | Issue via ResponseModal or `POST /endpoint/command` | Physical/console: `netsh interface set interface "<NIC>" enable` |
| `quarantine_file <path>` | `restore_quarantine_file <original_path>` | Issue via ResponseModal or `POST /endpoint/command` | Move `endpoint_agent/quarantine/<basename>` back manually |
| `lock_account <user>` | `unlock_account <user>` | Issue via ResponseModal or `POST /endpoint/command` | `net user <user> /active:yes` (as Administrator) |
| `kill_process <name/PID>` | N/A (no auto-rollback) | — | `sc start <service>` or relaunch application manually |
| `scan_filesystem` | N/A (read-only) | — | — |
| `monitor_persistence` | N/A (read-only) | — | — |

---

*Document generated and verified from source code: `rule_detector.py`, `hybrid_detector.py`, `network_detection_agent.py`, `user_behavior_agent.py`, `xdr_runtime.py`, `system_monitor_agent.py`, `malware_analysis_agent.py`, `fusion_engine_agent.py`, `fusion_engine.py`, `response_engine.py`, `command_listener.py` (endpoint), `backend.py` (`_server_soar_executor`, `_server_soar_loop`, `_ADVISORY_ACTIONS`). Updated 2026-05-18.*
