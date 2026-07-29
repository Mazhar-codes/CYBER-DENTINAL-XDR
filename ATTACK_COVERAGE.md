# Cyber Sentinel XDR — Attack Detection & Mitigation Reference

**Version:** 1.0 XDR Platform  
**Detection Layers:** Network · Malware · System · User Behavior · Fusion Engine  
**Total Attacks Covered:** 30+ distinct attack types across 4 ML/rule-based detection layers

---

## Detection Architecture

```
Endpoint Telemetry / Suricata / Winlogbeat / Sysmon
           │
           ▼
┌──────────────────────────────────────────────────────────┐
│                    DETECTION LAYER                       │
│                                                          │
│  ┌─────────────┐  ┌──────────┐  ┌────────┐  ┌────────┐ │
│  │   Network   │  │ Malware  │  │ System │  │  User  │ │
│  │  Detection  │  │Analysis  │  │Monitor │  │Behavior│ │
│  │ Rule + ML   │  │LightGBM  │  │  LSTM  │  │OC-SVM  │ │
│  └──────┬──────┘  └────┬─────┘  └───┬────┘  └───┬────┘ │
│         └──────────────┴────────────┴────────────┘      │
│                             │                            │
│                    FUSION ENGINE                         │
│           net=35% · mal=20% · sys=15% · usr=30%         │
└─────────────────────────────┬────────────────────────────┘
                              │
                       Threat Score
                     ≥0.85 → CRITICAL
                     ≥0.70 → HIGH
                     ≥0.35 → MEDIUM
                              │
                       SOAR Response
         block_ip · isolate_host · kill_process · quarantine_file
         lock_account · scan_filesystem · monitor_persistence
```

---

## Layer 1 — Network Detection

**Models:** Deterministic Rule Engine + Personal IsolationForest (Gate 1) + CIC-IDS2017 RandomForest (Gate 2)  
**Data Source:** Suricata eve.json / psutil net_connections from endpoint agents

---

### 1. Horizontal Port Scan

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1046 — Network Service Discovery |
| **Detection Method** | Rule Engine: ≥15 unique destination ports from a single source IP within the observation window |
| **Severity** | HIGH (confidence: 70 + 0.5 per extra port, max 99%) |
| **Indicators** | Single source hitting many ports in sequence or rapid bursts; low bytes-per-connection |

**Mitigation Actions:**
1. **block_ip** — Block the scanning source IP at the firewall to stop reconnaissance
2. **monitor_persistence** — Check for implants dropped during the reconnaissance phase
3. Disable unused services and ports exposed to the network
4. Enable port-knocking or firewall geo-blocking on sensitive services
5. Alert the SOC and review IDS rules for the scanned port range

---

### 2. Host Sweep (Network Sweep)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1046 — Network Service Discovery |
| **Detection Method** | Rule Engine: ≥10 unique destination IPs contacted from a single source (ICMP or TCP) |
| **Severity** | HIGH (confidence: 90%) |
| **Indicators** | Low-latency probes across many hosts; often precedes lateral movement |

**Mitigation Actions:**
1. **block_ip** — Block the source IP performing the sweep
2. **monitor_persistence** — Check endpoints that were probed for dropped payloads
3. Segment the network using VLANs to limit blast radius
4. Enable ICMP rate-limiting on perimeter routers
5. Correlate with lateral movement attempts that typically follow

---

### 3. SYN Flood (TCP Flood DoS)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1498 — Network Denial of Service |
| **Detection Method** | Rule Engine: ≥500 SYN packets with ACK ratio < 10% (half-open connection flood) |
| **Severity** | CRITICAL (confidence: 97%) |
| **Indicators** | Massive SYN packet volume; growing half-open connection table; service degradation |

**Mitigation Actions:**
1. **block_ip** — Block the flood source IP immediately
2. Enable SYN cookies on the operating system TCP stack
3. Configure rate-limiting on the perimeter firewall for SYN packets
4. Deploy upstream DDoS scrubbing or CDN rate-limiting
5. Scale horizontally or redirect traffic through a load balancer

---

### 4. DoS / Packet Flood

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1498 — Network Denial of Service |
| **Detection Method** | Rule Engine: ≥1,000 packets/second from a single source; also detected by CIC RandomForest (DoS class) |
| **Severity** | CRITICAL (confidence: 96%) |
| **Indicators** | Sustained high-rate packet flow; bandwidth saturation; service unavailability |

**Mitigation Actions:**
1. **block_ip** — Drop packets from the flood source
2. **scan_filesystem** — Check for DoS agent or botnet client installed on the host
3. Implement traffic policing and shaping at the network edge
4. Contact upstream ISP for blackhole routing if volumetric
5. Review bandwidth baselines and set automated ACL triggers

---

### 5. DDoS (Distributed Denial of Service)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1498 — Network Denial of Service |
| **Detection Method** | CIC-IDS2017 RandomForest classifier (DDoS label); flow features: high packets/s, high bytes/s, short flow duration from many sources |
| **Severity** | CRITICAL |
| **Indicators** | Traffic from many distinct source IPs; abnormal flow inter-arrival times; target service unreachable |

**Mitigation Actions:**
1. **block_ip** — Block known flood source IPs
2. **scan_filesystem** — Look for DDoS botnet agent on local host
3. Activate upstream scrubbing center or BGP blackhole routing
4. Deploy anycast routing to distribute and absorb traffic
5. Implement rate-limiting per-source-IP at CDN/WAF layer

---

### 6. Brute Force Attack

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Detection Method** | Rule Engine: ≥20 connections to brute-force target ports (SSH:22, RDP:3389, FTP:21, VNC:5900, MSSQL:1433, MySQL:3306, Telnet:23); also CIC RandomForest (BruteForce class) |
| **Severity** | HIGH (confidence: 75 + 0.5 per connection, max 99%) |
| **Indicators** | Rapid sequential auth attempts; multiple 401/403 responses; targeting credential ports |

**Mitigation Actions:**
1. **block_ip** — Block the brute-force source IP after threshold breach
2. **lock_account** — Temporarily lock the targeted account to prevent credential compromise
3. Enforce account lockout policy after 5–10 failed attempts
4. Enable MFA on all remote access services (SSH keys over passwords, TOTP for RDP)
5. Move SSH/RDP to non-standard ports and restrict by IP allowlist
6. Deploy fail2ban or equivalent adaptive blocking

---

### 7. Data Exfiltration

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1041 — Exfiltration Over C2 Channel |
| **Detection Method** | Rule Engine: outbound data ≥50 MB with upload-to-download ratio ≥5.0 |
| **Severity** | CRITICAL (confidence: 88%) |
| **Indicators** | Large sustained outbound transfers; unusual destination; data volume anomaly during off-hours |

**Mitigation Actions:**
1. **isolate_host** — Cut the exfiltrating host from the network immediately
2. **block_ip** — Block the destination IP receiving the exfiltrated data
3. Implement Data Loss Prevention (DLP) policies on endpoints
4. Monitor outbound traffic volume baselines with automated alerts
5. Encrypt sensitive data at rest so raw exfiltration is less valuable
6. Review and restrict data access permissions using least-privilege

---

### 8. PortScan (ML-Detected)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1046 — Network Service Discovery |
| **Detection Method** | CIC-IDS2017 RandomForest (PortScan label); flow features: many short-lived flows, diverse ports, low bytes-per-flow |
| **Severity** | HIGH |
| **Indicators** | Statistically abnormal port diversity in flow set; tool signatures (Nmap, Masscan patterns) |

**Mitigation Actions:**
Same as Horizontal Port Scan above. ML detection catches low-and-slow scans that evade the rule threshold.

---

### 9. Botnet / C2 Beaconing

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1071 — Application Layer Protocol (C2) |
| **Detection Method** | CIC-IDS2017 RandomForest (Botnet label); Fusion Engine correlation: periodic traffic pattern + system anomaly; flow features: regular inter-arrival times, small payload size, fixed destination |
| **Severity** | CRITICAL |
| **Indicators** | Periodic outbound connections at fixed intervals; encrypted small-payload traffic; unusual DNS queries |

**Mitigation Actions:**
1. **block_ip** — Block the C2 server IP to cut the command channel
2. **kill_process** — Terminate the process responsible for beaconing
3. **monitor_persistence** — Check for scheduled tasks or registry run-key persistence
4. Inspect DNS traffic for DGA (Domain Generation Algorithm) patterns
5. Implement DNS sinkholes for known C2 domains
6. Deploy endpoint behavioral detection for periodic callback activity
7. Rotate all credentials on the compromised host

---

### 10. Infiltration / Remote Exploitation

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1190 — Exploit Public-Facing Application |
| **Detection Method** | Rule Engine: large inbound payload + suspicious pattern; CIC-IDS2017 RandomForest (Infiltration label) |
| **Severity** | CRITICAL |
| **Indicators** | Exploitation payload in network flow; anomalous process spawned from network service; web shell activity |

**Mitigation Actions:**
1. **isolate_host** — Contain the compromised host immediately
2. **scan_filesystem** — Scan for web shells, backdoors, and dropped payloads
3. **block_ip** — Block the attacker's source IP
4. Patch the exploited vulnerability immediately
5. Review web application firewall (WAF) rules
6. Restore from a clean snapshot if exploitation is confirmed

---

### 11. Heartbleed (CVE-2014-0160)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1499 — Endpoint Denial of Service (OpenSSL memory disclosure) |
| **Detection Method** | CIC-IDS2017 RandomForest (Heartbleed label); characteristic malformed TLS heartbeat request |
| **Severity** | CRITICAL |
| **Indicators** | Oversized TLS heartbeat requests; OpenSSL version 1.0.1–1.0.1f in use |

**Mitigation Actions:**
1. **block_ip** — Block the source IP exploiting the Heartbleed vulnerability
2. **patch_openssl** — Apply OpenSSL security patch to version ≥1.0.1g *(advisory)*
3. **rotate_certificates** — Rotate all TLS certificates and private keys potentially exposed
4. **check_exposed_secrets** — Audit for secrets leaked from OpenSSL heap memory
5. Revoke and reissue all session tokens and cookies
6. Enable TLS 1.3 and disable affected versions

---

### 12. Web Attack

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1190 — Exploit Public-Facing Application |
| **Detection Method** | CIC-IDS2017 RandomForest (WebAttack label); covers SQL Injection, XSS, and HTTP-based exploits |
| **Severity** | HIGH |
| **Indicators** | Anomalous HTTP payload patterns; repeated 4xx/5xx errors; SQL metacharacters in request parameters |

**Mitigation Actions:**
1. **block_ip** — Block the attacking source IP
2. **scan_filesystem** — Check for web shells or backdoors deposited after exploitation
3. Deploy WAF rules for SQL injection, XSS, and LFI/RFI patterns
4. Implement input validation and parameterized queries in application code
5. Review application logs for successful exploitation indicators
6. Apply Content Security Policy (CSP) headers

---

## Layer 2 — Malware Analysis

**Model:** LightGBM on 280-dimensional EMBER PE feature vector  
**Performance:** AUC-ROC 0.9803 · F1 0.9298 · Accuracy 0.9284  
**Data Source:** File watcher on endpoints + `/predict/malware` API + process metadata heuristic

---

### 13. Malicious PE Executable (General Malware)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1204 — User Execution: Malicious File |
| **Detection Method** | LightGBM classifies 280-dim PE feature vector (byte histogram entropy, section RX/RW counts, import table size, signature presence, subsystem type); score ≥0.70 → MALICIOUS |
| **Severity** | CRITICAL (score ≥0.85 triggers Fusion hard-override to threat_score ≥0.93) |
| **Labels** | BENIGN (score <0.3) · SUSPICIOUS (0.3–0.7) · MALICIOUS (≥0.7) |

**Mitigation Actions:**
1. **quarantine_file** — Move the malicious file to quarantine directory immediately
2. **kill_process** — Terminate any running instance of the malicious executable
3. **scan_filesystem** — Full filesystem scan for additional dropped payloads
4. **block_ip** — Block any C2 communication IP associated with the malware
5. Hash the file and query threat intelligence feeds (VirusTotal, MalwareBazaar)
6. Review process creation logs (Event 4688) for the infection chain
7. Reset credentials for any accounts that touched the file

---

### 14. Trojan / Remote Access Trojan (RAT)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1204 — User Execution: Malicious File |
| **Detection Method** | PE feature classification (high import count, small virtual size, network-related imports); process name heuristic matches known RAT names |
| **Severity** | CRITICAL |
| **Indicators** | Network callbacks after execution; keylogger activity; screen capture functions in import table |

**Mitigation Actions:**
1. **quarantine_file** — Quarantine the trojan binary
2. **kill_process** — Kill the RAT process
3. **scan_filesystem** — Search for persistence and additional payloads
4. **block_ip** — Block C2 server IP
5. Re-image the host if deep persistence is suspected
6. Audit all data accessed during RAT dwell time

---

### 15. Worm

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1210 — Exploitation of Remote Services |
| **Detection Method** | PE classification + network anomaly correlation (self-replication pattern: rapid outbound connection attempts to many hosts after execution) |
| **Severity** | CRITICAL |
| **Indicators** | File copies appearing on network shares; sudden spike in SMB/RDP connection attempts post-execution |

**Mitigation Actions:**
1. **isolate_host** — Immediately isolate the host to prevent worm spread via SMB/RDP
2. **block_ip** — Block worm propagation source IPs
3. **kill_process** — Terminate the worm replication process
4. **scan_filesystem** — Scan for worm copies across all drives and shared paths
5. Disable SMBv1 across the network
6. Apply MS17-010 and related patches on all endpoints

---

### 16. Rootkit

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1014 — Rootkit |
| **Detection Method** | PE classification detects kernel-mode artifacts (SYS files, low section entropy, driver subsystem); process hiding indicators in SHAP explanation |
| **Severity** | CRITICAL |
| **Indicators** | Hidden processes; kernel driver loaded; discrepancy between OS process list and raw memory enumeration |

**Mitigation Actions:**
1. **scan_filesystem** — Scan for rootkit-installed drivers, hidden files, and hooked binaries
2. **monitor_persistence** — Enumerate persistence mechanisms installed by the rootkit
3. **lock_account** — Lock accounts that may have been backdoored
4. **isolate_host** — Isolate for forensic imaging *(advisory — confirm rootkit first)*
5. Boot from trusted external media to perform offline analysis
6. Full re-image is typically required; patch the entry-point vulnerability

---

### 17. Process Injection Payload

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1055 — Process Injection |
| **Detection Method** | PE features: high entropy sections (packed/encrypted shellcode), unusual VirtualAlloc/WriteProcessMemory imports, mismatched section names |
| **Severity** | HIGH → CRITICAL |
| **Indicators** | Executable sections with entropy >7.0; import of VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |

**Mitigation Actions:**
1. **kill_process** — Terminate the process hosting the injected shellcode or DLL
2. **scan_filesystem** — Scan for injected DLLs and dropper artifacts
3. **monitor_persistence** — Check for persistence installed alongside injection
4. **isolate_host** — If CRITICAL: isolate to contain active in-memory attack
5. Enable Windows Defender Credential Guard to protect LSASS
6. Deploy Attack Surface Reduction (ASR) rules blocking process injection APIs

---

### 18. Persistence Dropper

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1547 — Boot or Logon Autostart Execution |
| **Detection Method** | PE classification + monitor_persistence SOAR action findings (registry Run keys, startup folder, scheduled task artifacts); high-entropy small executable |
| **Severity** | HIGH |
| **Indicators** | File written to startup directory; registry Run key modified; scheduled task created (Event 4698) |

**Mitigation Actions:**
1. **monitor_persistence** — Enumerate registry run keys, startup folder, and scheduled tasks
2. **scan_filesystem** — Scan for dropper binaries recently written to disk
3. **kill_process** — Kill any process spawned by the persistence mechanism
4. Remove malicious registry entries and scheduled tasks
5. Review Event 4698/4699 (task created/deleted) for unauthorized tasks
6. Enable AppLocker or WDAC to block unauthorized executable paths

---

### 19. Known Malicious Tool (Heuristic)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1059 — Command and Scripting Interpreter / T1003 — Credential Dumping |
| **Detection Method** | Process name heuristic: substring match against 22 known-malicious tool names (see list below) running from suspicious paths (%TEMP%, %APPDATA%, Downloads) |
| **Severity** | HIGH → CRITICAL |
| **Detected Tools** | mimikatz, meterpreter, cobaltstrike, cobalt_strike, bloodhound, sharphound, rubeus, certify, powersploit, invoke-mimikatz, empire, ncat, netcat, nc.exe, psexec, wmiexec, smbexec, xmrig, monero, cryptonight, beacon.exe, metasploit |

**Mitigation Actions:**
1. **kill_process** — Terminate the detected offensive tool immediately
2. **isolate_host** — Isolate the host (these tools indicate active compromise)
3. **scan_filesystem** — Scan for additional tools and payloads dropped alongside
4. **lock_account** — Lock any account the tool was used against (credential dumping)
5. Rotate all credentials accessible from the compromised host
6. Use AppLocker to block execution from user-writable directories

---

### 20. Cryptominer

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1496 — Resource Hijacking |
| **Detection Method** | Process name heuristic (xmrig, monero, cryptonight); high CPU usage correlated with System Monitor anomaly; PE classification of miner binary |
| **Severity** | MEDIUM → HIGH |
| **Indicators** | Sustained 90–100% CPU; outbound connections to mining pool IPs; known miner process names |

**Mitigation Actions:**
1. **kill_process** — Terminate the miner process
2. **block_ip** — Block mining pool destination IPs
3. **scan_filesystem** — Find and remove the miner binary and any dropper
4. Review scheduled tasks for miner re-launch persistence
5. Patch the vulnerability used to deploy the miner (often public-facing service exploitation)

---

## Layer 3 — System Monitor

**Model:** LSTM Autoencoder (PyTorch) on 20-feature telemetry window (60-second rolling)  
**Data Source:** psutil local telemetry + Sysmon event forwarding  
**Features:** cpu_percent, mem_percent, disk_read/write_bytes, net_bytes_sent/recv, num_processes, num_threads, swap_percent, open_files_count, context_switches, interrupts, disk_read/write_count, net_packets, net_errors, mem_available

---

### 21. Ransomware Behavior

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1486 — Data Encrypted for Impact |
| **Detection Method** | LSTM Autoencoder detects simultaneous spike in: disk_write_bytes, disk_write_count, cpu_percent, num_threads — characteristic of mass encryption I/O pattern; Fusion correlation: system CRITICAL + malware MALICIOUS |
| **Severity** | CRITICAL |
| **Indicators** | Massive disk write activity; CPU spike; many files modified in seconds; file extension changes; shadow copy deletion (Event 4688 with vssadmin) |

**Mitigation Actions:**
1. **kill_process** — Terminate the ransomware encryption process immediately
2. **isolate_host** — Prevent ransomware lateral spread to network shares
3. **scan_filesystem** — Identify encrypted files and ransomware dropper artifacts
4. **monitor_persistence** — Check for persistence installed by the dropper
5. Disconnect network drives to protect shared folders
6. Restore from clean offline backup — do NOT pay ransom
7. Preserve a forensic image before remediation
8. Block SMBv1 and restrict access to network shares

---

### 22. CPU Spike / Resource Hijacking

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1496 — Resource Hijacking |
| **Detection Method** | LSTM anomaly: cpu_percent spike > pattern baseline; Resource-aware severity: cpu >85% → HIGH, cpu >95% → CRITICAL |
| **Severity** | MEDIUM → CRITICAL |
| **Indicators** | Sustained high CPU from unexpected process; possible miner or fork bomb; thermal throttling |

**Mitigation Actions:**
1. **kill_process** — Kill the process consuming excessive CPU
2. **scan_filesystem** — Identify miner or malicious script responsible
3. Set CPU usage limits via Windows Job Objects or resource policies
4. Monitor process CPU baselines and alert on deviations >50% sustained

---

### 23. Memory Pressure Anomaly

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1055 — Process Injection (memory allocation abuse) |
| **Detection Method** | LSTM anomaly: mem_percent sustained >90%, swap_percent elevated, mem_available_norm collapse |
| **Severity** | MEDIUM → HIGH (caps at HIGH unless cpu also >80%) |
| **Indicators** | Memory allocation growing unboundedly; swap usage; possible memory-resident malware or leak |

**Mitigation Actions:**
1. Identify the memory-consuming process and correlate with malware scan
2. **kill_process** — Terminate if confirmed malicious
3. Enable Windows memory integrity (HVCI) to block unsigned kernel drivers
4. Restart the host if memory is exhausted and service is degraded

---

### 24. Abnormal Disk I/O

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1486 / T1565 — Data Destruction / Data Manipulation |
| **Detection Method** | LSTM anomaly: disk_write_bytes_norm or disk_read_bytes_norm outside learned baseline; often coupled with ransomware or data staging |
| **Severity** | HIGH |
| **Indicators** | Sustained disk write rates far above baseline; unusual read patterns indicating data staging |

**Mitigation Actions:**
1. **scan_filesystem** — Identify files being written or read en masse
2. **kill_process** — Stop the process responsible for abnormal I/O
3. **isolate_host** — If data exfiltration or encryption is confirmed
4. Review file audit logs (Event 4663) for access patterns

---

### 25. Suspicious Process Chain (Sysmon)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1059 — Command and Scripting Interpreter |
| **Detection Method** | Sysmon EventID parsing: unusual parent-child process relationships (e.g. Word → PowerShell → cmd → net.exe); SHAP indicator analysis on behavioral event sequence |
| **Severity** | HIGH → CRITICAL |
| **Indicators** | Office application spawning shell; PowerShell with encoded commands; cmd spawning from browser; living-off-the-land binary (LOLBin) abuse |

**Mitigation Actions:**
1. **kill_process** — Terminate the suspicious child process chain
2. **scan_filesystem** — Search for scripts or payloads dropped by the chain
3. **monitor_persistence** — Check for persistence established via the chain
4. Enable ASR rules blocking Office from spawning child processes
5. Block PowerShell with `ConstrainedLanguageMode` for non-admin users
6. Review and restrict LOLBin execution policies

---

## Layer 4 — User Behavior Analysis

**Model:** One-Class SVM trained on CERT Insider Threat Dataset r4.2 + 12 active behavioral features  
**Data Source:** Winlogbeat NDJSON (Windows Security Event Log) + psutil session data  
**Features:** file_ops_count, file_write_count, logon_count, failed_logon_count, after_hours_activity, device_connects, emails_sent, unique_recipients, OCEAN proxies (O, C, E, A, N)

---

### 26. Insider Threat / Abnormal User Behavior

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1078.004 — Valid Accounts: Cloud Accounts / Insider Abuse |
| **Detection Method** | OC-SVM anomaly score ≥0.8 across behavioral feature vector; OCEAN proxy deviation from trained normal baseline; fast-path trigger: ≥500 file operations OR ≥100 unique directory scans |
| **Severity** | HIGH → CRITICAL |
| **Indicators** | Mass file access outside normal pattern; deviation from established working hours; access to sensitive data not normally touched |

**Mitigation Actions:**
1. **lock_account** — Lock the account associated with insider threat indicators
2. **monitor_persistence** — Check for data staging or persistence by the insider actor
3. Conduct a formal HR and security investigation before account termination
4. Preserve all access logs as legal evidence
5. Implement least-privilege and need-to-know data access controls
6. Deploy User and Entity Behavior Analytics (UEBA) baselining per user

---

### 27. After-Hours / Impossible Travel

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1078 — Valid Accounts |
| **Detection Method** | Session heuristic: login before 05:00 or at/after 23:00; remote session from external IP combined with unusual hours (score +0.50); session telemetry OC-SVM anomaly |
| **Severity** | HIGH |
| **Indicators** | Account active at unusual hours; geographic mismatch between consecutive logins; VPN bypass attempts |

**Mitigation Actions:**
1. **lock_account** — Lock the account pending verification with the user
2. Implement login-time restrictions via Group Policy for standard accounts
3. Enable geographic risk scoring on authentication events
4. Require step-up MFA for after-hours or remote logins
5. Review all actions performed during the suspicious session

---

### 28. Credential Stuffing / Account Brute Force (User Layer)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Detection Method** | Windows Event 4625 (failed logon) count within session window elevated above baseline; OC-SVM detects failed_logon_count feature spike |
| **Severity** | HIGH |
| **Indicators** | Many Event 4625 records in short window; targeting domain accounts; NTLM pass-the-hash indicators (Event 4776) |

**Mitigation Actions:**
1. **lock_account** — Lock after threshold failure count
2. Enable smart lockout with increasing delays
3. Enforce MFA on all accounts
4. Monitor Event 4776 for pass-the-hash indicators
5. Disable NTLM authentication where possible and enforce Kerberos

---

### 29. USB / Removable Device Abuse

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1091 — Replication Through Removable Media |
| **Detection Method** | device_connects/device_disconnects feature spike in OC-SVM window; USB override threshold: device_events ≥10 triggers immediate anomaly flag; Sysmon file creation events from removable paths |
| **Severity** | MEDIUM → HIGH |
| **Indicators** | Rapid USB insert/remove cycles; large file copies to removable media; files with autorun characteristics |

**Mitigation Actions:**
1. **lock_account** — Lock if data exfiltration via USB is suspected
2. Disable USB storage via Group Policy for non-authorized users
3. Deploy endpoint DLP to block writes to removable media above a threshold
4. Audit removable media access logs (Event 4663 + Sysmon Event 11)
5. Require encrypted, company-managed USB devices only

---

### 30. Privilege Escalation (Session Abuse)

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1068 — Exploitation for Privilege Escalation |
| **Detection Method** | System account (SYSTEM, NT AUTHORITY) detected in interactive session (psutil.users()); score +0.60 triggers HIGH threshold; Windows Event 4672 (special privileges assigned) |
| **Severity** | HIGH → CRITICAL |
| **Indicators** | SYSTEM account in interactive desktop session; unexpected Event 4672 entries; token manipulation artifacts |

**Mitigation Actions:**
1. **kill_process** — Terminate the escalated session process
2. **lock_account** — Lock the account from which escalation occurred
3. **monitor_persistence** — Enumerate persistence installed during escalation
4. Patch the exploit used for escalation
5. Enforce User Account Control (UAC) at highest level
6. Deploy Credential Guard to protect token manipulation

---

### 31. Lateral Movement Detection

| Field | Detail |
|-------|--------|
| **MITRE ATT&CK** | T1021 — Remote Services (SMB/RDP/WMI) |
| **Detection Method** | Session heuristic: remote_sessions ≥3 from external IPs (score +0.30); combined with network anomaly (host sweep); OC-SVM detects abnormal logon_count + remote logon proportion (Extraversion proxy) |
| **Severity** | HIGH |
| **Indicators** | Multiple simultaneous remote sessions; SMB authentication from unusual hosts; WMI process creation events |

**Mitigation Actions:**
1. **isolate_host** — Prevent further lateral movement to adjacent hosts via SMB/RDP
2. **block_ip** — Block inbound SMB (445) and RDP (3389) from the source IP
3. Disable SMBv1 and enforce SMB signing
4. Restrict RDP access to jump servers only via network segmentation
5. Enable Protected Users security group for high-value accounts
6. Monitor Event 4624 Type 3 (network logon) across all hosts

---

## Complete Attack-to-MITRE Mapping

| # | Attack Type | MITRE Technique | Severity | Detection Layer |
|---|-------------|-----------------|----------|-----------------|
| 1 | Horizontal Port Scan | T1046 | HIGH | Network (Rule) |
| 2 | Host / Network Sweep | T1046 | HIGH | Network (Rule) |
| 3 | SYN Flood | T1498 | CRITICAL | Network (Rule) |
| 4 | DoS Packet Flood | T1498 | CRITICAL | Network (Rule + ML) |
| 5 | DDoS | T1498 | CRITICAL | Network (ML) |
| 6 | Brute Force | T1110 | HIGH | Network (Rule + ML) |
| 7 | Data Exfiltration | T1041 | CRITICAL | Network (Rule) |
| 8 | PortScan (ML) | T1046 | HIGH | Network (ML) |
| 9 | Botnet / C2 Beaconing | T1071 | CRITICAL | Network (ML) + Fusion |
| 10 | Infiltration / RCE | T1190 | CRITICAL | Network (Rule + ML) |
| 11 | Heartbleed | T1499 | CRITICAL | Network (ML) |
| 12 | Web Attack (SQLi/XSS) | T1190 | HIGH | Network (ML) |
| 13 | Malicious PE Executable | T1204 | CRITICAL | Malware (LightGBM) |
| 14 | Trojan / RAT | T1204 | CRITICAL | Malware (LightGBM) |
| 15 | Worm | T1210 | CRITICAL | Malware + Network |
| 16 | Rootkit | T1014 | CRITICAL | Malware (LightGBM) |
| 17 | Process Injection Payload | T1055 | HIGH–CRITICAL | Malware (LightGBM) |
| 18 | Persistence Dropper | T1547 | HIGH | Malware + System |
| 19 | Known Offensive Tool | T1059 / T1003 | HIGH–CRITICAL | Malware (Heuristic) |
| 20 | Cryptominer | T1496 | MEDIUM–HIGH | Malware + System |
| 21 | Ransomware Behavior | T1486 | CRITICAL | System (LSTM) + Malware |
| 22 | CPU Spike / Resource Hijack | T1496 | MEDIUM–CRITICAL | System (LSTM) |
| 23 | Memory Pressure Anomaly | T1055 | MEDIUM–HIGH | System (LSTM) |
| 24 | Abnormal Disk I/O | T1486 / T1565 | HIGH | System (LSTM) |
| 25 | Suspicious Process Chain | T1059 | HIGH–CRITICAL | System (Sysmon) |
| 26 | Insider Threat | T1078.004 | HIGH–CRITICAL | User (OC-SVM) |
| 27 | After-Hours / Impossible Travel | T1078 | HIGH | User (Heuristic + OC-SVM) |
| 28 | Credential Stuffing | T1110 | HIGH | User (OC-SVM) |
| 29 | USB / Removable Device Abuse | T1091 | MEDIUM–HIGH | User (OC-SVM) |
| 30 | Privilege Escalation | T1068 | HIGH–CRITICAL | User (Heuristic) |
| 31 | Lateral Movement | T1021 | HIGH | User + Network (Fusion) |

---

## SOAR Automated Response Actions

All executable actions are dispatched to the relevant endpoint agent via the SOAR pipeline. Advisory actions are logged and surfaced to analysts in the Response Modal.

### Executable Actions (Automated)

| Action | Description | Typical Trigger |
|--------|-------------|-----------------|
| `block_ip` | Creates Windows Firewall inbound+outbound rules via `netsh advfirewall` blocking the target IP | PortScan, BruteForce, C2, DDoS |
| `unblock_ip` | Removes XDR_BLOCK_\<ip\> firewall rules | Manual analyst release |
| `kill_process` | Terminates process by PID or name via psutil | Ransomware, RAT, Miner, Tool detection |
| `isolate_host` | Disables the network interface via `netsh interface set interface <NIC> disable`; writes isolation_flag.txt | Ransomware, Worm, Infiltration |
| `unisolate_host` | Re-enables network interface; removes isolation_flag.txt | Manual analyst release |
| `quarantine_file` | Moves malicious file to `quarantine/` subfolder via shutil.move | Malware CRITICAL detections |
| `lock_account` | Runs `net user <username> /active:no` | Insider Threat, Brute Force, Privilege Escalation |
| `scan_filesystem` | Walks 4 watch paths for suspicious extensions (.exe, .dll, .ps1, .bat, .vbs, .scr) modified in last 3600s; returns top 10 by mtime | Ransomware, Worm, Rootkit |
| `monitor_persistence` | Reads HKCU Run registry keys, Startup folder, scheduled task list | C2, Persistence Dropper, Rootkit |

### Advisory Actions (Analyst-Reviewed)

| Action | Description |
|--------|-------------|
| `patch_openssl` | Recommendation to apply OpenSSL patch for Heartbleed |
| `rotate_certificates` | Recommendation to rotate TLS certificates and private keys |
| `check_exposed_secrets` | Audit for secrets leaked from memory disclosure |
| `alert_admin` | Notify security administrator of the detected event |
| `update_software` | Recommendation to update vulnerable software package |
| `force_logout` | Recommendation to terminate all active sessions for affected account |

---

## Fusion Engine — Cross-Layer Correlation Rules

These rules escalate threat scores when multiple detection layers fire simultaneously, catching attacks that each individual model would score below threshold.

| Correlation Rule | Condition | Effect |
|------------------|-----------|--------|
| **Ransomware Activity** | malware_score ≥0.85 AND is_malicious=True AND system_severity ≥HIGH | threat_score ≥0.93, attack_type="Ransomware Activity" |
| **Active Compromise** | network_score ≥0.80 AND system_score ≥0.50 | threat_score ≥0.82, CRITICAL escalation |
| **Insider Threat** | user_score ≥0.80 | threat_score ≥0.75, attack_type="Insider Threat" |
| **Malware + Network** | malware_score ≥0.60 AND network_score ≥0.50 | threat_score ≥0.75 |
| **Multi-model corroboration** | ≥3 models each score >0.30 | ×1.20 score multiplier |
| **Dual-model corroboration** | ≥2 models each score >0.30 | ×1.10 score multiplier |

**Model Weights in Fusion Score:**

```
Threat Score = (Network × 0.35) + (User × 0.30) + (Malware × 0.20) + (System × 0.15)
```

| Model | Weight | Rationale |
|-------|--------|-----------|
| Network Detection | 35% | Highest precision; rule engine eliminates false positives |
| User Behavior | 30% | Strong insider threat signal; 300-second event window reduces noise |
| Malware Analysis | 20% | High AUC (0.98) but file-only; no behavioral context |
| System Monitor | 15% | Leading indicator for ransomware/miner; noisy on memory-heavy workloads |

---

*Generated from Cyber Sentinel XDR codebase — rule_detector.py · hybrid_detector.py · response_engine.py · malware_analysis_agent.py · system_monitor_agent.py · xdr_runtime.py · user_behavior_agent.py · fusion_engine_agent.py*
