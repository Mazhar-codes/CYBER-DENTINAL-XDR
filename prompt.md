# 🔍 **CYBER SENTINEL XDR - INCIDENT INVESTIGATION WORKFLOW**

---

## **COMPLETE INVESTIGATION PROCESS (Step-by-Step)**

```
┌─────────────────────────────────────────────────────────────┐
│                    INCIDENT LIFECYCLE                        │
└─────────────────────────────────────────────────────────────┘

STAGE 1: DETECTION
     ↓
STAGE 2: TRIAGE & PRIORITIZATION
     ↓
STAGE 3: INITIAL INVESTIGATION
     ↓
STAGE 4: EVIDENCE GATHERING & CORRELATION
     ↓
STAGE 5: THREAT CONFIRMATION
     ↓
STAGE 6: RESPONSE PLANNING
     ↓
STAGE 7: REMEDIATION & CONTAINMENT
     ↓
STAGE 8: POST-INCIDENT FORENSICS
     ↓
STAGE 9: INCIDENT REPORTING & CLOSURE
```

---

## **🔴 STAGE 1: DETECTION (Automatic)**

### **How XDR Detects Threats:**

```
T+0 Seconds: Threat Occurs on Endpoint
│
├─ Endpoint Agent collects telemetry:
│  ├─ Network flows
│  ├─ Process execution
│  ├─ File operations
│  ├─ Registry changes
│  └─ User behavior
│
T+5 Seconds: Telemetry reaches XDR Server
│
├─ 4 AI Agents analyze in PARALLEL:
│  ├─ Network Detection Agent: 0.92 score
│  ├─ Malware Analysis Agent: 0.88 score
│  ├─ System Monitor Agent: 0.54 score
│  └─ User Behavior Agent: 0.35 score
│
T+6 Seconds: Fusion Engine Combines Scores
│
├─ Threat Score = (0.35×0.92) + (0.30×0.88) + (0.20×0.35) + (0.15×0.54)
├─ Threat Score = 0.74 (CRITICAL ALERT)
│
T+7 Seconds: Alert Generated
│
└─ Alert stored in MongoDB
   Alert broadcast via Socket.IO to SOC Dashboard
```

### **Alert Appears on SOC Dashboard:**

```
┌──────────────────────────────────────────────────────┐
│ 🚨 CRITICAL ALERT - Real-Time Notification           │
├──────────────────────────────────────────────────────┤
│                                                      │
│ Threat Score: 0.74 [████████░░]                     │
│ Severity: CRITICAL (Red)                            │
│                                                      │
│ Endpoint: PC-001 (John's Workstation)               │
│ User: john.doe@company.com                          │
│ Time: 2026-06-10 14:32:15 UTC                       │
│                                                      │
│ Detected By:                                        │
│ ✓ Network Detection (0.92) - Suspicious outbound   │
│ ✓ Malware Analysis (0.88) - Trojan signature       │
│ ⚠ System Monitor (0.54) - Minor CPU spike          │
│ ○ User Behavior (0.35) - Normal session             │
│                                                      │
│ [🔍 INVESTIGATE] [⏸ PAUSE] [↻ SNOOZE]             │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## **🟡 STAGE 2: TRIAGE & PRIORITIZATION**

### **SOC Analyst Reviews Alert**

**Triage Questions:**

```
1. Is this a REAL threat?
   ├─ Check: Known false positive patterns
   ├─ Check: Scheduled backup/scan processes
   ├─ Check: Third-party software updates
   └─ Decision: Real vs False Positive

2. What is the IMPACT?
   ├─ Check: Endpoint criticality (servers vs workstations)
   ├─ Check: User role (admin vs regular)
   ├─ Check: Data accessed (sensitive vs public)
   └─ Priority: P1 (critical), P2 (high), P3 (medium), P4 (low)

3. What is the SCOPE?
   ├─ Check: Single endpoint or multiple?
   ├─ Check: Lateral movement detected?
   ├─ Check: Network propagation?
   └─ Scope: Isolated vs Widespread
```

### **Dashboard Actions:**

```
Analyst clicks [🔍 INVESTIGATE]
     ↓
Alert moves to INVESTIGATION QUEUE
     ↓
Opens full investigation panel
     ↓
Assigns to self: "john.analyst@company.com"
     ↓
Status changes: OPEN → INVESTIGATING
     ↓
Starts timer: Investigation duration tracking
```

---

## **🔵 STAGE 3: INITIAL INVESTIGATION**

### **Analyst Gathers Initial Context**

```
┌─────────────────────────────────────────────────────┐
│         INVESTIGATION DETAILS PANEL                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│ ENDPOINT INFORMATION                                │
│ ├─ Hostname: PC-001                                │
│ ├─ IP Address: 192.168.1.100                       │
│ ├─ OS: Windows 11 Pro (Build 22621)                │
│ ├─ Status: Online (Last heartbeat: 2s ago)         │
│ ├─ Owner: John Doe (john.doe@company.com)          │
│ ├─ Department: Finance                             │
│ ├─ Location: Building A, Floor 3, Desk 301         │
│ └─ Last Updated: 2026-06-10 14:32:15               │
│                                                     │
│ ALERT TIMELINE (Chronological)                      │
│                                                     │
│ T+0s:    Malware Analysis detected suspicious PE   │
│ T+1s:    Network Detection flagged C2 beaconing    │
│ T+2s:    System Monitor reported CPU spike         │
│ T+3s:    4 agents converged → Fusion score 0.74    │
│ T+7s:    Alert generated & sent to SOC             │
│ T+30s:   Analyst assigned to case                  │
│                                                     │
│ AGENT DETAILS (Click to expand each)               │
│ ┌─────────────────────────────────────────────────┐│
│ │ ▼ Network Detection Agent (Score: 0.92)        ││
│ │   ├─ Source IP: 192.168.1.100                  ││
│ │   ├─ Dest IP: 185.220.101.45 (SUSPICIOUS)      ││
│ │   ├─ Port: 443 (HTTPS)                         ││
│ │   ├─ Bytes Sent: 5,120 KB                      ││
│ │   ├─ Bytes Received: 2,048 KB                  ││
│ │   ├─ Duration: 75 seconds                      ││
│ │   ├─ Pattern: Periodic beaconing every 30s     ││
│ │   └─ Confidence: Very High ✓✓✓                 ││
│ └─────────────────────────────────────────────────┘│
│                                                     │
│ ┌─────────────────────────────────────────────────┐│
│ │ ▼ Malware Analysis Agent (Score: 0.88)         ││
│ │   ├─ File: C:\Users\John\Downloads\invoice.exe ││
│ │   ├─ MD5: abc123def456...                      ││
│ │   ├─ SHA256: abc123def456...                   ││
│ │   ├─ File Size: 512 KB                         ││
│ │   ├─ Entropy: 7.8/8.0 (Packed/Encrypted)       ││
│ │   ├─ Verdict: Trojan.Generic                   ││
│ │   ├─ Confidence: Very High ✓✓✓                 ││
│ │   └─ Threat Intel: Known C2 malware (Emotet)  ││
│ └─────────────────────────────────────────────────┘│
│                                                     │
│ ┌─────────────────────────────────────────────────┐│
│ │ ▼ System Monitor Agent (Score: 0.54)           ││
│ │   ├─ CPU Usage: 85% (baseline: 12%)            ││
│ │   ├─ Memory: 78% (baseline: 45%)               ││
│ │   ├─ Disk I/O: 125 MB/s (baseline: 5 MB/s)     ││
│ │   ├─ Duration: 45 seconds                      ││
│ │   └─ Type: Crypto-mining or data compression   ││
│ └─────────────────────────────────────────────────┘│
│                                                     │
│ ┌─────────────────────────────────────────────────┐│
│ │ ▼ User Behavior Agent (Score: 0.35)            ││
│ │   ├─ Logon Time: 09:00 (Normal business hours) ││
│ │   ├─ Session Duration: 5 hours 32 minutes      ││
│ │   ├─ Files Accessed: 24 (normal)               ││
│ │   ├─ Data Volume: 45 MB (normal)               ││
│ │   └─ Assessment: No insider threat indicators  ││
│ └─────────────────────────────────────────────────┘│
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## **🟢 STAGE 4: EVIDENCE GATHERING & CORRELATION**

### **Analyst Correlates Events Across Data**

```
STEP 1: File Analysis
├─ Query MongoDB for file execution:
│  {
│    "event_type": "file_executed",
│    "file_path": "C:\\Users\\John\\Downloads\\invoice.exe",
│    "timestamp": {"$gte": T-300s, "$lte": T+300s}
│  }
│
├─ Results:
│  ├─ T-5m: File downloaded from email attachment
│  ├─ T-2m: File executed
│  ├─ T-1m: Network connection established
│  ├─ T+0s: CPU spike detected
│  └─ T+1m: Data exfiltration attempt detected
│
└─ Evidence: Malware execution timeline CONFIRMED

STEP 2: Network Correlation
├─ Query network flows for destination IP:
│  {
│    "destination_ip": "185.220.101.45",
│    "timestamp": {"$gte": T-1h, "$lte": T+1h}
│  }
│
├─ Results:
│  ├─ 185.220.101.45 identified as TOR exit node
│  ├─ 12 connections from this PC to same IP (periodic)
│  ├─ Each connection: 30-second duration
│  ├─ Pattern: Every 30 seconds (C2 beaconing)
│  └─ Threat Intel: Known Emotet C2 server
│
└─ Evidence: C2 beaconing pattern CONFIRMED

STEP 3: Endpoint Isolation Check
├─ Query: Are other endpoints connecting to same IP?
│  {
│    "destination_ip": "185.220.101.45",
│    "endpoint_id": {"$ne": "PC-001"}
│  }
│
├─ Results:
│  ├─ PC-002 (Jane): 3 connections
│  ├─ PC-005 (Bob): 8 connections
│  ├─ PC-012 (Server): 0 connections
│  └─ Assessment: LATERAL SPREAD DETECTED
│
└─ Evidence: Multi-endpoint compromise CONFIRMED

STEP 4: User Correlation
├─ Query: What else did user do today?
│  {
│    "user_id": "john.doe",
│    "timestamp": {"$gte": "2026-06-10 00:00", "$lte": "2026-06-10 23:59"}
│  }
│
├─ Results:
│  ├─ Normal file access (Finance spreadsheets)
│  ├─ Normal email usage
│  ├─ Downloaded invoice.exe at 2:15 PM (ANOMALY)
│  ├─ Email from unknown sender: "Your Invoice June.exe"
│  └─ User likely deceived (phishing email)
│
└─ Evidence: Social engineering attack CONFIRMED

STEP 5: Historical Analysis
├─ Query: Has this malware appeared before?
│  {
│    "file_hash": "abc123def456...",
│    "verdict": "malware"
│  }
│
├─ Results:
│  ├─ Emotet variant known since April 2026
│  ├─ 47 previous incidents in industry
│  ├─ Typical dwell time: 3-7 days
│  ├─ Common targets: Finance departments
│  └─ Known capabilities: C2, data theft, lateral movement
│
└─ Evidence: Known threat pattern CONFIRMED
```

### **Analyst Dashboard View (Correlation Map):**

```
┌─────────────────────────────────────────────────────┐
│         INVESTIGATION EVIDENCE MAP                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│                   Email Attack                      │
│                  (Phishing Email)                   │
│                        │                            │
│                        ↓                            │
│              [John's Inbox]                        │
│              Downloaded: invoice.exe               │
│                        │                            │
│                        ↓                            │
│         [C:\Users\John\Downloads\]                 │
│         File Execution: invoice.exe                │
│                        │                            │
│         ┌──────────────┼──────────────┐            │
│         ↓              ↓              ↓            │
│    [PC-001]      [PC-002]       [PC-005]          │
│    CPU Spike     Net Flow       Net Flow          │
│    Memory Spike  C2 Beacon      C2 Beacon         │
│         │              │              │            │
│         └──────────────┼──────────────┘            │
│                        ↓                            │
│      [Emotet C2 Server]                            │
│      185.220.101.45                                │
│      TOR Exit Node                                 │
│                        │                            │
│                        ↓                            │
│         [Data Exfiltration]                        │
│         Finance spreadsheets stolen                │
│         Contact lists compromised                  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## **⚪ STAGE 5: THREAT CONFIRMATION**

### **Analyst Makes Go/No-Go Decision:**

```
CONFIRMATION CHECKLIST:

✓ Is this a REAL threat?
  ├─ Evidence: Multiple corroborating signals
  ├─ Confidence: 95%+ (not false positive)
  ├─ Verdict: REAL THREAT
  └─ Action: Proceed to Response

✓ What is the SCOPE?
  ├─ Evidence: 3 endpoints compromised
  ├─ Pattern: Same malware family
  ├─ Assessment: EARLY-STAGE INFECTION
  └─ Action: Urgent containment needed

✓ What is the IMPACT?
  ├─ Affected: Finance department (sensitive data)
  ├─ Risk: Data theft, financial systems compromise
  ├─ Timeline: 75 seconds since initial execution
  ├─ Window: Still time to contain before exfiltration
  └─ Priority: P1 CRITICAL

ANALYST DECISION: REAL THREAT - ACTIVATE RESPONSE PLAN
```

### **Dashboard Status Change:**

```
Alert Status: INVESTIGATING → CONFIRMED THREAT
Severity: CRITICAL (RED)
Assigned To: john.analyst@company.com
Time Spent: 5 minutes 32 seconds
Evidence Collected: 23 correlations

Next Action: Response Planning
Auto-notified: Security Manager, IT Director
```

---

## **🟣 STAGE 6: RESPONSE PLANNING**

### **Analyst Reviews Automated Response Options:**

```
┌─────────────────────────────────────────────────────┐
│        AUTOMATED RESPONSE RECOMMENDATIONS             │
├─────────────────────────────────────────────────────┤
│                                                     │
│ System recommends (based on threat profile):       │
│                                                     │
│ IMMEDIATE ACTIONS (No user approval needed):       │
│ ✓ [x] Kill malicious process (invoice.exe)        │
│ ✓ [x] Block destination IP (185.220.101.45)       │
│ ✓ [x] Isolate endpoint from network               │
│ ✓ [x] Snapshot disk for forensics                 │
│                                                     │
│ MANUAL APPROVAL REQUIRED:                          │
│ ○ [ ] Terminate user session (PC-001)             │
│ ○ [ ] Reset user credentials                      │
│ ○ [ ] Disable user account temporarily            │
│ ○ [ ] Force password change for affected users    │
│ ○ [ ] Escalate to executive team                  │
│                                                     │
│ OPTIONAL RESPONSES:                                │
│ ○ [ ] Scan entire Finance department              │
│ ○ [ ] Block sender email domain                   │
│ ○ [ ] Alert all users about phishing email        │
│ ○ [ ] Trigger incident response call              │
│                                                     │
│              [✓ EXECUTE] [✗ CANCEL]              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### **Custom Response Plan:**

```
Analyst selects:
✓ Kill process on PC-001, PC-002, PC-005
✓ Block IP 185.220.101.45 (firewall rule)
✓ Isolate PC-001, PC-002, PC-005 from network
✓ Create memory dump for forensics
✓ Create disk snapshot
✗ Don't terminate session yet (preserve evidence)
✓ Email notification to manager
✓ Create incident ticket
✓ Schedule post-incident review

Response Plan Status: APPROVED & QUEUED
```

---

## **🔴 STAGE 7: REMEDIATION & CONTAINMENT**

### **Automated Execution:**

```
T+0s:   Response Plan Activated
        │
        ├─ PC-001: Kill process "invoice.exe"
        │  └─ Status: ✓ SUCCESS (Process terminated)
        │
        ├─ PC-002: Kill process "svchost_malware.exe"
        │  └─ Status: ✓ SUCCESS (Process terminated)
        │
        ├─ PC-005: Kill process "explorer_hook.exe"
        │  └─ Status: ✓ SUCCESS (Process terminated)
        │
        ├─ Firewall: Add rule "Block 185.220.101.45"
        │  └─ Status: ✓ SUCCESS (Rule added)
        │
        ├─ PC-001: Network Isolation
        │  └─ Status: ✓ SUCCESS (Disconnected)
        │
        ├─ PC-002: Network Isolation
        │  └─ Status: ✓ SUCCESS (Disconnected)
        │
        ├─ PC-005: Network Isolation
        │  └─ Status: ✓ SUCCESS (Disconnected)
        │
        ├─ Forensics: Disk snapshot initiated
        │  └─ Status: ⏳ IN PROGRESS (15% complete)
        │
        └─ Notifications sent to stakeholders
           └─ Status: ✓ SUCCESS

T+45s:  Containment Complete
        └─ All malicious processes terminated
        └─ All infected endpoints isolated
        └─ Firewall blocking C2 server
        └─ Evidence preserved for analysis
```

### **Dashboard Update:**

```
┌─────────────────────────────────────────────────────┐
│         CONTAINMENT STATUS - SUCCESS                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│ [████████████████████████████████████] 100%         │
│                                                     │
│ Actions Completed:                                  │
│ ✓ Processes terminated (3/3)                        │
│ ✓ IPs blocked (1/1)                                │
│ ✓ Endpoints isolated (3/3)                         │
│ ✓ Forensic images captured (3/3)                   │
│ ✓ Stakeholders notified (5/5)                      │
│                                                     │
│ Time to Contain: 48 seconds (Excellent)            │
│ Attack Dwell Time: 75 seconds (Quick response!)    │
│                                                     │
│ Next: Forensic Investigation Phase                 │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## **🟠 STAGE 8: POST-INCIDENT FORENSICS**

### **Analyst Investigates Compromised Systems**

```
FORENSIC INVESTIGATION ACTIVITIES:

1. MALWARE ANALYSIS
   ├─ Quarantine invoice.exe
   ├─ Hash: abc123def456...
   ├─ Analyze using YARA rules
   ├─ Extract strings: hardcoded C2 IPs
   ├─ Decompile malware (optional)
   └─ Identify: Emotet variant (v4.2.1)

2. TIMELINE RECONSTRUCTION
   ├─ T-300s: Email received "invoice June.exe"
   ├─ T-240s: User downloaded attachment
   ├─ T-120s: User executed invoice.exe
   ├─ T-90s:  Process spawned cmd.exe (lateral)
   ├─ T-75s:  Network connection established
   ├─ T-60s:  Data copy initiated
   ├─ T-30s:  Propagation to PC-002
   ├─ T-15s:  Propagation to PC-005
   └─ T+0s:   Alert generated

3. ARTIFACT COLLECTION
   ├─ Process execution logs
   ├─ Network connection logs
   ├─ File system changes
   ├─ Registry modifications
   ├─ Memory dump (malware behavior)
   └─ Email headers (phishing origin)

4. DATA EXFILTRATION CHECK
   ├─ Was data stolen?
   ├─ What files were accessed?
   │  ├─ Payroll_2026.xlsx
   │  ├─ Client_Accounts.xlsx
   │  ├─ Banking_Credentials.txt
   │  └─ ~150 MB data copied
   ├─ Was data sent to attacker?
   │  └─ Network logs show file transfer to C2
   └─ Verdict: DATA BREACH CONFIRMED

5. LATERAL MOVEMENT CHECK
   ├─ Did malware spread to servers?
   ├─ Check: DC01 (Domain Controller) - CLEAN
   ├─ Check: FILE-SERVER-01 - CLEAN
   ├─ Check: SQL-DB-01 - CLEAN
   └─ Verdict: Limited spread (only workstations)

6. PERSISTENCE MECHANISMS
   ├─ Did malware create backdoor?
   ├─ Check scheduled tasks: None found
   ├─ Check registry run keys: None found
   ├─ Check startup folder: None found
   ├─ Check Windows services: None found
   └─ Verdict: No persistence detected (good)

FORENSIC SUMMARY:
├─ Threat: Emotet banking malware
├─ Scope: 3 workstations compromised
├─ Duration: ~90 seconds from execution to containment
├─ Data Loss: ~150 MB (financial data)
├─ Lateral Movement: None to critical systems
├─ Persistence: Not established
└─ Recovery: Possible without rebuilding
```

---

## **📋 STAGE 9: INCIDENT REPORTING & CLOSURE**

### **Automated Incident Report Generation:**

```
┌─────────────────────────────────────────────────────┐
│          INCIDENT REPORT (Auto-Generated)             │
├─────────────────────────────────────────────────────┤
│                                                     │
│ INCIDENT ID: INC-2026-0001                         │
│ Title: Emotet C2 Malware Detection & Containment   │
│ Date: June 10, 2026                                │
│ Severity: CRITICAL                                 │
│ Status: CONTAINED                                  │
│                                                     │
│ ───────────────────────────────────────────────   │
│ EXECUTIVE SUMMARY                                  │
│ ───────────────────────────────────────────────   │
│                                                     │
│ On June 10, 2026 at 14:32:15 UTC, Cyber Sentinel  │
│ XDR detected and contained a sophisticated malware │
│ infection affecting 3 endpoints in the Finance     │
│ department. The malware (Emotet variant v4.2.1)   │
│ was executed via phishing email attachment. Swift  │
│ detection and automated response limited damage    │
│ to data exfiltration only. No lateral movement    │
│ to critical systems occurred.                      │
│                                                     │
│ ───────────────────────────────────────────────   │
│ TIMELINE                                           │
│ ───────────────────────────────────────────────   │
│                                                     │
│ 14:31:00  User received phishing email             │
│ 14:31:45  User downloaded "invoice.exe"           │
│ 14:32:00  User executed malware                   │
│ 14:32:15  PC-001 C2 connection established        │
│ 14:32:22  XDR 4 agents detected threat            │
│ 14:32:26  Alert generated & sent to SOC           │
│ 14:32:35  Analyst assigned & investigation begun  │
│ 14:33:10  Evidence correlation completed          │
│ 14:33:30  Threat confirmed (REAL)                 │
│ 14:33:45  Response plan approved                  │
│ 14:34:00  Automated containment executed          │
│ 14:34:45  Forensics investigation started         │
│ 14:35:00  Report generation started               │
│                                                     │
│ Total Response Time: 48 seconds (Excellent)       │
│ Attack Dwell Time: 75 seconds (Quick catch!)      │
│                                                     │
│ ───────────────────────────────────────────────   │
│ AFFECTED SYSTEMS                                   │
│ ───────────────────────────────────────────────   │
│                                                     │
│ Endpoint 1: PC-001 (John Doe)                     │
│ └─ Status: Isolated, Cleaned                      │
│                                                     │
│ Endpoint 2: PC-002 (Jane Smith)                   │
│ └─ Status: Isolated, Cleaned                      │
│                                                     │
│ Endpoint 3: PC-005 (Bob Johnson)                  │
│ └─ Status: Isolated, Cleaned                      │
│                                                     │
│ Critical Systems: UNAFFECTED                      │
│ ├─ Domain Controllers: CLEAN                      │
│ ├─ File Servers: CLEAN                            │
│ ├─ Database Servers: CLEAN                        │
│ └─ Network Infrastructure: CLEAN                  │
│                                                     │
│ ───────────────────────────────────────────────   │
│ DATA LOSS ASSESSMENT                               │
│ ───────────────────────────────────────────────   │
│                                                     │
│ Estimated Files Stolen: 47 files                  │
│ Data Volume: ~150 MB                              │
│ Sensitive Data: Financial records, client data    │
│ Notification Required: YES (GDPR, local laws)     │
│ Affected Parties: ~200 clients                    │
│                                                     │
│ ───────────────────────────────────────────────   │
│ ROOT CAUSE                                         │
│ ───────────────────────────────────────────────   │
│                                                     │
│ Primary: Phishing email with malicious attachment │
│ Attack Vector: Email spoofing (trusted sender)    │
│ User Factor: Social engineering                   │
│ Security Gap: Email filtering (bypass detected)   │
│                                                     │
│ ───────────────────────────────────────────────   │
│ RECOMMENDED ACTIONS                                │
│ ───────────────────────────────────────────────   │
│                                                     │
│ IMMEDIATE (Completed):                            │
│ ✓ Isolate infected endpoints                      │
│ ✓ Kill malicious processes                        │
│ ✓ Block C2 IP at firewall                         │
│ ✓ Preserve forensic evidence                      │
│                                                     │
│ SHORT-TERM (Next 24 hours):                       │
│ ☐ Rebuild affected endpoints from clean image     │
│ ☐ Reset user passwords                            │
│ ☐ Change compromised account credentials          │
│ ☐ Notify affected customers (data breach)         │
│ ☐ Review email gateway logs (trace attack)        │
│ ☐ Block attacker's other known C2 IPs             │
│                                                     │
│ LONG-TERM (Next 30 days):                         │
│ ☐ User security awareness training                │
│ ☐ Email authentication enhancement (SPF/DKIM)     │
│ ☐ Upgrade endpoint detection & response (EDR)     │
│ ☐ Implement web isolation for high-risk users     │
│ ☐ Conduct forensic deep-dive analysis             │
│ ☐ Post-incident review meeting                    │
│                                                     │
│ ───────────────────────────────────────────────   │
│ IMPACT ASSESSMENT                                  │
│ ───────────────────────────────────────────────   │
│                                                     │
│ Business Impact: MEDIUM                           │
│ ├─ Systems Compromised: 3 (not critical)         │
│ ├─ Downtime: 2-4 hours (rebuilding systems)      │
│ ├─ Data Loss: 150 MB (recoverable backups)        │
│ └─ Financial Impact: ~$50K (notification + review)│
│                                                     │
│ Risk Mitigation: EXCELLENT                        │
│ ├─ Quick Detection (48 seconds)                   │
│ ├─ Rapid Response (automation enabled)            │
│ ├─ Limited Lateral Movement                       │
│ ├─ Critical Systems Protected                     │
│ └─ Evidence Preserved for Legal                   │
│                                                     │
│ ───────────────────────────────────────────────   │
│ LESSONS LEARNED                                    │
│ ───────────────────────────────────────────────   │
│                                                     │
│ What Worked Well:                                  │
│ ✓ XDR multi-agent detection enabled quick find   │
│ ✓ Automated response contained threat             │
│ ✓ Forensic timeline reconstruction accurate       │
│ ✓ No spread to critical infrastructure            │
│                                                     │
│ What Could Improve:                                │
│ ⚠ Email filtering failed to catch phishing        │
│ ⚠ User didn't verify sender authenticity          │
│ ⚠ Backup strategy needs refinement                │
│ ⚠ Password rotation policy too infrequent         │
│                                                     │
│ ───────────────────────────────────────────────   │
│                                                     │
│ Report Generated: 2026-06-10 14:45:30             │
│ Analyst: John Analyst (SOC Lead)                  │
│ Reviewed By: Security Manager                     │
│ Approved By: Chief Information Security Officer   │
│                                                     │
│              [📥 DOWNLOAD PDF] [📧 EMAIL]        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### **Incident Closure:**

```
Alert Status: INVESTIGATING → CONFIRMED THREAT → CONTAINED → CLOSED

Incident Metrics:
├─ Detection Time: 48 seconds (Excellent ⭐)
├─ Response Time: 60 seconds (Excellent ⭐)
├─ Containment Time: 75 seconds total (Excellent ⭐)
├─ Investigation Time: 13 minutes (Good ✓)
├─ False Positive: NO (Confirmed threat)
├─ Systems Compromised: 3 (recovered)
├─ Data Loss: 150 MB (notifiable, recoverable)
├─ Critical Systems Affected: 0 (Protected)
└─ Overall Status: SUCCESSFULLY MANAGED ✓

Incident Closed: 2026-06-10 15:30:00
Post-Incident Review Scheduled: 2026-06-11 09:00 AM
```

---

## 📊 **COMPLETE INVESTIGATION WORKFLOW SUMMARY**

| Stage | What Happens | Time | Tools Used | Analyst Action |
|-------|--------------|------|-----------|-----------------|
| **1. Detection** | 4 AI agents find threat | 7s | XDR Agents | Monitor alerts |
| **2. Triage** | Assess severity/scope | 2m | Dashboard | Assign priority |
| **3. Investigation** | Gather initial context | 5m | Details panel | Review evidence |
| **4. Correlation** | Link events together | 3m | Queries | Connect dots |
| **5. Confirmation** | Verify it's real threat | 2m | Timeline | Make decision |
| **6. Planning** | Design response | 3m | Automation | Approve actions |
| **7. Remediation** | Execute response | 1m | SOAR | Monitor execution |
| **8. Forensics** | Deep analysis | 30m+ | Evidence | Investigate fully |
| **9. Reporting** | Document incident | 10m | Report gen | Sign off |

**Total Average Investigation Time: 60-90 minutes**  
**Detection to Containment: <2 minutes (Automated)**

---

## 🎯 **KEY INVESTIGATION PRINCIPLES**

```
1. SPEED IS CRITICAL
   └─ Faster detection = less damage
   └─ Your XDR: 48-75 seconds to containment

2. CORRELATION MATTERS
   └─ Single signal = could be false positive
   └─ Multiple signals = high confidence
   └─ Your 4 agents provide correlation

3. EVIDENCE PRESERVATION
   └─ Collect data before cleanup
   └─ Chain of custody important
   └─ Enables post-incident analysis

4. AUTOMATION SAVES TIME
   └─ Pre-defined response plans
   └─ Automated execution
   └─ Human oversight maintained

5. DOCUMENTATION IS CRITICAL
   └─ Incident report for audit
   └─ Timeline reconstruction
   └─ Legal protection
```

---

## 💡 **EXAMPLE INVESTIGATION SCENARIO**

**Scenario: Ransomware Detection**

```
T+0s:   Ransomware encrypts files on PC-007
        └─ System Monitor detects: Disk I/O spike (0.87 score)
        └─ Malware Agent flags: Ransomware signature (0.91 score)

T+5s:   Threat score calculated: 0.82 (HIGH)
        └─ Alert generated

T+10s:  SOC analyst sees alert
        └─ Clicks [INVESTIGATE]

T+30s:  Analyst correlates:
        └─ File extension changes (.txt → .encrypted)
        └─ Registry changes (ransomware indicators)
        └─ Ransom note appears in folder
        └─ Decision: REAL THREAT

T+45s:  Analyst approves auto-response:
        └─ Kill ransomware process
        └─ Disconnect from network
        └─ Snapshot disk for recovery
        └─ Trigger incident response

T+90s:  Containment complete
        └─ Ransomware stopped
        └─ Data corruption halted mid-process
        └─ Backups initiated
        └─ Recovery plan ready

Result: Limited damage, quick recovery, incident closed
```


# 🔍 **CYBER SENTINEL XDR - INCIDENT INVESTIGATION WORKFLOW WITH FLOWCHARTS**

---

## **FLOWCHART 1: COMPLETE INCIDENT LIFECYCLE**

```
┌─────────────────────────────────────────────────────────────────┐
│              INCIDENT DETECTION & INVESTIGATION FLOW              │
└─────────────────────────────────────────────────────────────────┘

                            START: Threat Event
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │  4 AI Detection Agents   │
                    │  (Parallel Processing)   │
                    └──────────────┬───────────┘
                                   │
                ┌──────────┬────────┼────────┬──────────┐
                │          │        │        │          │
                ▼          ▼        ▼        ▼          ▼
            Network    Malware  System   User Behavior
            Detection  Analysis Monitor  Analysis
            (0.92)     (0.88)   (0.54)   (0.35)
                │          │        │          │
                └──────────┴────────┴──────────┘
                           │
                           ▼
            ┌────────────────────────────┐
            │  Fusion Engine             │
            │  Calculate Threat Score    │
            │  (Weighted Combination)    │
            └────────────┬───────────────┘
                         │
                         ▼
                    ┌─────────────┐
                    │Threat Score │
                    │    0.74     │
                    └─────┬───────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
    <0.30            0.30-0.70          ≥0.70
    (LOW)           (MEDIUM-HIGH)      (CRITICAL)
        │                 │                 │
        ▼                 ▼                 ▼
    ┌─────────┐    ┌──────────────┐   ┌─────────────┐
    │   LOG   │    │   QUEUE FOR  │   │ IMMEDIATE   │
    │  ONLY   │    │  ANALYST     │   │ ESCALATION  │
    └────┬────┘    │ INVESTIGATION│   │  & ALERT    │
         │         └──────┬───────┘   └──────┬──────┘
         │                │                  │
         ▼                ▼                  ▼
    ┌─────────────────────────────────────────────┐
    │  ALERT GENERATED & SENT TO SOC DASHBOARD    │
    │  ├─ Real-time notification                  │
    │  ├─ Alert queued in Investigation Queue     │
    │  ├─ Severity color coded                    │
    │  └─ Auto-escalation if critical             │
    └────────┬────────────────────────────────────┘
             │
             ▼
    ┌─────────────────────────────┐
    │  SOC ANALYST ASSIGNMENT      │
    │  ┌─────────────────────────┐ │
    │  │ Click [INVESTIGATE]     │ │
    │  │ Alert Status: OPEN      │ │
    │  │ ├─ Assign to self       │ │
    │  │ ├─ Change status to     │ │
    │  │ │  INVESTIGATING        │ │
    │  │ └─ Start timer          │ │
    │  └─────────────────────────┘ │
    └────────┬────────────────────┘
             │
             ▼
      ┌──────────────────────┐
      │ INVESTIGATION BEGINS │
      │ (See Flowchart 2)    │
      └──────────┬───────────┘
                 │
                 ▼
          ┌──────────────┐
          │   TRIAGE &   │
          │  CORRELATION │
          │ (See Flowchart 3)
          └──────┬───────┘
                 │
                 ▼
          ┌──────────────┐
          │    THREAT    │
          │ CONFIRMATION │
          │ (See Flowchart 4)
          └──────┬───────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
    CONFIRMED          FALSE
    THREAT            POSITIVE
        │                 │
        ▼                 ▼
    ┌──────────┐    ┌──────────┐
    │ PROCEED  │    │ CLOSE    │
    │ TO       │    │ ALERT    │
    │ RESPONSE │    │ MARK:    │
    │ PLANNING │    │ FALSE POS│
    └────┬─────┘    └────┬─────┘
         │               │
         ▼               ▼
    Response Planning   END
    (Flowchart 5)
         │
         ▼
    Remediation & Containment
    (Flowchart 6)
         │
         ▼
    Post-Incident Forensics
    (Flowchart 7)
         │
         ▼
    Incident Report Generation
         │
         ▼
    ┌──────────────────┐
    │ INCIDENT CLOSED  │
    │ & DOCUMENTED     │
    └────────┬─────────┘
             │
             ▼
       Lessons Learned
       Review Meeting
             │
             ▼
           END
```

---

## **FLOWCHART 2: ALERT TRIAGE DECISION TREE**

```
┌─────────────────────────────────────────────────────────────────┐
│           ALERT TRIAGE & INITIAL INVESTIGATION FLOW              │
└─────────────────────────────────────────────────────────────────┘

              Alert Received by Analyst
                      │
                      ▼
         ┌─────────────────────────┐
         │  CHECK: Known False     │
         │  Positive?              │
         │                         │
         │  • Backup process       │
         │  • Scheduled scans      │
         │  • Maintenance windows  │
         │  • Third-party updates  │
         └────────┬────────────────┘
                  │
        ┌─────────┴──────────┐
        │ YES               NO
        ▼                   ▼
    ┌────────────┐   ┌─────────────────────┐
    │  SUPPRESS  │   │  Continue           │
    │  ALERT     │   │  Investigation      │
    │  UPDATE    │   └────────┬────────────┘
    │  KB        │            │
    └────┬───────┘            ▼
         │          ┌────────────────────────┐
         │          │  GATHER CONTEXT        │
         │          │                        │
         │          │  ├─ Endpoint info      │
         │          │  ├─ User info          │
         │          │  ├─ Alert timeline     │
         │          │  ├─ Agent scores       │
         │          │  └─ Affected resources │
         │          └────────┬───────────────┘
         │                   │
         │                   ▼
         │          ┌────────────────────────┐
         │          │  ASSESS: What is the  │
         │          │  CRITICALITY?          │
         │          │                        │
         │          │  • Endpoint type       │
         │          │  • User role           │
         │          │  • Data sensitivity    │
         │          │  • Business impact     │
         │          └────────┬───────────────┘
         │                   │
         │          ┌────────┴────────┬──────────────┐
         │          │                 │              │
         │          ▼                 ▼              ▼
         │      Workstation      Server          Domain Controller
         │          │                │              │
         │          ▼                ▼              ▼
         │      PRIORITY 2/3     PRIORITY 1   PRIORITY 0 (CRITICAL)
         │          │                │              │
         │          └────────┬───────┴──────────────┘
         │                   │
         │                   ▼
         │          ┌────────────────────────┐
         │          │  SET PRIORITY LEVEL    │
         │          │                        │
         │          │  P1: Immediate action  │
         │          │  P2: Hour response     │
         │          │  P3: Same day response │
         │          │  P4: Queue for later   │
         │          └────────┬───────────────┘
         │                   │
         │                   ▼
         │          ┌────────────────────────┐
         │          │  ALERT STATUS UPDATE   │
         │          │                        │
         │          │  Priority: ASSIGNED    │
         │          │  Status: INVESTIGATING │
         │          │  Owner: John Analyst   │
         │          │  Timer: STARTED        │
         │          └────────────────────────┘
         │
         └─────────────────────────┬────────────┐
                                   │            │
                                   ▼            ▼
                          Proceed to          Suppress &
                          Correlation         Move to KB
                          (Flowchart 3)       (Closed)
```

---

## **FLOWCHART 3: EVIDENCE GATHERING & CORRELATION**

```
┌─────────────────────────────────────────────────────────────────┐
│        EVIDENCE GATHERING & EVENT CORRELATION FLOW               │
└─────────────────────────────────────────────────────────────────┘

         Analyst Opens Investigation Details Panel
                          │
                          ▼
         ┌─────────────────────────────────────┐
         │  STEP 1: FILE ANALYSIS              │
         │                                     │
         │  Query MongoDB:                     │
         │  • File execution timeline          │
         │  • File hash (MD5/SHA256)           │
         │  • File origin (download/email)     │
         │  • Process spawn chain              │
         │  • Registry modifications           │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────┐
         │  Results: Evidence Timeline      │
         │                                  │
         │  T-5m: Downloaded from email     │
         │  T-2m: File executed             │
         │  T-1m: Network connection        │
         │  T+0s: CPU spike detected        │
         │  T+1m: Data copy detected        │
         └──────────────┬───────────────────┘
                        │
              ┌─────────┴──────────┐
              │ File evidence      │
              │ COLLECTED ✓        │
              └─────────┬──────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  STEP 2: NETWORK CORRELATION        │
         │                                     │
         │  Query MongoDB:                     │
         │  • Destination IP connections      │
         │  • Connection patterns              │
         │  • Data volume transferred          │
         │  • Threat Intel (IP reputation)     │
         │  • TOR/Proxy detection              │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────┐
         │  Results: Network Pattern        │
         │                                  │
         │  Dest IP: 185.220.101.45         │
         │  TOR Exit Node: YES              │
         │  Connections: 12 attempts        │
         │  Interval: Every 30 seconds      │
         │  Pattern: C2 Beaconing           │
         └──────────────┬───────────────────┘
                        │
              ┌─────────┴──────────┐
              │ Network evidence   │
              │ COLLECTED ✓        │
              └─────────┬──────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  STEP 3: LATERAL MOVEMENT CHECK      │
         │                                     │
         │  Query MongoDB:                     │
         │  • Other endpoints with same IP     │
         │  • Lateral movement patterns        │
         │  • Shared resource access           │
         │  • Domain privilege escalation      │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────┐
         │  Results: Lateral Spread         │
         │                                  │
         │  PC-001: PRIMARY (INFECTED)      │
         │  PC-002: SECONDARY (INFECTED)    │
         │  PC-005: SECONDARY (INFECTED)    │
         │  SERVERS: NO (SAFE)              │
         │  Spread: LIMITED (good)          │
         └──────────────┬───────────────────┘
                        │
              ┌─────────┴──────────┐
              │ Lateral movement   │
              │ evidence           │
              │ COLLECTED ✓        │
              └─────────┬──────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  STEP 4: USER BEHAVIOR ANALYSIS      │
         │                                     │
         │  Query MongoDB:                     │
         │  • User activity timeline           │
         │  • File access patterns             │
         │  • Anomalies in behavior            │
         │  • Social engineering indicators    │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────┐
         │  Results: User Context           │
         │                                  │
         │  Logon: 09:00 AM (Normal)        │
         │  Email: Phishing email detected  │
         │  Downloaded: invoice.exe         │
         │  Executed: Manually by user      │
         │  Verdict: Social engineering     │
         └──────────────┬───────────────────┘
                        │
              ┌─────────┴──────────┐
              │ User behavior      │
              │ evidence           │
              │ COLLECTED ✓        │
              └─────────┬──────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  STEP 5: THREAT INTELLIGENCE        │
         │                                     │
         │  Check External Sources:            │
         │  • VirusTotal (malware hashes)      │
         │  • AlienVault OTX (IP reputation)   │
         │  • Shodan (server fingerprinting)   │
         │  • Domain WHOIS (registrant info)   │
         │  • Threat intel feeds               │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────┐
         │  Results: Threat Intel           │
         │                                  │
         │  Malware: Emotet v4.2.1          │
         │  Known since: April 2026         │
         │  Previous incidents: 47          │
         │  Avg dwell time: 3-7 days        │
         │  Capabilities: C2, data theft    │
         └──────────────┬───────────────────┘
                        │
              ┌─────────┴──────────┐
              │ Threat intel       │
              │ evidence           │
              │ COLLECTED ✓        │
              └─────────┬──────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  EVIDENCE CORRELATION COMPLETE       │
         │                                     │
         │  Files Correlated: 5                │
         │  Network Events: 12                 │
         │  Timeline Events: 8                 │
         │  Threat Intel Hits: 8               │
         │  Lateral Movement: 2 systems        │
         │                                     │
         │  Evidence Quality: EXCELLENT ✓✓✓   │
         │  Confidence Level: 95%              │
         │                                     │
         │  VERDICT: REAL THREAT               │
         └────────────┬──────────────────────┘
                      │
                      ▼
         Proceed to Threat Confirmation
         (Flowchart 4)
```

---

## **FLOWCHART 4: THREAT CONFIRMATION DECISION TREE**

```
┌─────────────────────────────────────────────────────────────────┐
│           THREAT CONFIRMATION & GO/NO-GO DECISION                │
└─────────────────────────────────────────────────────────────────┘

         All Evidence Correlation Complete
                      │
                      ▼
         ┌─────────────────────────────────┐
         │  DECISION POINT 1:               │
         │  Is this a REAL threat?          │
         │                                  │
         │  Evidence Assessment:             │
         │  • Multiple corroborating        │
         │    signals: YES ✓                │
         │  • Timeline logical: YES ✓       │
         │  • Threat intel matches: YES ✓   │
         │  • Known false positive: NO ✗    │
         └────────────┬────────────────────┘
                      │
        ┌─────────────┴──────────────┐
        │                            │
        ▼ YES (REAL)                ▼ NO (FALSE POSITIVE)
    ┌────────────┐              ┌──────────────────┐
    │ CONTINUE   │              │  MARK AS FALSE   │
    │ ANALYSIS   │              │  POSITIVE        │
    └─────┬──────┘              │                  │
          │                     │  Update KB       │
          │                     │  (Known issue)   │
          │                     │                  │
          │                     │  CLOSE ALERT     │
          │                     │                  │
          │                     └────┬─────────────┘
          │                         │
          │                         ▼
          │                   ┌──────────────┐
          │                   │  END         │
          │                   │  (Alert      │
          │                   │   Closed)    │
          │                   └──────────────┘
          │
          ▼
    ┌──────────────────────────────┐
    │  DECISION POINT 2:            │
    │  What is the SCOPE?           │
    │                               │
    │  Scope Assessment:             │
    │  • Single endpoint: YES        │
    │  • Multiple endpoints: YES     │
    │  • Lateral to servers: NO      │
    │  • Network-wide: NO            │
    │  • Domain Controller: NO       │
    └──────────┬───────────────────┘
               │
        ┌──────┴──────┬──────────┬──────────┐
        │             │          │          │
        ▼             ▼          ▼          ▼
    ISOLATED    LIMITED    WIDESPREAD  CRITICAL
    (1 PC)      (2-5 PCs)  (>5 PCs)    (DC/Servers)
        │             │          │          │
        ▼             ▼          ▼          ▼
    P2/P3       P2         P1        P0/P1
    (Medium)    (High)     (Critical) (CRITICAL)
        │             │          │          │
        └─────────────┼──────────┼──────────┘
                      │          │
                      ▼          ▼
    ┌──────────────────────────────────────┐
    │  DECISION POINT 3:                   │
    │  What is the IMPACT?                 │
    │                                      │
    │  Impact Assessment:                   │
    │  • Endpoint type (workstation/server)│
    │  • User role (admin/regular)         │
    │  • Data sensitivity (public/secret)  │
    │  • Business continuity (high/low)    │
    └──────────┬───────────────────────────┘
               │
        ┌──────┴──────┬──────────┬──────────┐
        │             │          │          │
        ▼             ▼          ▼          ▼
    LOW         MEDIUM        HIGH     CRITICAL
    IMPACT      IMPACT        IMPACT   IMPACT
        │             │          │          │
        ├─────────────┼──────────┼──────────┤
        │             │          │          │
        ▼             ▼          ▼          ▼
    ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐
    │Proceed │ │Proceed   │ │Proceed │ │ESCALATE│
    │Normally│ │ with     │ │to      │ │IMMEDIATELY
    │        │ │Caution   │ │Response│ │        │
    │        │ │          │ │(P1)    │ │ Notify │
    │        │ │          │ │        │ │ Mgmt   │
    └───┬────┘ └────┬─────┘ └───┬────┘ └───┬────┘
        │           │           │         │
        └───────────┼───────────┼─────────┘
                    │           │
                    ▼           ▼
    ┌─────────────────────────────────────┐
    │  FINAL CONFIRMATION ASSESSMENT       │
    │                                     │
    │  ✓ Is Real Threat: YES              │
    │  ✓ Scope Defined: YES               │
    │  ✓ Impact Assessed: YES             │
    │  ✓ Priority Set: P1 CRITICAL        │
    │                                     │
    │  ANALYST DECISION: CONFIRMED THREAT │
    │  STATUS: ACTIVATE RESPONSE PLAN     │
    │  NEXT: Response Planning (FC5)      │
    └────────────┬──────────────────────┘
                 │
                 ▼
      Response Planning & Execution
      (Flowchart 5)
```

---

## **FLOWCHART 5: RESPONSE PLANNING & EXECUTION**

```
┌─────────────────────────────────────────────────────────────────┐
│         AUTOMATED RESPONSE PLANNING & EXECUTION FLOW              │
└─────────────────────────────────────────────────────────────────┘

      Analyst Confirms: Real Threat Detected
                      │
                      ▼
         ┌──────────────────────────────┐
         │  STEP 1: Retrieve Response   │
         │  Plan Templates              │
         │                              │
         │  XDR selects based on:       │
         │  • Threat type (malware)     │
         │  • Severity (critical)       │
         │  • Scope (multi-endpoint)    │
         │  • Industry (finance)        │
         └──────────────┬───────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────────┐
         │  STEP 2: Recommended Actions             │
         │  Presented to Analyst                    │
         │                                          │
         │  AUTO-EXECUTE (No approval):             │
         │  ☑ Kill malicious processes (PC-001)     │
         │  ☑ Kill malicious processes (PC-002)     │
         │  ☑ Kill malicious processes (PC-005)     │
         │  ☑ Block destination IP (FW rule)        │
         │  ☑ Create disk snapshots (forensics)     │
         │                                          │
         │  REQUIRES APPROVAL:                      │
         │  ☐ Isolate endpoints from network        │
         │  ☐ Terminate user session                │
         │  ☐ Reset user credentials                │
         │  ☐ Lock user account                     │
         │  ☐ Escalate to executive team            │
         │                                          │
         │  OPTIONAL:                               │
         │  ☐ Scan entire department                │
         │  ☐ Revoke user access                    │
         │  ☐ Trigger incident response call        │
         └──────────────┬───────────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────────────┐
         │  DECISION: Auto-Execute or Custom?   │
         └──────────┬──────────────────────────┘
                    │
        ┌───────────┴──────────┐
        │                      │
        ▼ AUTO                ▼ CUSTOM
    (Trusted)           (Analyst Review)
        │                    │
        ▼                    ▼
    ┌─────────────┐  ┌──────────────────┐
    │ EXECUTE     │  │ Analyst Modifies │
    │ IMMEDIATELY │  │ Plan:            │
    │             │  │                  │
    │ Run all     │  │ ☐ Skip steps     │
    │ actions     │  │ ☐ Add steps      │
    │             │  │ ☐ Change order   │
    │             │  │ ☐ Set delays     │
    └──────┬──────┘  │                  │
           │         └────────┬─────────┘
           │                  │
           │                  ▼
           │         ┌──────────────────┐
           │         │ Custom Plan      │
           │         │ Created          │
           │         └────────┬─────────┘
           │                  │
           └──────────┬───────┘
                      │
                      ▼
         ┌────────────────────────────────────┐
         │  APPROVAL CONFIRMATION             │
         │                                    │
         │  Response Plan Status:              │
         │  ✓ Confirmed                       │
         │  ✓ Reviewed                        │
         │  ✓ Approved by Analyst             │
         │  ✓ READY TO EXECUTE                │
         │                                    │
         │  [✓ EXECUTE] [✗ CANCEL]            │
         └────────────┬─────────────────────┘
                      │
        ┌─────────────┴──────────────┐
        │                            │
        ▼ APPROVED                   ▼ CANCELLED
    ┌─────────────┐          ┌──────────────┐
    │ EXECUTE     │          │ Response     │
    │ RESPONSE    │          │ Cancelled    │
    │ PLAN        │          │              │
    │ IMMEDIATELY │          │ Incident:    │
    └──────┬──────┘          │ UNRESOLVED   │
           │                 │              │
           │                 └──────┬───────┘
           │                        │
           ▼                        ▼
    ┌──────────────────────────────────────────────┐
    │  STEP 3: RESPONSE EXECUTION (Automated)      │
    │                                              │
    │  T+0s:  PC-001: Kill process invoice.exe     │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 0.5s                       │
    │                                              │
    │  T+0.5s: PC-002: Kill process svchost.exe    │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 0.5s                       │
    │                                              │
    │  T+1s:  PC-005: Kill process explorer.exe    │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 0.5s                       │
    │                                              │
    │  T+1.5s: Firewall: Add rule "Block IP"       │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 2s                         │
    │                                              │
    │  T+3.5s: PC-001: Network Isolation           │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 1s                         │
    │                                              │
    │  T+4.5s: PC-002: Network Isolation           │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 1s                         │
    │                                              │
    │  T+5.5s: PC-005: Network Isolation           │
    │         Status: ✓ SUCCESS                    │
    │         Duration: 1s                         │
    │                                              │
    │  T+6.5s: Disk Snapshots: Initiated           │
    │         Status: ⏳ IN PROGRESS                │
    │         Duration: 45s (15% complete)         │
    │                                              │
    │  ✓ ALL CRITICAL ACTIONS COMPLETED            │
    │  ✓ CONTAINMENT ACHIEVED                      │
    │  ⏳ FORENSICS IN PROGRESS                     │
    └──────────┬───────────────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │  STEP 4: STAKEHOLDER NOTIFICATIONS    │
    │                                      │
    │  Email alerts sent to:                │
    │  ✓ SOC Manager (john.manager@...)    │
    │  ✓ IT Director (jane.director@...)   │
    │  ✓ Security Officer (bob.sec@...)    │
    │  ✓ Incident Response Team            │
    │  ✓ Executive Sponsor (ciso@...)      │
    │                                      │
    │  Slack notifications posted to:       │
    │  ✓ #incident-response channel        │
    │  ✓ #security-team channel            │
    │                                      │
    │  Ticket created: INC-2026-0001       │
    │  Status: CONTAINMENT COMPLETED       │
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────┐
    │  CONTAINMENT COMPLETE             │
    │                                  │
    │  Response Time: 48 seconds        │
    │  Status: ✓ SUCCESS                │
    │  Threat Level: MITIGATED          │
    │  Next: Post-Incident Forensics    │
    └──────────┬───────────────────────┘
               │
               ▼
        Forensics Investigation
        (Flowchart 7)
```

---

## **FLOWCHART 6: POST-INCIDENT FORENSICS INVESTIGATION**

```
┌─────────────────────────────────────────────────────────────────┐
│         POST-INCIDENT FORENSICS INVESTIGATION FLOW                │
└─────────────────────────────────────────────────────────────────┘

      Threat Contained, Forensics Begin
                      │
                      ▼
         ┌──────────────────────────┐
         │  STEP 1: Malware         │
         │  Deep Analysis           │
         │                          │
         │  Actions:                │
         │  • Quarantine binary     │
         │  • Static analysis       │
         │  • Dynamic analysis      │
         │  • YARA rule matching    │
         │  • String extraction     │
         │  • API calls traced      │
         │  • Decompilation         │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Results:                    │
         │  • Emotet variant v4.2.1     │
         │  • Hardcoded C2 IPs: 3       │
         │  • Persistence: None found   │
         │  • Capabilities: Detailed    │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  STEP 2: Timeline        │
         │  Reconstruction          │
         │                          │
         │  Create sequence:        │
         │  • Email received        │
         │  • File downloaded       │
         │  • Malware executed      │
         │  • Network connections   │
         │  • Data exfiltration     │
         │  • Lateral movement      │
         │  • Endpoint spread       │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Timeline Created:           │
         │  T-300s to T+3600s           │
         │  Granularity: Per-second     │
         │  Events: 47 items            │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  STEP 3: Data Loss       │
         │  Assessment              │
         │                          │
         │  Check:                  │
         │  • Files accessed        │
         │  • Data volume           │
         │  • Exfiltration events   │
         │  • C2 data transfer      │
         │  • Backup integrity      │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Results:                    │
         │  • Files stolen: 47 docs     │
         │  • Data volume: 150 MB       │
         │  • Sensitive data: YES       │
         │  • Backup status: OK         │
         │  • Recovery: Possible        │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  STEP 4: Lateral         │
         │  Movement Analysis       │
         │                          │
         │  Check:                  │
         │  • Other PCs infected    │
         │  • Servers compromised   │
         │  • Domain escalation     │
         │  • Admin account abuse   │
         │  • Network shares        │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Results:                    │
         │  • PC-002: YES (infected)    │
         │  • PC-005: YES (infected)    │
         │  • Servers: NO (protected)   │
         │  • Domain: NO (protected)    │
         │  • Network shares: OK        │
         │  Scope: LIMITED              │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  STEP 5: Persistence     │
         │  Mechanisms Check        │
         │                          │
         │  Verify:                 │
         │  • Scheduled tasks       │
         │  • Startup registry      │
         │  • Windows services      │
         │  • Startup folder        │
         │  • Browser extensions    │
         │  • Rootkit indicators    │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Results:                    │
         │  • Persistence: NOT FOUND    │
         │  • No backdoors detected     │
         │  • Clean shutdown safe       │
         │  • Rebuild not needed        │
         │  • Restore from backup OK    │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  STEP 6: Attribution     │
         │  Analysis                │
         │                          │
         │  Research:               │
         │  • Threat actor          │
         │  • Attack infrastructure │
         │  • Motive (financial)    │
         │  • Previous incidents    │
         │  • Indicators of        │
         │    compromise (IoCs)     │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Results:                    │
         │  • Actor: Unknown            │
         │  • Likely: Eastern European  │
         │  • Motivation: Financial     │
         │  • Technique: Mass campaign  │
         │  • Previous 47 incidents     │
         │  • Confidence: Medium        │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │  STEP 7: Root Cause      │
         │  Analysis                │
         │                          │
         │  Primary:                │
         │  • Phishing email        │
         │                          │
         │  Contributing:           │
         │  • No email filtering    │
         │  • User awareness low    │
         │  • No EDR (now fixed)    │
         │  • Backup gaps           │
         └──────────┬───────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  FORENSICS INVESTIGATION     │
         │  COMPLETE                    │
         │                              │
         │  ✓ Malware analyzed          │
         │  ✓ Timeline reconstructed    │
         │  ✓ Data loss assessed        │
         │  ✓ Lateral movement checked  │
         │  ✓ Persistence analyzed      │
         │  ✓ Attribution attempted     │
         │  ✓ Root cause identified     │
         │                              │
         │  Next: Report Generation     │
         └──────────┬───────────────────┘
                    │
                    ▼
    Generate Incident Report
    & Recommendations
```

---

## **FLOWCHART 7: INCIDENT CLOSURE & REPORTING**

```
┌─────────────────────────────────────────────────────────────────┐
│         INCIDENT REPORTING & CLOSURE WORKFLOW                     │
└─────────────────────────────────────────────────────────────────┘

    Forensics Complete, Generate Report
                      │
                      ▼
         ┌──────────────────────────────┐
         │  AUTO-GENERATE REPORT        │
         │                              │
         │  Report sections:            │
         │  ✓ Executive summary         │
         │  ✓ Timeline                  │
         │  ✓ Affected systems          │
         │  ✓ Root cause                │
         │  ✓ Data impact               │
         │  ✓ Forensic findings         │
         │  ✓ Recommendations           │
         │  ✓ Lessons learned           │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  Incident Report Generated   │
         │                              │
         │  INC-2026-0001               │
         │  Title: Emotet C2 Detection  │
         │  Pages: 12                   │
         │  Status: DRAFT               │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  PEER REVIEW                 │
         │                              │
         │  Reviewed by:                │
         │  • Incident response lead    │
         │  • Security manager          │
         │  • CTO/CISO                  │
         │                              │
         │  Status: ✓ APPROVED          │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  DISTRIBUTE REPORT            │
         │                              │
         │  Recipients:                 │
         │  • Executive leadership      │
         │  • IT management             │
         │  • Legal team                │
         │  • Compliance team           │
         │  • Incident responders       │
         │  • Finance (cost estimate)   │
         │  • Board (if breach)         │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  CLOSE INCIDENT              │
         │                              │
         │  Update Ticket:              │
         │  • Status: CLOSED            │
         │  • Date Closed: 2026-06-10   │
         │  • Duration: 1h 13m          │
         │  • Resolution: CONTAINED     │
         │  • Impact: LIMITED           │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  SCHEDULE ACTIVITIES         │
         │                              │
         │  • Post-incident review      │
         │    (1 day after)             │
         │                              │
         │  • Lessons learned meeting   │
         │    (3 days after)            │
         │                              │
         │  • Remediation execution     │
         │    (1 week)                  │
         │                              │
         │  • Follow-up check-in        │
         │    (30 days after)           │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  INCIDENT METRICS            │
         │                              │
         │  Detection Time: 48s         │
         │  Response Time: 60s          │
         │  Containment: 75s total      │
         │  Forensics: 30 minutes       │
         │  Report: 15 minutes          │
         │  Total: 1h 13m               │
         │                              │
         │  Performance: ✓ EXCELLENT    │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  DATA BREACH NOTIFICATION    │
         │  (If Required)               │
         │                              │
         │  Trigger Assessment:         │
         │  ✓ Data stolen: YES          │
         │  ✓ PII involved: YES         │
         │  ✓ Notification: REQUIRED    │
         │  ✓ Timeframe: 30-60 days     │
         │                              │
         │  Actions:                    │
         │  • Draft notification letter │
         │  • Prepare credit monitoring │
         │  • Engage public relations   │
         │  • Legal review              │
         │  • Regulatory notification   │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────────┐
         │  INCIDENT OFFICIALLY CLOSED       │
         │                                  │
         │  ✓ All containment actions       │
         │    completed                     │
         │  ✓ Forensics analysis done       │
         │  ✓ Report generated              │
         │  ✓ Stakeholders notified         │
         │  ✓ Metrics recorded              │
         │  ✓ Follow-up scheduled           │
         │  ✓ Documentation archived        │
         │                                  │
         │  INCIDENT: INC-2026-0001         │
         │  Status: CLOSED                  │
         │  Date Closed: 2026-06-10 15:30   │
         └──────────┬───────────────────────┘
                    │
                    ▼
              PROCEED TO:
    ┌────────────────────────────────┐
    │ Post-Incident Review Meeting   │
    │ (Scheduled: 2026-06-11 09:00)  │
    │                                │
    │ Attendees:                     │
    │ • Incident response team       │
    │ • SOC analysts                 │
    │ • IT operations                │
    │ • Security management          │
    │ • Executive sponsor            │
    │                                │
    │ Agenda:                        │
    │ ✓ What went well               │
    │ ✓ What could improve           │
    │ ✓ Process refinements          │
    │ ✓ Training opportunities       │
    │ ✓ Action items                 │
    └────────────┬───────────────────┘
                 │
                 ▼
         Implementation of
         Lessons Learned
              (30 days)
                 │
                 ▼
           Follow-up Check-in
         (30-day assessment)
                 │
                 ▼
             ✓ COMPLETE
```

---

## **FLOWCHART 8: AUTOMATED ALERT SEVERITY MATRIX**

```
┌─────────────────────────────────────────────────────────────────┐
│        THREAT SCORE → SEVERITY → ACTION MATRIX                    │
└─────────────────────────────────────────────────────────────────┘

                    Threat Score Calculated
                            │
                            ▼
            ┌───────────────────────────────┐
            │ Threat Score: 0.00 - 1.00     │
            └───────┬──────────────┬────────┘
                    │              │
        ┌───────────┴──────┬───────┴──────────┬──────────┐
        │                  │                  │          │
        ▼                  ▼                  ▼          ▼
    <0.30             0.30-0.50          0.50-0.70    ≥0.70
    LOW              MEDIUM              HIGH        CRITICAL
        │                │                 │           │
        │                │                 │           │
        ▼                ▼                 ▼           ▼
    ┌────────┐      ┌──────────┐      ┌──────────┐  ┌──────────┐
    │Color:  │      │Color:    │      │Color:    │  │Color:    │
    │GREEN   │      │YELLOW    │      │ORANGE    │  │RED       │
    │        │      │          │      │          │  │CRITICAL  │
    │Severity│      │Severity: │      │Severity: │  │Severity: │
    │INFORMATIONAL  │MEDIUM    │      │HIGH      │  │CRITICAL  │
    │        │      │          │      │          │  │          │
    │Action: │      │Action:   │      │Action:   │  │Action:   │
    │LOG     │      │QUEUE FOR │      │IMMEDIATE │  │IMMEDIATE │
    │ONLY    │      │ANALYST   │      │ANALYST   │  │ESCALATE  │
    │        │      │          │      │REVIEW    │  │AUTO-EXEC │
    │Analyst │      │Analyst   │      │Analyst   │  │Auto-exec │
    │Review: │      │Review:   │      │Review:   │  │Response  │
    │NONE    │      │DEFERRED  │      │PRIORITY  │  │REQUIRED  │
    │        │      │          │      │          │  │          │
    │Response│      │Response: │      │Response: │  │Response: │
    │TIME:   │      │TIME:     │      │TIME:     │  │TIME:     │
    │Days    │      │24 hours  │      │1 hour    │  │Minutes   │
    └────────┘      └──────────┘      └──────────┘  └──────────┘
        │                │                 │           │
        └────────┬───────┴──────────┬──────┴───────────┘
                 │                  │
                 ▼                  ▼
         ┌─────────────────┐  ┌──────────────────┐
         │ AUTO-RESPONSE   │  │ MANUAL RESPONSE  │
         │ DISABLED        │  │ (Analyst-Driven) │
         │                 │  │                  │
         │ • Log only      │  │ • Decision tree  │
         │ • No alert      │  │ • Evidence check │
         │ • Archive       │  │ • Confirmation   │
         │                 │  │ • Plan approval  │
         └─────────────────┘  │ • Execute        │
                              │                  │
                              └──────────────────┘
```

---

## **FLOWCHART 9: EVIDENCE COLLECTION & CHAIN OF CUSTODY**

```
┌─────────────────────────────────────────────────────────────────┐
│        EVIDENCE COLLECTION & CHAIN OF CUSTODY FLOW                │
└─────────────────────────────────────────────────────────────────┘

    Incident Confirmed, Begin Evidence Collection
                      │
                      ▼
         ┌──────────────────────────────┐
         │  STEP 1: IDENTIFY            │
         │  EVIDENCE ITEMS              │
         │                              │
         │  Collect:                    │
         │  ✓ Malware samples           │
         │  ✓ Memory dumps              │
         │  ✓ Disk images               │
         │  ✓ Network logs              │
         │  ✓ System logs               │
         │  ✓ Application logs          │
         │  ✓ Email headers             │
         │  ✓ File hashes               │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  STEP 2: SECURE              │
         │  EVIDENCE                    │
         │                              │
         │  Ensure:                     │
         │  ✓ Hash/checksum files       │
         │  ✓ Write-lock storage        │
         │  ✓ Encryption during transit │
         │  ✓ Secure archive location   │
         │  ✓ Access control list (ACL) │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  STEP 3: DOCUMENT            │
         │  CHAIN OF CUSTODY            │
         │                              │
         │  Record:                     │
         │  ✓ What (evidence type)      │
         │  ✓ When (date/time)          │
         │  ✓ Who (person handling)     │
         │  ✓ Where (storage location)  │
         │  ✓ How (collection method)   │
         │  ✓ Hash (file verification)  │
         │  ✓ Signature (handler auth)  │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  CHAIN OF CUSTODY LOG        │
         │                              │
         │  Evidence ID: EV-001         │
         │  Item: malware.exe           │
         │  Type: Binary executable     │
         │  Hash: abc123def456...       │
         │                              │
         │  Collection:                 │
         │  Date: 2026-06-10 14:45:30   │
         │  Analyst: john.analyst@...   │
         │  Method: ForensicToolKit     │
         │  Signature: [signed]         │
         │                              │
         │  Analysis:                   │
         │  Date: 2026-06-10 15:30:00   │
         │  Analyst: jane.forensic@...  │
         │  Purpose: Static analysis    │
         │  Signature: [signed]         │
         │                              │
         │  Archive:                    │
         │  Date: 2026-06-10 16:00:00   │
         │  Location: Secure vault      │
         │  Signature: [signed]         │
         │                              │
         │  Status: ✓ VERIFIED          │
         └──────────┬───────────────────┘
                    │
                    ▼
         ┌──────────────────────────────┐
         │  EVIDENCE INTEGRITY          │
         │  VERIFIED                    │
         │                              │
         │  ✓ No tampering detected     │
         │  ✓ Hashes match              │
         │  ✓ All handlers authenticated
         │  ✓ Chain intact              │
         │  ✓ Legal admissibility: HIGH │
         │                              │
         │  Ready for:                  │
         │  • Forensic analysis         │
         │  • Legal proceedings         │
         │  • Regulatory reporting      │
         │  • Post-incident review      │
         └──────────┬───────────────────┘
                    │
                    ▼
           Archive & Retain
         (Per legal requirements)
```

---

## **SUMMARY: Investigation Flowchart Quick Reference**

```
╔═════════════════════════════════════════════════════════════════╗
║            INVESTIGATION FLOWCHART REFERENCE GUIDE               ║
╠═════════════════════════════════════════════════════════════════╣
║                                                                 ║
║  FC1: Complete Incident Lifecycle                              ║
║  └─ START → Detection → Triage → Investigation → Response      ║
║     → Forensics → Reporting → END                              ║
║                                                                 ║
║  FC2: Alert Triage Decision Tree                               ║
║  └─ Known False Positive? → Skip or Continue Investigation     ║
║     → Criticality Assessment → Priority Assignment             ║
║                                                                 ║
║  FC3: Evidence Gathering & Correlation                         ║
║  └─ File Analysis → Network Analysis → Lateral Movement        ║
║     → User Behavior → Threat Intel → Confidence Assessment     ║
║                                                                 ║
║  FC4: Threat Confirmation                                      ║
║  └─ Real Threat? → Scope Assessment → Impact Analysis          ║
║     → Go/No-Go Decision                                        ║
║                                                                 ║
║  FC5: Response Planning & Execution                            ║
║  └─ Template Selection → Action Review → Approval              ║
║     → Execution → Notifications → Containment Complete         ║
║                                                                 ║
║  FC6: Post-Incident Forensics                                  ║
║  └─ Malware Analysis → Timeline Reconstruction                 ║
║     → Data Loss Assessment → Lateral Movement → Root Cause     ║
║                                                                 ║
║  FC7: Incident Closure & Reporting                             ║
║  └─ Auto-Report Generation → Peer Review → Distribution        ║
║     → Close Incident → Schedule Follow-ups                     ║
║                                                                 ║
║  FC8: Severity Matrix                                          ║
║  └─ Threat Score (0.0-1.0) → Color Code → Action → Timeline    ║
║                                                                 ║
║  FC9: Chain of Custody                                         ║
║  └─ Identify → Secure → Document → Verify → Archive            ║
║                                                                 ║
╠═════════════════════════════════════════════════════════════════╣
║  AVERAGE INVESTIGATION TIME BREAKDOWN:                          ║
║  • Detection to Alert: 7 seconds (Automated)                   ║
║  • Triage: 2 minutes (Analyst)                                 ║
║  • Investigation: 5 minutes (Analyst)                          ║
║  • Evidence Correlation: 3 minutes (Analyst)                   ║
║  • Threat Confirmation: 2 minutes (Analyst)                    ║
║  • Response Planning: 3 minutes (Analyst)                      ║
║  • Execution: 1 minute (Automated)                             ║
║  • Forensics: 30+ minutes (Analyst)                            ║
║  • Reporting: 10 minutes (Automated)                           ║
║  ─────────────────────────────────────────────                 ║
║  TOTAL: ~60 minutes from alert to closure                      ║
║                                                                 ║
║  DETECTION TO CONTAINMENT: 48-75 seconds (Excellent!)          ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝
```

---

## 📊 **CREATE PROFESSIONAL FLOWCHARTS IN THESE TOOLS**

### **Option 1: Lucidchart (Recommended)**
```
https://www.lucidchart.com
• Drag-and-drop interface
• Professional templates
• Real-time collaboration
• Export to PDF/PNG/SVG
• Integrations available
```

### **Option 2: Draw.io (Free)**
```
https://www.draw.io
• Free online tool
• Professional quality
• Auto-save to cloud
• Export to many formats
• No login required
```

### **Option 3: Microsoft Visio**
```
https://www.microsoft.com/en-us/microsoft-365/visio/
• Enterprise standard
• Advanced features
• Integration with Office
• Professional templates
```

### **Option 4: OmniGraffle (Mac)**
```
https://www.omnigraffle.com
• Mac-native app
• Beautiful output
• Professional export
```

---

## 🎨 **RENDERING INSTRUCTIONS FOR YOUR DOCUMENTATION**

Copy the ASCII flowcharts into:

```
1. Lucidchart
   • File → Import → Paste ASCII art
   • Auto-converts to visual diagram

2. Draw.io
   • Arrange → Import
   • Paste ASCII → Convert to shapes

3. PowerPoint/Docs
   • Insert → Drawing → Recreate from ASCII guide
   • Use decision diamonds, process boxes, arrows

4. Markdown/HTML
   • Keep ASCII art as-is in code blocks
   • Renders with monospace font
```

