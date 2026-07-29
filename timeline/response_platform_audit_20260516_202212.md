# Response Platform Audit — 2026-05-16 20:22:12 UTC

**Analyst:** IDPS Project Analyst Agent
**Scope:** Enterprise Response Philosophy compliance — all 16 attack scenarios cross-referenced against `response_engine.py`, `command_listener.py`, `backend.py` (`_server_soar_executor`, `_emit_soc_alert_if_correlated`, `/response/execute`), `fusion_engine_agent.py`, `fusion_engine.py`

---

## Executive Summary

- The response platform is **functionally solid** for 9 of 16 attack types (well-specified MITRE mappings, correct SOAR action routing, proper advisory separation). Overall response platform health: **5.8 / 10**.
- **7 of 16 attack scenarios have no dedicated response plan** in `response_engine.py` — they all fall through to the generic default handler (`alert_admin` + `log_event` only), violating the philosophy's mandate for typed, severity-proportional response.
- **3 SOAR actions critical to reversibility are missing** from `_server_soar_executor` on the host side: `unisolate_host`, `lock_account`, and `unlock_account`. A host that has been isolated by the server SOAR cannot be re-enabled without manual CLI intervention.
- **`unlock_account` does not exist anywhere** in the codebase — endpoint agent, server executor, or response plan — making `lock_account` an irreversible action in violation of the philosophy's reversibility principle.
- **Severity mis-mapping on 4 attack types**: Port Scan and Heartbleed should never be CRITICAL-auto-execute; Ransomware and C2 Beaconing are correctly mapped. Two user-behaviour scenarios (Impossible Travel, Credential Stuffing) emit no severity gate whatsoever because they have no response plan entry.
- **`rate_limit_traffic` is declared advisory** but has zero server-side implementation — for DDoS/DoS this is the single most important mitigation and it is silently logged without effect.

---

## Coverage Matrix

| Attack Scenario | MITRE | Detected by XDR? | Dedicated Response Plan? | Severity Philosophy Correct? | Reversible? | Permissions OK? |
|---|---|---|---|---|---|---|
| 1. Port Scan | T1046 | Yes (rule_detector) | Yes — `block_ip` + `alert_admin` | PARTIAL — auto-executes at CRITICAL but Port Scan is typically LOW-MEDIUM severity | Yes — `unblock_ip` exists | Yes, with Admin caveat |
| 2. DDoS / DoS | T1498/T1499 | Yes (rule_detector SYN_FLOOD, IsolationForest) | Yes — `block_ip` + `rate_limit_traffic` | PARTIAL — `rate_limit_traffic` is advisory-only, no implementation | Partial — IP unblock OK; rate-limit has no undo | N/A (rate_limit_traffic never executes) |
| 3. Heartbleed | T1499 | Partial (label match only; no CVE-specific network rule) | Yes — 6 actions mapped | FAIL — CRITICAL auto-execute with 6 actions; philosophy says HIGH = analyst approval | Partial — IP unblock OK; cert rotation advisory | Advisory actions are not executed |
| 4. C2 Beaconing | T1071 | Yes (RandomForest Botnet/C2 label) | Yes — `block_ip` + `kill_process` + `monitor_persistence` | PASS — CRITICAL auto-executes appropriately | Partial — `unblock_ip` OK; kill_process irreversible (acceptable) | Admin required for block_ip |
| 5. Lateral Movement | T1021 | Partial (correlation: network+system chain rule) | Yes — `isolate_host` + `block_ip` + `alert_admin` | PARTIAL — CRITICAL auto-execute on correlation; philosophy says HIGH = analyst approval for lateral movement | Partial — `unisolate_host` exists in endpoint agent; MISSING from server executor | Admin required |
| 6. Process Injection | — | No dedicated detection | No — falls to default handler | FAIL — default handler only; no severity gate | N/A | N/A |
| 7. Privilege Escalation | T1068 | Partial (user behavior model) | Yes — `kill_process` + `log_user_session` + `restrict_access` | PARTIAL — `log_user_session` and `restrict_access` are advisory with no implementation | Partial — kill is irreversible | N/A (advisory never executes) |
| 8. Persistence Mechanism | — | Partial — `monitor_persistence` detects but does not auto-remediate | No — no dedicated plan entry | FAIL — falls to default handler; no removal action | No undo defined | HKCU read is fine; delete would need Admin |
| 9. Ransomware | T1486 | Yes — `_detect_ransomware()` correlation gate | Yes — `kill_process` + `isolate_host` + `scan_filesystem` | PASS — CRITICAL auto-executes | Partial — `unisolate_host` exists at endpoint; missing at server | Admin required |
| 10. Impossible Travel | — | Partial (user behavior OC-SVM catches anomaly) | No — falls to default handler | FAIL — no MFA/session invalidation response | N/A | N/A |
| 11. Credential Stuffing | — | Partial (BruteForce RandomForest label) | Partial — `brute force` branch handles it; no CAPTCHA/session action | PARTIAL — lockout is advisory and never executes | Partial — `unlock_account` does not exist | Admin required for net user |
| 12. Insider Threat | T1078 | Partial (user model + correlation) | Partial — MITRE_MAP entry exists; falls to default handler (no dedicated response block) | FAIL — shadow monitoring, session recording, USB restriction not implemented | N/A | N/A |
| 13. Trojan | T1204 | Partial (malware_analysis_agent heuristic process match) | Partial — malware branch triggers quarantine indirectly via fusion | PARTIAL — no dedicated Trojan plan block; startup entry removal missing | Partial — quarantine is one-way; no restore | Quarantine needs file permissions |
| 14. Worm | — | No dedicated detection | No — falls to default handler | FAIL — no network segmentation action | N/A | N/A |
| 15. Spyware | — | No dedicated detection | No — falls to default handler | FAIL — microphone/webcam disable not possible via current SOAR | N/A | N/A |
| 16. Rootkit | — | No dedicated detection | No — falls to default handler | FAIL — kernel integrity check, safe-mode scan not implemented | N/A | N/A |

**Summary:** 4 of 16 fully pass, 5 partially pass, 7 completely fail coverage.

---

## Gap Analysis by Attack Type

### 1. Port Scan (T1046)
**What exists:** `rule_detector.py` PORT_SCAN_HORIZONTAL rule (≥15 unique dst ports). `response_engine.py` has a dedicated block: `block_ip` + `alert_admin`. SHAP extraction for block target.
**What is missing:** The philosophy places Port Scan at LOW-MEDIUM severity (log + monitor; alert analyst). However, if the fusion score reaches CRITICAL (possible if correlated with network model), `auto_execute=True` fires. This means a port scan could trigger automatic IP blocking without analyst approval. Philosophy states HIGH requires analyst approval.
**Severity verdict:** PARTIAL FAIL. Needs severity cap: Port Scan should never auto_execute; it should be advisory-only or require analyst approval regardless of score.
**Recommended fix:** Add explicit severity override in the port scan branch — clamp `auto_execute = False` for this attack type, or cap severity at HIGH.

---

### 2. DDoS / DoS (T1498/T1499)
**What exists:** SYN_FLOOD rule in `rule_detector.py`. `response_engine.py` DDoS branch: `block_ip` + `rate_limit_traffic`.
**What is missing:** `rate_limit_traffic` is classified as `_ADVISORY_ACTIONS` in `backend.py` (line 3733), so it is logged to `response_advisory_logs` but never executed. For a DDoS scenario this is the primary mitigation — blocking a single flood source IP does not stop volumetric DDoS. No actual rate-limiting implementation exists anywhere in the codebase (no netsh, no Suricata rule injection, no iptables call).
**Severity verdict:** PARTIAL FAIL. The block_ip action is sound. The rate_limit_traffic action is a dead stub.
**Recommended fix:** Implement `rate_limit_traffic` in `_server_soar_executor` using Windows netsh QoS rules or Suricata threshold.conf dynamic injection. Alternatively, document it as a manual playbook step with explicit advisory wording.

---

### 3. Heartbleed (T1499)
**What exists:** `response_engine.py` Heartbleed branch with 6 actions: `block_ip`, `alert_admin`, `update_software`, `patch_openssl`, `rotate_certificates`, `check_exposed_secrets`.
**What is missing:** Detection is label-match only — the word "heartbleed" must appear in the attack_type string. The CIC-IDS2017 Heartbleed class is present in the RandomForest classifier so it should produce this label. However, Heartbleed is typically MEDIUM severity by the philosophy (alert + analyst recommendation), yet the response plan inherits the fusion severity which can be CRITICAL, triggering `auto_execute=True`. The philosophy says a Heartbleed event requires patching (manual) + block source — not auto-execution of 6 actions.
**Additionally:** `patch_openssl`, `rotate_certificates`, `check_exposed_secrets`, and `update_software` are all advisory — they are silently swallowed. Only `block_ip` and `alert_admin` have any execution path.
**Severity verdict:** PARTIAL FAIL. Over-mapped to auto-execute; most actions are dead stubs.
**Recommended fix:** Hard-code `auto_execute = severity == "CRITICAL" and "ransomware" in attack_lower` pattern; Heartbleed should be HIGH at most with manual approval. Add explicit advisory display on the response modal for the 4 advisory actions.

---

### 4. C2 Beaconing / Botnet (T1071)
**What exists:** RandomForest classifies Botnet. `response_engine.py` C2 branch: `block_ip` + `kill_process` + `monitor_persistence`. `monitor_persistence` is correctly advisory.
**What is missing:** Philosophy mandates "capture memory, forensic package" — memory dump is not implemented anywhere. Philosophy says "disable outbound" — only inbound+outbound block_ip is implemented (both directions in `_action_block_ip`). No forensic capture action exists.
**Severity verdict:** PASS for core actions. PARTIAL for forensics gap.
**Recommended fix:** Add `capture_memory` as a new advisory action with documentation for manual forensic tools (WinPmem, procdump). No auto-execute path needed.

---

### 5. Lateral Movement (T1021)
**What exists:** `fusion_engine.py` CorrelationEngine detects `network + system` chain → "Lateral Movement" / T1021. `response_engine.py` branch: `isolate_host` + `block_ip` + `alert_admin`.
**What is missing:** Philosophy says "disable lateral protocol, force re-auth" — there is no SMB or RDP firewall rule injection. `block_ip` blocks a specific source IP but does not disable port 445 or 3389 globally. "Force re-auth" / session revocation is missing. Philosophy also says HIGH = analyst approval, but the correlation engine can produce CRITICAL severity triggering auto_execute.
**Severity verdict:** PARTIAL FAIL. Auto-isolation without analyst approval is too aggressive for lateral movement which may be legitimate admin activity.
**Recommended fix:** Add `disable_smb_rdp` advisory action. Cap lateral movement auto_execute to analyst-approval-required (HIGH stays manual). Implement session revocation advisory.

---

### 6. Process Injection (RWX / Remote Thread)
**What exists:** Nothing. There is no detection rule, no ML classification label, no correlation rule, and no response plan entry for process injection. The Sysmon pipeline could detect CreateRemoteThread (EventID 8) and WriteProcessMemory patterns but there is no dedicated response handler.
**What is missing:** Everything. Sysmon EventID 8 feed exists but it goes into the generic sysmon_alert path without any "process injection" label being emitted to the response engine.
**Severity verdict:** COMPLETE FAIL.
**Recommended fix (Phase 1):** Add EventID 8 (CreateRemoteThread) and EventID 10 (ProcessAccess) detection in `sysmon_behavior_agent.py` emitting `attack_type = "process_injection"`. Add a response plan block in `response_engine.py` with `kill_process` (injected process) + `quarantine_file` (injector) + `alert_admin`. Severity: HIGH = analyst approval.

---

### 7. Privilege Escalation (T1068)
**What exists:** `_MITRE_MAP` entry. `response_engine.py` branch: `kill_process` + `log_user_session` + `restrict_access`.
**What is missing:** `log_user_session` and `restrict_access` are both in `_ADVISORY_ACTIONS` — they are logged but not executed. No actual session revocation, no token revocation. The `lock_account` action (which exists in endpoint agent) is not included in the privilege escalation plan. Philosophy says "revoke token, force logout" — the auth system has session revocation but it is not wired into the SOAR response path.
**Severity verdict:** PARTIAL FAIL. Core `kill_process` is sound; advisory actions are stubs with no implementation instructions.
**Recommended fix:** Add `lock_account` to the privilege escalation plan (it is executable). Wire `restrict_access` to call `/auth/force-logout` on the relevant user_id. Add RBAC-downgrade advisory step.

---

### 8. Persistence Mechanism (Registry / Scheduled Tasks)
**What exists:** `monitor_persistence` action in endpoint agent and server executor — detects HKCU Run keys, startup folder, and scheduled tasks. This is read-only surveillance.
**What is missing:** No `response_engine.py` entry for "persistence" attack type — it falls to the default handler (`alert_admin` + `log_event`). No remediation actions: no registry key deletion, no scheduled task removal, no startup entry cleanup. Philosophy says "remove persistence entry / delete autorun key / remove scheduled task."
**Severity verdict:** COMPLETE FAIL on remediation.
**Recommended fix (Phase 1):** Add `persistence` / `persistence mechanism` keyword branch in `response_engine.py` with `monitor_persistence` (detect first) + `kill_process` (persistence loader) + `alert_admin`. Add new `remove_persistence` advisory action with documented manual steps.

---

### 9. Ransomware (T1486)
**What exists:** `_detect_ransomware()` in `fusion_engine.py` with dual-gate: confirmed malicious file AND high/critical system anomaly. `response_engine.py` branch: `kill_process` + `isolate_host` + `scan_filesystem`. `auto_execute = severity == "CRITICAL"` fires immediately.
**What is missing:** Philosophy mandates "freeze shares, snapshot." No SMB share freeze action exists. No Volume Shadow Copy protection. Philosophy says "disable write access" — not implemented. Frontend siren trigger on ransomware is handled by AlertSiren for HIGH/CRITICAL (present), but the red UI state for ransomware specifically is CSS-only and not a separate state.
**Severity verdict:** PASS for core containment. PARTIAL for share freeze and snapshot gaps.
**Recommended fix:** Add `freeze_network_shares` advisory action. Add `check_volume_shadow_copies` advisory action (read-only vssadmin query).

---

### 10. Impossible Travel
**What exists:** User behavior OC-SVM can detect anomalous login patterns. The `user_anomaly` Socket.IO event is emitted. However, "impossible travel" is never labelled as such by the model — the OC-SVM outputs a binary anomaly flag with `anomaly_reason`.
**What is missing:** No response plan branch for "impossible_travel." Falls to default handler. Philosophy mandates "MFA revalidation, session invalidation." No automatic session invalidation SOAR action exists. The auth system has `POST /auth/force-logout` but it is not wired into response plans.
**Severity verdict:** COMPLETE FAIL on response.
**Recommended fix (Phase 2):** Add GeoIP enrichment to user behavior pipeline (impossible travel = same user, 2 IPs in different geographies within <1h). Add `invalidate_sessions` advisory action wired to `/auth/force-logout`. Add response plan branch.

---

### 11. Credential Stuffing
**What exists:** `brute force` / `bruteforce` branch in `response_engine.py` covers this: `block_ip` + `lock_account` + `alert_admin`.
**What is missing:** `lock_account` is classified as `_ADVISORY_ACTIONS` in `backend.py` (line 3733) — it is never executed automatically despite being a real executable action in `command_listener.py`. Philosophy also mandates CAPTCHA — not implementable via SOAR. No CAPTCHA advisory action exists. `unlock_account` does not exist anywhere (see Reversibility Audit below).
**Severity verdict:** PARTIAL FAIL. The plan exists but `lock_account` is incorrectly in the advisory set — it should be executable.
**Recommended fix:** Move `lock_account` from `_ADVISORY_ACTIONS` to `_ENDPOINT_VALID_ACTIONS`. Add `unlock_account` endpoint SOAR action. Add `captcha_required` advisory action.

---

### 12. Insider Threat (T1078)
**What exists:** `_MITRE_MAP` has `"insider threat": "T1078"`. User behavior model can detect anomalous session patterns. CorrelationEngine `user + malware` chain produces "Insider Threat with Malicious Execution." However, the `response_engine.py` has no dedicated `elif "insider threat" in attack_lower` block — it falls to the default handler.
**What is missing:** No shadow monitoring action. No session recording. No USB restriction SOAR action. No data exfiltration countermeasure. The philosophy requires MEDIUM-severity (alert + analyst recommendation) shadow monitoring, which is the most operationally appropriate response for insider threats to avoid wrongful action.
**Severity verdict:** COMPLETE FAIL.
**Recommended fix (Phase 2):** Add `insider_threat` branch in `response_engine.py` with `monitor_persistence` (observe registry, startup) + `alert_admin` + `log_user_session` advisory. Keep auto_execute=False (always analyst-approval). Add `disable_usb` advisory action documented as a manual Group Policy step.

---

### 13. Trojan (T1204)
**What exists:** `malware_analysis_agent.py` heuristic matches suspicious process names (22 IOC substrings). LightGBM PE file scanner labels trojans as "malicious." Confirmed malicious events flow through fusion to `quarantine_file` response suggestion in `_build_response_suggestions()`.
**What is missing:** No `response_engine.py` branch for "trojan" or "malware" attack type that reaches the plan generator. Trojan arrives through the malware pathway which may produce fusion alerts labelled "Malware" or "Drive-by Compromise / C2 Beaconing" depending on correlation. No startup entry removal action. No C2 domain block beyond source IP.
**Severity verdict:** PARTIAL — malware pathway fires quarantine correctly. Trojan-specific response (startup removal) is absent.
**Recommended fix:** Add `trojan` and `malware` keyword branch in `response_engine.py` with `quarantine_file` + `kill_process` + `monitor_persistence` + `alert_admin`. Advisory: `remove_startup_entry`.

---

### 14. Worm
**What exists:** Nothing. No detection rule for worm behaviour (rapid SMB/RDP propagation, self-replication patterns). No response plan entry.
**What is missing:** Network segmentation action. Rapid lateral replication detection. `isolate_host` exists and would be the correct containment but is never triggered for worm scenarios.
**Severity verdict:** COMPLETE FAIL.
**Recommended fix (Phase 1):** Add Suricata rules for SMB worm propagation patterns. Add `worm` branch in `response_engine.py`: CRITICAL → auto `isolate_host` + `kill_process` + `block_ip`. This is one scenario where CRITICAL auto-execute is fully justified by the philosophy.

---

### 15. Spyware
**What exists:** Nothing dedicated. Heuristic malware collector may flag suspicious process names. No spyware-specific detection label.
**What is missing:** Microphone/webcam disable action. Process kill. Hook removal. All are outside the current SOAR capability envelope.
**Severity verdict:** COMPLETE FAIL.
**Recommended fix (Phase 3):** Spyware detection requires kernel-level or driver-level telemetry (EDR hooks). For Windows: add WMI subscription monitoring. For response: `kill_process` is the only feasible action. Microphone/webcam disable requires OS-level API calls not currently in the SOAR toolset. Add advisory action `revoke_av_permissions`.

---

### 16. Rootkit
**What exists:** Nothing. No detection path, no response plan, no kernel integrity check.
**What is missing:** Safe-mode scan (offline scan). Kernel integrity check (DSE bypass detection). File system anomaly detection at kernel level. All require integration with external EDR or AV tools (Defender, Malwarebytes) not currently wired into Cyber Sentinel XDR.
**Severity verdict:** COMPLETE FAIL.
**Recommended fix (Phase 3):** Rootkit detection requires kernel-mode agent or Defender API integration. Add advisory action `initiate_offline_scan` that tells the SOC operator to reboot into Windows Defender Offline mode. Add `check_driver_signatures` advisory (sigcheck.exe or Get-AuthenticodeSignature PowerShell).

---

## Reversibility Audit

| SOAR Action | Undo Action | Endpoint Agent | Server Executor | Response Engine Plan | Notes |
|---|---|---|---|---|---|
| `block_ip` | `unblock_ip` | Present (`_action_unblock_ip`) | Present (`elif action == "unblock_ip"`) | Not included in any plan | Reversibility is TECHNICALLY present but no plan generates `unblock_ip` automatically. Must be manually issued. |
| `isolate_host` | `unisolate_host` | Present (`_action_unisolate_host`) | **ABSENT** — server executor `_server_soar_executor` has no `elif action == "unisolate_host"` branch. Falls to `else: return False, "Unknown SOAR action"`. | Not included in any plan | **CRITICAL GAP**: A server-host isolation cannot be reversed remotely via the SOAR pipeline. Manual netsh intervention required on the host. |
| `kill_process` | No undo (acceptable) | Present | Present | N/A | Acceptable per philosophy — process restart is operator-managed. |
| `quarantine_file` | No restore action | Quarantine is `shutil.move` to `quarantine/` | Same — `shutil.move` | N/A | No `restore_file` or `unquarantine_file` action exists. File is recoverable manually from quarantine directory but no SOAR undo path. |
| `lock_account` | `unlock_account` | Present — `net user <user> /active:no` | Present — same `net user` call | N/A | **CRITICAL GAP**: `unlock_account` (`net user <user> /active:yes`) does not exist anywhere in the codebase. An account locked via SOAR cannot be re-enabled via SOAR. |
| `scan_filesystem` | No undo needed | Present (read-only) | Present (read-only) | Advisory | Correct — observation only. |
| `monitor_persistence` | No undo needed | Present (read-only) | Present (read-only) | Advisory | Correct — observation only. |
| `rate_limit_traffic` | No undo defined | Not implemented | Not implemented | Advisory (dead stub) | Neither the action nor its undo exists. |
| `log_user_session` | No undo needed | Not implemented | Not implemented | Advisory | Stub — no session capture mechanism. |
| `restrict_access` | `restore_access` | Not implemented | Not implemented | Advisory | Neither exists. |
| `alert_admin` | N/A | Not implemented | Not implemented | Advisory | Notification stub — no email/Slack delivery. |
| `log_event` | N/A | Not implemented | Not implemented | Advisory | Stub — no structured event write beyond MongoDB existing writes. |

**Summary:** 2 critical reversibility gaps: `unisolate_host` missing from server executor; `unlock_account` missing from entire codebase.

---

## Permissions Audit

| SOAR Action | Command / API Used | Privilege Required | Current Handling | Risk If Standard User |
|---|---|---|---|---|
| `block_ip` | `netsh advfirewall firewall add rule` | **Windows Administrator** | No privilege pre-flight check. Fails silently with non-zero returncode. | Rule silently fails; IP remains unblocked. Host appears to SOC as "blocked" when it is not. |
| `unblock_ip` | `netsh advfirewall firewall delete rule` | **Windows Administrator** | No privilege check. Same failure mode. | Same as above — block persists. |
| `isolate_host` | `netsh interface set interface <iface> disable` | **Windows Administrator** | Isolation flag written even on netsh failure. Partial success logged. | Flag written incorrectly indicates isolation; network actually still live. |
| `unisolate_host` | `netsh interface set interface <iface> enable` | **Windows Administrator** | No privilege check. | Cannot re-enable NIC; host remains isolated. |
| `kill_process` (by PID) | `psutil.Process.terminate()` | Process owner or Administrator for cross-user kills | `psutil.AccessDenied` caught and returned as failure message. | Only own-user processes terminable; attacker process as SYSTEM survives. |
| `kill_process` (by name) | `psutil.process_iter + .terminate()` | Process owner or Administrator | Same — `AccessDenied` caught silently per-process. | Same risk. |
| `quarantine_file` | `shutil.move()` | Read+write permissions on source file | No permission pre-flight. `Exception` caught and returned. | System or protected files (SYSTEM32, locked PE) cannot be moved. No fallback. |
| `lock_account` | `net user <username> /active:no` | **Windows Administrator** | Username regex validated. `returncode != 0` handled. | Command fails silently; account remains active. |
| `scan_filesystem` | `os.walk` on `C:\Users`, `C:\Temp`, etc. | Standard user can walk own profile; `C:\Windows\Temp` and `C:\ProgramData` may require elevation | `Exception` caught per-root, continues scanning. | Partial results — sensitive system paths skipped without notice. |
| `monitor_persistence` (HKCU) | `winreg.OpenKey(HKEY_CURRENT_USER)` | Standard user — HKCU is always accessible | Correct. | No risk — HKCU is always readable. |
| `monitor_persistence` (schtasks) | `schtasks /query /fo CSV` | Standard user for own tasks; all tasks require elevation | `returncode` checked; on failure count = -1. | Only own scheduled tasks visible; attacker SYSTEM tasks not enumerated. |
| `monitor_persistence` (Startup folder) | `os.listdir(APPDATA/Startup)` | Standard user — own startup folder | `Exception` caught. | No risk for own user. ALLUSERS startup at `C:\ProgramData\...\Startup` not checked. |
| `lock_account` (server) | `net user <username> /active:no` | **Windows Administrator** | No input validation regex in server executor (contrast: endpoint agent validates username). | Username injection possible in server executor if attacker controls `target` field in a queued command. |

**Notable finding — IP validation inconsistency in server executor:**
`command_listener.py` uses the strict regex `_IP_RE` (validated with octet range checking: `(?:25[0-5]|2[0-4]\d|[01]?\d\d?)`) applied via `_validate_ip()`. The `_server_soar_executor` in `backend.py` uses a simpler pattern `r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"` which allows octets like `999.999.999.999`. This is a minor validation gap — netsh will reject the invalid IP but the input is still passed to a subprocess call.

**Notable finding — `lock_account` username validation missing from server executor:**
`command_listener.py` `_action_lock_account()` validates the username with `re.match(r'^[\w\-\. ]{1,20}$', username)`. `_server_soar_executor` in `backend.py` passes the `target` string directly to `["net", "user", username, "/active:no"]` with no regex validation before the subprocess call (uses `shell=False` so injection risk is low, but malformed usernames still reach net.exe).

---

## Missing SOAR Actions (High Priority)

Ordered by operational urgency:

1. **`unisolate_host` in `_server_soar_executor`** (backend.py)
   - Complexity: Low — mirror the `isolate_host` elif block, change `disabled` → `enable`; remove flag file.
   - Risk if absent: HIGH — server host cannot be remotely un-isolated via SOAR.

2. **`unlock_account`** (endpoint agent + server executor)
   - Complexity: Low — `net user <username> /active:yes`; add same username validation regex.
   - Risk if absent: HIGH — `lock_account` is permanently irreversible via SOAR.

3. **`restore_quarantine_file`** (endpoint agent + server executor)
   - Complexity: Low — `shutil.move` from `quarantine/<filename>` back to original path (store original path in command metadata).
   - Risk if absent: MEDIUM — forensic and operational risk from permanent file loss.

4. **`rate_limit_traffic` implementation** (server executor only)
   - Complexity: Medium — netsh QoS rule or Suricata threshold.conf injection or Windows Firewall bandwidth throttle.
   - Risk if absent: MEDIUM — DDoS response plan includes this action but it silently does nothing.

5. **`invalidate_sessions`** (advisory — calls `/auth/force-logout`)
   - Complexity: Low — HTTP call to internal `/auth/logout-all` or `/users/{id}/force-logout`; wired into privilege escalation + impossible travel response plans.
   - Risk if absent: MEDIUM — compromised sessions remain active after credential-based attacks.

6. **`remove_persistence`** (endpoint agent + server executor)
   - Complexity: Medium — `winreg.DeleteValue(HKEY_CURRENT_USER, key_path, value_name)` for registry keys; `os.remove` for startup files; `schtasks /delete /tn <name> /f` for tasks. Requires Admin for HKLM. Needs input validation.
   - Risk if absent: MEDIUM — persistence mechanisms survive detection.

7. **`disable_smb_rdp`** (server executor, advisory for endpoint)
   - Complexity: Medium — `netsh advfirewall firewall add rule name=XDR_BLOCK_SMB dir=in protocol=tcp localport=445 action=block`. Needs corresponding `enable_smb_rdp` undo.
   - Risk if absent: MEDIUM — lateral movement response lacks protocol-level blocking.

8. **`freeze_network_shares`** (advisory)
   - Complexity: High — requires net share + icacls manipulation or DFS namespace suspension. Document as manual playbook step.
   - Risk if absent: LOW-MEDIUM — ransomware can still encrypt UNC shares during containment window.

---

## Response Plan Coverage — 7 Missing Attack Branches in `response_engine.py`

The following attack type strings, if passed as `attack_type` in a fusion alert, fall to the generic default handler:

| Missing Branch | attack_type keyword needed | Target severity | Proposed actions |
|---|---|---|---|
| Process Injection | `process injection`, `remote thread` | HIGH (analyst approval) | `kill_process` + `quarantine_file` + `alert_admin` |
| Persistence Mechanism | `persistence`, `autorun`, `scheduled task` | MEDIUM | `monitor_persistence` + `kill_process` (loader) + `alert_admin` |
| Impossible Travel | `impossible travel`, `geo anomaly` | MEDIUM (advisory only) | `alert_admin` + `log_user_session` (advisory) + `invalidate_sessions` (advisory) |
| Insider Threat | `insider threat` | MEDIUM (never auto-execute) | `monitor_persistence` + `alert_admin` + `log_user_session` |
| Trojan | `trojan`, `malware` | HIGH | `quarantine_file` + `kill_process` + `monitor_persistence` |
| Worm | `worm` | CRITICAL (auto-execute justified) | `isolate_host` + `block_ip` + `kill_process` |
| Rootkit | `rootkit` | CRITICAL | `isolate_host` + `alert_admin` (advisory: offline scan) |

---

## Severity Philosophy Compliance Analysis

The enterprise philosophy mandates:
- LOW → log + monitor only
- MEDIUM → alert + analyst recommendation
- HIGH → semi-automatic (analyst approval required)
- CRITICAL → immediate auto-containment

**Current implementation:** `auto_execute = severity == "CRITICAL"` in `response_engine.py` line 398.

**Assessment of each attack type's severity assignment:**

| Attack | Expected Philosophy Tier | Auto-Execute Fires? | Verdict |
|---|---|---|---|
| Port Scan | LOW-MEDIUM (recon only) | YES if CRITICAL score reached | FAIL — needs hard cap `auto_execute=False` |
| DDoS / DoS | HIGH-CRITICAL (service disruption) | YES | PASS |
| Heartbleed | HIGH (data exposure, not RCE) | YES if CRITICAL score | PARTIAL FAIL — should stay HIGH/manual |
| C2 Beaconing | CRITICAL (active exfil) | YES | PASS |
| Lateral Movement | HIGH (analyst needed — may be admin) | YES if CRITICAL score | PARTIAL FAIL — needs analyst gate |
| Process Injection | HIGH | N/A (no plan) | FAIL |
| Privilege Escalation | HIGH | YES if CRITICAL score | PARTIAL |
| Persistence | MEDIUM | N/A (no plan, falls to default) | FAIL |
| Ransomware | CRITICAL | YES | PASS |
| Impossible Travel | MEDIUM | N/A | FAIL |
| Credential Stuffing | MEDIUM-HIGH | Partial (lock_account advisory) | PARTIAL |
| Insider Threat | MEDIUM | N/A | FAIL |
| Trojan | HIGH | Partial (malware fusion path) | PARTIAL |
| Worm | CRITICAL | N/A (no plan) | FAIL |
| Spyware | HIGH | N/A | FAIL |
| Rootkit | CRITICAL | N/A | FAIL |

**Root cause of severity mis-mapping:** `auto_execute` is derived purely from the fusion-assigned severity label. For attack types where the philosophy mandates analyst approval (HIGH), the `auto_execute` logic does not distinguish attack type — only severity label. A well-designed port scan that scores CRITICAL (unlikely but possible in a multi-source correlation) will auto-execute containment.

**Fix:** Add per-attack-type `auto_execute` overrides. Example:

```python
# Attack types that NEVER auto-execute regardless of severity
_NO_AUTO_EXECUTE_ATTACKS = frozenset({
    "port scan", "portscan", "insider threat",
    "impossible travel", "lateral movement",
    "privilege escalation",
})

auto_execute = severity == "CRITICAL" and attack_lower not in _NO_AUTO_EXECUTE_ATTACKS
```

---

## Host vs. Endpoint Gap Analysis

| Action | Endpoint Agent (remote) | Server Executor (local host) | Gap |
|---|---|---|---|
| `block_ip` | Present | Present | None — both directions covered. |
| `unblock_ip` | Present | Present | None. |
| `isolate_host` | Present | Present | None for isolation. |
| `unisolate_host` | Present | **ABSENT** | Server cannot remotely un-isolate itself. Endpoint can. |
| `kill_process` | Present | Present | None. |
| `quarantine_file` | Present | Present | None — both use shutil.move. |
| `lock_account` | Present (executable) | Present | None — both use net user. |
| `unlock_account` | **ABSENT** | **ABSENT** | Gap in both planes. |
| `scan_filesystem` | Present (advisory via endpoint) | Present | None. |
| `monitor_persistence` | Present (advisory) | Present | None. |
| `rate_limit_traffic` | **ABSENT** | **ABSENT** | Gap in both planes — no network throttling exists. |
| `log_user_session` | **ABSENT** | **ABSENT** | Advisory stub in both planes. |
| `restrict_access` | **ABSENT** | **ABSENT** | Advisory stub. |
| `invalidate_sessions` | **ABSENT** | **ABSENT** | Not wired to auth system in either plane. |
| `disable_smb_rdp` | **ABSENT** | **ABSENT** | Lateral movement gap. |
| `remove_persistence` | **ABSENT** | **ABSENT** | Persistence remediation gap. |

**Additionally:** `lock_account` is listed in `_ADVISORY_ACTIONS` in backend.py (line 3733), meaning the endpoint's executable `lock_account` action is never dispatched to the endpoint command queue — it is logged as advisory only. This is an architectural misclassification: the action is fully implemented and executable in both planes but administratively blocked by its advisory designation.

---

## Recommended Additions (Phased)

### Phase 1 — Critical Gaps (0–2 weeks)

1. **Add `unisolate_host` to `_server_soar_executor`** in `backend.py`.
   - File: `Backend/backend.py`, add `elif action == "unisolate_host":` block after `isolate_host` branch (line 3505).
   - Implementation: remove `isolation_flag.txt`, run `netsh interface set interface <iface> enable`.

2. **Implement `unlock_account`** in both `endpoint_agent/command_listener.py` and `backend.py` `_server_soar_executor`.
   - File: `endpoint_agent/command_listener.py` — add `_action_unlock_account()` mirroring `_action_lock_account()` with `/active:yes`.
   - File: `backend.py` — add `elif action == "unlock_account":` branch in `_server_soar_executor`.
   - Register in `execute_command` dispatch table.

3. **Move `lock_account` from `_ADVISORY_ACTIONS` to `_ENDPOINT_VALID_ACTIONS`** in `backend.py`.
   - File: `Backend/backend.py`, line 3725–3737.
   - Add `lock_account` to `_ENDPOINT_VALID_ACTIONS` frozenset; remove from `_ADVISORY_ACTIONS`.

4. **Add per-attack-type `auto_execute` override table** in `response_engine.py`.
   - File: `Backend/response_engine.py` — add `_NO_AUTO_EXECUTE_ATTACKS` frozenset and override the final `auto_execute` assignment.

5. **Add `worm` and `trojan` / `malware` branches** to `response_engine.py`.
   - Worm: CRITICAL auto-execute — `isolate_host` + `block_ip` + `kill_process`.
   - Trojan/Malware: HIGH analyst-approval — `quarantine_file` + `kill_process` + `monitor_persistence`.

6. **Fix IP validation regex in `_server_soar_executor`** (`backend.py` line 3335).
   - Change `r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"` to match endpoint agent's validated form: `r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"`.

7. **Add username validation to `lock_account` in `_server_soar_executor`** (`backend.py` line 3398–3414).
   - Add `re.match(r'^[\w\-\. ]{1,20}$', username)` check before subprocess call to match endpoint agent protection.

### Phase 2 — High-Impact Improvements (2–6 weeks)

8. **Add `process_injection` detection and response plan.**
   - File: `Backend/agents/sysmon_behavior_agent.py` — add EventID 8 (CreateRemoteThread) label.
   - File: `Backend/response_engine.py` — add `process_injection` branch.

9. **Add `persistence_mechanism` response plan branch** in `response_engine.py`.

10. **Add `insider_threat` response plan branch** in `response_engine.py` — advisory-only, never auto-execute.

11. **Add `invalidate_sessions` advisory action** wired to `POST /auth/logout-all` or `POST /users/{user_id}/force-logout`.

12. **Add `restore_quarantine_file`** action in both execution planes. Store original path in quarantine metadata file.

13. **Add `disable_smb_rdp`** advisory action in `response_engine.py` lateral movement branch with documented manual follow-up.

14. **Add `unlock_account`** to response plans for brute force and privilege escalation (unlock after containment window).

### Phase 3 — Advanced Features (6–12 weeks)

15. **Implement `rate_limit_traffic`** — netsh QoS rule injection or Suricata threshold.conf dynamic writer.

16. **Add `impossible_travel` detection** — GeoIP enrichment on user events + 1-hour velocity check in user behavior pipeline.

17. **Add `remove_persistence`** — winreg delete, startup file removal, schtasks /delete with full audit trail.

18. **Add `freeze_network_shares`** advisory — net share enumeration + documented icacls procedure.

19. **Add `capture_memory`** advisory — WinPmem or procdump invocation for forensic evidence preservation.

20. **Add `check_volume_shadow_copies`** advisory — vssadmin list shadows for ransomware snapshot audit.

---

## Implementation Roadmap — Specific File Changes

| Fix | File | Location | Lines Affected |
|---|---|---|---|
| `unisolate_host` in server executor | `Backend/backend.py` | After `isolate_host` branch in `_server_soar_executor` | ~line 3529 — add new `elif` block |
| `unlock_account` endpoint action | `endpoint_agent/command_listener.py` | After `_action_lock_account()` function | ~line 567 — add `_action_unlock_account()` |
| `unlock_account` dispatch entry | `endpoint_agent/command_listener.py` | `dispatch` dict in `execute_command()` | line 155 |
| `unlock_account` server executor | `Backend/backend.py` | After `lock_account` branch in `_server_soar_executor` | ~line 3414 |
| `lock_account` reclassify | `Backend/backend.py` | `_ENDPOINT_VALID_ACTIONS` and `_ADVISORY_ACTIONS` frozensets | lines 3725–3736 |
| Per-attack `auto_execute` | `Backend/response_engine.py` | Before `plan` dict construction | ~line 384 |
| `worm` response branch | `Backend/response_engine.py` | New `elif "worm"` before `else` default | ~line 363 |
| `trojan`/`malware` response branch | `Backend/response_engine.py` | New `elif "trojan" or "malware"` | ~line 363 |
| `process_injection` response branch | `Backend/response_engine.py` | New `elif "process injection"` | ~line 363 |
| `persistence` response branch | `Backend/response_engine.py` | New `elif "persistence"` | ~line 363 |
| `insider_threat` response branch | `Backend/response_engine.py` | New `elif "insider threat"` | ~line 363 |
| IP validation fix | `Backend/backend.py` | `_server_soar_executor` block_ip/unblock_ip | lines 3335, 3352 |
| Username validation fix | `Backend/backend.py` | `_server_soar_executor` lock_account branch | line 3399 |

---

## Metrics and KPIs to Track

| Metric | Target | Source |
|---|---|---|
| Response plan coverage rate (% of attack types with dedicated plan) | 100% of 16 attack scenarios | `response_engine.py` branch count |
| Advisory action execution rate | 0% auto-executed; 100% logged | `response_advisory_logs` collection count |
| `lock_account` reversals (unlock_account) | Must be > 0 within 24h of any lockout | New `audit_logs` action = `unlock_account` |
| `isolate_host` reversals (unisolate_host) | Must be available within SOAR pipeline | `endpoint_commands` action = `unisolate_host` completion rate |
| CRITICAL auto-execute false positive rate | < 5% of auto-executes reversed within 1h | `endpoint_commands` where `status=completed` then `unisolate_host` issued within 3600s |
| Severity mis-mapping rate | 0 LOW/MEDIUM alerts triggering auto-execute | `auto_execute=True` AND `severity != "CRITICAL"` count in `response_plans` |
| Mean Time to Contain (MTTC) HIGH severity | < 5 minutes with analyst approval | `response_plans.created_at` → `endpoint_commands.executed_at` |
| SOAR action privilege failure rate | < 2% | `endpoint_commands` where `status=failed` AND `result_message` contains "Access denied" |

---

================================================================================
END OF REPORT
Next Analysis Recommended: After Phase 1 fixes are implemented — estimated 2026-05-30
================================================================================
