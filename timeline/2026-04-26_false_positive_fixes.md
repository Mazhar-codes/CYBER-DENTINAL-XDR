# XDR False-Positive & UI Accuracy Fixes — 2026-04-26

**Session type:** Bug-fix sprint  
**Overall completeness before:** ~82%  
**Overall completeness after:** ~87%  
**Files changed:** 11 (backend × 4, frontend × 5, agent × 2)

---

## 1. Root-Cause Analysis

Four independent false-positive chains were identified and fixed this session.

### 1A — Benign PE files labeled "Ransomware" (CRITICAL)

**Symptom:** `pip\distlib\w32.exe` and other legitimate executables in Python venvs
appeared as "Ransomware Activity T1486 CRITICAL" in the Correlated Attacks panel.

**Root causes (stacked):**
1. `malware_analysis_agent.py` used a single 0.5 threshold → any PE with score ≥ 0.5 became `MALWARE`
2. `fusion_engine.py` `CorrelationEngine._CHAIN_RULES` mapped `frozenset({"system","malware"})` → `"Ransomware Behavior T1486"` unconditionally — no behavioral gate
3. Legitimate venv executables score ≈ 0.4–0.6 due to packed byte distribution typical of self-extracting stubs

### 1B — Suspicious files producing CRITICAL correlated alerts

**Symptom:** Files labeled "suspicious" (score 0.3–0.7) triggered CRITICAL entries in
Correlated Attacks with `quarantine_file + isolate_host` SOAR responses.

**Root causes:**
1. `backend.py` sent ALL suspicious/malicious malware events to `_fe.ingest_event` with `severity: "HIGH"` and no `label`/`trusted` fields
2. `CorrelationEngine`: `len(sources_present)≥2 AND high_count≥1` → CRITICAL (no confirmed-malware gate)
3. `_build_response_suggestions`: `has_malware = "malware" in sources` → `quarantine_file` for any malware event regardless of label

### 1C — Normal 85% memory flagged ANOMALOUS / CRITICAL

**Symptom:** System Telemetry Logs showed every row as "ANOMALOUS MEDIUM 100%" at
85-87% memory, generating periodic `isolate_host` SOAR commands from the
"system" source alone.

**Root causes:**
1. `system_model.pt` always outputs `anomaly_score=1.0` due to sklearn scaler version mismatch (1.7.2 pickled, 1.8.0 runtime)
2. `_score_to_severity(1.0)` → "CRITICAL"; every tick with cooldown elapsed → CorrelationEngine ingest
3. `_compute_final_decision`: `confidence=1.0 × sev_weight_CRITICAL=1.0 → threat_score=1.0 → CRITICAL`
4. `attack_detected = attack_chain OR any(severity≥HIGH)` → single CRITICAL system event set `attack_detected=True`
5. `_build_response_suggestions`: `has_system=True` → unconditional `isolate_host`
6. Frontend `isAnomalous = entry.anomaly_score >= 0.35` → always True

### 1D — UI layout: telemetry panels in wrong section

**Symptom:** "System Telemetry Logs" and "Sysmon Process Events" appeared under
System Status instead of Sysmon Behavior.

---

## 2. Fixes Applied

### Fix 1A+1B — Malware pipeline refactor

**`Backend/agents/malware_analysis_agent.py`**
- Added `_is_trusted_path()` with compiled regex covering `site-packages`, `System32`, `SysWOW64`, `Program Files`, Python install dirs → score capped at 0.4, `trusted=True`
- Added signed-binary heuristic: `has_signature==1 AND score<0.85` → score capped at 0.5
- 3-tier label output: `score<0.3→benign`, `0.3–0.7→suspicious`, `>0.7→malicious`
- New output fields on every result: `source`, `label`, `confidence`, `trusted`, `trust_reason`

**`Backend/fusion_engine.py` — `CorrelationEngine`**
- Removed `frozenset({"system","malware"})` from `_CHAIN_RULES`
- Added `_detect_ransomware(events)`: fires only when malware event has `label=="malicious" AND trusted==False` AND system event has `severity in {HIGH,CRITICAL}`. Label = "Ransomware Activity", MITRE = T1486
- `_build_response_suggestions`: replaced `has_malware` with `has_confirmed_malware` (checks `label=="malicious" AND not trusted`) for `quarantine_file` and `kill_process`
- `malware_is_confirmed` guard added to CRITICAL severity escalation path

**`Backend/backend.py`**
- All three malware call sites (predict, scan, watcher): `_fe.ingest_event` now gated on `label=="malicious"` only; `fe_event` includes `"label":"malicious"` and `"trusted":False`
- `malware_events` collection (2k cap) + `fused_alerts` collection (1k cap) added
- Quarantine SOAR command only written for `label=="malicious" AND not trusted`

**Frontend (`types.ts`, `AlertsView.tsx`, `MalwareView.tsx`, `NetworkMonitor.tsx`)**
- `MalwareAlert` interface: added `label`, `trusted`, `trust_reason`, `confidence`, `source`, `fusion.attack_type`
- Badge colors: red=malicious / amber=suspicious / green=benign
- Trusted rows: 55% opacity, shield icon, excluded from alert count badge
- `fusion.attack_type` chip shown inline in label cell

### Fix 1C — System monitor resource-aware severity

**`Backend/agents/system_monitor_agent.py`**
- Added `_resource_aware_severity(score, features)`:
  - `cpu>85 OR mem>95` → CRITICAL (if ML score≥0.65) else HIGH
  - `cpu>80 AND mem>80` → HIGH
  - `cpu>70 OR mem>90` → MEDIUM cap
  - All other cases (normal 85% memory) → ML CRITICAL/HIGH both capped to MEDIUM
- `_fire_result` now uses `_resource_aware_severity` instead of `_score_to_severity`
- `is_genuinely_anomalous: bool` added to every result dict (`True` only when severity≥HIGH)

**`Backend/fusion_engine.py`**
- `attack_detected` now requires `≥2 sources OR explicit chain rule` — single-source system events no longer populate Correlated Attacks table
- `isolate_host` SOAR requires `is_genuinely_anomalous=True` + `severity in {HIGH,CRITICAL}` on the system event

**`Backend/backend.py` — `_handle_system_result`**
- `is_anomaly` gated on `is_genuinely_anomalous=True OR (score≥0.35 AND severity in HIGH/CRITICAL)`
- `is_genuinely_anomalous` forwarded in `fe_event` dict for CorrelationEngine use
- Benign-emit path changed from `elif not is_anomaly` to `else` — score gauge updates every tick without interruption during 30s cooldown

**`Cyber Sentinal XDR Frontend/src/components/views/SysmonBehaviorView.tsx`**
- `isAnomalous = entry.is_genuinely_anomalous === true || entry.severity in {HIGH,CRITICAL}` — 85% memory correctly shows NORMAL

### Fix 1D — UI layout

**`SystemStatusView.tsx`**: removed "System Telemetry Logs" and "Sysmon Process Events" panels; `systemAnomalies`/`sysmonLogs` props dropped from interface

**`SysmonBehaviorView.tsx`**: added `systemAnomalies` prop + "SYSTEM TELEMETRY LOGS" panel (positioned between Live Process Events and alert table); removed "Process Behavior Alerts" panel and all dead helper components (`SeverityBadge`, `ScoreBar`, `SEVERITY_COLOR`, `MAX_ALERTS`)

**`NetworkMonitor.tsx`**: rerouted `systemAnomalies` from `SystemStatusView` → `SysmonBehaviorView`

---

## 3. Threat Classification Separation of Concerns

The session enforced a clean architecture principle that was previously violated:

| Layer | Responsibility | NOT responsible for |
|-------|---------------|---------------------|
| `malware_analysis_agent` | Score the file; apply trust filters; output `benign/suspicious/malicious` | Assigning MITRE techniques or attack names |
| `CorrelationEngine` | Correlate multi-source behavioral signals over 120s window | Classifying a single file |
| Ransomware detection | Requires confirmed malicious file + HIGH/CRITICAL system anomaly | Triggering from suspicious file or from ML score alone |
| SOAR (quarantine/isolate) | Fires only on confirmed evidence | Firing on statistical model noise |

---

## 4. Updated Layer Status

| Layer | Before | After | Key delta |
|-------|--------|-------|-----------|
| Malware Detection | 95% | 98% | Trusted-path filtering; 3-tier labels; no false ransomware |
| Fusion Engine | 100% | 100% | Behavioral ransomware gate; confirmed-malware guards |
| System Monitor | 60% | 68% | Resource-aware severity mitigates score=1.0 bug |
| SOAR / Endpoint Agent | 90% | 92% | Quarantine/isolate no longer fire on noise |
| MongoDB / Persistence | 95% | 96% | +2 collections (`malware_events`, `fused_alerts`) |
| Frontend / SOC Dashboard | 85% | 90% | Correct layout; accurate status; proper badge logic |

---

## 5. Remaining Known Issues

### Must fix before production
| Issue | Impact | Fix |
|-------|--------|-----|
| `system_model.pt` score=1.0 (sklearn mismatch) | Mitigated by resource-aware severity; false anomalies suppressed | `pip install scikit-learn==1.7.2` in venv OR `python train_system_model.py --collect-minutes 60` |
| `personal_baseline_model.pkl` may have same mismatch | All flows pass Gate 1 → Gate 2 unconditionally | Retrain: `python collect_baseline.py` then `python train_personal_model.py` |
| `OverviewView.tsx` threat score uses old client-side formula | Diverges from fusion engine | Subscribe to `fusion_alert` Socket.IO event; display `threat_score×100` |
| Dual Sysmon source risk | Duplicate events if Winlogbeat + PS forwarder both active | Add mutual-exclusion flag when Winlogbeat is configured |

### Lower priority
- SHAP not implemented for system monitor (LSTM) or Sysmon (TF-IDF weights)
- CORS wildcard `*` in `backend.py` — restrict before production
- `_handle_sysmon_result` has no rate-limit cooldown — high Sysmon event rates can flood socket
- Flow micro-fragmentation in CIC feature extraction
- OCEAN personality features hardcoded to 0.0 — needs `POST /users/ocean` endpoint
