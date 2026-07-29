# Cyber Sentinel XDR — Integration Session Report
**Date:** 2026-04-20  
**Scope:** Full project setup, Suricata fix, User Behavior integration, MongoDB Atlas storage management

---

## Summary of Changes

### Infrastructure Fixed
| Issue | Fix |
|-------|-----|
| Broken venv (moved from `Network model\venv`) | Recreated venv at `Backend\venv` |
| `config.py` model_dir pointed to non-existent `Network model\` | Changed to `BASE_DIR` (Backend/) |
| `config.py` user_model_dir pointed to `C:\XDR_Model` | Changed to `User Behavior\final_model_backend_only\` |
| Missing packages: psutil, requests, pymongo, shap, xgboost, lightgbm | Installed + added to requirements.txt |
| Frontend was Vite app (outdated) | Replaced with CRA app from `Backend\cyber-sentinal\`; missing deps installed |
| Frontend crash: `.toFixed()` on undefined from Nmap flows | Added `?? 0` guards across NetworkMonitor.tsx |

### Suricata Fixed
| Issue | Fix |
|-------|-----|
| Crashed immediately after startup | Root cause: suricata.yaml configured for 8.x, running 7.0.14 |
| 5 unsupported eve-log modules | Disabled: mdns, websocket, ldap, pop3, doh2 |
| 7 unsupported rules files | Disabled: websocket-events, stream-events, enip-events, dnp3-events, modbus-events, emerging-exploit, emerging-hunting |
| Wi-Fi interface name `"Wi-Fi"` not recognized | Changed to full GUID: `\Device\NPF_{B5A75558-6CB6-473B-B521-5B390F7ADE47}` |
| eve.json was stale (Feb 25) | Suricata now running live; file updates in real time |

### Network Detection Fixed
| Issue | Fix |
|-------|-----|
| `_parse_eve` re-read entire file every 10s | Added byte-offset tracking; only new lines processed per cycle |
| 12 CIC features hardcoded to 0.0 | CV-heuristic approximations (std≈mean×0.5, min≈mean×0.1) in collect_baseline.py + network_detection_agent.py |
| Nmap self-scan not captured | Documented: scan router (192.168.1.1) or other LAN device, not own IP |

### User Behavior Integration (NEW — 2026-04-20)
**Backend (`backend.py`):**
- `USER_LOG_DIR` and `USER_MODEL_DIR` env vars now set before UserBehaviorAgent import — resolves 0-events-per-cycle bug
- `/predict/user` now calls `_handle_user_result()` → Socket.IO emission + MongoDB write on demand
- OC-SVM raw score normalized via sigmoid before passing to fusion engine
- User behavior cycle summaries persisted to `user_behavior_cycles` MongoDB collection

**Security fixes (`xdr_runtime.py`):**
- CWE-78: `get_service_status()` PowerShell injection fixed — list-form subprocess + regex allowlist
- CWE-502: `joblib.load()` is now primary deserializer; `pickle.load()` is fallback only

**Frontend (`NetworkMonitor.tsx`):**
- `UserAnomalyRow` and `UserBehaviorSummary` TypeScript interfaces added
- `userAnomalies` (rolling 50-row) and `userSummary` state added
- Socket.IO listeners for `"user_anomaly"` and `"user_behavior_summary"` added with cleanup
- User Behavior Panel rendered below flow table:
  - Summary stat row: Total Users | Normal | Anomalies | Avg Score | Last Cycle
  - Anomaly table: User | Score | Severity | After-Hours | USB | Files | Emails | Time
  - Row tinting: CRITICAL=red, HIGH=orange

### MongoDB Atlas Storage Management (NEW — 2026-04-20)
- `_COLLECTION_CAP` dict defines max documents per collection
- `_trim_collection()` deletes oldest docs by `_id` when cap exceeded
- `_save()` detects Atlas storage-full errors (codes 8000/13297) → trims all collections to 50% cap → retries
- `_periodic_trim()` runs every 100 monitoring cycles (~16 min)
- `GET /storage-status` endpoint returns per-collection count/cap/pct_full

---

## Outstanding Work

1. **Winlogbeat setup** — must write `.ndjson` logs to `C:\XDR_Logs\` for user behavior to infer on real data
2. **Train missing models** — `network_classifier.pkl` and `personal_baseline_model.pkl`
3. **OCEAN features** — hardcoded 0.0; connect to user profile data source
4. **SHAP wiring** — `shap_agent.py` exists but not connected to classifier
5. **System LSTM Autoencoder** — not implemented
6. **Malware RF (EMBER)** — not implemented
7. **SOAR endpoint polling loop** — commands written to MongoDB but no agent executes them

---

*Next Analysis Recommended: After Winlogbeat is configured and first user behavior cycle produces real inference results.*
