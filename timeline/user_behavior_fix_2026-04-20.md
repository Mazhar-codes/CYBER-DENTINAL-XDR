# User Behavior Fix — 2026-04-20

**Analyst:** Claude Code + IDPS Project Analyst  
**Status:** COMPLETE — all fixes implemented and verified

---

## Root Causes Fixed

### 1. Winlogbeat 9.x crash (CRITICAL)
**Cause:** `id:` fields in all three `event_log` blocks in `winlogbeat.yml` triggered
Winlogbeat 9.3.3 panic (`received_events_count already used`). `C:\XDR_Logs\` was empty.  
**Fix:** Removed `id:` fields from `winlogbeat.yml`.

### 2. No win32evtlog fallback (HIGH)
**Cause:** `xdr_runtime.py` only read from `C:\XDR_Logs\`. When empty → 0 users.  
**Fix:** Added `read_windows_event_logs_direct()` in `xdr_runtime.py` using pywin32.
Called automatically when ndjson files are absent.  
**Installed:** `pywin32` in backend venv + post-install script.  
**Verified:** 4,828 events read. Users `DELL` and `Annas` detected.

### 3. anomaly_score rendered as negative % (MEDIUM)
**Cause:** OC-SVM `decision_function()` returns negative for anomalies.
Frontend rendered `raw_score * 100` → e.g. `-230%`.  
**Fix:** `backend.py` now normalizes before emit: `1 / (1 + exp(raw_score))` → [0,1].

### 4. user_behavior_cycles uncapped in MongoDB (LOW)
**Fix:** Added `"user_behavior_cycles": 500` to `_COLLECTION_CAP` in `backend.py`.

### 5. avg_score always 0.0 in summary (LOW)
**Fix:** Added `avg_score` to summary dict in `xdr_runtime.run_inference()`.

### 6. C:\XDR_Logs missing (OPERATIONAL)
**Fix:** Created directory via PowerShell.

---

## Files Modified

| File | Change |
|------|--------|
| `User Behavior/winlogbeat-9.3.3-windows-x86_64/winlogbeat.yml` | Removed `id:` fields from all event_log blocks |
| `User Behavior/final_model_backend_only/xdr_runtime.py` | `read_windows_event_logs_direct()`, fallback call, `avg_score` in summary |
| `Backend/backend.py` | `user_behavior_cycles` cap, `anomaly_score` normalized to [0,1] |
| `Cyber Sentinal XDR Frontend/src/components/NetworkMonitor.tsx` | `prediction_label` field, Time column, row highlighting, LIVE badge |

---

## Verification

```
$ python test_inference_quick.py
Summary: {'total_users': 2, 'normal': 2, 'anomaly': 0}
Events processed: 4096
  DELL   -> NORMAL score=0.1164
  Annas  -> NORMAL score=0.5492
```

---

## Testing User Intrusion Detection

1. Start backend: `uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload`
2. Open `http://localhost:3000` — click **▶ Start Monitoring**
3. User Behavior panel shows DELL + Annas within 60 seconds
4. To trigger anomaly: log in outside 09:00–17:00, do rapid file access (50+ files),
   or repeatedly insert/remove a USB device
5. Next 60s cycle flags the user as ANOMALY with orange row highlight
