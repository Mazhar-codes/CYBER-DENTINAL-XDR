# Cyber Sentinel XDR — Independent Copy: What We Did & How To Run It

_Working log + runbook for the C:-drive independent copy. Written 2026-07-30._

## Why this copy exists
Created an independent, self-owned copy of the whole project so it can't be locked away by
anyone else — its **own MongoDB cluster, own secrets, own GitHub repo**. The original E: project
is left untouched as a fallback.

## Where things live
| Thing | Location |
|---|---|
| **This (new) project** | `C:\Users\beeb9\Downloads\Compressed\New folder\` (a full copy of the E: parent folder) |
| App code | `…\New folder\cyber-sentinal-xdr-main\` (Backend, Frontend, etc.) |
| Old project (untouched) | `E:\Cyber Sentinal Endpoint\cyber-sentinal-xdr-main\` |
| **New MongoDB cluster** | Atlas `cluster0.xs3oza1.mongodb.net`, db `cyber_sentinel`, user `syedmazharhussainshah7_db_user` |
| Old MongoDB cluster | `cluster0.qtosxw2.mongodb.net` (still intact; only read during clone) |
| GitHub (private) | `https://github.com/Mazhar-codes/CYBER-DENTINAL-XDR.git` |
| Secrets (gitignored) | `…\cyber-sentinal-xdr-main\.env`, `…\Cyber Sentinal XDR Frontend\.env`, `…\endpoint_agent\.env`, `…\config.ini` |
| Launcher source | `…\New folder\launcher\` (`main_launcher.py`, `endpoint_gui.py`, `build_launchers.ps1`) |
| Launcher exes | `…\New folder\XDR-Launcher\` (rebuild from source — see below) |

## What was done, in order
1. Pushed the project to the new private GitHub repo (redacted 2 files that had a live API key/DB
   password before committing; `.env` is gitignored so no secrets were pushed).
2. Created a new MongoDB Atlas cluster and **cloned the old DB into it** (31 collections, ~22,789
   docs, all 5 user accounts) with a pymongo copy script.
3. Reconfigured the copy: new `MONGO_URI`, freshly generated `XDR_API_KEY` + `JWT_SECRET_KEY`,
   backend URLs → `127.0.0.1:8000`, all hardcoded `E:\…` paths rewritten to the new folder,
   cached endpoint identity deleted (regenerates per-machine).
4. Rebuilt a launcher for the new copy and fixed several latent bugs (below).

## Bugs fixed in this copy (not present / worked-around in the tuned E: setup)
- **Agent import crash** — `endpoint_agent/command_listener.py` relative import wrapped in
  try/except (only affected the repo's v1 agent; the whole-E copy's v2.0 standalone agent is fine).
- **`n_jobs=8` → `n_jobs=1`** in `Backend/hybrid_detector.py` (CIC RandomForest + IsolationForests).
  `n_jobs=8` made every real-time predict take 18–38s and hung the server; `n_jobs=1` is identical
  detection, milliseconds per call. **This was the root cause of the dashboard "Starting…" hang.**
- **Agent read-timeout / connectivity**: use **`http://127.0.0.1:8000`** (loopback) for agent +
  browser, NOT the LAN IP `192.168.100.127` (Windows Firewall silently drops the LAN IP; `localhost`
  can resolve to IPv6 `::1` and get refused). Agent HTTP read timeout widened for slow scoring.
- **Launcher**: `main_launcher.py` Start Backend now calls `python.exe` directly (a *copied* venv's
  `Activate.ps1` still points at E:). The `XDR-Launcher\*.exe` were stale (E: paths compiled in) →
  must be rebuilt from the fixed source.
- **SOAR `lock_account`** — fixed target resolution + safety (see below).

## SOAR lock_account (insider-threat response) — how it works now
- **Username resolution** (`response_engine.py`): targets the real flagged username, never the
  endpoint id (`server_host`). Was the cause of "The user name could not be found".
- **Server self-lock guard** (`backend.py`): on the SOC/server host it refuses to lock the
  operator's own account / an endpoint id → returns a safe ADVISORY (no self-lockout).
- **Endpoint quarantine flow** (`endpoint_agent/executor.py`): popup warning to the user (`msg`) →
  disable account (`net user /active:no`) → force sign-out of their session (`quser`/`logoff`);
  protects built-in accounts.

## RUNBOOK — how to start the stack (order matters)
Loopback everywhere; three windows.

**0. (once) clear stale isolation flag**
```powershell
Get-ChildItem "C:\Users\beeb9\Downloads\Compressed\New folder" -Filter isolation_flag.txt -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
```
**1. Backend** (admin PowerShell, keep open):
```powershell
Set-Location -LiteralPath "C:\Users\beeb9\Downloads\Compressed\New folder\cyber-sentinal-xdr-main\Backend"
& ".\venv\Scripts\python.exe" -m uvicorn backend:sio_app --host 0.0.0.0 --port 8000
```
Wait for `MongoDB connected — db='cyber_sentinel'` + `Uvicorn running`.
**2. Verify** → open `http://127.0.0.1:8000/health` (expect JSON, `mongo:true`).
**3. Start monitoring** → dashboard button, or open `http://127.0.0.1:8000/start-monitoring` once.
**4. Agent** (admin PowerShell):
```powershell
Set-Location -LiteralPath "C:\Users\beeb9\Downloads\Compressed\New folder"
python -m endpoint_agent.agent
```
Expect `Telemetry sent` (not `ConnectError`/`403`). Backend logs `[ENDPOINT] Telemetry received`.
**5. Frontend**:
```powershell
Set-Location -LiteralPath "C:\Users\beeb9\Downloads\Compressed\New folder\cyber-sentinal-xdr-main\Cyber Sentinal XDR Frontend"
npm start
```
Log in with an existing account (same password); Endpoints Online → 1.

_Or:_ `powershell -ExecutionPolicy Bypass -File "…\New folder\start_new_xdr.ps1"` starts backend+frontend.

## Rebuild the launcher exes (after any launcher source change)
```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\beeb9\Downloads\Compressed\New folder\launcher\build_launchers.ps1"
```
Then double-click `XDR-Launcher\CyberSentinelXDR-ControlPanel.exe`.

## Known remaining items (non-blocking)
- **System LSTM `score=1.0`** — sklearn 1.7.2↔1.8.0 pickle mismatch warning; mitigated by
  resource-aware severity. Retrain or `pip install scikit-learn==1.7.2` to clear.
- **Backend not always elevated** → server-host SOAR (block_ip/isolate) needs admin.
- **"Contributing Models" on the attack-graph node** shows a type-based guess (defaults to
  "Network" for endpoint nodes), not the real per-model fusion scores — display-only, fix pending.
- Model/methodology upgrades → see `IMPROVEMENTS_ANALYSIS.md`.

## Git — pushing changes
Code fixes (n_jobs, imports, SOAR) were committed to the GitHub repo. `.env`/secrets stay local
(gitignored). To push new changes: `git add -A; git commit -m "..."; git push` from
`…\cyber-sentinal-xdr-main\`.
