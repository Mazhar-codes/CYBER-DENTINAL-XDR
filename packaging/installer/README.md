# Cyber Sentinel XDR — Installer (Inno Setup)

Turns the frozen agent into a proper double-click `Setup.exe` with a EULA,
a Server/Endpoint role choice, and background auto-start.

## Prerequisites

1. **Build the agent first** (produces `packaging\dist\CyberSentinelAgent.exe`):
   ```powershell
   powershell -ExecutionPolicy Bypass -File ..\build_agent.ps1
   ```
2. **Install Inno Setup 6** (free): https://jrsoftware.org/isdl.php

## Build the installer

**Option A — GUI:** open `CyberSentinelXDR.iss` in Inno Setup, press **Build** (F9).

**Option B — command line:**
```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" CyberSentinelXDR.iss
```

Output: `packaging\dist\CyberSentinelXDR-Setup-1.0.0.exe`

## What the installer does

| Step | Behaviour |
|------|-----------|
| Elevation | Requests Administrator (required for response actions + task install) |
| EULA | User must accept `EULA.txt` to continue |
| Role page | Radio choice: **Server** or **Endpoint** |
| Endpoint config | Prompts for backend URL + API key (skipped for Server) |
| Install | Copies `CyberSentinelAgent.exe` to `C:\Program Files\Cyber Sentinel XDR` |
| Autostart | Registers a Task Scheduler task that runs the agent as **SYSTEM** at boot, and starts it now |
| Upgrade | Re-running a newer `Setup.exe` (same AppId) stops the agent, replaces files, restarts it — config preserved |
| Uninstall | Removes the task, kills the agent, deletes files |

## Notes / current limitations

- **Server role is disabled** in this build (`#define ServerBundled 0`). It shows a
  "coming soon" message. Flip to `1` and add the `[Files]` entries once
  `backend.exe` + dashboard + models are packaged.
- **Autostart uses Task Scheduler**, not a true Windows service. This needs no extra
  binaries. For production-grade behaviour (auto-restart on crash, `services.msc`
  entry), swap to **NSSM** later — bundle `nssm.exe` and replace the `schtasks`
  calls in the `[Code]` section.
- **API key** is written into `run_agent.cmd` in the install folder (admin-writable).
  Fine for a demo; for hardening, store it encrypted or use NSSM's per-service
  environment variables instead.
- **Code signing:** unsigned installers trigger a SmartScreen warning on download.
  Sign `Setup.exe` with an Authenticode certificate before public distribution.
