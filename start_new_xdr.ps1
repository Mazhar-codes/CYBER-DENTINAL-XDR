<#
  Cyber Sentinel XDR - launcher for the NEW independent copy (C: drive).
  Starts Backend (port 8000) and Frontend (port 3000) in separate windows,
  pointed at THIS copy's own venv/.env (new database + new secrets).

  Calls venv\Scripts\python.exe directly on purpose: a copied venv's
  Activate.ps1 still contains the original E: path, so we must NOT activate.

  Usage:
    cd "C:\Users\beeb9\Downloads\Compressed\New folder"
    .\start_new_xdr.ps1
#>

$REPO     = "C:\Users\beeb9\Downloads\Compressed\New folder"
$BACKEND  = "$REPO\Backend"
$FRONTEND = "$REPO\Cyber Sentinal XDR Frontend"
$PY       = "$BACKEND\venv\Scripts\python.exe"

Write-Host ""
Write-Host "=== CYBER SENTINEL XDR - NEW COPY LAUNCHER ===" -ForegroundColor Cyan
Write-Host "Repo: $REPO" -ForegroundColor DarkGray
Write-Host ""

# Sanity checks
if (-not (Test-Path $PY))       { Write-Warning "venv python not found: $PY"; return }
if (-not (Test-Path "$BACKEND\backend.py")) { Write-Warning "backend.py not found in $BACKEND"; return }

# Warn if something is already on port 8000 (likely the OLD backend still running)
$busy = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Write-Warning "Port 8000 is already in use - the OLD backend may be running."
    Write-Warning "Stop it first, or the new backend won't be able to bind."
}

# --- Backend (FastAPI + Socket.IO, port 8000) ---
Write-Host "[1/2] Starting Backend (new DB) on http://localhost:8000 ..." -ForegroundColor Cyan
$backendCmd = "cd `"$BACKEND`"; & `"$PY`" -m uvicorn backend:sio_app --host 0.0.0.0 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd

# Wait for /health
Write-Host "      Waiting for backend health check..." -ForegroundColor DarkGray
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 2
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 2
}
if ($ready) { Write-Host "      [OK] Backend healthy (connected to new cluster)" -ForegroundColor Green }
else        { Write-Warning "      Backend did not respond in 60s - check its window for errors." }

# --- Frontend (React dashboard, port 3000) ---
Write-Host "[2/2] Starting Frontend on http://localhost:3000 ..." -ForegroundColor Cyan
$frontendCmd = "cd `"$FRONTEND`"; npm start"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd

Write-Host ""
Write-Host "Backend : http://localhost:8000   (health: /health)" -ForegroundColor Green
Write-Host "Frontend: http://localhost:3000" -ForegroundColor Green
Write-Host ""
Write-Host "Tip: open http://localhost:8000/start-monitoring once to kick off detection loops." -ForegroundColor DarkGray
