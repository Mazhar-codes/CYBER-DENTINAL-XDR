<#
build_agent.ps1 — Build CyberSentinelAgent.exe (the endpoint agent) from source.

Usage (from anywhere):
    powershell -ExecutionPolicy Bypass -File packaging\build_agent.ps1

Output:
    packaging\dist\CyberSentinelAgent.exe   (single self-contained executable)

This uses a dedicated build virtualenv so the freeze is reproducible and does
not pollute your system Python. Re-run any time; it is idempotent.
#>
$ErrorActionPreference = "Stop"

$pkgDir  = $PSScriptRoot
$root    = Split-Path -Parent $pkgDir
$venvDir = Join-Path $pkgDir "build_env"
$venvPy  = Join-Path $venvDir "Scripts\python.exe"

Write-Host "[1/4] Ensuring build virtualenv..." -ForegroundColor Cyan
if (-not (Test-Path $venvPy)) {
    python -m venv $venvDir
}

Write-Host "[2/4] Installing build dependencies (pyinstaller, httpx, psutil)..." -ForegroundColor Cyan
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install --upgrade pyinstaller "httpx>=0.27.0" "psutil>=5.9.0"

Write-Host "[3/4] Freezing endpoint agent -> CyberSentinelAgent.exe..." -ForegroundColor Cyan
Push-Location $pkgDir
try {
    & $venvPy -m PyInstaller --clean --noconfirm (Join-Path $pkgDir "agent.spec")
} finally {
    Pop-Location
}

$exe = Join-Path $pkgDir "dist\CyberSentinelAgent.exe"
Write-Host "[4/4] Done." -ForegroundColor Green
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host "Built: $exe  ($size MB)" -ForegroundColor Green
    Write-Host "Smoke test it with:  `"$exe`" --simulate --backend-url http://<server-ip>:8001" -ForegroundColor Yellow
} else {
    Write-Host "ERROR: build did not produce $exe" -ForegroundColor Red
    exit 1
}
