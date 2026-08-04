<#
build_server_control.ps1 - Freeze the Server Control Panel into ServerControl.exe (onefile).

Uses the EXISTING Backend venv (which already has pymongo + dnspython, since
backend.py depends on them directly) - NOT packaging\build_env, which is a
lightweight venv dedicated to the endpoint agent (httpx/psutil only) and does
NOT have pymongo. Building ServerControl.exe with build_env silently ships
without pymongo (collect_submodules('pymongo') in ServerControl.spec just
warns and returns nothing if pymongo isn't importable at build time), which
is what caused "Test Database" to fail with "No module named 'pymongo'".

Usage:
    powershell -ExecutionPolicy Bypass -File packaging\build_server_control.ps1

Output:
    packaging\dist\ServerControl.exe   (single-file exe)
#>
$ErrorActionPreference = "Stop"

$pkgDir = $PSScriptRoot
$root   = Split-Path -Parent $pkgDir
$venvPy = Join-Path $root "Backend\venv\Scripts\python.exe"

if (-not (Test-Path $venvPy)) {
    Write-Host "ERROR: Backend venv not found at $venvPy" -ForegroundColor Red
    exit 1
}

Write-Host "[1/3] Ensuring PyInstaller is installed in the Backend venv..." -ForegroundColor Cyan
& $venvPy -m pip install --upgrade pyinstaller

Write-Host "[2/3] Freezing ServerControl.exe (bundling pymongo + dnspython)..." -ForegroundColor Cyan
Push-Location $pkgDir
try {
    & $venvPy -m PyInstaller --clean --noconfirm (Join-Path $pkgDir "ServerControl.spec")
} finally {
    Pop-Location
}

$exe = Join-Path $pkgDir "dist\ServerControl.exe"
Write-Host "[3/3] Done." -ForegroundColor Green
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host "Built: $exe  ($size MB)" -ForegroundColor Green
} else {
    Write-Host "ERROR: build did not produce $exe" -ForegroundColor Red
    exit 1
}
