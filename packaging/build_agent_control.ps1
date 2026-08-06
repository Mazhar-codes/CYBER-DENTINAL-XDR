<#
build_agent_control.ps1 - Freeze the Endpoint Agent Control Panel into
AgentControl.exe (onefile).

Uses the SAME lightweight build_env venv as build_agent.ps1 (Tkinter is
stdlib, so no extra dependencies are needed beyond pyinstaller itself).

Usage:
    powershell -ExecutionPolicy Bypass -File packaging\build_agent_control.ps1

Output:
    packaging\dist\AgentControl.exe   (single-file exe)
#>
$ErrorActionPreference = "Stop"

$pkgDir  = $PSScriptRoot
$venvDir = Join-Path $pkgDir "build_env"
$venvPy  = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPy)) {
    Write-Host "[0/3] Creating build virtualenv..." -ForegroundColor Cyan
    python -m venv $venvDir
}

Write-Host "[1/3] Ensuring PyInstaller is installed in the build venv..." -ForegroundColor Cyan
& $venvPy -m pip install --upgrade pyinstaller

Write-Host "[2/3] Freezing AgentControl.exe..." -ForegroundColor Cyan
Push-Location $pkgDir
try {
    & $venvPy -m PyInstaller --clean --noconfirm (Join-Path $pkgDir "AgentControl.spec")
} finally {
    Pop-Location
}

$exe = Join-Path $pkgDir "dist\AgentControl.exe"
Write-Host "[3/3] Done." -ForegroundColor Green
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host "Built: $exe  ($size MB)" -ForegroundColor Green
} else {
    Write-Host "ERROR: build did not produce $exe" -ForegroundColor Red
    exit 1
}
