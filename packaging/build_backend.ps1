<#
build_backend.ps1 - Freeze the Cyber Sentinel XDR backend into backend.exe (onedir).

Uses the EXISTING Backend venv (which already has torch + every dependency), so
nothing heavy is re-downloaded - it only adds PyInstaller.

Usage:
    powershell -ExecutionPolicy Bypass -File packaging\build_backend.ps1

Output:
    packaging\dist\backend\backend.exe   (+ its _internal\ folder, ~1.5-2.5 GB)

NOTE: this is a LARGE, SLOW build (10-20+ min). onedir is intentional - torch
makes a single-file exe impractical.
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

# Build to a SHORT path. torch bundles license/data trees nested ~160 chars deep;
# combined with this project's long source path they exceed Windows MAX_PATH (260)
# and the bundle copy fails with WinError 206. A short dist/work root avoids it.
$buildRoot = "C:\csxb"
$distPath  = Join-Path $buildRoot "dist"
$workPath  = Join-Path $buildRoot "build"

Write-Host "[2/3] Freezing backend to $buildRoot (short path; bundling torch + models)..." -ForegroundColor Cyan
Push-Location $pkgDir
try {
    & $venvPy -m PyInstaller --clean --noconfirm --distpath $distPath --workpath $workPath (Join-Path $pkgDir "backend.spec")
} finally {
    Pop-Location
}

$exe = Join-Path $distPath "backend\backend.exe"
Write-Host "[3/3] Done." -ForegroundColor Green
if (Test-Path $exe) {
    $size = [math]::Round((Get-ChildItem (Split-Path $exe) -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 0)
    Write-Host "Built OK: $exe  (bundle total ~$size MB)" -ForegroundColor Green
} else {
    Write-Host "ERROR: build did not produce backend.exe" -ForegroundColor Red
    exit 1
}
