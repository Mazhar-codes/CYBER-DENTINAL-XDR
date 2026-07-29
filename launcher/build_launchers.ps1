<#
  Builds the two launcher EXEs for the NEW C: copy using PyInstaller, then
  copies them into  <project>\XDR-Launcher\  (both must sit together so the
  Control Panel can find the Endpoint Agent exe beside it).

  Run:  powershell -ExecutionPolicy Bypass -File .\build_launchers.ps1
#>

$LAUNCHER = "C:\Users\beeb9\Downloads\Compressed\New folder\launcher"
$OUT      = "C:\Users\beeb9\Downloads\Compressed\New folder\XDR-Launcher"
$PY       = "C:\Users\beeb9\Downloads\Compressed\New folder\Backend\venv\Scripts\python.exe"

if (-not (Test-Path $PY)) { Write-Warning "venv python not found: $PY"; return }

Set-Location $LAUNCHER

Write-Host "[1/4] Ensuring PyInstaller is installed in the venv..." -ForegroundColor Cyan
& $PY -m pip install --quiet --disable-pip-version-check pyinstaller
if ($LASTEXITCODE -ne 0) { Write-Warning "pip install pyinstaller failed."; return }

Write-Host "[2/4] Building Control Panel exe..." -ForegroundColor Cyan
& $PY -m PyInstaller --noconfirm --onefile --windowed `
    --name CyberSentinelXDR-ControlPanel main_launcher.py
if ($LASTEXITCODE -ne 0) { Write-Warning "Control Panel build failed."; return }

Write-Host "[3/4] Building Endpoint Agent exe (UAC-admin)..." -ForegroundColor Cyan
& $PY -m PyInstaller --noconfirm --onefile --windowed --uac-admin `
    --name CyberSentinelXDR-EndpointAgent endpoint_gui.py
if ($LASTEXITCODE -ne 0) { Write-Warning "Endpoint Agent build failed."; return }

Write-Host "[4/4] Copying exes to $OUT ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $OUT | Out-Null
Copy-Item "$LAUNCHER\dist\CyberSentinelXDR-ControlPanel.exe"  $OUT -Force
Copy-Item "$LAUNCHER\dist\CyberSentinelXDR-EndpointAgent.exe" $OUT -Force

Write-Host ""
Write-Host "DONE. Launchers built for the new copy:" -ForegroundColor Green
Get-ChildItem $OUT -Filter *.exe | ForEach-Object { "   $($_.FullName)  ($([math]::Round($_.Length/1MB,1)) MB)" }
Write-Host ""
Write-Host "Double-click CyberSentinelXDR-ControlPanel.exe to start the new stack." -ForegroundColor Green
