# Cyber Sentinel XDR — Manual capture startup
# Run as Administrator. The dashboard's "Start Monitoring" button does this automatically.

Write-Host "Starting Suricata..." -ForegroundColor Cyan
Start-Process -FilePath "C:\Program Files\Suricata\suricata.exe" `
    -ArgumentList '-c "C:\Program Files\Suricata\suricata.yaml" -i "\Device\NPF_{B5A75558-6CB6-473B-B521-5B390F7ADE47}" -l "C:\SuricataLogs"' `
    -Verb RunAs

Write-Host "Starting Winlogbeat..." -ForegroundColor Cyan
$winlogbeat = Join-Path $PSScriptRoot "User Behavior\winlogbeat-9.3.3-windows-x86_64\winlogbeat.exe"
$winlogbeatCfg = Join-Path $PSScriptRoot "User Behavior\winlogbeat-9.3.3-windows-x86_64\winlogbeat.yml"
Start-Process -FilePath $winlogbeat `
    -ArgumentList "-c `"$winlogbeatCfg`" -e" `
    -Verb RunAs

Write-Host "Both capture processes launched. Open http://localhost:8000/start-monitoring to begin ML monitoring." -ForegroundColor Green
