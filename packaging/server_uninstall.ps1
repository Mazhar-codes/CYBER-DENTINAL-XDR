# Cyber Sentinel XDR Server - Uninstaller
$ErrorActionPreference = 'SilentlyContinue'
$installRoot = 'C:\Program Files\Cyber Sentinel XDR Server'

# Relaunch elevated from %TEMP% so this script can delete its own install directory.
if ($args -notcontains '-FromTemp') {
    $tmp = Join-Path $env:TEMP 'csx_uninstall.ps1'
    Copy-Item $PSCommandPath $tmp -Force
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $tmp + '"'),'-FromTemp'
    return
}

# --- elevated, running from %TEMP% ---
Get-Process backend, ServerControl -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# firewall rule
cmd /c 'netsh advfirewall firewall delete rule name="CyberSentinelXDR Server 8000"' | Out-Null

# shortcuts
Remove-Item "$env:PUBLIC\Desktop\Cyber Sentinel XDR Server.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Cyber Sentinel XDR Server" -Recurse -Force -ErrorAction SilentlyContinue

# Add/Remove Programs registry entry
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9C4B2E1F-7A83-4D26-B1E5-3F6A8C2D9E40}_is1' -Recurse -Force -ErrorAction SilentlyContinue

# the install directory
Remove-Item $installRoot -Recurse -Force -ErrorAction SilentlyContinue

(New-Object -ComObject WScript.Shell).Popup('Cyber Sentinel XDR Server has been uninstalled.', 6, 'Cyber Sentinel XDR', 64) | Out-Null
