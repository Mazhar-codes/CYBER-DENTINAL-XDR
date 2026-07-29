# uninstall_service.ps1 — Run as Administrator
# Stops and removes the Cyber Sentinel XDR Endpoint Agent scheduled task.

#Requires -RunAsAdministrator

$TaskName = "CyberSentinelXDR-EndpointAgent"

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $Task) {
    Write-Host "Task '$TaskName' not found — nothing to remove."
    exit 0
}

Write-Host "Stopping task '$TaskName'..."
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

Write-Host "Unregistering task '$TaskName'..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "Task '$TaskName' removed."
Write-Host ""
Write-Host "Note: agent_env.ps1 and agent.log in the agent directory were not deleted."
Write-Host "Remove them manually if no longer needed."
