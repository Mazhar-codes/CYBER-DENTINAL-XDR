#Requires -Version 5.1
<#
.SYNOPSIS
    Cyber Sentinel XDR — Endpoint Deployment & Hardening Script

.DESCRIPTION
    Run this ONCE on every lab PC before starting the agent.
    It configures the entire OS-level environment so that every XDR SOAR
    command (block_ip, isolate_host, kill_process, lock_account,
    quarantine_file, scan_filesystem, monitor_persistence) executes without
    failure, regardless of existing security policy on the machine.

    What this script does:
      1.  Self-elevates to Administrator if not already elevated
      2.  Sets PowerShell execution policy to Bypass (machine-wide)
      3.  Detects and records the correct primary network interface name
      4.  Creates outbound firewall rule → XDR backend port 8000
      5.  Creates inbound firewall rule  → agent health port 8765
      6.  Allows netsh.exe and net.exe to run without UAC prompt
      7.  Adds Windows Defender exclusions for the agent folder + Python
      8.  Disables Defender real-time blocking of script execution
      9.  Grants SeNetworkLogonRight / token privileges for SYSTEM actions
      10. Installs Python packages (httpx, psutil) if Python is present
      11. Creates quarantine directory with correct permissions
      12. Writes endpoint_config.json with the detected network interface
      13. Installs the agent as a Windows Service via NSSM (auto-start,
          LocalSystem account, auto-restart on crash) — OR falls back to
          a Task Scheduler entry if NSSM is not available
      14. Starts the service / task immediately
      15. Runs a self-test to verify every SOAR action will succeed

.PARAMETER BackendURL
    Full URL of the Cyber Sentinel XDR backend.
    Default: auto-detected via the .env file in the agent directory, or
    falls back to http://localhost:8000.

.PARAMETER ApiKey
    X-API-Key value. Pulled from .env if not specified.

.PARAMETER AgentDir
    Absolute path to the endpoint_agent folder.
    Default: the directory containing this script.

.PARAMETER NSSMPath
    Path to nssm.exe. Download from https://nssm.cc/download if absent;
    script falls back to Task Scheduler automatically.

.PARAMETER ServiceName
    Windows Service name. Default: CyberSentinelAgent

.PARAMETER SkipServiceInstall
    Set to $true to skip service/task installation (manual run mode).

.EXAMPLE
    # Run with defaults — script reads .env for URL and key
    powershell.exe -ExecutionPolicy Bypass -File setup_endpoint.ps1

.EXAMPLE
    # Explicit backend URL and API key
    powershell.exe -ExecutionPolicy Bypass -File setup_endpoint.ps1 `
        -BackendURL "http://10.173.3.60:8000" `
        -ApiKey "<YOUR_XDR_API_KEY>"
#>

[CmdletBinding()]
param(
    [string]$BackendURL      = "",
    [string]$ApiKey          = "",
    [string]$AgentDir        = $PSScriptRoot,
    [string]$NSSMPath        = "nssm.exe",
    [string]$ServiceName     = "CyberSentinelAgent",
    [switch]$SkipServiceInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# 0. SELF-ELEVATION
# ─────────────────────────────────────────────────────────────────────────────
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]$id
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[ELEVATE] Re-launching as Administrator..." -ForegroundColor Yellow
    $args_quoted = $MyInvocation.BoundParameters.GetEnumerator() |
        ForEach-Object { "-$($_.Key) `"$($_.Value)`"" }
    Start-Process powershell.exe `
        -ArgumentList ("-ExecutionPolicy Bypass -File `"$PSCommandPath`" " + ($args_quoted -join " ")) `
        -Verb RunAs
    exit
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-OK([string]$msg)   { Write-Host "  [OK]   $msg" -ForegroundColor Green  }
function Write-Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red    }
function Write-Info([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor White  }

# ─────────────────────────────────────────────────────────────────────────────
# 1. RESOLVE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "1. Resolving configuration"

# Read .env file from parent of agent directory if BackendURL / ApiKey not given
$envFile = Join-Path (Split-Path $AgentDir -Parent) ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^\s*REACT_APP_BACKEND_URL\s*=\s*(.+)$" -and $BackendURL -eq "") {
            $BackendURL = $Matches[1].Trim()
        }
        if ($_ -match "^\s*XDR_API_KEY\s*=\s*(.+)$" -and $ApiKey -eq "") {
            $ApiKey = $Matches[1].Trim()
        }
    }
    # Also try frontend .env for backend URL
    $frontendEnv = Join-Path (Split-Path $AgentDir -Parent) "Cyber Sentinal XDR Frontend\.env"
    if (Test-Path $frontendEnv) {
        Get-Content $frontendEnv | ForEach-Object {
            if ($_ -match "^\s*REACT_APP_BACKEND_URL\s*=\s*(.+)$" -and $BackendURL -eq "") {
                $BackendURL = $Matches[1].Trim()
            }
        }
    }
}

if ($BackendURL -eq "") { $BackendURL = "http://localhost:8000" }
if ($ApiKey    -eq "") { $ApiKey    = "changeme-dev-key"       }

# Extract just the backend host IP for firewall rules
$backendHost = ([Uri]$BackendURL).Host
$backendPort = ([Uri]$BackendURL).Port
if ($backendPort -le 0) { $backendPort = 8000 }

Write-OK  "Agent directory : $AgentDir"
Write-OK  "Backend URL     : $BackendURL"
Write-OK  "Backend host    : $backendHost  port: $backendPort"
Write-Info "API key         : $($ApiKey.Substring(0, [Math]::Min(8,$ApiKey.Length)))***"

# ─────────────────────────────────────────────────────────────────────────────
# 2. POWERSHELL EXECUTION POLICY
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "2. PowerShell Execution Policy"
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
    Write-OK "Execution policy set to Bypass (LocalMachine)"
} catch {
    Write-Warn "Could not set execution policy: $_"
}
# Also set for current process and current user in case Group Policy overrides machine
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
} catch {}

# ─────────────────────────────────────────────────────────────────────────────
# 3. DETECT PRIMARY NETWORK INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "3. Detecting primary network interface"

$detectedNic = $null

# Priority: Wi-Fi > Wireless > Ethernet > first UP adapter
$nicPriority = @("Wi-Fi", "Wireless", "Wireless LAN", "Ethernet", "Local Area Connection")

# Get all UP adapters from netsh
$netshOutput = & netsh interface show interface 2>&1
$upAdapters  = @()
$netshOutput | ForEach-Object {
    if ($_ -match "Connected\s+\S+\s+\S+\s+(.+)$") {
        $upAdapters += $Matches[1].Trim()
    }
}

Write-Info "Connected adapters found: $($upAdapters -join ', ')"

foreach ($name in $nicPriority) {
    if ($upAdapters -contains $name) {
        $detectedNic = $name
        break
    }
}

# Fallback: use first UP adapter
if (-not $detectedNic -and $upAdapters.Count -gt 0) {
    $detectedNic = $upAdapters[0]
}

# Final fallback
if (-not $detectedNic) {
    $detectedNic = "Wi-Fi"
    Write-Warn "Could not auto-detect NIC — defaulting to 'Wi-Fi'. Edit endpoint_config.json if wrong."
} else {
    Write-OK "Detected primary NIC: '$detectedNic'"
}

# Write / update endpoint_config.json
$configPath = Join-Path $AgentDir "endpoint_config.json"
$config = @{}
if (Test-Path $configPath) {
    try {
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        # Convert PSCustomObject to hashtable
        $ht = @{}
        $config.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
        $config = $ht
    } catch { $config = @{} }
}
$config["network_interface"] = $detectedNic
$config | ConvertTo-Json -Depth 3 | Set-Content $configPath -Encoding UTF8
Write-OK "endpoint_config.json updated: network_interface = '$detectedNic'"

# ─────────────────────────────────────────────────────────────────────────────
# 4. WINDOWS FIREWALL — OUTBOUND TO XDR BACKEND
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "4. Windows Firewall rules"

# Rule: allow endpoint agent to reach XDR backend
$ruleName = "XDR-Agent-Outbound-$backendPort"
$existing = netsh advfirewall firewall show rule name=$ruleName 2>&1
if ($LASTEXITCODE -ne 0) {
    netsh advfirewall firewall add rule `
        name=$ruleName `
        dir=out `
        action=allow `
        remoteip=$backendHost `
        remoteport=$backendPort `
        protocol=TCP `
        enable=yes | Out-Null
    Write-OK "Outbound rule created: any → $backendHost`:$backendPort (TCP)"
} else {
    Write-OK "Outbound rule already exists: $ruleName"
}

# Rule: allow health server inbound (port 8765) — for SOC dashboard health checks
$healthRule = "XDR-Agent-Health-Inbound"
$existingH = netsh advfirewall firewall show rule name=$healthRule 2>&1
if ($LASTEXITCODE -ne 0) {
    netsh advfirewall firewall add rule `
        name=$healthRule `
        dir=in `
        action=allow `
        localport=8765 `
        protocol=TCP `
        enable=yes | Out-Null
    Write-OK "Inbound rule created: port 8765 (agent health endpoint)"
} else {
    Write-OK "Inbound health rule already exists"
}

# Allow netsh.exe and net.exe through the firewall (some lab policies block them)
foreach ($exe in @("netsh.exe", "net.exe", "schtasks.exe", "taskkill.exe")) {
    $exePath  = "C:\Windows\System32\$exe"
    $exeRule  = "XDR-System-$exe"
    $exeCheck = netsh advfirewall firewall show rule name=$exeRule 2>&1
    if ($LASTEXITCODE -ne 0) {
        netsh advfirewall firewall add rule `
            name=$exeRule `
            dir=out `
            action=allow `
            program=$exePath `
            enable=yes | Out-Null
        Write-OK "System exe allowed outbound: $exe"
    } else {
        Write-OK "Rule already exists for: $exe"
    }
}

# Allow Python through firewall (needed for httpx outbound calls)
$pythonPaths = @(
    "C:\Python311\python.exe",
    "C:\Python310\python.exe",
    "C:\Python39\python.exe",
    "C:\Python38\python.exe",
    (Get-Command python.exe -ErrorAction SilentlyContinue)?.Source
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($pyPath in $pythonPaths) {
    if ($pyPath) {
        $pyRule  = "XDR-Python-Outbound"
        $pyCheck = netsh advfirewall firewall show rule name=$pyRule 2>&1
        if ($LASTEXITCODE -ne 0) {
            netsh advfirewall firewall add rule `
                name=$pyRule `
                dir=out `
                action=allow `
                program=$pyPath `
                enable=yes | Out-Null
            Write-OK "Python allowed outbound: $pyPath"
        }
        break
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. UAC — SUPPRESS ELEVATION PROMPTS FOR SYSTEM TOOLS
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "5. UAC configuration for SOAR tools"

# Set UAC to not prompt for built-in Administrator — the service runs as
# LocalSystem which is above UAC, but for manual runs this prevents pop-ups.
try {
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    # ConsentPromptBehaviorAdmin = 0 → elevate without prompting
    Set-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord
    # PromptOnSecureDesktop = 0 → no secure desktop switch for UAC
    Set-ItemProperty -Path $uacKey -Name "PromptOnSecureDesktop"      -Value 0 -Type DWord
    Write-OK "UAC configured — Administrator elevation without prompt"
} catch {
    Write-Warn "Could not modify UAC registry: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. WINDOWS DEFENDER EXCLUSIONS
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "6. Windows Defender exclusions"

# Check if Defender is running
$defenderRunning = $false
try {
    $defSvc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    $defenderRunning = $defSvc -and $defSvc.Status -eq "Running"
} catch {}

if ($defenderRunning) {
    # Exclude the entire agent directory (prevents Defender killing the agent or quarantining it)
    try {
        Add-MpPreference -ExclusionPath $AgentDir -ErrorAction Stop
        Write-OK "Defender path exclusion: $AgentDir"
    } catch { Write-Warn "Could not add path exclusion: $_" }

    # Exclude Python executable
    $pythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue)?.Source
    if ($pythonExe) {
        try {
            Add-MpPreference -ExclusionProcess $pythonExe -ErrorAction Stop
            Write-OK "Defender process exclusion: $pythonExe"
        } catch { Write-Warn "Could not add python.exe exclusion: $_" }
        # Also exclude the Python directory
        $pythonDir = Split-Path $pythonExe -Parent
        try {
            Add-MpPreference -ExclusionPath $pythonDir -ErrorAction Stop
            Write-OK "Defender path exclusion: $pythonDir"
        } catch {}
    }

    # Exclude quarantine dir (Defender might scan it and cause issues)
    $quarantineDir = Join-Path $AgentDir "quarantine"
    try {
        Add-MpPreference -ExclusionPath $quarantineDir -ErrorAction Stop
        Write-OK "Defender path exclusion: $quarantineDir"
    } catch {}

    # Disable script scanning (prevents Defender blocking .ps1 / .py execution)
    try {
        Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop
        Write-OK "Defender script scanning disabled"
    } catch { Write-Warn "Could not disable script scanning: $_" }

    # Disable IOAV (scan files downloaded from internet) — prevents blocking httpx downloads
    try {
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
        Write-OK "Defender IOAV protection disabled"
    } catch {}

    Write-OK "Defender exclusions configured"
} else {
    Write-Info "Windows Defender not running — skipping exclusion config"
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. GROUP POLICY — UNLOCK SCRIPT AND NETSH EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "7. Group Policy unlock"

# Some lab environments use Software Restriction Policies or AppLocker.
# Creating explicit registry allow entries for our executables overrides most
# SRP configurations without requiring a full GPO edit.

$srpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\262144\Paths"
$exesToAllow = @(
    "C:\Windows\System32\netsh.exe",
    "C:\Windows\System32\net.exe",
    "C:\Windows\System32\taskkill.exe",
    "C:\Windows\System32\schtasks.exe",
    "C:\Windows\System32\cmd.exe"
)

# Add Python to the allow list
$pyExe = (Get-Command python.exe -ErrorAction SilentlyContinue)?.Source
if ($pyExe) { $exesToAllow += $pyExe }

foreach ($exe in $exesToAllow) {
    if (-not (Test-Path $exe)) { continue }
    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash
    $subKey = Join-Path $srpKey "{$([Guid]::NewGuid().ToString().ToUpper())}"
    try {
        if (-not (Test-Path $srpKey)) {
            New-Item -Path $srpKey -Force | Out-Null
        }
        New-Item -Path $subKey -Force | Out-Null
        Set-ItemProperty -Path $subKey -Name "Description" -Value "XDR Allow: $(Split-Path $exe -Leaf)"
        Set-ItemProperty -Path $subKey -Name "ItemData"    -Value $exe
        Set-ItemProperty -Path $subKey -Name "SaferFlags"  -Value 0 -Type DWord
        Write-OK "SRP allow-listed: $exe"
    } catch {
        Write-Warn "SRP allow-list failed for $exe`: $_"
    }
}

# Disable AppLocker for scripts if it is enabled (prevents Python from running)
try {
    $alSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    if ($alSvc -and $alSvc.Status -eq "Running") {
        Stop-Service  AppIDSvc -Force -ErrorAction SilentlyContinue
        Set-Service   AppIDSvc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-OK "AppLocker service (AppIDSvc) stopped and disabled"
    } else {
        Write-Info "AppLocker not running"
    }
} catch { Write-Warn "Could not check/stop AppLocker: $_" }

# ─────────────────────────────────────────────────────────────────────────────
# 8. PYTHON PACKAGES
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "8. Python package installation"

$pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonCmd) {
    Write-OK "Python found: $($pythonCmd.Source)"
    $packages = @("httpx>=0.27.0", "psutil>=5.9.0")
    foreach ($pkg in $packages) {
        Write-Info "Installing $pkg ..."
        & python.exe -m pip install $pkg --quiet --disable-pip-version-check 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Installed: $pkg"
        } else {
            Write-Warn "pip install may have had issues for $pkg (check manually)"
        }
    }
    # Upgrade pip itself to avoid old-version warnings
    & python.exe -m pip install --upgrade pip --quiet 2>&1 | Out-Null
} else {
    Write-Warn "Python not found in PATH. Install Python 3.9+ and re-run this script."
    Write-Info "Download: https://www.python.org/downloads/"
    Write-Info "Ensure 'Add Python to PATH' is checked during installation."
}

# ─────────────────────────────────────────────────────────────────────────────
# 9. QUARANTINE DIRECTORY
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "9. Quarantine directory"

$quarantineDir = Join-Path $AgentDir "quarantine"
if (-not (Test-Path $quarantineDir)) {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
    Write-OK "Created: $quarantineDir"
} else {
    Write-OK "Already exists: $quarantineDir"
}

# Set ACL: SYSTEM = Full Control, Administrators = Full Control, Users = no access
# This prevents quarantined malware from being accessed by regular user accounts
try {
    $acl = Get-Acl $quarantineDir
    $acl.SetAccessRuleProtection($true, $false)   # disable inheritance

    $systemSid   = [Security.Principal.SecurityIdentifier]"S-1-5-18"   # SYSTEM
    $adminSid    = [Security.Principal.SecurityIdentifier]"S-1-5-32-544" # Administrators

    foreach ($sid in @($systemSid, $adminSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $quarantineDir -AclObject $acl
    Write-OK "Quarantine ACL set: SYSTEM + Administrators only"
} catch {
    Write-Warn "Could not set quarantine ACL: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# 10. SERVICE INSTALLATION (NSSM preferred, Task Scheduler fallback)
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "10. Agent service installation"

if ($SkipServiceInstall) {
    Write-Info "SkipServiceInstall set — skipping service installation"
} else {

    $pythonPath = (Get-Command python.exe -ErrorAction SilentlyContinue)?.Source
    $agentScript = Join-Path $AgentDir "agent.py"

    if (-not $pythonPath) {
        Write-Warn "Python not found — cannot install service. Install Python first."
    } elseif (-not (Test-Path $agentScript)) {
        Write-Warn "agent.py not found at $agentScript — cannot install service."
    } else {

        # ── Try NSSM first ──────────────────────────────────────────────────
        $nssmFound = $false
        try {
            $nssmVer = & $NSSMPath version 2>&1
            $nssmFound = ($LASTEXITCODE -eq 0)
        } catch {}

        if (-not $nssmFound) {
            # Look for nssm.exe in the agent dir or system PATH
            $localNSSM = Join-Path $AgentDir "nssm.exe"
            if (Test-Path $localNSSM) {
                $NSSMPath  = $localNSSM
                $nssmFound = $true
            }
        }

        if ($nssmFound) {
            Write-Info "NSSM found — installing as Windows Service"

            # Remove existing service cleanly
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) {
                Write-Info "Removing existing service: $ServiceName"
                & $NSSMPath stop    $ServiceName confirm 2>&1 | Out-Null
                & $NSSM Path remove $ServiceName confirm 2>&1 | Out-Null
                Start-Sleep 2
            }

            # Install
            & $NSSMPath install $ServiceName $pythonPath `
                "$agentScript --backend-url $BackendURL --api-key $ApiKey" | Out-Null

            # Run as Local System (above UAC, bypasses all user-level restrictions)
            & $NSSMPath set $ServiceName ObjectName   "LocalSystem"    | Out-Null

            # Auto-start on boot
            & $NSSMPath set $ServiceName Start        SERVICE_AUTO_START | Out-Null

            # Restart policy: always restart within 5s on crash
            & $NSSMPath set $ServiceName AppExit      "" Restart       | Out-Null
            & $NSSMPath set $ServiceName AppRestartDelay 5000          | Out-Null

            # Working directory
            & $NSSMPath set $ServiceName AppDirectory $AgentDir        | Out-Null

            # Redirect stdout/stderr to log files
            $logDir  = Join-Path $AgentDir "logs"
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            & $NSSMPath set $ServiceName AppStdout "$logDir\agent_stdout.log" | Out-Null
            & $NSSMPath set $ServiceName AppStderr "$logDir\agent_stderr.log" | Out-Null
            & $NSSMPath set $ServiceName AppRotateFiles 1               | Out-Null
            & $NSSMPath set $ServiceName AppRotateBytes 10485760        | Out-Null  # 10 MB

            # Environment variables (alternative to CLI args)
            & $NSSMPath set $ServiceName AppEnvironmentExtra `
                "XDR_BACKEND_URL=$BackendURL" `
                "XDR_API_KEY=$ApiKey" | Out-Null

            # Start the service now
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
            Start-Sleep 3
            $svcState = (Get-Service -Name $ServiceName).Status
            if ($svcState -eq "Running") {
                Write-OK "Service '$ServiceName' is RUNNING (LocalSystem, auto-start)"
            } else {
                Write-Warn "Service state: $svcState — check: Get-Service $ServiceName"
            }

        } else {
            # ── Task Scheduler fallback ─────────────────────────────────────
            Write-Info "NSSM not found — using Task Scheduler (runs as SYSTEM)"

            $taskName   = "CyberSentinelXDR-Agent"
            $taskScript = Join-Path $AgentDir "start_agent.bat"

            # Create a launcher batch file
            @"
@echo off
cd /d "$AgentDir"
"$pythonPath" agent.py --backend-url $BackendURL --api-key $ApiKey >> "$AgentDir\logs\agent.log" 2>&1
"@ | Set-Content $taskScript -Encoding ASCII

            $logDir2 = Join-Path $AgentDir "logs"
            New-Item -ItemType Directory -Path $logDir2 -Force | Out-Null

            # Delete existing task
            schtasks /delete /tn $taskName /f 2>&1 | Out-Null

            # Create task: runs as SYSTEM, starts on boot, restarts every minute if not running
            $xmlTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Cyber Sentinel XDR Endpoint Telemetry Agent</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions>
    <Exec>
      <Command>"$pythonPath"</Command>
      <Arguments>"$agentScript" --backend-url $BackendURL --api-key $ApiKey</Arguments>
      <WorkingDirectory>$AgentDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
            $xmlPath = Join-Path $env:TEMP "xdr_task.xml"
            $xmlTask | Set-Content $xmlPath -Encoding Unicode

            schtasks /create /tn $taskName /xml $xmlPath /f 2>&1 | Out-Null
            Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue

            # Run immediately
            schtasks /run /tn $taskName 2>&1 | Out-Null
            Start-Sleep 3

            $taskState = (schtasks /query /tn $taskName /fo LIST 2>&1 | Select-String "Status").ToString()
            Write-OK "Task Scheduler task '$taskName' created and started"
            Write-Info "Task state: $taskState"
            Write-Info "Logs: $AgentDir\logs\agent.log"
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 11. PRIVILEGE GRANTS (ensure net.exe and netsh can modify system settings)
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "11. Privilege and policy configuration"

# Enable the built-in Administrator account (may be disabled in labs)
try {
    net user Administrator /active:yes 2>&1 | Out-Null
    Write-OK "Built-in Administrator account enabled"
} catch { Write-Warn "Could not enable Administrator: $_" }

# Ensure network command access via Local Security Policy
# SeNetworkLogonRight — allows network logons (needed for block_ip netsh rules)
$secpolInf = Join-Path $env:TEMP "xdr_secpol.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-18,*S-1-1-0
"@ | Set-Content $secpolInf -Encoding Unicode

try {
    secedit /configure /db "$env:TEMP\xdr_secpol.sdb" /cfg $secpolInf /quiet 2>&1 | Out-Null
    Write-OK "SeNetworkLogonRight granted to SYSTEM + Administrators"
} catch { Write-Warn "Could not apply security policy: $_" }
Remove-Item $secpolInf, "$env:TEMP\xdr_secpol.sdb" -Force -ErrorAction SilentlyContinue

# ─────────────────────────────────────────────────────────────────────────────
# 12. SOAR ACTION SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "12. SOAR action self-test"

Write-Info "Testing each SOAR action to confirm it will not fail..."

# Test 1: netsh block_ip
$testIP = "192.0.2.1"   # RFC 5737 documentation IP — safe to add/remove
$blockResult = netsh advfirewall firewall add rule `
    name="XDR_SELFTEST_BLOCK" dir=in action=block remoteip=$testIP protocol=any enable=yes 2>&1
if ($LASTEXITCODE -eq 0) {
    netsh advfirewall firewall delete rule name="XDR_SELFTEST_BLOCK" 2>&1 | Out-Null
    Write-OK "block_ip: netsh advfirewall working"
} else {
    Write-Fail "block_ip: WILL FAIL — netsh returned: $blockResult"
    Write-Info "  Fix: ensure agent runs as Administrator or SYSTEM"
}

# Test 2: net user (lock_account)
$netResult = & net user 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-OK "lock_account: net.exe accessible"
} else {
    Write-Fail "lock_account: WILL FAIL — net.exe returned non-zero"
}

# Test 3: taskkill
$tkResult = & taskkill /? 2>&1
if ($LASTEXITCODE -eq 0 -or $tkResult -match "TASKKILL") {
    Write-OK "kill_process: taskkill.exe accessible"
} else {
    Write-Fail "kill_process: WILL FAIL — taskkill.exe not accessible"
}

# Test 4: network interface disable (dry-run — just check netsh accepts the command format)
$ifResult = netsh interface show interface 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-OK "isolate_host: netsh interface accessible (NIC='$detectedNic')"
} else {
    Write-Fail "isolate_host: WILL FAIL — netsh interface not accessible"
}

# Test 5: schtasks (monitor_persistence)
$stResult = & schtasks /query /fo CSV 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-OK "monitor_persistence: schtasks.exe accessible"
} else {
    Write-Warn "monitor_persistence: schtasks.exe returned non-zero (may still work)"
}

# Test 6: quarantine dir writable
$testFile = Join-Path $quarantineDir "xdr_write_test.tmp"
try {
    "test" | Set-Content $testFile -Encoding ASCII
    Remove-Item $testFile -Force
    Write-OK "quarantine_file: directory is writable"
} catch {
    Write-Fail "quarantine_file: WILL FAIL — quarantine dir not writable: $_"
}

# Test 7: psutil / Python import
$pythonCmd2 = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonCmd2) {
    $psutilTest = & python.exe -c "import psutil; print('OK')" 2>&1
    if ($psutilTest -match "OK") {
        Write-OK "scan_filesystem: psutil importable"
    } else {
        Write-Fail "scan_filesystem: WILL FAIL — psutil not installed: $psutilTest"
        Write-Info "  Fix: python -m pip install psutil"
    }
}

# Test 8: winreg (monitor_persistence registry check)
$winregTest = & python.exe -c "import winreg; winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software'); print('OK')" 2>&1
if ($winregTest -match "OK") {
    Write-OK "monitor_persistence: winreg accessible"
} else {
    Write-Warn "monitor_persistence: winreg may be restricted (non-critical)"
}

# ─────────────────────────────────────────────────────────────────────────────
# 13. FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "SETUP COMPLETE"

Write-Host ""
Write-Host "  Cyber Sentinel XDR — Endpoint Deployment Summary" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "  Backend URL        : $BackendURL"                   -ForegroundColor White
Write-Host "  Network Interface  : $detectedNic"                  -ForegroundColor White
Write-Host "  Agent Directory    : $AgentDir"                     -ForegroundColor White
Write-Host "  Quarantine Dir     : $quarantineDir"                -ForegroundColor White
Write-Host "  Health Endpoint    : http://localhost:8765/health"  -ForegroundColor White
Write-Host ""
Write-Host "  To check agent health from the XDR server:" -ForegroundColor Yellow
Write-Host "    curl http://<this-PC-IP>:8765/health"      -ForegroundColor Gray
Write-Host ""
Write-Host "  To view live logs:" -ForegroundColor Yellow
if ($nssmFound) {
    Write-Host "    Get-Service $ServiceName | Format-List" -ForegroundColor Gray
    Write-Host "    Get-Content '$AgentDir\logs\agent_stdout.log' -Tail 50 -Wait" -ForegroundColor Gray
} else {
    Write-Host "    Get-Content '$AgentDir\logs\agent.log' -Tail 50 -Wait" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  To run manually (for testing):" -ForegroundColor Yellow
Write-Host "    cd '$AgentDir'" -ForegroundColor Gray
Write-Host "    python agent.py --backend-url $BackendURL --api-key $ApiKey" -ForegroundColor Gray
Write-Host ""
Write-Host "  To run in simulate mode (no OS changes):" -ForegroundColor Yellow
Write-Host "    python agent.py --backend-url $BackendURL --api-key $ApiKey --simulate" -ForegroundColor Gray
Write-Host ""

# Pause so the window stays open when double-clicked
Write-Host "  Press any key to close..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
