# retrain.ps1 — convenience launcher for the offline feedback retraining tool.
# Activates the project venv (if present) and forwards all args to the Python script.
#
# Examples:
#   .\retrain.ps1 -Stats
#   .\retrain.ps1 -Target personal_baseline
#   .\retrain.ps1 -Target personal_baseline -DryRun
#   .\retrain.ps1 -Promote
#
# Anything you can pass to retrain_from_feedback.py, you can pass here after the
# named switches via -Extra, e.g.:  .\retrain.ps1 -Target personal_baseline -Extra '--min-labels 30'

param(
    [switch]$Stats,
    [string]$Target,
    [switch]$DryRun,
    [switch]$Promote,
    [string]$Extra = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Resolve a Python interpreter: prefer the project venv, else system python.
$venvPy = Join-Path $scriptDir "venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    $python = $venvPy
} else {
    $python = "python"
    Write-Host "[retrain] venv not found at $venvPy — using system python." -ForegroundColor Yellow
}

# Build argument list.
$pyArgs = @("retrain_from_feedback.py")
if ($Stats)   { $pyArgs += "--stats" }
if ($Target)  { $pyArgs += @("--target", $Target) }
if ($DryRun)  { $pyArgs += "--dry-run" }
if ($Promote) { $pyArgs += "--promote" }
if ($Extra)   { $pyArgs += $Extra.Split(" ") }

if ($pyArgs.Count -eq 1) {
    Write-Host "[retrain] No action given. Try: .\retrain.ps1 -Stats" -ForegroundColor Cyan
    & $python "retrain_from_feedback.py" "--help"
    exit 0
}

Write-Host "[retrain] $python $($pyArgs -join ' ')" -ForegroundColor Cyan
& $python @pyArgs
exit $LASTEXITCODE
