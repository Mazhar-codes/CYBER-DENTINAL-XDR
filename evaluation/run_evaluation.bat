@echo off
REM =============================================================================
REM  Cyber Sentinel XDR — Model Evaluation Runner  (Windows)
REM  Usage: Double-click or run from Command Prompt
REM =============================================================================

title Cyber Sentinel XDR — Model Evaluation
color 0A

echo.
echo =====================================================================
echo    CYBER SENTINEL XDR - Model Evaluation Runner  ^(Windows^)
echo =====================================================================
echo.

REM ── Python check ─────────────────────────────────────────────────────────

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Python not found in PATH.
    echo          Install Python 3.8+ from https://python.org
    echo          Make sure to tick "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%V in ('python --version 2^>^&1') do echo   [OK] Found: %%V
echo.

REM ── install dependencies ──────────────────────────────────────────────────

echo   Installing required packages...
echo   (scikit-learn, numpy, pandas, matplotlib, seaborn)
echo.

python -m pip install --quiet --upgrade ^
    scikit-learn numpy pandas matplotlib seaborn

if %errorlevel% neq 0 (
    echo   [WARN] Some packages may not have installed correctly.
    echo          Continuing - evaluation will skip optional dependencies.
) else (
    echo   [OK] Dependencies installed / up-to-date
)
echo.

REM ── locate evaluation script ──────────────────────────────────────────────

set "SCRIPT_DIR=%~dp0"
set "EVAL_SCRIPT=%SCRIPT_DIR%evaluate_all_models.py"

if not exist "%EVAL_SCRIPT%" (
    echo   [ERROR] evaluate_all_models.py not found in:
    echo          %SCRIPT_DIR%
    echo          Make sure all 3 files are in the same folder.
    echo.
    pause
    exit /b 1
)

echo   [OK] Found: %EVAL_SCRIPT%
echo.

REM ── run evaluation ────────────────────────────────────────────────────────

echo   Running model evaluation...
echo   (This may take 15-60 seconds depending on your machine)
echo.

cd /d "%SCRIPT_DIR%"
python "%EVAL_SCRIPT%"
set EVAL_EXIT=%errorlevel%

echo.

if %EVAL_EXIT% neq 0 (
    echo   [ERROR] Evaluation failed with exit code %EVAL_EXIT%
    echo          Check the error messages above.
    echo.
    pause
    exit /b %EVAL_EXIT%
)

REM ── verify outputs ────────────────────────────────────────────────────────

echo   ---------------------------------------------------------------------
echo   OUTPUT FILES
echo   ---------------------------------------------------------------------

set "REPORT="
for /f "tokens=*" %%F in ('dir /b /o-d "%SCRIPT_DIR%model_evaluation_report*.txt" 2^>nul') do (
    if not defined REPORT set "REPORT=%%F"
)

if defined REPORT (
    echo   [OK] Report  : %SCRIPT_DIR%%REPORT%
) else (
    echo   [WARN] Report not found - check errors above
)

if exist "%SCRIPT_DIR%model_evaluation_metrics.json" (
    echo   [OK] Metrics : %SCRIPT_DIR%model_evaluation_metrics.json
)

if exist "%SCRIPT_DIR%evaluation_plots\" (
    echo   [OK] Plots   : %SCRIPT_DIR%evaluation_plots\
)

echo.

REM ── open report in Notepad ────────────────────────────────────────────────

if defined REPORT (
    echo   Opening report in Notepad...
    start notepad "%SCRIPT_DIR%%REPORT%"
)

echo =====================================================================
echo   Evaluation complete!
echo   Review model_evaluation_report.txt for teacher presentation tips.
echo =====================================================================
echo.

pause
exit /b 0
