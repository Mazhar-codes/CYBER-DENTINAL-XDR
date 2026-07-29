@echo off
title Cyber Sentinel XDR — Launcher
color 0A

echo.
echo  ============================================================
echo   CYBER SENTINEL XDR — AUTO-IP LAUNCHER
echo  ============================================================
echo.

REM ── Step 1: Auto-detect IP and patch both .env files ────────────────────────
echo  [1/2] Updating IP addresses in .env files...
cd /d "D:\Cyber Sentinal"
call "D:\Cyber Sentinal\Backend\venv\Scripts\python.exe" "D:\Cyber Sentinal\update_ip.py"
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] IP update failed. Check that the venv exists.
    pause
    exit /b 1
)

REM ── Step 2: Start the FastAPI backend ───────────────────────────────────────
echo  [2/2] Starting FastAPI backend on port 8000...
echo.
cd /d "D:\Cyber Sentinal\Backend"
call "D:\Cyber Sentinal\Backend\venv\Scripts\activate.bat"
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload
