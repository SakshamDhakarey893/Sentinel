@echo off
setlocal
title Sentinel Relay — 24/7 Windows Auto-Start Setup
echo ======================================================================
echo    Sentinel Relay Server — Windows 24/7 Background Auto-Start Setup
echo ======================================================================
echo.

set SCRIPT_DIR=%~dp0
set VBS_LAUNCHER=%SCRIPT_DIR%start-backend-silent.vbs

if not exist "%VBS_LAUNCHER%" (
    echo [ERROR] Launcher file not found: %VBS_LAUNCHER%
    pause
    exit /b 1
)

echo [1] Registering Sentinel Relay to run silently at Windows logon...
schtasks /create /tn "SentinelRelayServer" /tr "wscript.exe \"%VBS_LAUNCHER%\"" /sc onlogon /f /rl HIGHEST >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Elevated Task Scheduler failed. Falling back to CurrentUser Run Registry...
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SentinelRelay" /t REG_SZ /d "wscript.exe \"%VBS_LAUNCHER%\"" /f >nul
)

echo.
echo [OK] Sentinel Relay is configured to start automatically on boot / logon!
echo.
echo [2] Starting the Sentinel Relay background process right now...
wscript.exe "%VBS_LAUNCHER%"
timeout /t 2 >nul

powershell -Command "try { (Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 3).status } catch { 'down' }" | findstr "ok" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] Sentinel Relay is verified ONLINE and running 24/7 in the background!
    echo Health endpoint: http://127.0.0.1:8080/health
) else (
    echo [WARNING] Relay launched. Verifying startup in progress...
)

echo.
echo To stop it at any time, run: scripts\stop-backend.bat
echo ======================================================================
echo.
pause
