@echo off
setlocal
title Sentinel Relay — Remove Windows Auto-Start
echo ======================================================================
echo    Removing Sentinel Relay 24/7 Auto-Start from Windows
echo ======================================================================
echo.

schtasks /delete /tn "SentinelRelayServer" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SentinelRelay" /f >nul 2>&1

echo [OK] Auto-start task and registry entry removed.
echo.
echo Stopping any active background relay process...
taskkill /F /IM sentinel-backend.exe >nul 2>&1
echo [OK] Done.
timeout /t 2 >nul
