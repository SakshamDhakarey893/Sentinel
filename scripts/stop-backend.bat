@echo off
title Stop Sentinel Backend Relay
echo [INFO] Stopping any running sentinel-backend.exe processes...
taskkill /F /IM sentinel-backend.exe 2>nul
if %errorlevel% equ 0 (
    echo [OK] Sentinel Backend Relay stopped successfully.
) else (
    echo [INFO] No running sentinel-backend.exe process was found.
)
timeout /t 2 >nul
