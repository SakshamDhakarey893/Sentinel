@echo off
setlocal enabledelayedexpansion
title Sentinel Desktop App — Production Release Builder
echo ======================================================================
echo       Sentinel Desktop App — Building Production .exe Release
echo ======================================================================
echo.

set SCRIPT_DIR=%~dp0
set SENTINEL_DIR=%SCRIPT_DIR%..
set DIST_DIR=%SENTINEL_DIR%\dist

echo [1/4] Checking environment...
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is required. Install from https://nodejs.org
    pause
    exit /b 1
)

where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Rust / Cargo is required. Install from https://rustup.rs
    pause
    exit /b 1
)

echo [OK] Node.js and Rust found.
echo.

echo [2/4] Building Next.js static export...
cd /d "%SENTINEL_DIR%\frontend"
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] Next.js build failed.
    pause
    exit /b 1
)

echo.
echo [3/4] Compiling native Windows Tauri 2 release bundle...
call npm run tauri:build
if %errorlevel% neq 0 (
    echo [ERROR] Tauri build failed.
    pause
    exit /b 1
)

echo.
echo [4/4] Packaging outputs into dist\ ...
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

set FOUND=0

for %%f in ("%SENTINEL_DIR%\frontend\src-tauri\target\release\bundle\nsis\*.exe") do (
    copy /y "%%f" "%DIST_DIR%\Sentinel-Setup-x64.exe" >nul
    echo   [+] Installer copied: dist\Sentinel-Setup-x64.exe
    set FOUND=1
)

for %%f in ("%SENTINEL_DIR%\frontend\src-tauri\target\release\bundle\msi\*.msi") do (
    copy /y "%%f" "%DIST_DIR%\Sentinel-Installer-x64.msi" >nul
    echo   [+] MSI package copied: dist\Sentinel-Installer-x64.msi
    set FOUND=1
)

if exist "%SENTINEL_DIR%\frontend\src-tauri\target\release\sentinel.exe" (
    copy /y "%SENTINEL_DIR%\frontend\src-tauri\target\release\sentinel.exe" "%DIST_DIR%\Sentinel-Standalone.exe" >nul
    echo   [+] Standalone executable copied: dist\Sentinel-Standalone.exe
    set FOUND=1
)

echo.
if !FOUND! equ 1 (
    echo ======================================================================
    echo [SUCCESS] Your Windows Desktop .exe is ready in:
    echo   %DIST_DIR%
    echo ======================================================================
    explorer "%DIST_DIR%"
) else (
    echo [WARNING] Build finished, but binaries were in an unexpected directory.
    echo Check: %SENTINEL_DIR%\frontend\src-tauri\target\release
)

echo.
pause
