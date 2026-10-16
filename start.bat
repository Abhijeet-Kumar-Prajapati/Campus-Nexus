@echo off
title Campus Nexus
cd /d "%~dp0"

echo.
echo   ============================================================
echo      C A M P U S   N E X U S
echo      Library . Store . Arcade
echo   ============================================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo   [X] Node.js is not installed or not on your PATH.
  echo       Download it from https://nodejs.org  ^(version 22 or newer^)
  echo.
  pause
  exit /b 1
)

echo   Starting server...
start "" http://localhost:3000
node server.js

echo.
echo   Server stopped. Press any key to close.
pause >nul