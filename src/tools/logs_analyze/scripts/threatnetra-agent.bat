@echo off
TITLE Threat Netra Telemetry Forwarder
echo ======================================================================
echo   THREAT NETRA // CONTINUOUS LOG INGESTION AGENT (WINDOWS LAUNCHER)
echo ======================================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0threatnetra-agent.ps1" %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Script ended with an error or was terminated.
    pause
)
