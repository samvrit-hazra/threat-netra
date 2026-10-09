# Launcher script for Threat Netra
Set-Location -Path $PSScriptRoot
& "$PSScriptRoot\.venv\Scripts\python.exe" -m uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload
