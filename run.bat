@echo off
echo Starting Threat Netra Local Server...
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python -m uvicorn src.main:app --host 127.0.0.1 --port 8000 --reload
pause
