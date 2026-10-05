@echo off
title SampleKernel1 Web Control Panel
echo ======================================================================
echo          Starting SampleKernel1 Web Control Panel (FastAPI + React)
echo ======================================================================
cd /d "%~dp0"
python -m uvicorn server:app --host 127.0.0.1 --port 8000
pause
