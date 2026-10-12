@echo off
title Kernel Studio
echo Starting Kernel Studio - default address: http://127.0.0.1:8005/
cd /d "%~dp0"
python kernel_studio.py %*
pause
