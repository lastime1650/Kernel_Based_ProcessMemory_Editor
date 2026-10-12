@echo off
setlocal
cd /d "%~dp0.."
rem Always collect into a fresh version directory; existing runtime/data folders may be in use.
for /f "delims=" %%P in ('python -c "from pathlib import Path; from datetime import datetime; from build_info import PANEL_VERSION; p=Path('dist')/PANEL_VERSION; stamp=datetime.now().isoformat(timespec='microseconds').replace(':','').replace('.',''); print(p if not p.exists() else p/('build-'+stamp))"') do set "TASK_PANEL_DIST=%%P"
if not defined TASK_PANEL_DIST exit /b 1
python -m PyInstaller --noconfirm --clean --distpath "%TASK_PANEL_DIST%" tools\KernelStudio.spec
exit /b %errorlevel%
