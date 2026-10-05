@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%
set "DIA_SDK=C:\Program Files\Microsoft Visual Studio\2022\Professional\DIA SDK"
cl /nologo /EHsc /std:c++17 /O2 /W4 /utf-8 /I"%DIA_SDK%\include" pdb_symbols.cpp /Fepdb_symbols.exe /Fopdb_symbols.obj /link /LIBPATH:"%DIA_SDK%\lib\amd64" diaguids.lib ole32.lib oleaut32.lib
exit /b %errorlevel%
