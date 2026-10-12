@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%
pushd "%~dp0"
cl /nologo /EHsc /std:c++17 /O2 /W4 /WX /utf-8 /MT /Zi /LD hwbp_capture.cpp /FeKernelStudioCapture.dll /Fohwbp_capture.obj /link /DEBUG /PDB:KernelStudioCapture.pdb
if errorlevel 1 goto failed
cl /nologo /EHsc /std:c++17 /O2 /W4 /WX /utf-8 /MT /Zi fixture.cpp /FeHwbpFixture.exe /Fofixture.obj /link /DEBUG /PDB:HwbpFixture.pdb
if errorlevel 1 goto failed
cl /nologo /EHsc /std:c++17 /O2 /W4 /WX /utf-8 /MT capture_selftest.cpp /FeCaptureSelftest.exe /Focapture_selftest.obj
if errorlevel 1 goto failed
popd
exit /b 0
:failed
set "BUILD_RESULT=%errorlevel%"
popd
exit /b %BUILD_RESULT%
