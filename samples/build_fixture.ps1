$ErrorActionPreference = 'Stop'
$vsLocator = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vsLocator)) { throw 'vswhere.exe unavailable' }
$vsInstall = & $vsLocator -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw 'Visual Studio 2022 C++ tools unavailable' }
Push-Location $PSScriptRoot
try {
    $buildCommand = "call `"$vsInstall\VC\Auxiliary\Build\vcvars64.bat`" >nul && cl /nologo /LD /MD /EHsc /std:c++17 /Od /Zi /W4 /utf-8 PanelHello.cpp /FePanelHello.dll /FoPanelHello.obj /link /DEBUG:FULL /PDB:PanelHello.pdb /INCREMENTAL:NO"
    & $env:ComSpec /d /s /c $buildCommand
    if ($LASTEXITCODE -ne 0) { throw 'PanelHello fixture build failed' }
} finally { Pop-Location }
