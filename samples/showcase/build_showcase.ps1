[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$vsLocator = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vsLocator)) { throw 'vswhere.exe is unavailable.' }
$vsInstall = & $vsLocator -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw 'Install the Visual Studio C++ x64 build tools.' }
$vcvarsPath = Join-Path $vsInstall 'VC\Auxiliary\Build\vcvars64.bat'
$outputPath = Join-Path $PSScriptRoot 'build'
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
$commandPath = Join-Path $outputPath 'compile_showcase.cmd'
$sourcePath = $PSScriptRoot
$commandText = @"
@echo off
call "$vcvarsPath" >nul
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /MD /EHsc /Od /Zi /W4 /WX /utf-8 /DUNICODE /D_UNICODE "$sourcePath\Asterfall.cpp" /Fe"$outputPath\Asterfall.exe" /Fo"$outputPath\Asterfall.obj" /Fd"$outputPath\Asterfall-compiler.pdb" /link /DEBUG:FULL /PDB:"$outputPath\Asterfall.pdb" /INCREMENTAL:NO /SUBSYSTEM:WINDOWS User32.lib Gdi32.lib Shell32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /LD /MD /EHsc /Od /Zi /W4 /WX /utf-8 "$sourcePath\ShowcasePlugin.cpp" /Fe"$outputPath\ShowcasePlugin.dll" /Fo"$outputPath\ShowcasePlugin.obj" /Fd"$outputPath\ShowcasePlugin-compiler.pdb" /link /DEBUG:FULL /PDB:"$outputPath\ShowcasePlugin.pdb" /INCREMENTAL:NO /IMPLIB:"$outputPath\ShowcasePlugin.lib"
if errorlevel 1 exit /b 1
"@
Set-Content -LiteralPath $commandPath -Value $commandText -Encoding ascii
Push-Location $outputPath
try {
    & $env:ComSpec /d /s /c "`"$commandPath`""
    if ($LASTEXITCODE -ne 0) { throw 'Showcase build failed.' }
} finally {
    Pop-Location
}
Write-Host "Built x64 showcase and PDBs in $outputPath"
