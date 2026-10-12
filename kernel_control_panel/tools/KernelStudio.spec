from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

panel=Path(SPECPATH).parent
datas=[(str(panel/'static'),'static'),(str(panel/'presets'),'presets')]
binaries=[]
for path in (panel/'native').rglob('*'):
    if not path.is_file() or path.suffix.lower() not in ('.dll','.exe'):continue
    if any(part.lower()=='manual_v4' for part in path.parts):continue
    if path.name.lower().startswith(('manualv4engine','manualmapper','kernelmapperbeta')):continue
    binaries.append((str(path),str(path.parent.relative_to(panel))))
hiddenimports=collect_submodules('uvicorn')+collect_submodules('websockets')
for name in ['capstone','keystone']:
    data,binary,hidden=collect_all(name);datas+=data;binaries+=binary;hiddenimports+=hidden
a=Analysis([str(panel/'kernel_studio.py')],pathex=[str(panel)],binaries=binaries,datas=datas,
           hiddenimports=hiddenimports,hookspath=[],hooksconfig={},runtime_hooks=[],excludes=[],noarchive=False,optimize=0)
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,[],exclude_binaries=True,name='KernelStudio',debug=False,
        bootloader_ignore_signals=False,strip=False,upx=False,console=True,
        version=str(Path(SPECPATH)/'panel_version.txt'))
coll=COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='KernelStudio')
