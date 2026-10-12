"""Build/run current kernel mapper with mock DDIs; never opens a driver or target process."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(output):
    repository = Path(__file__).resolve().parents[3]
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = (repository / 'MANUAL_KERNEL.hpp').read_text(encoding='utf-8-sig')
    source_hash = hashlib.sha256((repository / 'MANUAL_KERNEL.hpp').read_bytes()).hexdigest()
    # Only includes are adapted. The entire current mapper implementation is tested unchanged.
    source = re.sub(r'^#include ["<](?:helper.hpp|manual_map_protocol.h|ntstrsafe.h)[">]\s*$', '', source, flags=re.M)
    (output / 'manual_kernel_under_test.hpp').write_text(source, encoding='utf-8')
    installer = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    toolchain = subprocess.check_output([str(installer), '-latest', '-products', '*', '-requires',
                                        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
    setup = Path(toolchain) / 'Common7/Tools/VsDevCmd.bat'
    fixture = Path(__file__).with_name('failcode_selftest.cpp')
    executable = output / 'failcode_selftest.exe'
    command = (f'call "{setup}" -arch=x64 -host_arch=x64 >nul\n'
               f'cl /nologo /std:c++17 /EHsc /utf-8 /W4 /I"{repository}" /I"{output}" '
               f'"{fixture}" /Fe:"{executable}" /Fo:"{output / "failcode_selftest.obj"}"\n'
               'if errorlevel 1 exit /b 1\n'
               f'cl /nologo /std:c++17 /EHsc /utf-8 /c "{repository / "test_client.cpp"}" '
               f'/Fo:"{output / "test_client.obj"}"\n'
               'if errorlevel 1 exit /b 1\n'
               f'"{executable}"\n')
    script = output / 'build_selftest.cmd'
    script.write_text('@echo off\n' + command, encoding='utf-8')
    result = subprocess.run(['cmd', '/d', '/c', str(script)], capture_output=True)
    stdout = result.stdout.decode('utf-8', errors='replace')
    stderr = result.stderr.decode('utf-8', errors='replace')
    (output / 'selftest.log').write_text(stdout + stderr, encoding='utf-8')
    examples = [line.partition(': ')[2] for line in stdout.splitlines()
                if line.startswith('PREPROTECT_DIAGNOSTIC_EXAMPLE: ')]
    if examples:
        (output / 'preprotect_example.txt').write_text('\n\n'.join(examples) + '\n', encoding='utf-8')
    summary = re.search(r'PASS native manual-map: (\d+) checks; (\d+) distinct failure locations', stdout)
    evidence = {
        'source': str(repository / 'MANUAL_KERNEL.hpp'),
        'source_sha256': source_hash,
        'includes_only_adaptation': True,
        'mocked_ddis_only': True,
        'return_code': result.returncode,
        'checks': int(summary.group(1)) if summary else None,
        'distinct_failure_locations': int(summary.group(2)) if summary else None,
        'preprotect_example': str(output / 'preprotect_example.txt') if examples else None,
        'preprotect_example_message_bytes': [len(value.encode('ascii')) for value in examples],
    }
    (output / 'selftest_result.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(stdout + stderr)
    return result.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    args = parser.parse_args()
    if args.output:
        raise SystemExit(run(args.output))
    with tempfile.TemporaryDirectory(prefix='manual-map-selftest-') as folder:
        raise SystemExit(run(folder))
