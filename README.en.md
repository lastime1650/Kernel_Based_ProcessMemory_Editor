# Kernel Based Process Memory Editor

[한국어](README.md) · [English](README.en.md) · [简体中文](README.zh-CN.md) · [Español](README.es.md)

A Windows process memory analysis and editing project combining the **SampleKernel1** kernel driver with the local **Kernel Studio** web workspace. Inspect and scan memory, edit bytes and structures, dump images, inspect PE files, manage threads and registers, and review or restore changes from a browser.

![Kernel Studio dashboard](docs/images/01-dashboard.jpg)

> Four languages are supported in the **repository documentation**. The original application UI remains Korean. Imported program sources and existing Korean documentation are unchanged. Source driver: v2.3; API: v3.0.0. The driver loaded when screenshots were captured was v2.2.

## Features

- Kernel IOCTL process queries, memory maps, read/write, allocation, release, protection and copy.
- Numeric, string, AOB and structure New/Next/Unknown scans with SQLite candidates, paged/full candidate browsing and CSV export.
- ReClass style byte editing, nested pointers, Watch/freeze and Wide View (Beta).
- Dumps up to 16GiB, MEM_IMAGE bundles, progress, cancellation, resume and hashes.
- PE imports/exports, optional PDB symbols, assembly, control flow graphs and conservative C pseudocode.
- Validated instruction patches, Undo/Redo, typed structures/classes, saved projects, change journals and sampled timelines.
- Thread contexts, priorities and CPU masks, hardware breakpoints, DLL loading and single argument function calls.

## Quick start

Use Windows x64 and 64-bit Python. Python 3.14.5 was verified locally. First prepare a compatible signed driver using the [build and loading guide](docs/en/GUIDE.md#build-and-driver-loading). The web server does not install or load it.

```powershell
git clone https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor.git
cd Kernel_Based_ProcessMemory_Editor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r kernel_control_panel\requirements.txt
cd kernel_control_panel
..\.venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8005
```

Open the [local UI](http://127.0.0.1:8005/) and follow **target selection → memory scan → New → Next → save addresses → Hex/Watch/analysis**. If port 8005 already hosts a server, use it or choose another port. Original `python server.py` and `start_panel.bat` default to **8000**.

## Documentation

| Topic | Link |
|---|---|
| Setup, build, workflows, API and troubleshooting | [English guide](docs/en/GUIDE.md) |
| Every source file and its role | [Source map](docs/SOURCE_MAP.md) |
| Complete HTTP routes and IOCTL identifiers | [API / ABI reference](docs/reference/API_ABI.md) |
| Test evidence and limitations | [Validation record](docs/VALIDATION.md) |
| Contributing, support, security and license status | [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md) · [Security](SECURITY.md) · [License status](LICENSE_STATUS.md) |
| Changes | [Changelog](CHANGELOG.md) |

## Validation and distribution

On 2026-10-05–06 the copy passed **314 regression tests**, x64 **Release/Debug builds**, a **DIA helper build**, and **7 read-only diagnostics** against the loaded driver. These do not constitute complete live mutation tests of a reloaded v2.3 driver. CI runs the existing mocked regression tests on Windows.

The workspace connects 34 of 37 ABI identifiers. Two event operations and thread termination are excluded from the UI. PID discovery and returned lists have limits; reads and patches of running memory are not atomic. See the guide for details.

All sources, tests, static UI and project configuration are included. IDE caches, build outputs, user DLL/PDB uploads, scan databases, dumps, runtime journals and generated reports remain in the local copy and are excluded from public Git tracking. [Source map](docs/SOURCE_MAP.md) includes source hashes and file coverage.

**Usage:** use test processes you own or are authorized to inspect. The API has no authentication layer; run with its loopback binding. No public-release signed package or installer is provided. An open-source license has not been selected.
