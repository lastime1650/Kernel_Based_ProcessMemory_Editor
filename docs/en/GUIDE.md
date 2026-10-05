# Setup and user guide

[English overview](../../README.en.md) · [한국어](../ko/GUIDE.md) · [简体中文](../zh-CN/GUIDE.md) · [Español](../es/GUIDE.md)

## Architecture and requirements

The active path is browser → FastAPI → `KernelOnlyBridge` → `DeviceIoControl` → `SampleKernel1.sys`. The device is `\\.\MyDriver`. Python uses `CreateFileW`, `DeviceIoControl` and `CloseHandle` for the device connection. Target reads, scans and maps use the kernel path. NumPy comparison, PE parsing and instruction analysis operate on returned bytes in user mode. `memory_scanner.py` also retains an older Win32 scanner which the current server does not use for target scans.

- Windows x64, 64-bit Python, C++ tools and a matching Windows SDK/WDK.
- Verified environment: Python 3.14.5, Visual Studio 2022 Professional, SDK 10.0.26100.0, WDK 10.0.26100.6584.
- Original dependencies: FastAPI, Uvicorn, psutil, Capstone 5, Keystone 0.9.2 and NumPy. Version ranges are preserved; there is no reproducible dependency lock.
- ARM64 configurations exist in the solution, but register/context and remote-call code depends on x64. ARM64 compatibility is unverified.
- The original UI remains Korean; the Korean menu labels below identify the controls to use.

## Build and driver loading

Prepare a compatible Visual Studio/SDK/WDK combination using [Microsoft's WDK instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk). Run these commands in Developer PowerShell at the repository root. The environment above was tested; other toolchain combinations were not.

```powershell
msbuild SampleKernel1.sln /m /p:Configuration=Release /p:Platform=x64
msbuild SampleKernel1.sln /m /p:Configuration=Debug /p:Platform=x64
```

```powershell
sc.exe create SampleKernel1 type= kernel start= demand binPath= "C:\Kernel_Based_ProcessMemory_Editor\x64\Release\SampleKernel1.sys"
sc.exe start SampleKernel1
sc.exe query SampleKernel1
```


The `sc.exe` example registers a manual service for an **appropriately signed driver permitted to load on your test system**. Use an administrator terminal and replace the absolute path with your build output. If the service already exists, inspect `sc.exe qc SampleKernel1` before changing it. Follow [Microsoft's signing documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing). Certificates and scripts to change security settings are not supplied.

The original INF contains manufacturer, hardware ID and DriverVer template entries. Public distribution requires preparing these in your own working copy and validating/signing the chosen package. This repository is not a completed INF installer package.

Before replacing the driver, stop the server and clients and restore managed patches, freezes and breakpoints as needed. Use `sc.exe stop SampleKernel1`, prepare the new build and start again. Use `sc.exe delete SampleKernel1` only when removing the service. Releasing call tracking or unloading the driver does not terminate a target function thread already created.

Optional PDB helper: run `build_pdb_symbols.cmd` inside `kernel_control_panel/native`. The original helper script and `Symbols.dia` in `image_workbench.py` use fixed VS 2022 Professional paths. For another installation, align both paths in your working copy. Applying symbols requires matching the image's CodeView GUID and Age.

## Run the server

Follow the [virtual environment commands](../../README.en.md#quick-start) and open the [8005 UI](http://127.0.0.1:8005/). Original `python server.py` and the batch launcher use 8000; use Uvicorn's `--port 8005` for this guide. Run a single worker: each worker has independent device and management state. Stop with Ctrl+C in the server terminal.

## 1. Connection and target selection

![Dashboard](../images/01-dashboard.jpg)

Check connection and version on the dashboard. Open **대상 프로세스 선택** (select target), search by name/PID, or enter a PID manually. Selection rechecks liveness and creation identity. Discovery queries PIDs in steps of four because no full PID enumeration IOCTL exists. Default range is 4–65,536; expand to 262,144 or 1,048,576 or enter an out-of-range PID manually. The list is not guaranteed complete.

Changing or reselecting the target can clear inputs and sessions. It does not automatically restore changes already applied. Restore required changes before switching.

## 2. Scan and narrow candidates

![Memory scan](../images/03-memory-scan.jpg)

Open **메모리 스캔** (memory scan), choose type/condition/value and run **New**. For example, scan for a 32-bit integer 100 in your own test program, change it to 101 in that program and run **Next** with 101 or Increased. Unknown starts numeric/structure scans without a known value. **Rescan** refreshes the baseline while retaining readable candidates. Live refresh does not change Next's baseline.

Supported input includes signed/unsigned numbers, UTF-8/UTF-16LE, AOB such as `DE AD ?? A? ?F`, and structures with numeric fields. Addresses and 64-bit integers stay strings. Alignment 1 includes unaligned values; start is inclusive and end exclusive. Save candidates or route them to Hex, disassembly or structures.

The new workspace stores candidates in SQLite and does not stop at the legacy 50,000-candidate cap. Default scan budget is 256MiB, maximum 4GiB. Partial scans and read failures are reported. Pages hold 50/100/200/500 rows, with 256 saved addresses per session. Distinguish current-page from full-candidate filtering/sorting; full CSV is produced as an export job. Legacy compatibility scan APIs retain their separate 50,000 limit.

## 3. Edit, watch, structures and allocation

![Memory editor](../images/02-memory-editor.jpg)

In **메모리 편집** (memory editor), open a hex address and double-click bytes/numbers or use typed editing. Ctrl+→ expands pointers; Ctrl+← collapses them; the wheel browses adjacent addresses. Restoring recent edits checks current bytes first. **Watch / 값 고정** (Watch/freeze) and saved-address Freeze perform repeated writes, stopping on failure, termination or PID reuse.

**구조체 / 클래스** defines fields, arrays, nested structures and pointers. Change sets use preview → original-byte verification → apply → readback. **프로젝트 작업 공간** stores views and address locators for reconnection; **변경 기록 / 묶음** manages recovery records; **변화 타임라인** compares sampled values. Timelines do not capture every intervening change.

**메모리 할당** accepts an ANSI/UTF-16LE string with a terminating NULL or raw file bytes, calculates the size and allocates read/write memory. It writes and checks readback through the kernel; the limit is 1MiB including NULL. Release uses the recorded BaseAddress. Clearing history does not free target memory. **메모리 관리** changes protection, copies and fills memory. Wide View is Beta. Write, free, freeze and restore controls alter actual target memory.

## 4. Dumps, modules and functions

**메모리 / 이미지 덤프** supports range/image/images. A range may be up to 16GiB. Output goes to `dumps/` or `KERNEL_STUDIO_DUMP_DIR`. Cancellation waits for the current request and retains `.part`; resume within the same server session checks process identity, length and hash. Completed download records survive restart; active jobs do not. Zero policy records unreadable, zero-filled spans in the manifest. These zeros are not original data.

Image dumps use mapped RVA layout: file offset = VA − image base. They are not reconstructed executable disk PE files. **모듈 / PE / 주소** shows modules, headers, sections, imports/IAT, exports and address membership. Beyond MEM_IMAGE it checks valid PE headers at committed region starts, not every byte in a region.

In **DLL / 이미지 함수**, select an image and analyze its functions. Verify actual DLL appearance in the module list even after a successful load request. PDB is optional; absent symbols can leave functions missing or types inferred. Function calls require driver 2.2+, an x64 target, one 64-bit integer/pointer argument and a 32-bit exit value. Poll the existing CallId after a timeout; do not automatically repeat creation. Releasing tracking neither terminates the thread nor unloads the DLL.

## 5. Code, threads and breakpoints

![Disassembly](../images/04-disassembly.jpg)

In **디스어셈블리**, set address, size and x86/x64. Double-click an ASM/Graph instruction, validate one Intel-syntax line and stage it. Longer encodings are rejected; shorter ones are NOP padded. Target bytes change only on **편집 적용** (apply). Address Undo/Redo navigates; patch Undo/Redo writes. Recovery requires expected current bytes. C pseudocode does not promise original source or compilable C.

Patches are not atomic with respect to executing threads and do not supply instruction-cache synchronization. Apply while the code is not executing in a controlled test. **스레드 / 레지스터** verifies PID/TID/creation time, temporarily suspends, changes requested fields, checks readback and restores suspend count. The ABI exposes 18 general register fields, not XMM/YMM. Hardware breakpoints support execution/write/read-write and lengths 1/2/4/8, retaining recovery data on removal failure.

## API and limits

`/docs` provides Swagger, `/redoc` ReDoc and `/openapi.json` the schema. Replace example PID/address values with your authorized test target.

```powershell
Invoke-RestMethod http://127.0.0.1:8005/api/status
Invoke-RestMethod http://127.0.0.1:8005/api/studio/capabilities
$requestBody = '{"operation":"read","args":{"pid":1234,"address":"0x140000000","size":64}}'
Invoke-RestMethod http://127.0.0.1:8005/api/studio/execute -Method Post -ContentType application/json -Body $requestBody
```

Check `success`, `result_status` and `driver_response`, not HTTP 200 alone. See the [complete API/ABI inventory](../reference/API_ABI.md). Poll job IDs for large dumps/scans and wait for cancellation completion.

Ordinary transfers are limited to 1MiB, kernel read pieces to 4KiB, ordinary tables to 5,000, internal maps to 50,000, kernel result nodes to 65,536, threads to 64 and handles to 128. Operations requiring a full map reject truncated maps. Snapshots (16), maps (8) and patch records (64) are server-session state. Projects, journals, PDBs, uploaded DLLs and dumps live on disk; bookmarks live in the browser. Sequential reads of an active process are not atomic snapshots.

## Troubleshooting and tests

| Symptom | Check |
|---|---|
| Device cannot open | Administrator access, service state, signing/load errors, `\\.\MyDriver` |
| Invalid address | Process identity, user address range, Guard/NoAccess, exit or PID reuse |
| Missing process | Expand range or enter PID; discovery is not complete enumeration |
| Cannot connect to 8005 | Uvicorn port/errors; original launchers use 8000 |
| Old UI | Refresh, browser cache and the running server's actual source directory |
| PDB failure | DIA SDK, helper build/path and matching GUID/Age |
| Partial scan/quota | Narrow range and run New; inspect budget, limits and read failures |

Full discovery needs the DIA helper plus `samples/PanelHello.dll` and its matching PDB. Build the [fixture source](../../samples/README.md) below to avoid the original tests' external-path dependency. CI maps the actual VS 2022 installation to the original Professional path and builds both helper and fixture without editing original source.

```powershell
cd kernel_control_panel
powershell -NoProfile -ExecutionPolicy Bypass -File ../samples/build_fixture.ps1
python -m unittest discover -p 'test*.py' -v
python test_driver_readonly.py
```

The `unittest` command runs existing mocked regressions. `test_driver_readonly.py` performs seven read-only queries against the diagnostic process itself using the loaded driver. `test_driver_all_ioctl.py` is the same diagnostic entry point, not a full live mutation suite. Consult [validation scope](../VALIDATION.md). Supply synthetic reproductions instead of private dumps, PDBs or real memory contents in public issues.
