# Setup and user guide

[English overview](../../README.en.md) · [한국어](../ko/GUIDE.md) · [简体中文](../zh-CN/GUIDE.md) · [Español](../es/GUIDE.md)

**Driver 2.6.0.2 · Kernel Studio 3.2.3 · Windows x64 · ManualV4 ABI v3 / 2104 bytes**

> [!IMPORTANT]
> Use the updated driver and panel together. The dashboard shows the device's **loaded version**, not the version of a `.sys` on disk. Build success and driver load success are separate checks.

## 1. Prepare and build

Use Windows x64, 64-bit Python, Visual Studio 2022 C++ tools and matching Windows SDK/WDK. Development checks used Python 3.14.5 and VS 2022 Professional. ARM64 configurations do not establish ARM64 support. The UI is Korean; Korean labels below identify the controls.

From Developer PowerShell at the repository root:

```powershell
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
msbuild SampleKernel1.sln /t:Rebuild /m /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off
```

Outputs are `x64\Release\SampleKernel1.sys` and `x64\Debug\SampleKernel1.sys`. `SignMode=Off` produces unsigned build outputs; it does not make Windows accept them. Use the signing and driver deployment setup appropriate to your test system. The source repository is not a certified installation package.

When replacing a loaded driver, close clients and restore managed freezes, patches and breakpoints as needed before your normal driver update procedure. The control device is `\\.\MyDriver`.

## 2. Start Kernel Studio

```powershell
cd kernel_control_panel
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python kernel_studio.py
```

Open [http://127.0.0.1:8005/](http://127.0.0.1:8005/). Both `kernel_studio.py` and `server.py` default to **8005**. Use `python kernel_studio.py --port 8006` for another port. The server binds to loopback; run one worker because device and management state are local to that process. Stop the source server with Ctrl+C.

For a packaged build, install PyInstaller in the build environment and run `tools\build_release.cmd` from this directory. Output uses `dist/3.2.3/KernelStudio`, or a fresh timestamped child if that version directory exists. Run the new `KernelStudio.exe` after closing the old panel.

> [!NOTE]
> `/api/build` describes the running panel. `/api/status` reports the actual connected driver. Replacing files alone updates neither an already running panel nor an already loaded driver.

## 3. Select, read, then narrow

Open **대상 프로세스 선택** (select target), search by name/PID, or enter a PID directly. Selection rechecks liveness and creation identity. Discovery probes PID ranges in steps of four; it is not a complete system enumeration. Default range is 4–65,536, with larger ranges available.

In **메모리 스캔** (memory scan), choose a type, condition and range. Run **New**, change a value in your own test program, then run **Next** with the new value or a comparison such as Increased. **Live** refreshes displayed values without replacing Next's baseline.

Move a result to **메모리 편집** (memory editor), Watch, structures or disassembly. Typed writes, freeze, allocation, release, protection and thread tools change the real target. Preview bytes and inspect readback/recovery status when applying a change.

> [!TIP]
> A bookmark remembers an address, not the lifetime of a process. Check the target again before treating yesterday's address as today's evidence.

## 4. Read ManualV4 results correctly

Choose a target and click **DLL 파일 선택** in **ManualV4** to open the native Windows picker. The panel passes the selected DLL’s original absolute path directly to the kernel; it does not upload the file bytes or copy the DLL into `assets`. The picker checks that the file exists and is 1 byte to 64 MiB. Process identity is checked again immediately before the kernel request. Select **매핑만 수행** to skip DllMain. In **ManualV4_Viewer**, choose the successful mapping and its matching PDB to inspect function addresses and parameters after validating the mapping base, process identity and PDB GUID/Age. Refreshing the page or job list does not submit another mapping request.

| Result | Interpretation |
|---|---|
| `state: mapped` with validated kernel success | Mapping completed according to the current request contract |
| Positive `failcode` | Exact failure branch in `manual_map_protocol.h` |
| `failmessage` | API/validation details, values and NTSTATUS observed at that branch |
| Missing / invalid response | Indeterminate result; diagnosis is `null`, without automatic retry |

The v3 packet is **2104 bytes**. `failcode` is at offset **1076**; `failmessage[1024]` is at **1080**. Input diagnostics are all zero; success returns code 0 and an empty message. Failures preserve the first code/message even if cleanup changes the final status. Message bytes are ASCII/ANSI, NUL terminated with a zero tail; overflow is marked `[truncated]`.

For **119**, inspect the section name/RVA, requested address/size/protection and `ZwProtectVirtualMemory` status. The pre-call fields also report:

- `pre_page`: the first region's state, type, protections and coverage of the rounded request.
- `pre_dynamic`: dynamic-code policy flags and decoded bits.
- `pre_protection`: protection level, type, audit and signer.

> [!IMPORTANT]
> The added policy/page queries are read-only and do not alter protection arguments or policies. `UNAVAILABLE` means the query could not establish a valid result. The first region does not necessarily describe the whole request, and these observations are not an atomic snapshot.

> [!WARNING]
> HTTP 200, job polling success or IOCTL transport success is not mapping success. Check the validated job state, NTSTATUS and diagnostics. `ACCESS_DENIED` identifies the returned status, not a proven internal policy cause. Failed API output fields may still contain their initialized values.

Full API/ABI details: [reference](../reference/API_ABI.md). Current Korean feature details: [panel guide](../../kernel_control_panel/README_ko.md).

## 5. Storage, symbols and limits

The packaged application stores assets, symbols, workspaces and dumps under `data/` beside the executable. `KERNEL_STUDIO_DATA_DIR` changes that root. Source execution keeps its source-mode locations; earlier data is not automatically copied into a new package.

PDB analysis uses `native/pdb_symbols.exe` and a Microsoft DIA x64 runtime. Build the helper with `native/build_pdb_symbols.cmd`; its default paths refer to VS 2022 Professional. Adjust the helper toolchain paths for another installation and set `KERNEL_STUDIO_DIA_DLL` for a different DIA runtime location. PDB GUID/Age must match the image.

Ordinary transfers have a 1MiB limit; driver reads are completed in pieces up to 4KiB. Large range dumps can reach 16GiB and stream to disk. Zero-filled dump gaps are recorded in the manifest and are not original bytes. Image dumps retain mapped RVA layout, not disk PE reconstruction. Cancellation waits for the current request; resume checks process identity and partial-file integrity within the same server session.

## 6. Test and troubleshoot

From the repository root, build the synthetic fixture; then run panel tests:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File samples/build_fixture.ps1
cd kernel_control_panel
python -m unittest discover -p 'test*.py' -v
node test_manual_v4_ui.js
python native/manual_map/run_selftest.py
```

Full discovery needs the fixture and DIA helper. The native harness uses the current mapper with mock DDIs and does not open a real driver or target. Seven optional loaded-driver read-only diagnostics are available via `test_driver_readonly.py`; `test_driver_all_ioctl.py` is an alias of that scope, not a complete live IOCTL suite. See [fixture instructions](../../samples/README.md) and [validation scope](../VALIDATION.md).

| Symptom | Check |
|---|---|
| Device connection fails | Loaded service, accepted signature, administrator access and `\\.\MyDriver` |
| Panel looks old | Running executable/source directory, `/api/build`, then browser refresh |
| Process missing | Increase discovery range or enter its PID |
| ManualV4 packet mismatch | Updated driver and panel, v3 / 2104-byte ABI |
| Mapping denied | NTSTATUS, failcode, failmessage and valid pre-call observations |
| `pre_*: UNAVAILABLE` | Query status, returned length and payload validation; do not assume zero policy |
| PDB unavailable | Helper, DIA runtime, matching GUID/Age and runtime path |

Use synthetic reproductions in public issues rather than private dumps or user DLL/PDB files. License information is in [LICENSE_STATUS.md](../../LICENSE_STATUS.md).
