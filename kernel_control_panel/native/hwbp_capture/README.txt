KernelStudioCapture x64 VEH capture helper, ABI 1

Transport and handler
- There is no pipe, network connection, target process handle, sender thread,
  event signaling, wait or dynamic allocation in the exception callback.
- StartCapture registers VEH in the target process. The panel loads/calls this
  DLL through existing kernel requests and reads its static ring through the
  existing kernel memory-read request.
- Exception callback captures the complete 1232-byte Windows x64 CONTEXT before
  changing Resume Flag / DR6, together with QPC, PID/TID, hit slots and address.
  CONTEXT validity remains governed by its ContextFlags. This is the fixed x64
  CONTEXT structure, not variable-size extended XSTATE beyond that structure.
- Only EXCEPTION_SINGLE_STEP with enabled DR7 slots, matching registered
  address/type/length and DR6 hit bits is resumed. TF, BS/BD/BT, disabled slots,
  mismatched or unowned slots and other exception codes pass unchanged.
- Execute breakpoints receive RF to pass the faulting instruction. Only handled
  DR6 B0..B3 are cleared. Data breakpoints resume after the faulting access.

Exports (existing remote call ABI DWORD WINAPI function(void*))
  GetCaptureAbiVersion(null) -> 1
  GetCaptureBuffer(uint64_t* output) -> Win32 error code; writes the ring pointer
  StartCapture(StartConfig*) -> Win32 error code; 0 success
  StopCapture(null) -> Win32 error code; pauses recording, retains owned resume
  ShutdownCapture(StartConfig* flags=1, owner_count=0) -> Win32 error code
  Never use a 32-bit return value as the ring pointer.

StartConfig is exactly 128 bytes, little endian, pack8:
  magic@0 uint64 ASCII KSCFG001
  abi_version@8 uint32=1, struct_size@12 uint32=128
  owner_count@16 uint32=0..4, flags@20 uint32=0 (start)
  reserved@24 uint64=0, Owner[4]@32
Owner is24bytes: addressuint64@0,typeuint32@8,sizeuint32@12,
  enableduint32@16=1,reserveduint32@20=0.
type DR7 RW: execute0/write1/readwrite3; reserved2 rejected.
size1/2/4/8; data addresses must align; execute size1.
Start with owner_count0 prepares VEH before the first hardware breakpoint.
Later Start calls publish immutable ownership additions before returning.
Historical ownership remains immutable until process termination (maximum1024
unique address/type/length keys). Previously owned exceptions can thus resume
safely across pause/configuration changes. This does not intercept a different
address/type/length. Current header owner array is informative; event validity
uses per-slot guards, not that mutable array.

Ring: 344320bytes = header256 + 256 slots1344bytes
Header offsets:
  magic uint64@0 ASCII KSHWBP01, abi uint32@8=1
  header_size uint32@12=256, slot_size uint32@16=1344
  capacity uint32@20=256, context_size uint32@24=1232
  state uint32@28 (0 unregistered,1capture,3guard/paused)
  pid uint32@32, qpc_frequency uint64@40
  next_ticket uint64@48, published_count uint64@56
  contention_dropped uint64@64, overwritten_records uint64@72
  handlers_inflight uint32@80, current_owner_count uint32@84
  current Owner[4]@96.
Slot offsets:
  guard_begin uint64@0, ticket uint64@8, qpc int64@16
  pid uint32@24, tid uint32@28, hit_mask uint32@32, execute_maskuint32@36
  exception_addressuint64@40, exception_codeuint32@48
  ContextFlagsuint32@52, context_sizeuint32@56
  raw CONTEXT[1232]@64, guard_enduint64@1296, writer_lockuint32@1304
  padding through1343.

Reader must copy slot body and then reread both guard words through the kernel.
Accept only matching nonzero even guards = 2*ticket in the copy and reread.
Only expose complete accepted entries; sort byticket and suppress duplicates.
A remote body read alone is insufficient: a writer may replace it concurrently.
Capacity256 is bounded history. Overwritten_records counts replaced historical
records (including already read records); it is NOT the exact number of unseen
lost events. Ticket gaps and contention_dropped show overload. No finite ring
can guarantee lossless delivery during an unbounded breakpoint burst.

Stop and lifetime safety
StopCapture changes to guard-only state3. It intentionally does not unregister
VEH while hardware breakpoints may remain. Before ShutdownCapture, the panel
must clear its breakpoints through kernel requests and verify they are cleared
in every applicable live thread. flags1 is that explicit confirmation. Failure
to clear/verify must retain VEH and its whitelist. Remove failure retains guard.
DLL is pinned with GetModuleHandleEx(PIN|FROM_ADDRESS) outside DllMain. It cannot
be unloaded until process termination, which prevents a dangling VEH callback
or invalid static ring during outstanding exceptions/control calls. Even after
unregister, static code/ring/history remain valid for an already dispatched VEH.
There is no unload API and no claim of debugger coexistence when an external
debugger owns exactly the same address/type/length previously registered here.

Build and verification
build.cmd requires installed VS2022 Professional MSVC x64. /W4 /WX /MT /O2.
python verify_native.py checks synthetic exception filtering, raw context
preservation, resume semantics, 8 producers x20000hits, guard consistency,
expected process termination for unrelated exceptions, and fixture commands.
Native synthetic checks do not replace real kernel-backed breakpoint tests.
HwbpFixture.exe has no VEH in normal operation and6workerthreads. stdout/ready
JSON give addresses and TIDs; stdin execute/write/readwrite/burst N triggers
all workers and returns updated JSON; status/noop returns JSON; exit is graceful.
The explicit --capture-unrelated-* verification modes load the helper only to
confirm unrelated exception propagation; normal fixture never loads the DLL.

Windows reference documentation:
https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler
https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
