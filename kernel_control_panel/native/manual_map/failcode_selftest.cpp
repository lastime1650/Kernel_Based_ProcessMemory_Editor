// Compiles the current MANUAL_KERNEL.hpp body against deterministic in-process DDI mocks.
// No device, mock_target process, remote thread, or DLL initialization is actually opened/executed.
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
#include <cstdarg>
#include <malloc.h>
#include "manual_map_protocol.h"

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define PASSIVE_LEVEL 0
#define KernelMode 0
#define UserMode 1
#define Executive 0
#define PAGE_SIZE 4096
#define MAXULONG 0xffffffffUL
#define MAXUSHORT 0xffff
#define POOL_FLAG_PAGED 1
#define OBJ_CASE_INSENSITIVE 0x40
#define OBJ_KERNEL_HANDLE 0x200
#define FILE_OPEN 1
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20
#define FILE_NON_DIRECTORY_FILE 0x40
#define FileStandardInformation 5
#define ThreadBasicInformation 0
#define MemoryBasicInformation 0
#define DPFLTR_IHVDRIVER_ID 0
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_TRACE_LEVEL 0
#define DbgPrintEx(...) ((void)0)

using HELPER_IMAGE_DOS_HEADER = IMAGE_DOS_HEADER;
using PHELPER_IMAGE_DOS_HEADER = IMAGE_DOS_HEADER*;
using HELPER_IMAGE_NT_HEADERS64 = IMAGE_NT_HEADERS64;
using PHELPER_IMAGE_NT_HEADERS64 = IMAGE_NT_HEADERS64*;
using HELPER_IMAGE_OPTIONAL_HEADER64 = IMAGE_OPTIONAL_HEADER64;
using HELPER_IMAGE_SECTION_HEADER = IMAGE_SECTION_HEADER;
using PHELPER_IMAGE_SECTION_HEADER = IMAGE_SECTION_HEADER*;
using HELPER_IMAGE_EXPORT_DIRECTORY = IMAGE_EXPORT_DIRECTORY;
#define HELPER_IMAGE_DOS_SIGNATURE IMAGE_DOS_SIGNATURE
#define HELPER_IMAGE_NT_SIGNATURE IMAGE_NT_SIGNATURE
#define HELPER_IMAGE_NT_OPTIONAL_HDR64_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define HELPER_IMAGE_NUMBEROF_DIRECTORY_ENTRIES IMAGE_NUMBEROF_DIRECTORY_ENTRIES

struct UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; };
struct PEB_LDR_DATA { LIST_ENTRY InMemoryOrderModuleList; };
using PPEB_LDR_DATA = PEB_LDR_DATA*;
struct PEB { PPEB_LDR_DATA Ldr; PVOID ApiSetMap; };
using PPEB = PEB*;
struct LDR_DATA_TABLE_ENTRY { LIST_ENTRY InMemoryOrderLinks; UNICODE_STRING BaseDllName; PVOID DllBase; };
struct TestProcess { PEB* peb = nullptr; };
struct TestThread { TestProcess* process; HANDLE id; };
using PEPROCESS = TestProcess*;
using PETHREAD = TestThread*;
struct CLIENT_ID { HANDLE UniqueProcess, UniqueThread; };
using PCLIENT_ID = CLIENT_ID*;
struct IO_STATUS_BLOCK { NTSTATUS Status; ULONG_PTR Information; };
struct FILE_STANDARD_INFORMATION { LARGE_INTEGER EndOfFile; };
struct OBJECT_ATTRIBUTES { ULONG Attributes = 0; };
using KIRQL = UCHAR;
using PROCESSINFOCLASS = int;
struct KAPC_STATE {};
struct THREAD_BASIC_INFORMATION { NTSTATUS ExitStatus; ULONG Padding; };
struct TestFile { PVOID FsContext2 = nullptr; };
struct TestStack { struct { struct { ULONG InputBufferLength, OutputBufferLength; } DeviceIoControl; } Parameters; TestFile* FileObject; };
struct TestIrp { struct { PVOID SystemBuffer; } AssociatedIrp; int RequestorMode; TestStack stack; };
using PIRP = TestIrp*;

static TestProcess mock_target, system_process, caller;
static TestThread thread{&mock_target, HANDLE(42)};
static PEPROCESS PsInitialSystemProcess = &system_process;
static PVOID MmHighestUserAddress = PVOID(0x7fffffffffffULL);
static PVOID process_type = PVOID(1), thread_type = PVOID(2);
static PVOID* PsProcessType = &process_type;
static PVOID* PsThreadType = &thread_type;
static std::vector<UCHAR> file_bytes;
static std::set<PVOID> allocations;
static std::set<ULONG> covered;
static std::string failure;
static ULONG pool_failure_tag = 0;
static KIRQL mock_irql = 0;
static bool wow64 = false, owner_mismatch = false, thread_mismatch = false;
static bool short_read = false, query_short = false, thread_no_handle = false;
static bool fail_cleanup = false;
static ULONG read_probes = 0, fail_read_probe_at = 0;
static NTSTATUS exit_status = 1, wait_status = STATUS_SUCCESS;
static ULONG attach_count = 0, allocation_attempts = 0, pool_live = 0;
static PVOID remote_image = nullptr;
static int checks = 0;
static char diagnostic[MKM_FAILMESSAGE_BYTES]{};
static void Require(bool value, const char* message);

// Read-only query fixtures are independent from the mapper's primary DDI status.
// They track protection transitions, so a snapshot after a denied call is detectably
// different from the required snapshot immediately before that call.
static NTSTATUS memory_query_status = STATUS_SUCCESS;
static NTSTATUS mitigation_query_status = STATUS_SUCCESS;
static NTSTATUS protection_query_status = STATUS_SUCCESS;
static bool memory_query_short = false, mitigation_query_short = false, protection_query_short = false;
static bool memory_query_invalid_extent = false;
static bool mitigation_query_wrong_selector = false;
static ULONG dynamic_code_flags = 0;
static UCHAR process_protection = 0;
static ULONG query_calls = 0, protect_calls = 0;
static std::vector<ULONG> image_page_protections;
static std::vector<std::string> ddi_events;
static std::vector<ULONG> queried_page_protections;

static NTSTATUS ZwQueryVirtualMemory(HANDLE, PVOID address, int, PVOID output, SIZE_T capacity, SIZE_T* returned) {
    ++query_calls; ddi_events.push_back("memory_query");
    if (!NT_SUCCESS(memory_query_status)) {
        std::memset(output, 0x5a, capacity); *returned = capacity;
        return memory_query_status;
    }
    MEMORY_BASIC_INFORMATION info{};
    const auto value = reinterpret_cast<ULONG_PTR>(address);
    const auto image = reinterpret_cast<ULONG_PTR>(remote_image);
    ULONG page = 0;
    if (value >= image && value - image < image_page_protections.size() * PAGE_SIZE) {
        page = ULONG((value - image) / PAGE_SIZE);
        ULONG start = page, end = page + 1;
        while (start && image_page_protections[start - 1] == image_page_protections[page]) --start;
        while (end < image_page_protections.size() && image_page_protections[end] == image_page_protections[page]) ++end;
        info.BaseAddress = PVOID(image + start * PAGE_SIZE);
        info.AllocationBase = remote_image;
        info.RegionSize = (end - start) * PAGE_SIZE;
        info.Protect = image_page_protections[page];
    } else {
        info.BaseAddress = address; info.AllocationBase = address;
        info.RegionSize = PAGE_SIZE; info.Protect = PAGE_READWRITE;
    }
    if (memory_query_invalid_extent) info.RegionSize = 0;
    info.AllocationProtect = PAGE_READWRITE; info.State = MEM_COMMIT; info.Type = MEM_PRIVATE;
    queried_page_protections.push_back(info.Protect);
    std::memcpy(output, &info, (std::min)(capacity, sizeof(info)));
    *returned = memory_query_short ? sizeof(info) - 1 : sizeof(info);
    return STATUS_SUCCESS;
}
static NTSTATUS ZwQueryInformationProcess(HANDLE, PROCESSINFOCLASS info_class, PVOID output, ULONG capacity, PULONG returned) {
    ++query_calls;
    if (info_class == 52) {
        ddi_events.push_back("mitigation_query");
        if (!NT_SUCCESS(mitigation_query_status)) {
            std::memset(output, 0x5a, capacity); *returned = capacity;
            return mitigation_query_status;
        }
        // PROCESS_MITIGATION_POLICY_INFORMATION: policy selector followed by the
        // queried flags union. The mapper initializes the selector before calling.
        Require(capacity >= 8, "dynamic-code query supplies complete policy selector and flags");
        Require(*static_cast<ULONG*>(output) == 2, "query selects ProcessDynamicCodePolicy");
        *reinterpret_cast<ULONG*>(static_cast<PUCHAR>(output) + sizeof(ULONG)) = dynamic_code_flags;
        if (mitigation_query_wrong_selector) *static_cast<ULONG*>(output) = 99;
        *returned = mitigation_query_short ? capacity - 1 : capacity;
        return STATUS_SUCCESS;
    }
    ddi_events.push_back("protection_query");
    if (info_class != 61) { *returned = 0; return STATUS_INVALID_INFO_CLASS; }
    if (!NT_SUCCESS(protection_query_status)) {
        std::memset(output, 0x5a, capacity); *returned = capacity;
        return protection_query_status;
    }
    std::memcpy(output, &process_protection, (std::min)(SIZE_T(capacity), sizeof(process_protection)));
    *returned = protection_query_short ? 0 : capacity;
    return STATUS_SUCCESS;
}

// User-mode substitute for the single ntstrsafe formatter used by the mapper.
// The production implementation is still compiled unchanged below.
static NTSTATUS RtlStringCbVPrintfA(PCHAR destination, SIZE_T bytes, PCSTR format, va_list arguments) {
    if (!destination || bytes == 0 || !format) return STATUS_INVALID_PARAMETER;
    const int result = _vsnprintf_s(destination, bytes, _TRUNCATE, format, arguments);
    return result < 0 ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

static NTSTATUS ApiStatus(const char* name) { return failure == name ? STATUS_ACCESS_DENIED : STATUS_SUCCESS; }
static PVOID PoolAlloc(SIZE_T size, ULONG tag) {
    if (pool_failure_tag == tag) return nullptr;
    auto p = std::calloc(1, size); if (p) ++pool_live; return p;
}
static void PoolFree(PVOID pointer, ULONG tag) { UNREFERENCED_PARAMETER(tag); if (pointer) { --pool_live; std::free(pointer); } }
#define ExAllocatePool2(flags, size, tag) PoolAlloc(size, tag)
#define ExFreePoolWithTag(pointer, tag) PoolFree(pointer, tag)
static void RtlInitUnicodeString(UNICODE_STRING* value, PCWSTR text) { value->Buffer = const_cast<PWSTR>(text); value->Length = USHORT(std::wcslen(text) * 2); value->MaximumLength = value->Length + 2; }
static void InitializeObjectAttributes(OBJECT_ATTRIBUTES* attributes, UNICODE_STRING*, ULONG flags, PVOID, PVOID) { attributes->Attributes = flags; }
static PVOID MmGetSystemRoutineAddress(UNICODE_STRING*) { return nullptr; }
static void ProbeForRead(PVOID pointer, SIZE_T, ULONG) { ++read_probes; if (!pointer || failure == "probe_read" || read_probes == fail_read_probe_at) RaiseException(static_cast<DWORD>(STATUS_ACCESS_VIOLATION), 0, 0, nullptr); }
static void ProbeForWrite(PVOID pointer, SIZE_T, ULONG) { if (!pointer || failure == "probe_write") RaiseException(static_cast<DWORD>(STATUS_ACCESS_VIOLATION), 0, 0, nullptr); }
static void KeStackAttachProcess(PEPROCESS, KAPC_STATE*) { ++attach_count; }
static void KeUnstackDetachProcess(KAPC_STATE*) { --attach_count; }
static PPEB PsGetProcessPeb(PEPROCESS process) { return process->peb; }
static KIRQL KeGetCurrentIrql() { return mock_irql; }
static bool IoIs32bitProcess(PIRP) { return wow64; }
static TestStack* IoGetCurrentIrpStackLocation(PIRP irp) { return &irp->stack; }
static PEPROCESS IoGetRequestorProcess(PIRP) { return owner_mismatch ? &mock_target : &caller; }
static PEPROCESS PsGetCurrentProcess() { return &caller; }
static PVOID PsGetProcessWow64Process(PEPROCESS) { return wow64 ? PVOID(1) : nullptr; }
static NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS* output) { *output = &mock_target; return ApiStatus("lookup"); }
static void ObDereferenceObject(PVOID) {}
static PEPROCESS PsGetThreadProcess(PETHREAD object) { return thread_mismatch ? &caller : object->process; }
static HANDLE PsGetThreadId(PETHREAD object) { return object->id; }
static NTSTATUS ZwCreateFile(PHANDLE handle, ULONG, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) { *handle = HANDLE(1); return ApiStatus("file_open"); }
static NTSTATUS ZwQueryInformationFile(HANDLE, IO_STATUS_BLOCK*, FILE_STANDARD_INFORMATION* info, ULONG, int) { info->EndOfFile.QuadPart = file_bytes.size(); return ApiStatus("file_query"); }
static NTSTATUS ZwReadFile(HANDLE, PVOID, PVOID, PVOID, IO_STATUS_BLOCK* info, PVOID data, ULONG size, LARGE_INTEGER*, PVOID) { std::memcpy(data, file_bytes.data(), size); info->Information = size - (short_read ? 1 : 0); return ApiStatus("file_read"); }
static NTSTATUS ZwClose(HANDLE) { return STATUS_SUCCESS; }
static NTSTATUS ZwAllocateVirtualMemory(HANDLE, PVOID* base, ULONG_PTR, SIZE_T* size, ULONG, ULONG) {
    ++allocation_attempts;
    if (failure == "remote_alloc" || (failure == "preferred_alloc" && allocation_attempts == 1)) return STATUS_NO_MEMORY;
    if (failure == "remote_range") { *base = PVOID(~ULONG_PTR(0)); return STATUS_SUCCESS; }
    if (*base == remote_image && remote_image) return STATUS_SUCCESS;
    if (failure == "stub_alloc" && *size == 39) return STATUS_NO_MEMORY;
    *base = _aligned_malloc(*size, PAGE_SIZE); if (*base) std::memset(*base, 0, *size);
    allocations.insert(*base); return *base ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}
static NTSTATUS ZwFreeVirtualMemory(HANDLE, PVOID* base, SIZE_T*, ULONG) {
    if (fail_cleanup) return STATUS_INVALID_PARAMETER;
    if (failure == "stub_free" && *base != remote_image) return STATUS_ACCESS_DENIED;
    if (allocations.erase(*base)) _aligned_free(*base); *base = nullptr; return STATUS_SUCCESS;
}
static NTSTATUS ZwProtectVirtualMemory(HANDLE, PVOID* base, SIZE_T* size, ULONG protection, PULONG old_protection) {
    ++protect_calls; ddi_events.push_back("protect");
    if (failure == "image_protect" && protection == PAGE_NOACCESS) return STATUS_ACCESS_DENIED;
    if (failure == "headers_protect" && protection == PAGE_READONLY) return STATUS_ACCESS_DENIED;
    if (failure == "section_protect" && *base == static_cast<PUCHAR>(remote_image) + PAGE_SIZE) {
        // Verify that diagnostics distinguish the input span from DDI in/out values.
        *size = PAGE_SIZE; *old_protection = PAGE_READWRITE; return STATUS_ACCESS_DENIED;
    }
    if (failure == "stub_protect" && *size == 39) return STATUS_ACCESS_DENIED;
    const auto value = reinterpret_cast<ULONG_PTR>(*base), image = reinterpret_cast<ULONG_PTR>(remote_image);
    if (value >= image && value - image < image_page_protections.size() * PAGE_SIZE) {
        const auto start = SIZE_T((value - image) / PAGE_SIZE);
        const auto end = (std::min)(image_page_protections.size(), SIZE_T((value - image + *size + PAGE_SIZE - 1) / PAGE_SIZE));
        *old_protection = image_page_protections[start];
        for (auto i = start; i < end; ++i) image_page_protections[i] = protection;
    }
    return STATUS_SUCCESS;
}
static NTSTATUS ObOpenObjectByPointer(PVOID object, ULONG, PVOID, ULONG access, PVOID, int, PHANDLE handle) {
    *handle = HANDLE(2);
    if (object == &mock_target) return ApiStatus("process_open");
    return ApiStatus(access == THREAD_SUSPEND_RESUME ? "resume_handle" : "query_handle");
}
static NTSTATUS ObReferenceObjectByHandle(HANDLE, ULONG, PVOID, int, PVOID* object, PVOID) { *object = &thread; return ApiStatus("thread_reference"); }
static NTSTATUS ZwResumeThread(HANDLE, PVOID) { return ApiStatus("resume"); }
static NTSTATUS KeWaitForSingleObject(PVOID, int, int, bool, LARGE_INTEGER*) { return wait_status; }
static NTSTATUS ZwQueryInformationThread(HANDLE, int, THREAD_BASIC_INFORMATION* output, ULONG size, PULONG returned) { output->ExitStatus = exit_status; *returned = query_short ? 0 : size; return ApiStatus("query_thread"); }
static NTSTATUS NTAPI MockCreateThread(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE handle, PCLIENT_ID cid) { *handle = thread_no_handle ? nullptr : HANDLE(3); cid->UniqueThread = thread.id; return ApiStatus("thread_create"); }
static NTSTATUS NTAPI MockFlush(HANDLE, PVOID base, SIZE_T) { return ApiStatus(base == remote_image ? "image_flush" : "stub_flush"); }
static NTSTATUS NTAPI MockAcquireExit(PEPROCESS) { return ApiStatus("exit_sync"); }
static VOID NTAPI MockReleaseExit(PEPROCESS) {}

// The runner adapts includes only; the entire current mapper implementation follows.
#include "manual_kernel_under_test.hpp"
using namespace helper::manual_map;

static void Require(bool value, const char* message) { ++checks; if (!value) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); } }
static void RequireDiagnostic(const char* message, bool success = false) {
    const auto terminator = static_cast<const char*>(std::memchr(message, '\0', MKM_FAILMESSAGE_BYTES));
    Require(terminator != nullptr, "bounded diagnostic NUL terminator");
    Require(success ? message[0] == '\0' : message[0] != '\0', success ? "success has no failure message" : "failure has a message");
    bool ascii = true, cleared_tail = true;
    for (auto cursor = message; cursor != terminator; ++cursor) {
        const unsigned char value = static_cast<unsigned char>(*cursor);
        ascii = ascii && ((value >= 32 && value < 127) || value == '\r' || value == '\n' || value == '\t');
    }
    for (auto cursor = terminator; cursor != message + MKM_FAILMESSAGE_BYTES; ++cursor) cleared_tail = cleared_tail && *cursor == '\0';
    Require(ascii, "diagnostic is printable ANSI ASCII");
    Require(cleared_tail, "diagnostic tail is fully initialized");
}
static void Expect(NTSTATUS status, const ULONG& code, MKM_FAIL_CODE expected, const char* message = diagnostic) {
    if (status == STATUS_SUCCESS || code != expected) std::fprintf(stderr, "status=%08lX failcode=%lu expected=%lu\n", static_cast<ULONG>(status), code, static_cast<ULONG>(expected));
    Require(status != STATUS_SUCCESS, "failure status"); Require(code == expected, "exact failcode"); covered.insert(code);
    RequireDiagnostic(message);
    const auto prefix = "failcode=" + std::to_string(expected) + ";";
    Require(std::strstr(message, prefix.c_str()) != nullptr, "message identifies exact failure location");
    std::memset(diagnostic, 0, sizeof(diagnostic));
}
static IMAGE_NT_HEADERS64* Nt() { return reinterpret_cast<IMAGE_NT_HEADERS64*>(file_bytes.data() + 128); }
static IMAGE_SECTION_HEADER* Sect() { return reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<PUCHAR>(&Nt()->OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER64)); }
static void FormatterTests() {
    struct GuardedMessage { char before[16]; char message[MKM_FAILMESSAGE_BYTES]; char after[16]; } guarded;
    std::memset(&guarded, 0x5a, sizeof(guarded));
    ULONG code = 0;
    const std::string long_detail(4096, 'A');
    const auto status = MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_PROTECT_SECTION, guarded.message, "%s", long_detail.c_str());
    Expect(status, code, MKM_FAIL_PROTECT_SECTION, guarded.message);
    Require(std::strlen(guarded.message) == MKM_FAILMESSAGE_BYTES - 1, "maximum diagnostic is bounded to 1023 bytes");
    Require(std::strstr(guarded.message, " [truncated]") != nullptr, "truncated diagnostic is explicitly marked");
    Require(std::strstr(guarded.message, "STATUS_ACCESS_DENIED") != nullptr && std::strstr(guarded.message, "C0000022") != nullptr, "symbolic and numeric NTSTATUS");
    Require(std::all_of(std::begin(guarded.before), std::end(guarded.before), [](char byte) { return byte == 0x5a; }) &&
        std::all_of(std::begin(guarded.after), std::end(guarded.after), [](char byte) { return byte == 0x5a; }), "formatter stays within message buffer");

    code = 0; std::memset(diagnostic, 0x5a, sizeof(diagnostic));
    MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN, diagnostic, "ZwCreateFile failed; path=fixture.dll; handle=%p", HANDLE(1));
    const std::string first_message(diagnostic);
    MkmFail(STATUS_INVALID_PARAMETER, &code, MKM_FAIL_MAP_REMOTE_CLEANUP, diagnostic, "ZwFreeVirtualMemory failed during cleanup");
    Require(code == MKM_FAIL_READ_FILE_OPEN && first_message == diagnostic, "secondary error preserves original code and complete message");
    Expect(STATUS_ACCESS_DENIED, code, MKM_FAIL_READ_FILE_OPEN);

    code = 0; MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN, diagnostic);
    Expect(STATUS_ACCESS_DENIED, code, MKM_FAIL_READ_FILE_OPEN);
    code = 0; MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN, diagnostic, "raw name bytes=%s", "name:\x80\xff\x01\t\r\n");
    Expect(STATUS_ACCESS_DENIED, code, MKM_FAIL_READ_FILE_OPEN);
    code = 0; MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN, diagnostic, "ZwCreateFile failed");
    MkmAppendImagePath(diagnostic, L"\\??\\C:\\테스트\\hello\".dll");
    Require(std::strstr(diagnostic, "\\uD14C\\uC2A4\\uD2B8") != nullptr &&
        std::strstr(diagnostic, "hello\\\".dll\"") != nullptr && std::strstr(diagnostic, "image_path=\"\\\\??\\\\C:") != nullptr,
        "Unicode UTF-16 path, backslashes and quotes are escaped into bounded ASCII");
    Expect(STATUS_ACCESS_DENIED, code, MKM_FAIL_READ_FILE_OPEN);
    WCHAR long_path[MKM_MAX_PATH]; std::fill(std::begin(long_path), std::end(long_path), WCHAR(0xac00));
    long_path[MKM_MAX_PATH - 1] = L'\0';
    code = 0; MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN, diagnostic, "ZwCreateFile failed");
    MkmAppendImagePath(diagnostic, long_path);
    Require(std::strstr(diagnostic, " [truncated]") != nullptr, "oversized escaped path has explicit truncation marker");
    Expect(STATUS_ACCESS_DENIED, code, MKM_FAIL_READ_FILE_OPEN);
    std::fill(std::begin(long_path), std::end(long_path), L'A');
    code = 0; MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN, diagnostic, "ZwCreateFile failed");
    MkmAppendImagePath(diagnostic, long_path);
    Require(std::strstr(diagnostic, " [truncated]") != nullptr, "path helper obeys 520-unit bound for missing terminator");
    Expect(STATUS_ACCESS_DENIED, code, MKM_FAIL_READ_FILE_OPEN);
    MkmAppendImagePath(diagnostic, L"\\??\\C:\\fixture.dll");
    RequireDiagnostic(diagnostic, true);
    code = 0; MkmFail(STATUS_ACCESS_DENIED, &code, MKM_FAIL_READ_FILE_OPEN);
    Require(code == MKM_FAIL_READ_FILE_OPEN, "optional diagnostic remains backward compatible for helper callers");
}
static void Reset(bool entry = false) {
    for (auto pointer : allocations) _aligned_free(pointer);
    allocations.clear(); Require(pool_live == 0 && attach_count == 0, "pool and attachment cleanup");
    failure.clear(); pool_failure_tag = allocation_attempts = 0; mock_irql = 0;
    memory_query_status = mitigation_query_status = protection_query_status = STATUS_SUCCESS;
    memory_query_short = mitigation_query_short = protection_query_short = memory_query_invalid_extent = mitigation_query_wrong_selector = false;
    dynamic_code_flags = 0; process_protection = 0; query_calls = protect_calls = 0;
    image_page_protections.assign(2, PAGE_READWRITE);
    ddi_events.clear(); queried_page_protections.clear();
    std::memset(diagnostic, 0, sizeof(diagnostic));
    wow64 = owner_mismatch = thread_mismatch = short_read = query_short = thread_no_handle = false;
    fail_cleanup = false; read_probes = fail_read_probe_at = 0;
    exit_status = 1; wait_status = STATUS_SUCCESS; mock_target.peb = nullptr;
    remote_image = _aligned_malloc(PAGE_SIZE * 2, PAGE_SIZE);
    Require(remote_image != nullptr, "page-aligned remote fixture allocation");
    std::memset(remote_image, 0, PAGE_SIZE * 2); allocations.insert(remote_image);
    file_bytes.assign(768, 0);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file_bytes.data()); dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 128;
    Nt()->Signature = IMAGE_NT_SIGNATURE;
    Nt()->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64; Nt()->FileHeader.NumberOfSections = 1;
    Nt()->FileHeader.Characteristics = IMAGE_FILE_DLL; Nt()->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    Nt()->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC; Nt()->OptionalHeader.SizeOfImage = PAGE_SIZE * 2;
    Nt()->OptionalHeader.SizeOfHeaders = 512; Nt()->OptionalHeader.SectionAlignment = PAGE_SIZE;
    Nt()->OptionalHeader.NumberOfRvaAndSizes = 16; Nt()->OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(remote_image);
    Nt()->OptionalHeader.AddressOfEntryPoint = entry ? PAGE_SIZE : 0;
    Sect()->VirtualAddress = PAGE_SIZE; Sect()->Misc.VirtualSize = Sect()->SizeOfRawData = 256;
    Sect()->PointerToRawData = 512; Sect()->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    std::memcpy(Sect()->Name, ".text", 5);
    g_MkmReady = true; g_MkmCreateThread = MockCreateThread; g_MkmFlushCache = MockFlush;
    g_MkmAcquireExit = MockAcquireExit; g_MkmReleaseExit = MockReleaseExit;
}
static NTSTATUS Parse(ULONG& code) { PHELPER_IMAGE_NT_HEADERS64 nth; PHELPER_IMAGE_SECTION_HEADER sections; USHORT count; return MkmParseHeaders(file_bytes.data(), ULONG(file_bytes.size()), &nth, &sections, &count, &code, diagnostic); }
static void RequirePreProtectOrder() {
    Require(ddi_events.size() == SIZE_T(protect_calls) * 4, "three read-only diagnostic queries accompany each protection call");
    for (SIZE_T i = 0; i < ddi_events.size(); i += 4) {
        Require(ddi_events[i] == "mitigation_query" && ddi_events[i + 1] == "protection_query" &&
            ddi_events[i + 2] == "memory_query" && ddi_events[i + 3] == "protect",
            "page snapshot is the last query immediately before the actual protection DDI");
    }
}
static MKM_PRE_PROTECT_SNAPSHOT Capture(SIZE_T bytes = 256, ULONG offset = PAGE_SIZE) {
    MKM_PRE_PROTECT_SNAPSHOT snapshot{};
    MkmCapturePreProtect(HANDLE(2), reinterpret_cast<ULONGLONG>(remote_image) + offset, bytes, &snapshot);
    return snapshot;
}
static void SnapshotText(const MKM_PRE_PROTECT_SNAPSHOT& snapshot) {
    std::memset(diagnostic, 0, sizeof(diagnostic));
    MkmAppendPreProtect(diagnostic, snapshot);
    RequireDiagnostic(diagnostic);
}
static void PreProtectTests() {
    Reset(); const auto initial_pages = image_page_protections;
    const auto snapshot = Capture();
    Require(query_calls == 3 && protect_calls == 0 && allocation_attempts == 0,
        "capture uses three read-only queries and performs no allocation or protection operation");
    Require(image_page_protections == initial_pages && std::all_of(static_cast<PUCHAR>(remote_image),
        static_cast<PUCHAR>(remote_image) + PAGE_SIZE * 2, [](UCHAR byte) { return byte == 0; }),
        "capture does not modify target bytes or their protection");
    Require(snapshot.PageStatus == STATUS_SUCCESS && snapshot.PageReturnLength == sizeof(MEMORY_BASIC_INFORMATION) &&
        snapshot.Page.State == MEM_COMMIT && snapshot.Page.Type == MEM_PRIVATE && snapshot.Page.Protect == PAGE_READWRITE &&
        snapshot.Page.AllocationProtect == PAGE_READWRITE && snapshot.Page.AllocationBase == remote_image &&
        snapshot.PageRangeValid && snapshot.FirstRegionCoversRequest,
        "capture retains complete queried allocation and page facts");
    SnapshotText(snapshot);
    Require(std::strstr(diagnostic, "State=MEM_COMMIT(0x1000)") && std::strstr(diagnostic, "Type=MEM_PRIVATE(0x20000)") &&
        std::strstr(diagnostic, "Protect=PAGE_READWRITE(0x4)") && std::strstr(diagnostic, "AllocationProtect=PAGE_READWRITE(0x4)") &&
        std::strstr(diagnostic, "first_region_only=1,covers_page_request=1"), "queried page facts and extent caveat are readable");
    Require(std::strstr(diagnostic, "pre_dynamic{q=0x00000000,bytes=8,Flags=0x0,ProhibitDynamicCode=0,AllowThreadOptOut=0,AllowRemoteDowngrade=0,AuditProhibitDynamicCode=0}") &&
        std::strstr(diagnostic, "pre_protection{q=0x00000000,bytes=1,Level=0x00,Type=None(0),Audit=0,Signer=None(0)}"),
        "successful zero policy and protection values are known disabled values rather than unavailable");
    struct PolicyCase { ULONG flags; const char* enabled; } policy_cases[] = {
        {1, "ProhibitDynamicCode=1,AllowThreadOptOut=0,AllowRemoteDowngrade=0,AuditProhibitDynamicCode=0"},
        {2, "ProhibitDynamicCode=0,AllowThreadOptOut=1,AllowRemoteDowngrade=0,AuditProhibitDynamicCode=0"},
        {4, "ProhibitDynamicCode=0,AllowThreadOptOut=0,AllowRemoteDowngrade=1,AuditProhibitDynamicCode=0"},
        {8, "ProhibitDynamicCode=0,AllowThreadOptOut=0,AllowRemoteDowngrade=0,AuditProhibitDynamicCode=1"},
        {15, "Flags=0xF,ProhibitDynamicCode=1,AllowThreadOptOut=1,AllowRemoteDowngrade=1,AuditProhibitDynamicCode=1"},
        {0x80000001, "Flags=0x80000001,ProhibitDynamicCode=1,AllowThreadOptOut=0,AllowRemoteDowngrade=0,AuditProhibitDynamicCode=0"},
    };
    for (const auto& item : policy_cases) {
        Reset(); dynamic_code_flags = item.flags; const auto value = Capture(); SnapshotText(value);
        Require(value.DynamicPolicyValid && value.DynamicFlags == item.flags && std::strstr(diagnostic, item.enabled),
            "dynamic policy keeps raw flags and independently decodes the four documented bits");
    }
    Reset(); process_protection = 0x39; SnapshotText(Capture());
    Require(std::strstr(diagnostic, "Level=0x39,Type=ProtectedLight/PPL(1),Audit=1,Signer=Antimalware(3)"),
        "protection query decodes PPL type signer and audit from actual raw byte");
    Reset(); process_protection = 0x12; SnapshotText(Capture());
    Require(std::strstr(diagnostic, "Level=0x12,Type=Protected(2),Audit=0,Signer=Authenticode(1)"),
        "protected-process type differs from PPL");
    Reset(); process_protection = 0xff; SnapshotText(Capture());
    Require(std::strstr(diagnostic, "Level=0xFF,Type=Unknown(7),Audit=1,Signer=Unknown(15)"),
        "unknown protection bit patterns retain raw numeric values");

    for (const auto status : {STATUS_ACCESS_DENIED, STATUS_INVALID_INFO_CLASS, STATUS_NOT_SUPPORTED}) {
        Reset(); memory_query_status = mitigation_query_status = protection_query_status = status;
        const auto unavailable = Capture(); SnapshotText(unavailable);
        Require(!unavailable.DynamicPolicyValid && !unavailable.PageRangeValid && unavailable.ProtectionLevel == 0,
            "failed queries never accept their nonzero garbage output buffers as actual values");
        Require(std::strstr(diagnostic, "pre_page{UNAVAILABLE") && std::strstr(diagnostic, "pre_dynamic{UNAVAILABLE") &&
            std::strstr(diagnostic, "pre_protection{UNAVAILABLE") && !std::strstr(diagnostic, "ProhibitDynamicCode=0") &&
            !std::strstr(diagnostic, "Type=None(0)") && !std::strstr(diagnostic, "5A5A"),
            "unsupported or denied queries produce unavailable facts instead of false disabled values");
        Require(std::strstr(diagnostic, MkmStatusName(status)), "unavailable snapshot reports exact independent query status");
        failure = "section_protect"; ULONGLONG base = 0, entry = 0; ULONG code = 0;
        std::memset(diagnostic, 0, sizeof(diagnostic)); ddi_events.clear(); query_calls = protect_calls = 0;
        const auto mapped = MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic);
        Require(mapped == STATUS_ACCESS_DENIED && code == MKM_FAIL_PROTECT_SECTION && !base && !entry,
            "failed diagnostic queries preserve protection error 119 and original ACCESS_DENIED");
        RequirePreProtectOrder();
        Expect(mapped, code, MKM_FAIL_PROTECT_SECTION);
    }
    Reset(); memory_query_short = mitigation_query_short = protection_query_short = true;
    const auto short_snapshot = Capture(); SnapshotText(short_snapshot);
    Require(std::strstr(diagnostic, "pre_page{UNAVAILABLE,q=STATUS_SUCCESS(0x00000000),bytes=47,required=48") &&
        std::strstr(diagnostic, "pre_dynamic{UNAVAILABLE,q=STATUS_SUCCESS(0x00000000),bytes=7,required=8") &&
        std::strstr(diagnostic, "pre_protection{UNAVAILABLE,q=STATUS_SUCCESS(0x00000000),bytes=0,required=1"),
        "short successful query results are unavailable with original status and actual returned lengths");
    Reset(); memory_query_invalid_extent = true; SnapshotText(Capture());
    Require(std::strstr(diagnostic, "pre_page{UNAVAILABLE") && std::strstr(diagnostic, "range_valid=0"),
        "zero-length MBI region is invalid rather than claimed as a real page observation");
    Reset(); mitigation_query_wrong_selector = true; dynamic_code_flags = 15; const auto wrong_policy = Capture(); SnapshotText(wrong_policy);
    Require(!wrong_policy.DynamicPolicyValid && wrong_policy.DynamicReturnLength == 8 &&
        std::strstr(diagnostic, "pre_dynamic{UNAVAILABLE,q=STATUS_SUCCESS(0x00000000),bytes=8,required=8,payload_valid=0}") &&
        !std::strstr(diagnostic, "ProhibitDynamicCode=1"),
        "wrong returned native policy selector is rejected without rewriting actual returned length");
    Reset(); image_page_protections[0] = PAGE_NOACCESS; image_page_protections[1] = PAGE_READONLY;
    const auto mixed = Capture(PAGE_SIZE * 2, 0); SnapshotText(mixed);
    Require(mixed.PageRangeValid && !mixed.FirstRegionCoversRequest && mixed.Page.RegionSize == PAGE_SIZE &&
        std::strstr(diagnostic, "first_region_only=1,covers_page_request=0") && std::strstr(diagnostic, "Protect=PAGE_NOACCESS(0x1)"),
        "mixed adjacent regions expose only the first observed region and explicitly deny full request coverage");
    Reset(); const auto overflow = Capture(~SIZE_T(0), 0); SnapshotText(overflow);
    Require(!overflow.FirstRegionCoversRequest && std::strstr(diagnostic, "covers_page_request=0"),
        "overflowing request extent cannot claim first-region coverage");
    Reset(); auto reserved = Capture(); reserved.Page.State = MEM_RESERVE; SnapshotText(reserved);
    Require(std::strstr(diagnostic, "Protect=UNDEFINED(MEM_RESERVE)") && !std::strstr(diagnostic, ",Protect=PAGE_READWRITE"),
        "reserved pages do not claim a defined current protection");
    auto free_region = reserved; free_region.Page.State = MEM_FREE; SnapshotText(free_region);
    Require(std::strstr(diagnostic, "Type/Protect/AllocationProtect/AllocationBase=UNDEFINED(MEM_FREE)"),
        "free pages do not expose undefined MBI members as real attributes");

    for (const char* action : {"image_protect", "headers_protect", "section_protect", "stub_protect"}) {
        Reset(true); failure = action; ULONGLONG base = 0, entry = 0; ULONG code = 0;
        const auto status = MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic);
        RequirePreProtectOrder();
        const bool initial = std::strcmp(action, "image_protect") == 0 || std::strcmp(action, "stub_protect") == 0;
        Require(std::strstr(diagnostic, initial ? "Protect=PAGE_READWRITE(0x4)" : "Protect=PAGE_NOACCESS(0x1)"),
            "each protection stage records its own actual preceding page protection");
        Require(std::strstr(diagnostic, "pre_page{") && std::strstr(diagnostic, "pre_dynamic{") && std::strstr(diagnostic, "pre_protection{") &&
            std::strstr(diagnostic, "output_old_protect=") && std::strstr(diagnostic, "untrusted_on_failure"),
            "bounded failure packet retains all three diagnostic categories and labels API output as untrusted");
        if (std::strcmp(action, "stub_protect") == 0)
            Require(std::strstr(diagnostic, "ZwProtectVirtualMemory(DllMain stub)") && std::strstr(diagnostic, "requested_size=39"),
                "stub diagnostic queries its own allocation instead of the image region");
        if (std::strcmp(action, "section_protect") == 0) {
            std::printf("PREPROTECT_DIAGNOSTIC_EXAMPLE: %s\n", diagnostic);
            Require(std::strlen(diagnostic) < MKM_FAILMESSAGE_BYTES && !std::strstr(diagnostic, "[truncated]"),
                "ordinary section diagnostic fits without truncating its page policy and output fields");
        }
        Expect(status, code, std::strcmp(action, "image_protect") == 0 ? MKM_FAIL_PROTECT_IMAGE :
            std::strcmp(action, "headers_protect") == 0 ? MKM_FAIL_PROTECT_HEADERS :
            std::strcmp(action, "section_protect") == 0 ? MKM_FAIL_PROTECT_SECTION : MKM_FAIL_DLL_MAIN_STUB_PROTECT);
    }
    Reset(true); memory_query_status = STATUS_ACCESS_DENIED; mitigation_query_status = STATUS_INVALID_INFO_CLASS;
    protection_query_status = STATUS_NOT_SUPPORTED; ULONGLONG base = 0, entry = 0; ULONG code = 99;
    Require(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic) == STATUS_SUCCESS && code == 0 && base && entry,
        "diagnostic query failures do not turn successful protection and DllMain mapping into a failure");
    RequirePreProtectOrder(); RequireDiagnostic(diagnostic, true);
    // Representative formatting fixture for the reported hello.dll failure.
    // These are explicit synthetic observation values; no target is opened.
    Reset(); dynamic_code_flags = 15; process_protection = 0x39; auto detailed_snapshot = Capture();
    detailed_snapshot.Page.BaseAddress = PVOID(0x180001000ULL);
    detailed_snapshot.Page.AllocationBase = PVOID(0x180000000ULL);
    detailed_snapshot.Page.RegionSize = 8192; detailed_snapshot.Page.Protect = PAGE_NOACCESS;
    auto detailed_section = *Sect(); detailed_section.Misc.VirtualSize = 0x1e30;
    detailed_section.SizeOfRawData = 0x2000; detailed_section.Characteristics = 0x60000020;
    code = 0;
    const auto detailed_status = MkmFailProtection(STATUS_ACCESS_DENIED, &code, MKM_FAIL_PROTECT_SECTION,
        diagnostic, "section", HANDLE(0xffffffff80007564ULL), 0x180001000ULL, 8192, PAGE_EXECUTE_READ,
        PVOID(0x180001000ULL), 8192, 0, detailed_snapshot, &detailed_section, 0);
    MkmAppendResult(diagnostic, detailed_status);
    MkmAppendImagePath(diagnostic, L"\\??\\C:\\TestData\\hello.dll");
    Require(std::strstr(diagnostic, "failcode=119") && std::strstr(diagnostic, "NTSTATUS=STATUS_ACCESS_DENIED(0xC0000022)") &&
        std::strstr(diagnostic, "requested_VA=0x180001000") && std::strstr(diagnostic, "requested_size=8192") &&
        std::strstr(diagnostic, "requested_protect=PAGE_EXECUTE_READ(0x20)") && std::strstr(diagnostic, "section_name=.text") &&
        std::strstr(diagnostic, "State=MEM_COMMIT") && std::strstr(diagnostic, "Type=MEM_PRIVATE") &&
        std::strstr(diagnostic, "Protect=PAGE_NOACCESS(0x1)") && std::strstr(diagnostic, "AllocationProtect=PAGE_READWRITE") &&
        std::strstr(diagnostic, "ProhibitDynamicCode=1") && std::strstr(diagnostic, "AllowThreadOptOut=1") &&
        std::strstr(diagnostic, "AllowRemoteDowngrade=1") && std::strstr(diagnostic, "AuditProhibitDynamicCode=1") &&
        std::strstr(diagnostic, "Type=ProtectedLight/PPL(1),Audit=1,Signer=Antimalware(3)") &&
        std::strstr(diagnostic, "output_old_protect=0x0(untrusted_on_failure)"),
        "1024-byte message preserves primary call facts all page/policy/protection categories and untrusted API outputs");
    std::printf("PREPROTECT_DIAGNOSTIC_EXAMPLE: %s\n", diagnostic);
    Expect(detailed_status, code, MKM_FAIL_PROTECT_SECTION);
    Reset(); ULONG first_code = 0; MkmFail(STATUS_ACCESS_DENIED, &first_code, MKM_FAIL_READ_FILE_OPEN, diagnostic, "first failure");
    const std::string first_message(diagnostic); const auto later_snapshot = Capture();
    MkmFailProtection(STATUS_INVALID_PARAMETER, &first_code, MKM_FAIL_PROTECT_SECTION, diagnostic, "section", HANDLE(2),
        reinterpret_cast<ULONGLONG>(remote_image), 256, PAGE_EXECUTE_READ, remote_image, 256, 0, later_snapshot);
    Require(first_code == MKM_FAIL_READ_FILE_OPEN && first_message == diagnostic,
        "protection-specific diagnostic keeps an earlier primary failure and message unchanged");
}
static void RequestTests() {
    Reset(); MANUAL_MAP_REQUEST packet{}; packet.Version = MKM_VERSION; packet.ProcessId = 123; wcscpy_s(packet.ImagePath, MKM_MAX_PATH, L"\\??\\C:\\fixture.dll");
    TestFile file; TestIrp irp{{&packet}, UserMode, {{{sizeof(packet), sizeof(packet)}}, &file}}; ULONG_PTR returned = 0;
    Require(Request(&irp, &returned) == STATUS_SUCCESS && packet.ResultStatus == STATUS_SUCCESS && packet.failcode == 0 && returned == sizeof(packet), "complete successful IOCTL");
    RequireDiagnostic(packet.failmessage, true);
    auto valid = packet; valid.MappedBase = valid.EntryPoint = 0;
    auto run = [&](MKM_FAIL_CODE expected) { returned = 0; Require(Request(&irp, &returned) == STATUS_SUCCESS && returned == sizeof(packet), "complete failure packet"); Expect(packet.ResultStatus, packet.failcode, expected, packet.failmessage); packet = valid; };
    packet = valid; g_MkmReady = false; run(MKM_FAIL_REQUEST_NOT_READY); g_MkmReady = true;
    mock_irql = 1; run(MKM_FAIL_REQUEST_IRQL); mock_irql = 0;
    irp.RequestorMode = KernelMode; run(MKM_FAIL_REQUEST_REQUESTOR_MODE); irp.RequestorMode = UserMode;
    wow64 = true; run(MKM_FAIL_REQUEST_WOW64); wow64 = false;
    file.FsContext2 = PVOID(1); run(MKM_FAIL_REQUEST_FILE_HANDLE); file.FsContext2 = nullptr;
    packet.Version = 1; run(MKM_FAIL_REQUEST_VERSION);
    packet.Version = 2; run(MKM_FAIL_REQUEST_VERSION);
    packet.Reserved = 1; run(MKM_FAIL_REQUEST_RESERVED);
    packet.ProcessId = 0; run(MKM_FAIL_REQUEST_PROCESS_ID);
    packet.failcode = 99; run(MKM_FAIL_REQUEST_OUTPUT_FIELDS);
    packet.failmessage[0] = 'x'; run(MKM_FAIL_REQUEST_OUTPUT_FIELDS);
    packet.failmessage[MKM_FAILMESSAGE_BYTES - 1] = 'x'; run(MKM_FAIL_REQUEST_OUTPUT_FIELDS);
    std::fill(std::begin(packet.ImagePath), std::end(packet.ImagePath), L'A'); run(MKM_FAIL_REQUEST_IMAGE_PATH);
    owner_mismatch = true; run(MKM_FAIL_REQUEST_OWNER); owner_mismatch = false;
    failure = "section_protect";
    Require(Request(&irp, &returned) == STATUS_SUCCESS && returned == sizeof(packet), "mapping API failure returns complete v3 packet");
    Require(packet.ResultStatus == STATUS_ACCESS_DENIED && packet.MappedBase == 0 && packet.EntryPoint == 0, "failed section protection status and cleanup addresses");
    Require(std::strstr(packet.failmessage, "ZwProtectVirtualMemory") && std::strstr(packet.failmessage, ".text"), "IOCTL transports detailed mapper diagnostic");
    RequirePreProtectOrder();
    Expect(packet.ResultStatus, packet.failcode, MKM_FAIL_PROTECT_SECTION, packet.failmessage);
    packet = valid; failure.clear();
    irp.stack.Parameters.DeviceIoControl.InputBufferLength = 1076;
    Require(Request(&irp, &returned) == STATUS_INVALID_PARAMETER && returned == 0, "old ABI rejected without writable response");
    irp.stack.Parameters.DeviceIoControl.InputBufferLength = 1080;
    Require(Request(&irp, &returned) == STATUS_INVALID_PARAMETER && returned == 0, "v2 ABI rejected without writable response");
    irp.stack.Parameters.DeviceIoControl.InputBufferLength = sizeof(packet);
    irp.stack.Parameters.DeviceIoControl.OutputBufferLength = 1080;
    Require(Request(&irp, &returned) == STATUS_INVALID_PARAMETER && returned == 0, "v3 request with v2 response capacity rejected");
}
static void HeaderTests() {
    struct Case { MKM_FAIL_CODE code; void (*mutate)(); } cases[] = {
        {MKM_FAIL_HEADERS_RAW_SIZE, [] { file_bytes.resize(1); }},
        {MKM_FAIL_HEADERS_DOS_SIGNATURE, [] { reinterpret_cast<IMAGE_DOS_HEADER*>(file_bytes.data())->e_magic = 0; }},
        {MKM_FAIL_HEADERS_NT_OFFSET, [] { reinterpret_cast<IMAGE_DOS_HEADER*>(file_bytes.data())->e_lfanew = -1; }},
        {MKM_FAIL_HEADERS_NT_RANGE, [] { reinterpret_cast<IMAGE_DOS_HEADER*>(file_bytes.data())->e_lfanew = 760; }},
        {MKM_FAIL_HEADERS_NT_SIGNATURE, [] { Nt()->Signature = 0; }},
        {MKM_FAIL_HEADERS_MACHINE, [] { Nt()->FileHeader.Machine = IMAGE_FILE_MACHINE_I386; }},
        {MKM_FAIL_HEADERS_OPTIONAL_MAGIC, [] { Nt()->OptionalHeader.Magic = 0; }},
        {MKM_FAIL_HEADERS_DLL_FLAG, [] { Nt()->FileHeader.Characteristics = 0; }},
        {MKM_FAIL_HEADERS_IMAGE_SIZE, [] { Nt()->OptionalHeader.SizeOfImage = 0; }},
        {MKM_FAIL_HEADERS_OPTIONAL_SIZE, [] { Nt()->FileHeader.SizeOfOptionalHeader = 1; }},
        {MKM_FAIL_HEADERS_SECTION_ALIGNMENT, [] { Nt()->OptionalHeader.SectionAlignment = 1; }},
        {MKM_FAIL_HEADERS_SECTION_COUNT, [] { Nt()->FileHeader.NumberOfSections = 0; }},
        {MKM_FAIL_HEADERS_SECTION_TABLE, [] { Nt()->FileHeader.NumberOfSections = 96; }},
        {MKM_FAIL_HEADERS_HEADER_EXTENT, [] { Nt()->OptionalHeader.SizeOfHeaders = 1; }},
        {MKM_FAIL_HEADERS_PREFERRED_RANGE, [] { Nt()->OptionalHeader.ImageBase = ~ULONGLONG(0); }},
        {MKM_FAIL_HEADERS_DIRECTORY_PAIR, [] { Nt()->OptionalHeader.DataDirectory[0].Size = 1; }},
        {MKM_FAIL_HEADERS_SECURITY_RANGE, [] { Nt()->OptionalHeader.DataDirectory[4] = {760, 32}; }},
        {MKM_FAIL_HEADERS_DIRECTORY_RANGE, [] { Nt()->OptionalHeader.DataDirectory[0] = {8190, 32}; }},
        {MKM_FAIL_HEADERS_TLS, [] { Nt()->OptionalHeader.DataDirectory[9] = {4096, 16}; }},
        {MKM_FAIL_HEADERS_DELAY_IMPORT, [] { Nt()->OptionalHeader.DataDirectory[13] = {4096, 16}; }},
        {MKM_FAIL_HEADERS_SECTION_EXTENT, [] { Sect()->VirtualAddress = 4097; }},
        {MKM_FAIL_HEADERS_ENTRY_POINT, [] { Nt()->OptionalHeader.AddressOfEntryPoint = 8000; }}
    };
    for (const auto& test : cases) { Reset(); test.mutate(); ULONG code = 0; Expect(Parse(code), code, test.code); }
    Reset(); auto original = *Sect(); Nt()->FileHeader.NumberOfSections = 2; Sect()[1] = original; ULONG code = 0; Expect(Parse(code), code, MKM_FAIL_HEADERS_SECTION_OVERLAP);
}
static void MappingTests() {
    struct Case { const char* action; MKM_FAIL_CODE code; bool entry; } cases[] = {
        {"file_open", MKM_FAIL_READ_FILE_OPEN, false}, {"file_query", MKM_FAIL_READ_FILE_QUERY, false},
        {"file_read", MKM_FAIL_READ_FILE_READ, false}, {"lookup", MKM_FAIL_MAP_PROCESS_LOOKUP, false},
        {"process_open", MKM_FAIL_MAP_PROCESS_OPEN, false}, {"exit_sync", MKM_FAIL_MAP_EXIT_SYNC, false},
        {"remote_alloc", MKM_FAIL_REMOTE_ALLOC_FALLBACK, false}, {"probe_write", MKM_FAIL_REMOTE_WRITE_EXCEPTION, false},
        {"image_protect", MKM_FAIL_PROTECT_IMAGE, false}, {"headers_protect", MKM_FAIL_PROTECT_HEADERS, false},
        {"section_protect", MKM_FAIL_PROTECT_SECTION, false}, {"image_flush", MKM_FAIL_MAP_IMAGE_FLUSH, false},
        {"stub_alloc", MKM_FAIL_DLL_MAIN_STUB_ALLOC, true}, {"stub_protect", MKM_FAIL_DLL_MAIN_STUB_PROTECT, true},
        {"stub_flush", MKM_FAIL_DLL_MAIN_STUB_FLUSH, true}, {"thread_create", MKM_FAIL_DLL_MAIN_THREAD_CREATE, true},
        {"thread_reference", MKM_FAIL_DLL_MAIN_THREAD_REFERENCE, true}, {"resume_handle", MKM_FAIL_DLL_MAIN_RESUME_HANDLE, true},
        {"resume", MKM_FAIL_DLL_MAIN_RESUME, true}, {"query_handle", MKM_FAIL_DLL_MAIN_QUERY_HANDLE, true},
        {"query_thread", MKM_FAIL_DLL_MAIN_QUERY, true}, {"stub_free", MKM_FAIL_DLL_MAIN_STUB_FREE, true}
    };
    for (const auto& test : cases) {
        Reset(test.entry); failure = test.action; ULONGLONG base = 0, entry = 0; ULONG code = 0;
        auto status = MkmMapDll(&caller, 123, L"\\??\\C:\\fixture.dll", &base, &entry, &code, diagnostic);
        if (test.code == MKM_FAIL_PROTECT_SECTION) {
            RequirePreProtectOrder();
            Require(queried_page_protections.size() == 3 && queried_page_protections[0] == PAGE_READWRITE &&
                queried_page_protections[1] == PAGE_NOACCESS && queried_page_protections[2] == PAGE_NOACCESS,
                "section snapshot reads actual PAGE_NOACCESS after earlier image and header operations");
            Require(std::strstr(diagnostic, "ZwProtectVirtualMemory") && std::strstr(diagnostic, ".text"), "section failure names API and actual section");
            Require(std::strstr(diagnostic, "STATUS_ACCESS_DENIED") && std::strstr(diagnostic, "C0000022"), "section failure preserves actual API status");
            Require(std::strstr(diagnostic, "section_index=0") && std::strstr(diagnostic, "RVA=0x1000"), "section failure contains actual index and RVA");
            Require(std::strstr(diagnostic, "requested_size=256") && std::strstr(diagnostic, "output_size=4096"), "section failure distinguishes requested size from adjusted output size");
            Require(std::strstr(diagnostic, "requested_protect=PAGE_EXECUTE_READ(0x20)") && std::strstr(diagnostic, "output_old_protect=0x4(untrusted_on_failure)"), "section failure includes requested protection meaning and explicitly untrusted API output");
            char expected_address[64]{};
            sprintf_s(expected_address, "requested_VA=0x%llX", reinterpret_cast<ULONGLONG>(remote_image) + PAGE_SIZE);
            Require(std::strstr(diagnostic, expected_address) && std::strstr(diagnostic, "proc_h=0000000000000002"), "section failure contains actual process handle and VA");
        }
        Expect(status, code, test.code); Require(pool_live == 0 && attach_count == 0, "failed map cleanup");
    }
    for (ULONG tag : {ULONG(MKM_TAG_RAW), ULONG(MKM_TAG_IMG), ULONG(MKM_TAG_META)}) {
        Reset(); pool_failure_tag = tag; ULONGLONG base, entry; ULONG code;
        auto status = MkmMapDll(&caller, 123, L"\\??\\C:\\fixture.dll", &base, &entry, &code, diagnostic);
        Expect(status, code, tag == MKM_TAG_RAW ? MKM_FAIL_READ_FILE_ALLOC : tag == MKM_TAG_IMG ? MKM_FAIL_LOCAL_IMAGE_ALLOC : MKM_FAIL_MAP_SECTION_METADATA_ALLOC);
    }
    Reset(); short_read = true; ULONGLONG base, entry; ULONG code; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_READ_FILE_SHORT_READ);
    Reset(true); wait_status = STATUS_TIMEOUT; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_WAIT); Require(base != 0, "timeout retains image");
    Reset(true); exit_status = 0; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_FALSE);
    Reset(true); exit_status = STATUS_ACCESS_VIOLATION; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_EXIT_STATUS);
    Reset(true); query_short = true; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_QUERY_SIZE);
    Reset(true); thread_mismatch = true; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_THREAD_IDENTITY);
    Reset(true); thread_no_handle = true; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_THREAD_CREATE);
    Reset(true); Require(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic) == STATUS_SUCCESS && code == 0 && base && entry, "successful DllMain map resets code");
    RequireDiagnostic(diagnostic, true);
    Reset(); g_MkmReady = false; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_MAP_NOT_READY);
    Reset(); wow64 = true; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_MAP_UNSUPPORTED_PROCESS);
    Reset(); failure = "remote_range"; Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_MAP_REMOTE_RANGE);
    Reset(); file_bytes.clear(); Expect(MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic), code, MKM_FAIL_READ_FILE_SIZE);
    Reset(); failure = "image_flush"; fail_cleanup = true;
    const auto cleanup_status = MkmMapDll(&caller, 123, L"x", &base, &entry, &code, diagnostic);
    Require(std::strstr(diagnostic, "Flush") && !std::strstr(diagnostic, "ZwFreeVirtualMemory"), "failed cleanup preserves original flush diagnostic");
    Require(cleanup_status == STATUS_INVALID_PARAMETER && std::strstr(diagnostic, "returned=STATUS_ACCESS_DENIED(0xC0000022)") &&
        std::strstr(diagnostic, "operation_status=STATUS_INVALID_PARAMETER(0xC000000D)"), "root API failure and final cleanup status remain distinguishable");
    Expect(cleanup_status, code, MKM_FAIL_MAP_IMAGE_FLUSH); Require(base != 0, "failed cleanup preserves original code and surviving base");
    Reset(true); g_MkmCreateThread = nullptr; bool retain; code = 0; Expect(MkmCallDllMain(&caller, &mock_target, HANDLE(2), reinterpret_cast<ULONGLONG>(remote_image), 4096, &retain, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_ROUTINE);
    Reset(true); failure = "probe_write"; code = 0; Expect(MkmCallDllMain(&caller, &mock_target, HANDLE(2), reinterpret_cast<ULONGLONG>(remote_image), 4096, &retain, &code, diagnostic), code, MKM_FAIL_DLL_MAIN_STUB_WRITE);
    Reset(); code = 0; failure = "preferred_alloc"; auto old_preferred = Nt()->OptionalHeader.ImageBase;
    PVOID image = nullptr; Require(MkmBuildLocalImage(file_bytes.data(), ULONG(file_bytes.size()), Nt(), Sect(), 1, reinterpret_cast<PUCHAR*>(&image), &code, diagnostic) == 0, "local image fixture");
    Require(MkmAllocRemote(HANDLE(2), 8192, old_preferred, &base, &code, diagnostic) == 0 && code == 0 && allocation_attempts == 2, "recoverable preferred allocation leaves zero"); MkmFree(image, MKM_TAG_IMG);
    RequireDiagnostic(diagnostic, true);
    code = 0; MkmSetFailcode(&code, MKM_FAIL_READ_FILE_OPEN); MkmSetFailcode(&code, MKM_FAIL_MAP_REMOTE_CLEANUP); Require(code == MKM_FAIL_READ_FILE_OPEN, "first error survives cleanup");
}
static void ApiSetTests() {
    Reset(); UCHAR bytes[256]{}; auto ns = reinterpret_cast<MKM_APISET_NS*>(bytes); *ns = {6, sizeof(bytes), 0, 1, 28, 0, 0};
    auto item = reinterpret_cast<MKM_APISET_ENTRY*>(bytes + 28); *item = {0, 76, 20, 20, 52, 1};
    auto value = reinterpret_cast<MKM_APISET_VALUE*>(bytes + 52); *value = {0, 0, 0, 100, 16};
    std::memcpy(bytes + 76, L"api-test-x", 20); std::memcpy(bytes + 100, L"host.dll", 16);
    char output[260]{}; ULONG code = 0;
    Require(MkmResolveApiSetNamespace(bytes, sizeof(bytes), "api-test-x.dll", output, sizeof(output), &code, diagnostic) && code == 0 && std::strcmp(output, "host.dll") == 0, "API-set success");
    RequireDiagnostic(diagnostic, true);
    code = 0; ns->Version = 5; Require(!MkmResolveApiSetNamespace(bytes, sizeof(bytes), "api-test-x", output, sizeof(output), &code, diagnostic), "API-set malformed"); Expect(STATUS_INVALID_IMAGE_FORMAT, code, MKM_FAIL_APISET_NAMESPACE_HEADER);
    ns->Version = 6; code = 0; Require(!MkmResolveApiSetNamespace(bytes, sizeof(bytes), "api-absent", output, sizeof(output), &code, diagnostic), "API-set missing contract"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_APISET_NAMESPACE_CONTRACT_NOT_FOUND);
    code = 0; Require(!MkmResolveApiSetAttached(&mock_target, "api-test-x", output, sizeof(output), &code, diagnostic), "API-set missing PEB"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_APISET_ATTACHED_PEB);
    code = 0; Require(!MkmFindModule(&mock_target, "host.dll", &code, diagnostic), "module missing PEB"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_MODULE_PEB);
    auto ns_test = [&](MKM_FAIL_CODE expected, PCSTR name = "api-test-x", bool null_data = false, ULONG capacity = 260) {
        code = 0; Require(!MkmResolveApiSetNamespace(null_data ? nullptr : bytes, sizeof(bytes), name, output, capacity, &code, diagnostic), "API-set terminal failure"); Expect(STATUS_DLL_NOT_FOUND, code, expected);
    };
    code = 0; Require(!MkmResolveApiSetNamespace(bytes, sizeof(bytes), "api-test-x", nullptr, sizeof(output), &code, diagnostic), "API-set output"); Expect(STATUS_INVALID_PARAMETER, code, MKM_FAIL_APISET_NAMESPACE_OUTPUT);
    ns_test(MKM_FAIL_APISET_NAMESPACE_INPUT, "api-test-x", true);
    ns_test(MKM_FAIL_APISET_NAMESPACE_QUERY_ASCII, "api-\x80");
    std::string long_name = "api-" + std::string(300, 'a'); ns_test(MKM_FAIL_APISET_NAMESPACE_QUERY_LENGTH, long_name.c_str());
    ns_test(MKM_FAIL_APISET_NAMESPACE_EMPTY_CONTRACT, "api-");
    item->ValueCount = 0; ns_test(MKM_FAIL_APISET_NAMESPACE_VALUE_TABLE); item->ValueCount = 1;
    value->ValueLength = 0; ns_test(MKM_FAIL_APISET_NAMESPACE_HOST_NOT_FOUND); value->ValueLength = 16;
    ns_test(MKM_FAIL_APISET_NAMESPACE_HOST_LENGTH, "api-test-x", false, 3);
    PEB peb{nullptr, bytes}; mock_target.peb = &peb;
    auto attached_test = [&](MKM_FAIL_CODE expected) { code = 0; Require(!MkmResolveApiSetAttached(&mock_target, "api-test-x", output, sizeof(output), &code, diagnostic), "attached API-set failure"); Expect(STATUS_DLL_NOT_FOUND, code, expected); };
    code = 0; Require(!MkmResolveApiSetAttached(&mock_target, "api-test-x", nullptr, 0, &code, diagnostic), "attached output"); Expect(STATUS_INVALID_PARAMETER, code, MKM_FAIL_APISET_ATTACHED_OUTPUT);
    code = 0; Require(!MkmResolveApiSetAttached(nullptr, "api-test-x", output, sizeof(output), &code, diagnostic), "attached input"); Expect(STATUS_INVALID_PARAMETER, code, MKM_FAIL_APISET_ATTACHED_INPUT);
    mock_target.peb = reinterpret_cast<PPEB>(~ULONG_PTR(0)); attached_test(MKM_FAIL_APISET_ATTACHED_PEB_RANGE); mock_target.peb = &peb;
    peb.ApiSetMap = PVOID(~ULONG_PTR(0)); attached_test(MKM_FAIL_APISET_ATTACHED_NAMESPACE_RANGE); peb.ApiSetMap = bytes;
    ns->Version = 5; attached_test(MKM_FAIL_APISET_ATTACHED_HEADER); ns->Version = 6;
    pool_failure_tag = MKM_TAG_APISET; attached_test(MKM_FAIL_APISET_ATTACHED_ALLOC); pool_failure_tag = 0;
    failure = "probe_read"; attached_test(MKM_FAIL_APISET_ATTACHED_EXCEPTION); failure.clear();
    code = 0; Require(!MkmFindModule(nullptr, "host.dll", &code, diagnostic), "module input"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_MODULE_INPUT);
    code = 0; Require(!MkmFindModule(&mock_target, "host.dll", &code, diagnostic), "module LDR"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_MODULE_LDR);
    failure = "probe_read"; code = 0; Require(!MkmFindModule(&mock_target, "host.dll", &code, diagnostic), "module read exception"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_MODULE_EXCEPTION); failure.clear();
    PEB_LDR_DATA ldr{}; ldr.InMemoryOrderModuleList.Flink = &ldr.InMemoryOrderModuleList; peb.Ldr = &ldr;
    code = 0; Require(!MkmFindModule(&mock_target, "host.dll", &code, diagnostic), "module not found"); Expect(STATUS_DLL_NOT_FOUND, code, MKM_FAIL_MODULE_NOT_FOUND);
}
static PUCHAR LocalImage() {
    PUCHAR image = nullptr; ULONG code = 0;
    Require(MkmBuildLocalImage(file_bytes.data(), ULONG(file_bytes.size()), Nt(), Sect(), 1, &image, &code, diagnostic) == 0 && code == 0, "local image setup");
    RequireDiagnostic(diagnostic, true);
    return image;
}
static void LocalAndRelocationTests() {
    for (MKM_FAIL_CODE expected : {MKM_FAIL_LOCAL_IMAGE_HEADER_EXTENT, MKM_FAIL_LOCAL_IMAGE_VIRTUAL_RANGE, MKM_FAIL_LOCAL_IMAGE_RAW_RANGE}) {
        Reset(); if (expected == MKM_FAIL_LOCAL_IMAGE_HEADER_EXTENT) Nt()->OptionalHeader.SizeOfHeaders = 9000;
        else if (expected == MKM_FAIL_LOCAL_IMAGE_VIRTUAL_RANGE) Sect()->Misc.VirtualSize = 9000;
        else Sect()->PointerToRawData = 9000;
        PUCHAR image; ULONG code = 0; Expect(MkmBuildLocalImage(file_bytes.data(), ULONG(file_bytes.size()), Nt(), Sect(), 1, &image, &code, diagnostic), code, expected);
    }
    for (MKM_FAIL_CODE expected : {MKM_FAIL_RELOCATE_DIRECTORY_MISSING, MKM_FAIL_RELOCATE_DIRECTORY_RANGE,
            MKM_FAIL_RELOCATE_BLOCK_HEADER, MKM_FAIL_RELOCATE_BLOCK_SIZE, MKM_FAIL_RELOCATE_TYPE,
            MKM_FAIL_RELOCATE_RVA_OVERFLOW, MKM_FAIL_RELOCATE_PATCH_RANGE, MKM_FAIL_SUCCESS}) {
        Reset(); Nt()->OptionalHeader.DataDirectory[5] = {4096, 12}; PUCHAR image = LocalImage();
        auto nth = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + 128);
        auto block = reinterpret_cast<MKM_BASE_RELOC*>(image + 4096); *block = {6000, 12};
        auto entries = reinterpret_cast<USHORT*>(image + 4104); entries[0] = (MKM_REL_DIR64 << 12) | 16;
        if (expected == MKM_FAIL_RELOCATE_DIRECTORY_MISSING) nth->OptionalHeader.NumberOfRvaAndSizes = 0;
        if (expected == MKM_FAIL_RELOCATE_DIRECTORY_RANGE) nth->OptionalHeader.DataDirectory[5].Size = 1;
        if (expected == MKM_FAIL_RELOCATE_BLOCK_HEADER) { block->SizeOfBlock = 10; entries[0] = 0; }
        if (expected == MKM_FAIL_RELOCATE_BLOCK_SIZE) block->SizeOfBlock = 13;
        if (expected == MKM_FAIL_RELOCATE_TYPE) entries[0] = 9 << 12;
        if (expected == MKM_FAIL_RELOCATE_RVA_OVERFLOW) block->VirtualAddress = MAXULONG;
        if (expected == MKM_FAIL_RELOCATE_PATCH_RANGE) block->VirtualAddress = 8192;
        auto patch = reinterpret_cast<ULONGLONG*>(image + 6016); *patch = 100;
        ULONG code = 0; auto status = MkmRelocate(image, 8192, 1, 2, &code, diagnostic);
        if (expected) Expect(status, code, expected); else { Require(status == 0 && code == 0 && *patch == 101, "relocation success"); RequireDiagnostic(diagnostic, true); }
        MkmFree(image, MKM_TAG_IMG);
    }
}
struct ExportFixture {
    std::vector<UCHAR> bytes;
    PEB_LDR_DATA ldr{}; PEB peb{}; LDR_DATA_TABLE_ENTRY module{};
    ExportFixture() : bytes(8192, 0) {
        std::memcpy(bytes.data(), file_bytes.data(), 512); nt()->OptionalHeader.DataDirectory[0] = {1024, 256};
        auto directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(bytes.data() + 1024);
        directory->NumberOfFunctions = directory->NumberOfNames = directory->Base = 1;
        directory->AddressOfFunctions = 1408; directory->AddressOfNames = 1416; directory->AddressOfNameOrdinals = 1424;
        *reinterpret_cast<ULONG*>(bytes.data() + 1408) = 2048; *reinterpret_cast<ULONG*>(bytes.data() + 1416) = 1432;
        std::memcpy(bytes.data() + 1432, "Func", 5);
        ldr.InMemoryOrderModuleList.Flink = &module.InMemoryOrderLinks;
        module.InMemoryOrderLinks.Flink = &ldr.InMemoryOrderModuleList;
        module.BaseDllName = {16, 18, const_cast<PWSTR>(L"host.dll")}; module.DllBase = bytes.data();
        peb.Ldr = &ldr; mock_target.peb = &peb;
    }
    IMAGE_NT_HEADERS64* nt() { return reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + 128); }
    IMAGE_EXPORT_DIRECTORY* directory() { return reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(bytes.data() + 1024); }
    void forward(const char* value) { *reinterpret_cast<ULONG*>(bytes.data() + 1408) = 1100; strcpy_s(reinterpret_cast<PCHAR>(bytes.data() + 1100), 180, value); }
};
static void ExportTests() {
    const MKM_FAIL_CODE cases[] = {MKM_FAIL_EXPORT_BASE, MKM_FAIL_EXPORT_DEPTH, MKM_FAIL_EXPORT_DOS_SIGNATURE,
        MKM_FAIL_EXPORT_NT_RANGE, MKM_FAIL_EXPORT_NT_SIGNATURE, MKM_FAIL_EXPORT_IMAGE_RANGE,
        MKM_FAIL_EXPORT_DIRECTORY_MISSING, MKM_FAIL_EXPORT_DIRECTORY_RANGE, MKM_FAIL_EXPORT_ARRAY_RANGE,
        MKM_FAIL_EXPORT_HEADER_EXCEPTION, MKM_FAIL_EXPORT_ARRAY_ALLOC, MKM_FAIL_EXPORT_ARRAY_EXCEPTION,
        MKM_FAIL_EXPORT_SYMBOL_NOT_FOUND, MKM_FAIL_EXPORT_FUNCTION_RANGE, MKM_FAIL_EXPORT_FORWARDER_SYNTAX,
        MKM_FAIL_EXPORT_FORWARDER_ORDINAL_EMPTY, MKM_FAIL_EXPORT_FORWARDER_ORDINAL_DIGIT, MKM_FAIL_EXPORT_FORWARDER_ORDINAL_RANGE};
    for (auto expected : cases) {
        Reset(); ExportFixture f; PVOID base = f.bytes.data(); ULONG depth = 0, code = 0; PCSTR name = "Func"; ULONGLONG address = 0;
        switch (expected) {
        case MKM_FAIL_EXPORT_BASE: base = nullptr; break;
        case MKM_FAIL_EXPORT_DEPTH: depth = 4; break;
        case MKM_FAIL_EXPORT_DOS_SIGNATURE: reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_magic = 0; break;
        case MKM_FAIL_EXPORT_NT_RANGE: reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew = -1; break;
        case MKM_FAIL_EXPORT_NT_SIGNATURE: f.nt()->Signature = 0; break;
        case MKM_FAIL_EXPORT_IMAGE_RANGE: f.nt()->OptionalHeader.SizeOfImage = 0; break;
        case MKM_FAIL_EXPORT_DIRECTORY_MISSING: f.nt()->OptionalHeader.DataDirectory[0] = {}; break;
        case MKM_FAIL_EXPORT_DIRECTORY_RANGE: f.nt()->OptionalHeader.DataDirectory[0].Size = 1; break;
        case MKM_FAIL_EXPORT_ARRAY_RANGE: f.directory()->NumberOfFunctions = 0; break;
        case MKM_FAIL_EXPORT_HEADER_EXCEPTION: failure = "probe_read"; break;
        case MKM_FAIL_EXPORT_ARRAY_ALLOC: pool_failure_tag = MKM_TAG_EXP; break;
        case MKM_FAIL_EXPORT_ARRAY_EXCEPTION: fail_read_probe_at = 4; break;
        case MKM_FAIL_EXPORT_SYMBOL_NOT_FOUND: name = "Missing"; break;
        case MKM_FAIL_EXPORT_FUNCTION_RANGE: *reinterpret_cast<ULONG*>(f.bytes.data() + 1408) = 8192; break;
        case MKM_FAIL_EXPORT_FORWARDER_SYNTAX: f.forward("invalid"); break;
        case MKM_FAIL_EXPORT_FORWARDER_ORDINAL_EMPTY: f.forward("host.#"); break;
        case MKM_FAIL_EXPORT_FORWARDER_ORDINAL_DIGIT: f.forward("host.#x"); break;
        case MKM_FAIL_EXPORT_FORWARDER_ORDINAL_RANGE: f.forward("host.#65536"); break;
        default: break;
        }
        Expect(MkmResolveExport(&mock_target, base, name, 0, &address, depth, &code, diagnostic), code, expected); Require(address == 0, "failed export clears VA");
    }
    Reset(); ExportFixture f; ULONG code = 0; ULONGLONG address;
    f.directory()->NumberOfNames = 2; auto names = reinterpret_cast<ULONG*>(f.bytes.data() + 1416); names[0] = 8192; names[1] = 1432;
    Require(MkmResolveExport(&mock_target, f.bytes.data(), "Func", 0, &address, 0, &code, diagnostic) == 0 && code == 0, "skipped malformed name does not poison successful export search");
    RequireDiagnostic(diagnostic, true);
    code = 0; Expect(MkmResolveExport(&mock_target, f.bytes.data(), "Missing", 0, &address, 0, &code, diagnostic), code, MKM_FAIL_EXPORT_STRING_RANGE);
    char out[3]; code = 0; Expect(MkmCopyExportString(f.bytes.data(), 1432, 8192, out, 3, &code, diagnostic), code, MKM_FAIL_EXPORT_STRING_UNTERMINATED);
    failure = "probe_read"; code = 0; Expect(MkmCopyExportString(f.bytes.data(), 1432, 8192, out, 3, &code, diagnostic), code, MKM_FAIL_EXPORT_STRING_EXCEPTION);
}
static void IatTests() {
    const MKM_FAIL_CODE cases[] = {MKM_FAIL_IAT_DIRECTORY_RANGE, MKM_FAIL_IAT_DESCRIPTOR_NAME,
        MKM_FAIL_IAT_DLL_NAME_EMPTY, MKM_FAIL_IAT_THUNK_RANGE, MKM_FAIL_IAT_ORDINAL_BITS,
        MKM_FAIL_IAT_NAME_RVA, MKM_FAIL_IAT_IMPORT_NAME, MKM_FAIL_IAT_SYMBOL_EMPTY,
        MKM_FAIL_IAT_THUNK_TERMINATOR, MKM_FAIL_IAT_DESCRIPTOR_TERMINATOR, MKM_FAIL_SUCCESS};
    for (auto expected : cases) {
        Reset(); Nt()->OptionalHeader.DataDirectory[1] = {4096, 40}; PUCHAR image = LocalImage(); ExportFixture f;
        auto nth = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + 128); auto desc = reinterpret_cast<MKM_IMPORT_DESC*>(image + 4096);
        desc->Name = 4300; desc->FirstThunk = 4500; desc->OriginalFirstThunk = 4400;
        std::memcpy(image + 4300, "host.dll", 9); *reinterpret_cast<ULONGLONG*>(image + 4400) = 4600;
        std::memcpy(image + 4602, "Func", 5);
        switch (expected) {
        case MKM_FAIL_IAT_DIRECTORY_RANGE: nth->OptionalHeader.DataDirectory[1].Size = 1; break;
        case MKM_FAIL_IAT_DESCRIPTOR_NAME: desc->Name = 0; break;
        case MKM_FAIL_IAT_DLL_NAME_EMPTY: image[4300] = 0; break;
        case MKM_FAIL_IAT_THUNK_RANGE: desc->FirstThunk = 100; break;
        case MKM_FAIL_IAT_ORDINAL_BITS: *reinterpret_cast<ULONGLONG*>(image + 4400) = MKM_ORDINAL_FLAG64 | 0x10000; break;
        case MKM_FAIL_IAT_NAME_RVA: *reinterpret_cast<ULONGLONG*>(image + 4400) = 0x100000000; break;
        case MKM_FAIL_IAT_IMPORT_NAME: *reinterpret_cast<ULONGLONG*>(image + 4400) = 8192; break;
        case MKM_FAIL_IAT_SYMBOL_EMPTY: image[4602] = 0; break;
        case MKM_FAIL_IAT_THUNK_TERMINATOR: desc->OriginalFirstThunk = 8184; desc->FirstThunk = 8176; *reinterpret_cast<ULONGLONG*>(image + 8184) = MKM_ORDINAL_FLAG64 | 1; break;
        case MKM_FAIL_IAT_DESCRIPTOR_TERMINATOR: nth->OptionalHeader.DataDirectory[1].Size = 20; break;
        default: break;
        }
        ULONG code = 0; auto status = MkmResolveIAT(&mock_target, image, 8192, &code, diagnostic);
        if (expected) Expect(status, code, expected); else { Require(status == 0 && code == 0 && *reinterpret_cast<ULONGLONG*>(image + 4500) == reinterpret_cast<ULONGLONG>(f.bytes.data()) + 2048, "successful IAT"); RequireDiagnostic(diagnostic, true); }
        Require(attach_count == 0, "IAT always detaches"); MkmFree(image, MKM_TAG_IMG);
    }
}
int main() {
    Require(sizeof(MANUAL_MAP_REQUEST) == MKM_REQUEST_BYTES && MKM_REQUEST_BYTES == 2104 && FIELD_OFFSET(MANUAL_MAP_REQUEST, failcode) == 1076 &&
        FIELD_OFFSET(MANUAL_MAP_REQUEST, failmessage) == 1080 && sizeof(MANUAL_MAP_REQUEST::failmessage) == MKM_FAILMESSAGE_BYTES && MKM_VERSION == 3, "shared Windows v3 ABI");
    FormatterTests(); PreProtectTests(); RequestTests(); HeaderTests(); MappingTests(); ApiSetTests(); LocalAndRelocationTests(); ExportTests(); IatTests(); Reset();
    for (auto pointer : allocations) _aligned_free(pointer);
    std::printf("PASS native manual-map: %d checks; %zu distinct failure locations exercised; current kernel source + mocked DDIs\n", checks, covered.size());
    return 0;
}
