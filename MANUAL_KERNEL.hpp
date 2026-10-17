#pragma once
//
// MANUAL_KERNEL.hpp
// ─────────────────────────────────────────────────────────────────────────
//  Kernel-mode manual PE64 DLL mapping  —  IOCTL_MANUAL_MAP (0x878)
//  x64 only  |  PASSIVE_LEVEL only  |  METHOD_BUFFERED
// ─────────────────────────────────────────────────────────────────────────
//
//  매핑 단계 (모두 커널 안에서 완결):
//   ①  ZwCreateFile / ZwReadFile → raw 파일 bytes를 paged pool에 로드
//   ②  PE64 헤더 검증 (MZ → PE\0\0 → x64 DLL)
//   ③  paged pool에 SizeOfImage 크기 "local image" 할당 (zero-init)
//   ④  섹션 복사: 파일 오프셋(raw) → 가상 주소 레이아웃
//   ⑤  IAT 해결 (Import Address Table)
//        ▸ 한 번의 KeStackAttachProcess로 전체 구간 처리
//        ▸ PEB_LDR_DATA → LDR_DATA_TABLE_ENTRY 리스트를 BaseDllName으로 순회
//        ▸ 대상 프로세스 VA에서 각 의존 모듈의 export table 직접 읽기
//        ▸ 이름/서수 해결, 포워딩 익스포트 재귀 처리 (최대 3단계)
//        ▸ 해결된 절대 VA를 local image의 IAT 슬롯에 기록
//   ⑥  베이스 재배치 (IMAGE_REL_BASED_DIR64 in-place 적용)
//   ⑦  ZwAllocateVirtualMemory: 대상 프로세스에 원격 메모리 확보
//        (선호 베이스 우선 시도, 실패 시 ASLR 임의 주소)
//   ⑧  local image → 원격 VA 복사 (attach + ProbeForWrite + RtlCopyMemory)
//   ⑨  ZwProtectVirtualMemory: 섹션 Characteristics → 페이지 보호 속성
//   ⑩  ZwFlushInstructionCache
//   ⑪  OnlyMapping=FALSE이면 39-byte x64 DllMain stub → 원격 스레드 →
//       최대 5초 완료 대기; TRUE이면 진입점 호출을 생략하고 매핑 성공 반환
//  지원 범위: 이미 로드된 의존 DLL만 해결. TLS/delay import는 거부하며,
//  API-set v6 계약은 대상 PEB.ApiSetMap으로 해석. LDR 등록 및
//  x64 unwind function-table 등록은 수행하지 않음.
//
//  통합:
//   • ioctl_helper.hpp DeviceControlRoutineImpl 상단 (기존 rundown 보호 안):
//       if (ioctl_code == IOCTL_MANUAL_MAP) {
//           status = helper::manual_map::Request(irp, &information);
//           irp->IoStatus.Status      = status;
//           irp->IoStatus.Information = information;
//           IoCompleteRequest(irp, IO_NO_INCREMENT);
//           return status;
//       }
//   • main.cpp DriverEntry:
//       helper::manual_map::Initialize();
// ─────────────────────────────────────────────────────────────────────────

#include "helper.hpp"
#include "manual_map_protocol.h"
#include <ntstrsafe.h>

namespace helper { namespace manual_map {

// Preserve existing qualified kernel type names while sharing the wire ABI with clients.
using ::MANUAL_MAP_REQUEST;
using ::PMANUAL_MAP_REQUEST;

// ═══════════════════════════════════════════════════════════════════════
//  IOCTL 코드 (0x878)
// ═══════════════════════════════════════════════════════════════════════

#define MKM_MAX_SIZE     (64ULL << 20)   // 64 MB 상한
#define MKM_MAX_EXPORTS  65536u
#define MKM_MAX_SECTIONS    96u
#define MKM_FWD_DEPTH        3u          // forwarded export 재귀 깊이 한도

// ═══════════════════════════════════════════════════════════════════════
//  utils.hpp에 없는 PE 보조 타입
// ═══════════════════════════════════════════════════════════════════════

#pragma pack(push, 1)

// IMAGE_IMPORT_DESCRIPTOR
struct MKM_IMPORT_DESC
{
    union { ULONG Characteristics; ULONG OriginalFirstThunk; };
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;          // RVA → ANSI DLL 이름
    ULONG FirstThunk;    // RVA → IAT 슬롯 배열
};

// IMAGE_IMPORT_BY_NAME
struct MKM_IMPORT_BY_NAME { USHORT Hint; CHAR Name[1]; };

// IMAGE_BASE_RELOCATION 블록 헤더
struct MKM_BASE_RELOC { ULONG VirtualAddress; ULONG SizeOfBlock; };

// PEB.ApiSetMap namespace layout, version 6 (Windows 10+).
struct MKM_APISET_NS
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
};
struct MKM_APISET_ENTRY
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;       // UTF-16 bytes, excluding any terminator
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
};
struct MKM_APISET_VALUE
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;       // zero denotes the default host
    ULONG ValueOffset;
    ULONG ValueLength;      // UTF-16 bytes
};

#pragma pack(pop)

static_assert(sizeof(MKM_APISET_NS) == 28, "API-set namespace layout mismatch");
static_assert(sizeof(MKM_APISET_ENTRY) == 24, "API-set entry layout mismatch");
static_assert(sizeof(MKM_APISET_VALUE) == 20, "API-set value layout mismatch");

// PE 상수
#define MKM_ORDINAL_FLAG64              0x8000000000000000ULL
#define MKM_REL_DIR64                   10u
#define MKM_REL_ABSOLUTE                0u
#define MKM_FILE_MACHINE_AMD64          0x8664u
#define MKM_DLLCHAR_DYNAMIC_BASE        0x0040u

// 섹션 Characteristics 비트
#define MKM_SCN_MEM_EXECUTE             0x20000000UL
#define MKM_SCN_MEM_READ                0x40000000UL
#define MKM_SCN_MEM_WRITE               0x80000000UL

// 풀 태그
#define MKM_TAG_RAW     'wRkM'   // 파일 raw 버퍼
#define MKM_TAG_IMG     'mIkM'   // local 매핑 이미지
#define MKM_TAG_EXP     'pEkM'   // export 테이블 배열
#define MKM_TAG_META    'tMkM'   // immutable section metadata
#define MKM_TAG_APISET  'sAkM'   // target API-set namespace snapshot
#define MKM_MAX_APISET_SIZE (16UL << 20)

// ═══════════════════════════════════════════════════════════════════════
//  동적 함수 포인터  (Initialize()에서 MmGetSystemRoutineAddress로 해결)
// ═══════════════════════════════════════════════════════════════════════

using FnCreateThread = NTSTATUS (NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN,
                                         ULONG, SIZE_T, SIZE_T, PVOID, PVOID,
                                         PHANDLE, PCLIENT_ID);
using FnFlushCache   = NTSTATUS (NTAPI*)(HANDLE, PVOID, SIZE_T);
using FnAcquireExit  = NTSTATUS (NTAPI*)(PEPROCESS);
using FnReleaseExit  = VOID     (NTAPI*)(PEPROCESS);

static FnCreateThread  g_MkmCreateThread = nullptr;
static FnFlushCache    g_MkmFlushCache   = nullptr;
static FnAcquireExit   g_MkmAcquireExit  = nullptr;
static FnReleaseExit   g_MkmReleaseExit  = nullptr;
static bool            g_MkmReady        = false;

inline PVOID MkmResolve(PCWSTR name)
{
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, name);
    return MmGetSystemRoutineAddress(&n);
}

//
// main.cpp DriverEntry 에서 반드시 호출.
//
inline void Initialize()
{
#if defined(_M_AMD64)
    g_MkmCreateThread = reinterpret_cast<FnCreateThread>(MkmResolve(L"RtlCreateUserThread"));
    g_MkmFlushCache   = reinterpret_cast<FnFlushCache>  (MkmResolve(L"ZwFlushInstructionCache"));
    g_MkmAcquireExit  = reinterpret_cast<FnAcquireExit> (MkmResolve(L"PsAcquireProcessExitSynchronization"));
    g_MkmReleaseExit  = reinterpret_cast<FnReleaseExit> (MkmResolve(L"PsReleaseProcessExitSynchronization"));
    g_MkmReady = g_MkmCreateThread && g_MkmFlushCache &&
                 g_MkmAcquireExit  && g_MkmReleaseExit;
#endif
}

// ═══════════════════════════════════════════════════════════════════════
//  인라인 유틸리티
// ═══════════════════════════════════════════════════════════════════════

// Per-request diagnostics. First terminal failure owns both fields, including cleanup.
// ASCII makes the wire message independent of the client/system ANSI code page.
inline PCSTR MkmStatusName(NTSTATUS status)
{
    switch (static_cast<ULONG>(status)) {
    case 0x00000000UL: return "STATUS_SUCCESS";
    case 0x00000102UL: return "STATUS_TIMEOUT";
    case 0x80000005UL: return "STATUS_BUFFER_OVERFLOW";
    case 0x8000000DUL: return "STATUS_PARTIAL_COPY";
    case 0xC0000001UL: return "STATUS_UNSUCCESSFUL";
    case 0xC0000003UL: return "STATUS_INVALID_INFO_CLASS";
    case 0xC0000004UL: return "STATUS_INFO_LENGTH_MISMATCH";
    case 0xC0000005UL: return "STATUS_ACCESS_VIOLATION";
    case 0xC0000008UL: return "STATUS_INVALID_HANDLE";
    case 0xC000000BUL: return "STATUS_INVALID_CID";
    case 0xC000000DUL: return "STATUS_INVALID_PARAMETER";
    case 0xC0000017UL: return "STATUS_NO_MEMORY";
    case 0xC0000018UL: return "STATUS_CONFLICTING_ADDRESSES";
    case 0xC000001EUL: return "STATUS_INVALID_LOCK_SEQUENCE";
    case 0xC000001FUL: return "STATUS_INVALID_VIEW_SIZE";
    case 0xC0000022UL: return "STATUS_ACCESS_DENIED";
    case 0xC0000023UL: return "STATUS_BUFFER_TOO_SMALL";
    case 0xC0000034UL: return "STATUS_OBJECT_NAME_NOT_FOUND";
    case 0xC0000035UL: return "STATUS_OBJECT_NAME_COLLISION";
    case 0xC000003AUL: return "STATUS_OBJECT_PATH_NOT_FOUND";
    case 0xC0000043UL: return "STATUS_SHARING_VIOLATION";
    case 0xC0000054UL: return "STATUS_FILE_LOCK_CONFLICT";
    case 0xC0000055UL: return "STATUS_LOCK_NOT_GRANTED";
    case 0xC000007BUL: return "STATUS_INVALID_IMAGE_FORMAT";
    case 0xC000009AUL: return "STATUS_INSUFFICIENT_RESOURCES";
    case 0xC00000A1UL: return "STATUS_WORKING_SET_QUOTA";
    case 0xC00000BBUL: return "STATUS_NOT_SUPPORTED";
    case 0xC00000B5UL: return "STATUS_IO_TIMEOUT";
    case 0xC000010AUL: return "STATUS_PROCESS_IS_TERMINATING";
    case 0xC000012FUL: return "STATUS_INVALID_IMAGE_NOT_MZ";
    case 0xC0000135UL: return "STATUS_DLL_NOT_FOUND";
    case 0xC0000139UL: return "STATUS_ENTRYPOINT_NOT_FOUND";
    case 0xC0000142UL: return "STATUS_DLL_INIT_FAILED";
    case 0xC0000206UL: return "STATUS_INVALID_BUFFER_SIZE";
    case 0xC0000141UL: return "STATUS_INVALID_ADDRESS";
    case 0xC0000904UL: return "STATUS_FILE_TOO_LARGE";
    case 0xC0000604UL: return "STATUS_DYNAMIC_CODE_BLOCKED";
    default: return "NTSTATUS_UNRECOGNIZED"; // The numeric value remains exact.
    }
}

inline NTSTATUS MkmPrint(PCHAR output, SIZE_T bytes, PCSTR format, ...)
{
    va_list args;
    va_start(args, format);
    const NTSTATUS status = RtlStringCbVPrintfA(output, bytes, format, args);
    va_end(args);
    return status;
}

inline ULONG MkmMessageLength(PCSTR message)
{
    ULONG n = 0;
    while (n + 1 < MKM_FAILMESSAGE_BYTES && message[n]) ++n;
    return n;
}

inline void MkmFinishMessage(PCHAR message, bool truncated)
{
    if (!message) return;
    message[MKM_FAILMESSAGE_BYTES - 1] = '\0';
    if (truncated) {
        static const CHAR marker[] = " [truncated]";
        const ULONG length = MkmMessageLength(message);
        const ULONG maximum_start = MKM_FAILMESSAGE_BYTES - sizeof(marker);
        const ULONG start = length < maximum_start ? length : maximum_start;
        RtlCopyMemory(message + start, marker, sizeof(marker));
    }
    const ULONG length = MkmMessageLength(message);
    for (ULONG i = 0; i < length; ++i) {
        const UCHAR c = static_cast<UCHAR>(message[i]);
        if (c > 0x7e || (c < 0x20 && c != '\t' && c != '\r' && c != '\n'))
            message[i] = '?';
    }
    RtlZeroMemory(message + length, MKM_FAILMESSAGE_BYTES - length);
}

inline bool MkmClaimFailure(ULONG* failcode, MKM_FAIL_CODE code, PCHAR failmessage)
{
    if (code == MKM_FAIL_SUCCESS || (failcode && *failcode) ||
        (!failcode && failmessage && failmessage[0])) return false;
    if (failcode) *failcode = static_cast<ULONG>(code);
    if (failmessage) RtlZeroMemory(failmessage, MKM_FAILMESSAGE_BYTES);
    return true;
}

inline void MkmFormatFailureV(PCHAR message, MKM_FAIL_CODE code,
    bool has_status, NTSTATUS status, PCSTR format, va_list args)
{
    if (!message) return;
    NTSTATUS formatted = has_status
        ? MkmPrint(message, MKM_FAILMESSAGE_BYTES,
            "failcode=%lu; NTSTATUS=%s(0x%08lX); ", static_cast<ULONG>(code),
            MkmStatusName(status), static_cast<ULONG>(status))
        : MkmPrint(message, MKM_FAILMESSAGE_BYTES, "failcode=%lu; ", static_cast<ULONG>(code));
    const ULONG used = MkmMessageLength(message);
    if (format && NT_SUCCESS(formatted))
        formatted = RtlStringCbVPrintfA(message + used, MKM_FAILMESSAGE_BYTES - used, format, args);
    else if (!format && NT_SUCCESS(formatted))
        formatted = MkmPrint(message + used, MKM_FAILMESSAGE_BYTES - used, "Failure at mapper validation/operation.");
    MkmFinishMessage(message, !NT_SUCCESS(formatted));
}

inline void MkmSetFailcode(ULONG* failcode, MKM_FAIL_CODE code,
    PCHAR failmessage = nullptr, PCSTR format = nullptr, ...)
{
    if (!MkmClaimFailure(failcode, code, failmessage)) return;
    va_list args;
    va_start(args, format);
    MkmFormatFailureV(failmessage, code, false, STATUS_SUCCESS, format, args);
    va_end(args);
}
inline NTSTATUS MkmFail(NTSTATUS status, ULONG* failcode, MKM_FAIL_CODE code,
    PCHAR failmessage = nullptr, PCSTR format = nullptr, ...)
{
    if (MkmClaimFailure(failcode, code, failmessage)) {
        va_list args;
        va_start(args, format);
        MkmFormatFailureV(failmessage, code, true, status, format, args);
        va_end(args);
    }
    return status;
}
inline bool MkmReject(ULONG* failcode, MKM_FAIL_CODE code,
    PCHAR failmessage = nullptr, PCSTR format = nullptr, ...)
{
    if (MkmClaimFailure(failcode, code, failmessage)) {
        va_list args;
        va_start(args, format);
        MkmFormatFailureV(failmessage, code, false, STATUS_SUCCESS, format, args);
        va_end(args);
    }
    return false;
}

// Append only independently known final response facts; do not replace the root failure.
inline void MkmAppendResult(PCHAR message, NTSTATUS result)
{
    if (!message || !message[0]) return;
    const ULONG used = MkmMessageLength(message);
    const NTSTATUS formatted = MkmPrint(message + used, MKM_FAILMESSAGE_BYTES - used,
        "; operation_status=%s(0x%08lX)", MkmStatusName(result), static_cast<ULONG>(result));
    MkmFinishMessage(message, !NT_SUCCESS(formatted));
}

// Only called with the mapper's immutable, request-validated bounded ImagePath.
// Render every UTF-16 unit as printable ASCII or a reversible \uXXXX escape.
inline void MkmAppendImagePath(PCHAR message, PCWSTR path)
{
    if (!message || !message[0] || !path) return;
    ULONG used = MkmMessageLength(message);
    const NTSTATUS formatted = MkmPrint(message + used, MKM_FAILMESSAGE_BYTES - used, "; image_path=\"");
    if (!NT_SUCCESS(formatted)) { MkmFinishMessage(message, true); return; }
    used = MkmMessageLength(message);
    bool terminated = false, truncated = false;
    static const CHAR hex[] = "0123456789ABCDEF";
    for (ULONG i = 0; i < MKM_MAX_PATH; ++i) {
        const USHORT c = static_cast<USHORT>(path[i]);
        if (!c) { terminated = true; break; }
        const ULONG needed = (c < 0x20 || c > 0x7e) ? 6u :
            ((c == '\\' || c == '"') ? 2u : 1u);
        if (needed >= MKM_FAILMESSAGE_BYTES - used) { truncated = true; break; }
        if (needed == 6) {
            message[used++] = '\\'; message[used++] = 'u';
            message[used++] = hex[(c >> 12) & 15]; message[used++] = hex[(c >> 8) & 15];
            message[used++] = hex[(c >> 4) & 15]; message[used++] = hex[c & 15];
        } else {
            if (needed == 2) message[used++] = '\\';
            message[used++] = static_cast<CHAR>(c);
        }
        message[used] = '\0';
    }
    if (terminated && used + 1 < MKM_FAILMESSAGE_BYTES) message[used++] = '"';
    else truncated = true;
    message[used] = '\0';
    MkmFinishMessage(message, truncated);
}

inline PCSTR MkmExportStringFailureReason(ULONG code)
{
    switch (code) {
    case MKM_FAIL_EXPORT_STRING_RANGE: return "source RVA/output capacity invalid";
    case MKM_FAIL_EXPORT_STRING_EXCEPTION: return "exception during ProbeForRead/string copy";
    case MKM_FAIL_EXPORT_STRING_UNTERMINATED: return "no NUL inside validated string extent/capacity";
    default: return "no failed name probe";
    }
}

inline PVOID MkmAlloc(SIZE_T n, ULONG tag)
{
    return n ? ExAllocatePool2(POOL_FLAG_PAGED, n, tag) : nullptr;
}
inline void MkmFree(PVOID p, ULONG tag)
{
    if (p) ExFreePoolWithTag(p, tag);
}

// CRT 의존 없는 문자열 유틸
inline ULONG MkmStrLen(PCSTR s)          { ULONG n = 0; while (s[n]) ++n; return n; }
inline PCHAR MkmStrchr(PCHAR s, CHAR c)  { while (*s && *s != c) ++s; return *s ? s : nullptr; }
inline void  MkmStrCopy(PCHAR d, PCSTR s, ULONG max)
{
    ULONG i = 0; while (i + 1 < max && s[i]) { d[i] = s[i]; ++i; } d[i] = '\0';
}

// "MODULE" → "MODULE.dll" (없을 때만 추가)
inline void MkmAppendDll(PCHAR buf, ULONG max)
{
    ULONG n = MkmStrLen(buf);
    if (n >= 4) {
        UCHAR a=(UCHAR)buf[n-4], b=(UCHAR)buf[n-3], c=(UCHAR)buf[n-2], d=(UCHAR)buf[n-1];
        if (a>='A'&&a<='Z')a+=32; if (b>='A'&&b<='Z')b+=32;
        if (c>='A'&&c<='Z')c+=32; if (d>='A'&&d<='Z')d+=32;
        if (a=='.'&&b=='d'&&c=='l'&&d=='l') return;
    }
    if (n + 4 < max) { buf[n]='.'; buf[n+1]='d'; buf[n+2]='l'; buf[n+3]='l'; buf[n+4]='\0'; }
}

// 대소문자 구분 비교 (함수명은 case-sensitive)
inline INT MkmStrcmpA(PCSTR a, PCSTR b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (UCHAR)*a - (UCHAR)*b;
}

// 대소문자 무시 비교 (모듈명 비교용, ASCII DLL 이름 한정)
inline INT MkmStricmpA(PCSTR a, PCSTR b)
{
    while (*a && *b) {
        UCHAR ca = (UCHAR)*a, cb = (UCHAR)*b;
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return (INT)ca - (INT)cb;
        ++a; ++b;
    }
    UCHAR ca = (UCHAR)*a, cb = (UCHAR)*b;
    if (ca >= 'a' && ca <= 'z') ca -= 32;
    if (cb >= 'a' && cb <= 'z') cb -= 32;
    return (INT)ca - (INT)cb;
}

// ANSI vs UNICODE 대소문자 무시 비교 (LDR BaseDllName 매칭)
inline bool MkmMatchW(PCSTR ansi, PCWSTR wide, USHORT wide_bytes)
{
    const USHORT wn = wide_bytes / sizeof(WCHAR);
    for (USHORT i = 0; ; ++i) {
        UCHAR a = (UCHAR)ansi[i];
        WCHAR w = (i < wn) ? wide[i] : 0;
        if (w > 0x7F) return false;
        if (a >= 'a' && a <= 'z') a -= 32;
        if (w >= 'a' && w <= 'z') w -= 32;
        if (a != w) return false;
        if (!a)     return true;
    }
}

// RVA 범위 검사
inline bool MkmRvaOk(ULONG rva, ULONG sz, ULONG img_sz)
{
    return rva < img_sz && sz <= img_sz - rva;
}

inline bool MkmUserRange(ULONGLONG address, ULONGLONG size)
{
    const ULONGLONG highest = reinterpret_cast<ULONGLONG>(MmHighestUserAddress);
    return address && size && address <= highest && size - 1 <= highest - address;
}

inline bool MkmImageString(PUCHAR img, ULONG rva, ULONG img_sz, ULONG capacity = 256)
{
    if (!MkmRvaOk(rva, 1, img_sz)) return false;
    const ULONG available = img_sz - rva;
    const ULONG count = available < capacity ? available : capacity;
    for (ULONG i = 0; i < count; ++i)
        if (!img[rva + i]) return true;
    return false;
}

// Called while attached. Copy only within the module's validated image extent.
inline NTSTATUS MkmCopyExportString(PUCHAR base, ULONG rva, ULONG image_size,
    PCHAR output, ULONG capacity, _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    if (!capacity || !MkmRvaOk(rva, 1, image_size))
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_STRING_RANGE, failmessage, "Export string source range/output capacity is invalid before reading; module_base=%p; string_RVA=0x%lX; validated_extent=0x%lX; output=%p; capacity=%lu.", base, rva, image_size, output, capacity);
    const ULONG available = image_size - rva;
    const ULONG count = available < capacity ? available : capacity;
    __try {
        for (ULONG i = 0; i < count; ++i) {
            ProbeForRead(base + rva + i, 1, 1);
            output[i] = static_cast<CHAR>(base[rva + i]);
            if (!output[i]) return STATUS_SUCCESS;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return MkmFail(GetExceptionCode(), failcode, MKM_FAIL_EXPORT_STRING_EXCEPTION, failmessage, "Exception during ProbeForRead/export string copy; module_base=%p; string_RVA=0x%lX; validated_extent=0x%lX; output_capacity=%lu; maximum_read=%lu.", base, rva, image_size, capacity, count); }
    output[capacity - 1] = '\0';
    return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_STRING_UNTERMINATED, failmessage, "Export string has no NUL within the validated bound; module_base=%p; string_RVA=0x%lX; validated_extent=0x%lX; capacity=%lu; scanned_bytes=%lu.", base, rva, image_size, capacity, count);
}

inline PCSTR MkmProtectionName(ULONG protection)
{
    switch (protection) {
    case PAGE_NOACCESS: return "PAGE_NOACCESS";
    case PAGE_READONLY: return "PAGE_READONLY";
    case PAGE_READWRITE: return "PAGE_READWRITE";
    case PAGE_EXECUTE: return "PAGE_EXECUTE";
    case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
    default: return "PAGE_PROTECTION_OTHER";
    }
}

// 섹션 Characteristics → 페이지 보호 속성
inline ULONG MkmSectProt(ULONG ch)
{
    const bool x = !!(ch & MKM_SCN_MEM_EXECUTE);
    const bool w = !!(ch & MKM_SCN_MEM_WRITE);
    const bool r = !!(ch & MKM_SCN_MEM_READ);
    if (x && w)  return PAGE_EXECUTE_READWRITE;
    if (x && r)  return PAGE_EXECUTE_READ;
    if (x)       return PAGE_EXECUTE;
    if (w)       return PAGE_READWRITE;
    if (r)       return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  ①  디스크에서 DLL 파일 읽기 → paged pool 버퍼
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmReadFile(
    _In_  PCWSTR  nt_path,
    _Out_ PUCHAR* out_buf,
    _Out_ ULONG*  out_size,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    *out_buf = nullptr; *out_size = 0;

    UNICODE_STRING us; RtlInitUnicodeString(&us, nt_path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE /*| OBJ_FORCE_ACCESS_CHECK*/, nullptr, nullptr);

    IO_STATUS_BLOCK isb = {};
    HANDLE fh = nullptr;
    NTSTATUS st = ZwCreateFile(&fh,
        GENERIC_READ | SYNCHRONIZE, &oa, &isb, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr, 0);
    if (!NT_SUCCESS(st)) return MkmFail(st, failcode, MKM_FAIL_READ_FILE_OPEN, failmessage, "ZwCreateFile failed; nt_path=%p; path_utf16_bytes=%u; desired_access=0x%08lX; object_attributes=0x%08lX; share=FILE_SHARE_READ; disposition=FILE_OPEN; options=0x%08lX; handle=%p; io_status=%s(0x%08lX); io_information=%llu.", nt_path, us.Length, static_cast<ULONG>(GENERIC_READ | SYNCHRONIZE), oa.Attributes, static_cast<ULONG>(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE), fh, MkmStatusName(isb.Status), static_cast<ULONG>(isb.Status), static_cast<ULONGLONG>(isb.Information));

    FILE_STANDARD_INFORMATION fsi = {};
    st = ZwQueryInformationFile(fh, &isb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) { ZwClose(fh); return MkmFail(st, failcode, MKM_FAIL_READ_FILE_QUERY, failmessage, "ZwQueryInformationFile(handle=%p, class=FileStandardInformation, buffer_bytes=%llu) failed; nt_path=%p; io_status=%s(0x%08lX); io_information=%llu.", fh, static_cast<ULONGLONG>(sizeof(fsi)), nt_path, MkmStatusName(isb.Status), static_cast<ULONG>(isb.Status), static_cast<ULONGLONG>(isb.Information)); }

    const LONGLONG fsz = fsi.EndOfFile.QuadPart;
    if (fsz <= 0 || fsz > static_cast<LONGLONG>(MKM_MAX_SIZE)) {
        ZwClose(fh);
        return MkmFail((fsz <= 0) ? STATUS_INVALID_IMAGE_FORMAT : STATUS_FILE_TOO_LARGE, failcode, MKM_FAIL_READ_FILE_SIZE, failmessage, "File size validation failed: EndOfFile=%lld bytes; allowed range=1..%llu bytes; nt_path=%p.", fsz, static_cast<ULONGLONG>(MKM_MAX_SIZE), nt_path);
    }

    const ULONG file_sz = static_cast<ULONG>(fsz);
    PUCHAR buf = static_cast<PUCHAR>(MkmAlloc(file_sz, MKM_TAG_RAW));
    if (!buf) { ZwClose(fh); return MkmFail(STATUS_INSUFFICIENT_RESOURCES, failcode, MKM_FAIL_READ_FILE_ALLOC, failmessage, "ExAllocatePool2(PAGED, raw file) returned NULL; bytes=%lu; tag=0x%08lX; nt_path=%p.", file_sz, static_cast<ULONG>(MKM_TAG_RAW), nt_path); }

    LARGE_INTEGER off = {};
    st = ZwReadFile(fh, nullptr, nullptr, nullptr, &isb, buf, file_sz, &off, nullptr);
    ZwClose(fh);

    if (!NT_SUCCESS(st) || isb.Information != file_sz) {
        MkmFree(buf, MKM_TAG_RAW);
        return MkmFail(NT_SUCCESS(st) ? STATUS_INVALID_IMAGE_FORMAT : st, failcode,
            NT_SUCCESS(st) ? MKM_FAIL_READ_FILE_SHORT_READ : MKM_FAIL_READ_FILE_READ, failmessage, "ZwReadFile failed or returned a short read; handle=%p (closed after read); buffer=%p (released); requested_bytes=%lu; offset=%lld; bytes_read=%llu; API_return=%s(0x%08lX); io_status=%s(0x%08lX); nt_path=%p.", fh, buf, file_sz, off.QuadPart, static_cast<ULONGLONG>(isb.Information), MkmStatusName(st), static_cast<ULONG>(st), MkmStatusName(isb.Status), static_cast<ULONG>(isb.Status), nt_path);
    }

    *out_buf  = buf;
    *out_size = file_sz;
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  ②  PE64 헤더 검증 및 내부 포인터 반환 (raw 버퍼 내부 포인터)
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmParseHeaders(
    _In_  PUCHAR                         raw,
    _In_  ULONG                          raw_sz,
    _Out_ PHELPER_IMAGE_NT_HEADERS64*    out_nth,
    _Out_ PHELPER_IMAGE_SECTION_HEADER*  out_sects,
    _Out_ USHORT*                        out_nsect,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    *out_nth = nullptr; *out_sects = nullptr; *out_nsect = 0;

    if (raw_sz < sizeof(HELPER_IMAGE_DOS_HEADER)) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_RAW_SIZE, failmessage, "PE DOS header is truncated; raw=%p; raw_size=%lu; required=%llu.", raw, raw_sz, static_cast<ULONGLONG>(sizeof(HELPER_IMAGE_DOS_HEADER)));
    auto* dos = reinterpret_cast<PHELPER_IMAGE_DOS_HEADER>(raw);
    if (dos->e_magic != HELPER_IMAGE_DOS_SIGNATURE) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_DOS_SIGNATURE, failmessage, "PE DOS signature mismatch; e_magic=0x%04X; expected=0x%04X; raw=%p; raw_size=%lu.", dos->e_magic, HELPER_IMAGE_DOS_SIGNATURE, raw, raw_sz);

    if (dos->e_lfanew <= 0) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_NT_OFFSET, failmessage, "PE NT header offset must be positive; e_lfanew=%ld; raw_size=%lu.", dos->e_lfanew, raw_sz);
    const ULONG e_lfa = static_cast<ULONG>(dos->e_lfanew);
    if (e_lfa >= raw_sz || raw_sz - e_lfa < sizeof(HELPER_IMAGE_NT_HEADERS64))
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_NT_RANGE, failmessage, "PE NT header is outside file extent; e_lfanew=0x%lX; raw_size=0x%lX; required_nt_bytes=%llu.", e_lfa, raw_sz, static_cast<ULONGLONG>(sizeof(HELPER_IMAGE_NT_HEADERS64)));

    auto* nth = reinterpret_cast<PHELPER_IMAGE_NT_HEADERS64>(raw + e_lfa);
    if (nth->Signature != HELPER_IMAGE_NT_SIGNATURE) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_NT_SIGNATURE, failmessage, "PE NT signature mismatch; signature=0x%08lX; expected=0x%08lX; nt_offset=0x%lX.", nth->Signature, static_cast<ULONG>(HELPER_IMAGE_NT_SIGNATURE), e_lfa);
    if (nth->FileHeader.Machine != MKM_FILE_MACHINE_AMD64) return MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_HEADERS_MACHINE, failmessage, "Only AMD64 PE images are supported; machine=0x%04X; required=0x%04X.", nth->FileHeader.Machine, MKM_FILE_MACHINE_AMD64);
    if (nth->OptionalHeader.Magic != HELPER_IMAGE_NT_OPTIONAL_HDR64_MAGIC) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_OPTIONAL_MAGIC, failmessage, "PE optional header magic mismatch; magic=0x%04X; required_PE64=0x%04X.", nth->OptionalHeader.Magic, HELPER_IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!(nth->FileHeader.Characteristics & IMAGE_FILE_DLL)) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_DLL_FLAG, failmessage, "IMAGE_FILE_DLL flag is absent; FileHeader.Characteristics=0x%04X; required_flag=0x%04X.", nth->FileHeader.Characteristics, IMAGE_FILE_DLL);
    if (!nth->OptionalHeader.SizeOfImage  || nth->OptionalHeader.SizeOfImage > MKM_MAX_SIZE)
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_IMAGE_SIZE, failmessage, "Invalid SizeOfImage; actual=0x%lX; allowed=1..0x%llX.", nth->OptionalHeader.SizeOfImage, static_cast<ULONGLONG>(MKM_MAX_SIZE));
    if (nth->FileHeader.SizeOfOptionalHeader < sizeof(HELPER_IMAGE_OPTIONAL_HEADER64) ||
        nth->OptionalHeader.NumberOfRvaAndSizes > HELPER_IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_OPTIONAL_SIZE, failmessage, "Invalid optional header/directory count; SizeOfOptionalHeader=%u; minimum=%llu; NumberOfRvaAndSizes=%lu; maximum=%u.", nth->FileHeader.SizeOfOptionalHeader, static_cast<ULONGLONG>(sizeof(HELPER_IMAGE_OPTIONAL_HEADER64)), nth->OptionalHeader.NumberOfRvaAndSizes, HELPER_IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    // This mapper applies per-section protection at page granularity.
    if (nth->OptionalHeader.SectionAlignment < PAGE_SIZE)
        return MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_HEADERS_SECTION_ALIGNMENT, failmessage, "SectionAlignment is smaller than page protection granularity; actual=0x%lX; minimum=0x%lX.", nth->OptionalHeader.SectionAlignment, static_cast<ULONG>(PAGE_SIZE));

    // 섹션 테이블: Optional 헤더 직후
    const ULONG sect_off = e_lfa
        + static_cast<ULONG>(FIELD_OFFSET(HELPER_IMAGE_NT_HEADERS64, OptionalHeader))
        + nth->FileHeader.SizeOfOptionalHeader;

    const USHORT ns = nth->FileHeader.NumberOfSections;
    if (!ns || ns > MKM_MAX_SECTIONS) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_SECTION_COUNT, failmessage, "Invalid section count; NumberOfSections=%u; allowed=1..%u.", ns, MKM_MAX_SECTIONS);
    const ULONG table_size = static_cast<ULONG>(ns) * sizeof(HELPER_IMAGE_SECTION_HEADER);
    if (sect_off > raw_sz || table_size > raw_sz - sect_off)
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_SECTION_TABLE, failmessage, "Section table exceeds file extent; table_offset=0x%lX; table_bytes=0x%lX; section_count=%u; raw_size=0x%lX.", sect_off, table_size, ns, raw_sz);
    const ULONG headers = nth->OptionalHeader.SizeOfHeaders;
    const ULONG image_size = nth->OptionalHeader.SizeOfImage;
    if (headers < sect_off + table_size || headers > raw_sz || headers > image_size ||
        !headers || (image_size % PAGE_SIZE) != 0)
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_HEADER_EXTENT, failmessage, "Invalid header/image extent or image page alignment; SizeOfHeaders=0x%lX; section_table_end=0x%lX; raw_size=0x%lX; SizeOfImage=0x%lX; page_size=0x%lX.", headers, sect_off + table_size, raw_sz, image_size, static_cast<ULONG>(PAGE_SIZE));
    if (nth->OptionalHeader.ImageBase &&
        !MkmUserRange(nth->OptionalHeader.ImageBase, image_size))
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_PREFERRED_RANGE, failmessage, "Preferred image allocation is outside user address range; ImageBase=0x%llX; SizeOfImage=0x%lX; highest_user=%p.", nth->OptionalHeader.ImageBase, image_size, MmHighestUserAddress);
    for (ULONG i = 0; i < nth->OptionalHeader.NumberOfRvaAndSizes; ++i) {
        const auto& d = nth->OptionalHeader.DataDirectory[i];
        if (!!d.VirtualAddress != !!d.Size) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_DIRECTORY_PAIR, failmessage, "PE directory RVA/size must both be zero or both be nonzero; directory_index=%lu; VirtualAddress=0x%lX; Size=0x%lX.", i, d.VirtualAddress, d.Size);
        // SECURITY uses a file offset, not an image RVA.
        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
            if (d.VirtualAddress &&
                (d.VirtualAddress > raw_sz || d.Size > raw_sz - d.VirtualAddress))
                return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_SECURITY_RANGE, failmessage, "PE SECURITY directory file-offset range exceeds raw file; directory_index=%lu; file_offset=0x%lX; size=0x%lX; raw_size=0x%lX.", i, d.VirtualAddress, d.Size, raw_sz);
        } else if (d.VirtualAddress && !MkmRvaOk(d.VirtualAddress, d.Size, image_size)) {
            return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_DIRECTORY_RANGE, failmessage, "PE directory image RVA range exceeds SizeOfImage; directory_index=%lu; rva=0x%lX; size=0x%lX; image_size=0x%lX.", i, d.VirtualAddress, d.Size, image_size);
        }
    }
    // No TLS callback/static TLS or delay-import initializer is implemented.
    if (nth->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS &&
        nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
        return MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_HEADERS_TLS, failmessage, "TLS directory is unsupported by this mapper; directory_rva=0x%lX; directory_size=0x%lX; TLS initialization has not been performed.", nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
    if (nth->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT &&
        nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
        return MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_HEADERS_DELAY_IMPORT, failmessage, "Delay import directory is unsupported by this mapper; directory_rva=0x%lX; directory_size=0x%lX.", nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
    auto sections = reinterpret_cast<PHELPER_IMAGE_SECTION_HEADER>(raw + sect_off);
    bool executable_entry = nth->OptionalHeader.AddressOfEntryPoint == 0;
    const ULONG first_section = (headers + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    for (USHORT i = 0; i < ns; ++i) {
        const auto& s = sections[i];
        const ULONG span = s.Misc.VirtualSize > s.SizeOfRawData
            ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (!span) continue;
        if (s.VirtualAddress < first_section || (s.VirtualAddress % PAGE_SIZE) ||
            !MkmRvaOk(s.VirtualAddress, span, image_size) ||
            (s.SizeOfRawData &&
             (s.PointerToRawData > raw_sz || s.SizeOfRawData > raw_sz - s.PointerToRawData)))
            return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_SECTION_EXTENT, failmessage, "Invalid PE section extent/alignment; section_index=%u; section_name=%.8s; RVA=0x%lX; VirtualSize=0x%lX; RawSize=0x%lX; RawOffset=0x%lX; span=0x%lX; first_section=0x%lX; image_size=0x%lX; raw_size=0x%lX; page_size=0x%lX.", i, reinterpret_cast<PCSTR>(s.Name), s.VirtualAddress, s.Misc.VirtualSize, s.SizeOfRawData, s.PointerToRawData, span, first_section, image_size, raw_sz, static_cast<ULONG>(PAGE_SIZE));
        const ULONG section_end = (s.VirtualAddress + span + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        for (USHORT j = 0; j < i; ++j) {
            const auto& old = sections[j];
            const ULONG old_span = old.Misc.VirtualSize > old.SizeOfRawData
                ? old.Misc.VirtualSize : old.SizeOfRawData;
            if (old_span && s.VirtualAddress <
                ((old.VirtualAddress + old_span + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) &&
                old.VirtualAddress < section_end)
                return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_SECTION_OVERLAP, failmessage, "PE sections overlap after page rounding; section_index=%u; name=%.8s; RVA=0x%lX; page_end=0x%lX; previous_index=%u; previous_name=%.8s; previous_RVA=0x%lX; previous_span=0x%lX; page_size=0x%lX.", i, reinterpret_cast<PCSTR>(s.Name), s.VirtualAddress, section_end, j, reinterpret_cast<PCSTR>(old.Name), old.VirtualAddress, old_span, static_cast<ULONG>(PAGE_SIZE));
        }
        const ULONG entry = nth->OptionalHeader.AddressOfEntryPoint;
        if (entry >= s.VirtualAddress && entry - s.VirtualAddress < span &&
            (s.Characteristics & MKM_SCN_MEM_EXECUTE))
            executable_entry = true;
    }
    if (!executable_entry) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_HEADERS_ENTRY_POINT, failmessage, "AddressOfEntryPoint is not inside any executable section; entry_RVA=0x%lX; section_count=%u; SizeOfImage=0x%lX.", nth->OptionalHeader.AddressOfEntryPoint, ns, image_size);

    *out_nth   = nth;
    *out_sects = reinterpret_cast<PHELPER_IMAGE_SECTION_HEADER>(raw + sect_off);
    *out_nsect = ns;
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  ③④  커널 local image 구성 (paged pool, zero-init된 SizeOfImage 버퍼)
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmBuildLocalImage(
    _In_  PUCHAR                        raw,
    _In_  ULONG                         raw_sz,
    _In_  PHELPER_IMAGE_NT_HEADERS64    nth,
    _In_  PHELPER_IMAGE_SECTION_HEADER  sects,
    _In_  USHORT                        nsect,
    _Out_ PUCHAR*                       out_img,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    *out_img = nullptr;
    const ULONG img_sz = nth->OptionalHeader.SizeOfImage;
    const ULONG hdr_sz = nth->OptionalHeader.SizeOfHeaders;
    if (hdr_sz > img_sz || hdr_sz > raw_sz) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_LOCAL_IMAGE_HEADER_EXTENT, failmessage, "Local image header copy range is invalid; header_size=0x%lX; image_size=0x%lX; raw_size=0x%lX; raw=%p.", hdr_sz, img_sz, raw_sz, raw);

    // ExAllocatePool2는 자동으로 zero-init → BSS 섹션 별도 처리 불필요
    PUCHAR img = static_cast<PUCHAR>(MkmAlloc(img_sz, MKM_TAG_IMG));
    if (!img) return MkmFail(STATUS_INSUFFICIENT_RESOURCES, failcode, MKM_FAIL_LOCAL_IMAGE_ALLOC, failmessage, "ExAllocatePool2(PAGED, local image) returned NULL; SizeOfImage=%lu; tag=0x%08lX.", img_sz, static_cast<ULONG>(MKM_TAG_IMG));

    // PE 헤더 복사
    RtlCopyMemory(img, raw, hdr_sz);

    // 각 섹션: 파일 오프셋 → 가상 주소 위치로 복사
    for (USHORT i = 0; i < nsect; ++i)
    {
        const auto& s    = sects[i];
        const ULONG vaz  = s.VirtualAddress;
        const ULONG vsz  = s.Misc.VirtualSize > s.SizeOfRawData
            ? s.Misc.VirtualSize : s.SizeOfRawData;
        const ULONG rsz  = s.SizeOfRawData;
        const ULONG roff = s.PointerToRawData;

        if (!vsz) continue;

        if (!MkmRvaOk(vaz, vsz, img_sz)) {
            MkmFree(img, MKM_TAG_IMG); return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_LOCAL_IMAGE_VIRTUAL_RANGE, failmessage, "Local image section destination exceeds image extent; section_index=%u; name=%.8s; RVA=0x%lX; span=0x%lX; image_size=0x%lX; local_image=%p (released).", i, reinterpret_cast<PCSTR>(s.Name), vaz, vsz, img_sz, img);
        }
        if (static_cast<ULONGLONG>(roff) + rsz > raw_sz) {
            MkmFree(img, MKM_TAG_IMG); return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_LOCAL_IMAGE_RAW_RANGE, failmessage, "Local image section source exceeds raw file extent; section_index=%u; name=%.8s; RawOffset=0x%lX; RawSize=0x%lX; raw_size=0x%lX; raw=%p.", i, reinterpret_cast<PCSTR>(s.Name), roff, rsz, raw_sz, raw);
        }

        if (rsz) RtlCopyMemory(img + vaz, raw + roff, rsz);
    }

    *out_img = img;
    return STATUS_SUCCESS;
}

// local image 버퍼에서 섹션 테이블 포인터를 재유도하는 헬퍼.
// raw 해제 후 nth/sects 포인터가 무효화됐을 때 사용.
inline PHELPER_IMAGE_SECTION_HEADER MkmSects(PUCHAR img, USHORT* out_ns)
{
    auto* dos = reinterpret_cast<PHELPER_IMAGE_DOS_HEADER>(img);
    auto* nth = reinterpret_cast<PHELPER_IMAGE_NT_HEADERS64>(img + dos->e_lfanew);
    if (out_ns) *out_ns = nth->FileHeader.NumberOfSections;
    return reinterpret_cast<PHELPER_IMAGE_SECTION_HEADER>(
        reinterpret_cast<PUCHAR>(&nth->OptionalHeader)
        + nth->FileHeader.SizeOfOptionalHeader);
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑤-A  대상 프로세스 PEB LDR에서 모듈 베이스 탐색
//        KeStackAttachProcess가 이미 적용된 상태에서 호출해야 함
// ═══════════════════════════════════════════════════════════════════════

inline UCHAR MkmAsciiLower(UCHAR c)
{
    return c >= 'A' && c <= 'Z' ? static_cast<UCHAR>(c + ('a' - 'A')) : c;
}

inline bool MkmIsApiSet(PCSTR name)
{
    if (!name) return false;
    UCHAR prefix[4];
    for (ULONG i = 0; i < 4; ++i) {
        if (!name[i]) return false;
        prefix[i] = MkmAsciiLower(static_cast<UCHAR>(name[i]));
    }
    return (prefix[0] == 'a' && prefix[1] == 'p' && prefix[2] == 'i' && prefix[3] == '-') ||
           (prefix[0] == 'e' && prefix[1] == 'x' && prefix[2] == 't' && prefix[3] == '-');
}

inline bool MkmExactMatchW(PCSTR a, ULONG alen, PCWSTR w, ULONG wlen)
{
    if (!a || !w || alen != wlen) return false;
    for (ULONG i = 0; i < alen; ++i) {
        // Do not truncate a non-ASCII WCHAR into a matching ASCII byte.
        if (static_cast<USHORT>(w[i]) > 0x7f ||
            MkmAsciiLower(static_cast<UCHAR>(a[i])) !=
            MkmAsciiLower(static_cast<UCHAR>(w[i]))) return false;
    }
    return true;
}

inline bool MkmApiSetRange(ULONG offset, SIZE_T bytes, ULONG size)
{
    return offset >= sizeof(MKM_APISET_NS) && offset <= size &&
           bytes <= static_cast<SIZE_T>(size - offset);
}

// Parse an immutable, bounded kernel snapshot. No target pointers are used here.
inline bool MkmResolveApiSetNamespace(
    _In_ PUCHAR ns_base, _In_ ULONG ns_size, _In_ PCSTR api_name,
    _Out_ PCHAR out_name, _In_ ULONG out_max, _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    if (!out_name || !out_max) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_OUTPUT, failmessage, "API-set snapshot resolver output is invalid; output=%p; capacity=%lu; expected writable bounded string buffer.", out_name, out_max);
    out_name[0] = '\0';
    if (!ns_base || !api_name || ns_size < sizeof(MKM_APISET_NS) ||
        ns_size > MKM_MAX_APISET_SIZE || !MkmIsApiSet(api_name)) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_INPUT, failmessage, "API-set snapshot resolver input is invalid; namespace=%p; namespace_size=%lu; allowed_bytes=%llu..%lu; contract_pointer=%p; required_prefix=api-/ext-.", ns_base, ns_size, static_cast<ULONGLONG>(sizeof(MKM_APISET_NS)), MKM_MAX_APISET_SIZE, api_name);

    CHAR query[260] = {};
    ULONG qlen = 0;
    while (qlen < sizeof(query) - 1 && api_name[qlen]) {
        if (static_cast<UCHAR>(api_name[qlen]) > 0x7f) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_QUERY_ASCII, failmessage, "API-set contract has a non-ASCII byte; byte_index=%lu; actual_byte=0x%02X; namespace=%p; namespace_size=%lu.", qlen, static_cast<UCHAR>(api_name[qlen]), ns_base, ns_size);
        query[qlen] = api_name[qlen];
        ++qlen;
    }
    if (api_name[qlen]) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_QUERY_LENGTH, failmessage, "API-set contract exceeds bounded query capacity; capacity=%llu; scanned_bytes=%lu; contract_pointer=%p; validated_prefix=%.259s.", static_cast<ULONGLONG>(sizeof(query)), qlen, api_name, query); // reject truncation
    if (qlen >= 4 && query[qlen - 4] == '.' &&
        MkmAsciiLower(static_cast<UCHAR>(query[qlen - 3])) == 'd' &&
        MkmAsciiLower(static_cast<UCHAR>(query[qlen - 2])) == 'l' &&
        MkmAsciiLower(static_cast<UCHAR>(query[qlen - 1])) == 'l') {
        qlen -= 4;
        query[qlen] = '\0';
    }
    if (qlen <= 4) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_EMPTY_CONTRACT, failmessage, "API-set contract is too short after removing .dll suffix; contract_length=%lu; contract=%.259s.", qlen, query);

    MKM_APISET_NS ns;
    RtlCopyMemory(&ns, ns_base, sizeof(ns));
    if (ns.Version != 6 || ns.Size != ns_size || !ns.Count ||
        ns.EntryOffset % sizeof(ULONG) ||
        !MkmApiSetRange(ns.EntryOffset, 0, ns_size) ||
        ns.Count > (ns_size - ns.EntryOffset) / sizeof(MKM_APISET_ENTRY)) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_HEADER, failmessage, "Invalid API-set v6 snapshot header; Version=%lu; Size=%lu; snapshot_size=%lu; Count=%lu; EntryOffset=0x%lX; entry_bytes=%llu; required_version=6; entry_alignment=%llu.", ns.Version, ns.Size, ns_size, ns.Count, ns.EntryOffset, static_cast<ULONGLONG>(sizeof(MKM_APISET_ENTRY)), static_cast<ULONGLONG>(sizeof(ULONG)));

    for (ULONG i = 0; i < ns.Count; ++i) {
        MKM_APISET_ENTRY entry;
        RtlCopyMemory(&entry, ns_base + ns.EntryOffset +
            static_cast<SIZE_T>(i) * sizeof(entry), sizeof(entry));
        if (!entry.NameLength || entry.NameLength % sizeof(WCHAR) ||
            entry.NameOffset % sizeof(WCHAR) ||
            !MkmApiSetRange(entry.NameOffset, entry.NameLength, ns_size)) continue;
        PCWSTR name = reinterpret_cast<PCWSTR>(ns_base + entry.NameOffset);
        if (!MkmExactMatchW(query, qlen, name, entry.NameLength / sizeof(WCHAR))) continue;

        if (!entry.ValueCount || entry.ValueOffset % sizeof(ULONG) ||
            !MkmApiSetRange(entry.ValueOffset, 0, ns_size) ||
            entry.ValueCount > (ns_size - entry.ValueOffset) / sizeof(MKM_APISET_VALUE)) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_VALUE_TABLE, failmessage, "Invalid API-set host value table; contract=%.259s; entry_index=%lu; ValueOffset=0x%lX; ValueCount=%lu; value_bytes=%llu; namespace_size=%lu.", query, i, entry.ValueOffset, entry.ValueCount, static_cast<ULONGLONG>(sizeof(MKM_APISET_VALUE)), ns_size);

        ULONG best_offset = 0, best_length = 0;
        bool got_default = false;
        for (ULONG v = 0; v < entry.ValueCount; ++v) {
            MKM_APISET_VALUE value;
            RtlCopyMemory(&value, ns_base + entry.ValueOffset +
                static_cast<SIZE_T>(v) * sizeof(value), sizeof(value));
            if (!value.ValueLength || value.ValueLength % sizeof(WCHAR) ||
                value.ValueOffset % sizeof(WCHAR) ||
                !MkmApiSetRange(value.ValueOffset, value.ValueLength, ns_size) ||
                value.NameLength % sizeof(WCHAR) ||
                (value.NameLength && (value.NameOffset % sizeof(WCHAR) ||
                 !MkmApiSetRange(value.NameOffset, value.NameLength, ns_size)))) continue;

            const ULONG chars = value.ValueLength / sizeof(WCHAR);
            PCWSTR host = reinterpret_cast<PCWSTR>(ns_base + value.ValueOffset);
            bool ascii = true;
            for (ULONG c = 0; c < chars; ++c) {
                if (!host[c] || static_cast<USHORT>(host[c]) > 0x7f) { ascii = false; break; }
            }
            if (!ascii) continue;
            // Requested compatibility policy: default first, otherwise last valid alias.
            if (!value.NameLength || !got_default) {
                best_offset = value.ValueOffset;
                best_length = value.ValueLength;
                if (!value.NameLength) got_default = true;
            }
        }
        if (!best_length) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_HOST_NOT_FOUND, failmessage, "API-set contract matched but no bounded valid ASCII host was found; contract=%.259s; entry_index=%lu; ValueCount=%lu; ValueOffset=0x%lX; namespace_size=%lu.", query, i, entry.ValueCount, entry.ValueOffset, ns_size);
        PCWSTR host = reinterpret_cast<PCWSTR>(ns_base + best_offset);
        const ULONG chars = best_length / sizeof(WCHAR);
        if (chars >= out_max) return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_HOST_LENGTH, failmessage, "API-set host does not fit output buffer; contract=%.259s; entry_index=%lu; host_utf16_chars=%lu; output_capacity=%lu; chosen_offset=0x%lX; chosen_bytes=%lu.", query, i, chars, out_max, best_offset, best_length);
        for (ULONG c = 0; c < chars; ++c) out_name[c] = static_cast<CHAR>(host[c]);
        out_name[chars] = '\0';
        return true;
    }
    return MkmReject(failcode, MKM_FAIL_APISET_NAMESPACE_CONTRACT_NOT_FOUND, failmessage, "API-set contract was not found in target namespace snapshot; contract=%.259s; entry_count=%lu; namespace_size=%lu; EntryOffset=0x%lX.", query, ns.Count, ns_size, ns.EntryOffset);
}

// Caller must already be attached to target at PASSIVE_LEVEL.
inline bool MkmResolveApiSetAttached(
    _In_ PEPROCESS target, _In_ PCSTR api_name,
    _Out_ PCHAR out_name, _In_ ULONG out_max, _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    if (!out_name || !out_max) return MkmReject(failcode, MKM_FAIL_APISET_ATTACHED_OUTPUT, failmessage, "Attached API-set resolver output is invalid; output=%p; capacity=%lu; target=%p.", out_name, out_max, target);
    out_name[0] = '\0';
    if (!target || !api_name) return MkmReject(failcode, MKM_FAIL_APISET_ATTACHED_INPUT, failmessage, "Attached API-set resolver input is invalid; target=%p; contract_pointer=%p.", target, api_name);
    PUCHAR snapshot = nullptr;
    bool found = false;
    __try {
        PPEB peb = PsGetProcessPeb(target);
        if (!peb) { MkmSetFailcode(failcode, MKM_FAIL_APISET_ATTACHED_PEB, failmessage, "PsGetProcessPeb(target=%p) returned NULL while resolving API-set; contract=%.259s.", target, api_name); __leave; }
        const SIZE_T peb_bytes = FIELD_OFFSET(PEB, ApiSetMap) + sizeof(PVOID);
        if (!MkmUserRange(reinterpret_cast<ULONGLONG>(peb), peb_bytes)) { MkmSetFailcode(failcode, MKM_FAIL_APISET_ATTACHED_PEB_RANGE, failmessage, "Target PEB user range is invalid before ProbeForRead; target=%p; peb=%p; required_bytes=%llu; highest_user=%p; contract=%.259s.", target, peb, static_cast<ULONGLONG>(peb_bytes), MmHighestUserAddress, api_name); __leave; }
        ProbeForRead(peb, peb_bytes, sizeof(PVOID));
        PUCHAR ns_base = nullptr;
        RtlCopyMemory(&ns_base, &peb->ApiSetMap, sizeof(ns_base));
        if (!MkmUserRange(reinterpret_cast<ULONGLONG>(ns_base), sizeof(MKM_APISET_NS))) { MkmSetFailcode(failcode, MKM_FAIL_APISET_ATTACHED_NAMESPACE_RANGE, failmessage, "Target PEB.ApiSetMap user range is invalid before reading namespace; target=%p; peb=%p; ApiSetMap=%p; required_header_bytes=%llu; contract=%.259s.", target, peb, ns_base, static_cast<ULONGLONG>(sizeof(MKM_APISET_NS)), api_name); __leave; }
        ProbeForRead(ns_base, sizeof(MKM_APISET_NS), sizeof(ULONG));
        MKM_APISET_NS ns;
        RtlCopyMemory(&ns, ns_base, sizeof(ns));
        if (ns.Version != 6 || ns.Size < sizeof(ns) || ns.Size > MKM_MAX_APISET_SIZE ||
            !MkmUserRange(reinterpret_cast<ULONGLONG>(ns_base), ns.Size)) { MkmSetFailcode(failcode, MKM_FAIL_APISET_ATTACHED_HEADER, failmessage, "Invalid target API-set namespace header/range; namespace=%p; Version=%lu; Size=%lu; minimum=%llu; maximum=%lu; highest_user=%p; contract=%.259s.", ns_base, ns.Version, ns.Size, static_cast<ULONGLONG>(sizeof(ns)), MKM_MAX_APISET_SIZE, MmHighestUserAddress, api_name); __leave; }
        snapshot = static_cast<PUCHAR>(MkmAlloc(ns.Size, MKM_TAG_APISET));
        if (!snapshot) { MkmSetFailcode(failcode, MKM_FAIL_APISET_ATTACHED_ALLOC, failmessage, "ExAllocatePool2(PAGED, API-set snapshot) returned NULL; target=%p; namespace=%p; bytes=%lu; tag=0x%08lX; contract=%.259s.", target, ns_base, ns.Size, static_cast<ULONG>(MKM_TAG_APISET), api_name); __leave; }
        ProbeForRead(ns_base, ns.Size, sizeof(ULONG));
        RtlCopyMemory(snapshot, ns_base, ns.Size);
        found = MkmResolveApiSetNamespace(snapshot, ns.Size, api_name, out_name, out_max, failcode, failmessage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { MkmSetFailcode(failcode, MKM_FAIL_APISET_ATTACHED_EXCEPTION, failmessage, "Exception during target PEB/API-set ProbeForRead or snapshot copy; target=%p; snapshot=%p; contract=%.259s; exception=%s(0x%08lX).", target, snapshot, api_name, MkmStatusName(GetExceptionCode()), static_cast<ULONG>(GetExceptionCode())); found = false; }
    MkmFree(snapshot, MKM_TAG_APISET);
    if (!found) out_name[0] = '\0';
    return found;
}

inline PVOID MkmFindModule(_In_ PEPROCESS target, _In_ PCSTR ansi_name, _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    if (!target || !ansi_name || !ansi_name[0]) { MkmSetFailcode(failcode, MKM_FAIL_MODULE_INPUT, failmessage, "Loaded module lookup input is invalid; target=%p; name_pointer=%p; expected nonempty module name.", target, ansi_name); return nullptr; }
    // Also covers API-set targets encountered while resolving forwarded exports.
    CHAR resolved[260] = {};
    if (MkmIsApiSet(ansi_name)) {
        if (!MkmResolveApiSetAttached(target, ansi_name, resolved, sizeof(resolved), failcode, failmessage)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[MKM] Module: API set resolution failed: %s\n", ansi_name);
            return nullptr;
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "[MKM] Module: %s -> %s\n", ansi_name, resolved);
        ansi_name = resolved;
    }
    PVOID result = nullptr;
    __try {
        PPEB peb = PsGetProcessPeb(target);
        if (!peb) { MkmSetFailcode(failcode, MKM_FAIL_MODULE_PEB, failmessage, "PsGetProcessPeb(target=%p) returned NULL during loaded module lookup; module=%.259s.", target, ansi_name); __leave; }
        ProbeForRead(peb, sizeof(PEB), sizeof(PVOID));

        PEB local_peb; RtlCopyMemory(&local_peb, peb, sizeof(PEB));

        PPEB_LDR_DATA ldr_user = local_peb.Ldr;
        if (!ldr_user) { MkmSetFailcode(failcode, MKM_FAIL_MODULE_LDR, failmessage, "Target PEB.Ldr is NULL; target=%p; peb=%p; module=%.259s.", target, peb, ansi_name); __leave; }
        ProbeForRead(ldr_user, sizeof(PEB_LDR_DATA), sizeof(PVOID));

        PEB_LDR_DATA local_ldr; RtlCopyMemory(&local_ldr, ldr_user, sizeof(PEB_LDR_DATA));

        // InMemoryOrderModuleList의 센티넬 주소 (유저 VA)
        PLIST_ENTRY head = &ldr_user->InMemoryOrderModuleList;
        PLIST_ENTRY cur  = local_ldr.InMemoryOrderModuleList.Flink;

        for (ULONG guard = 0; cur && cur != head && guard < 512; ++guard)
        {
            auto* ent = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            ProbeForRead(ent, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(PVOID));

            LDR_DATA_TABLE_ENTRY e; RtlCopyMemory(&e, ent, sizeof(e));

            // BaseDllName.Buffer는 유저 VA — 별도로 읽음
            WCHAR wname[260] = {};
            const USHORT wlen = e.BaseDllName.Length;
            if (e.BaseDllName.Buffer && wlen && wlen <= 258 * sizeof(WCHAR) &&
                wlen <= e.BaseDllName.MaximumLength && !(wlen % sizeof(WCHAR))) {
                ProbeForRead(e.BaseDllName.Buffer, wlen, sizeof(WCHAR));
                RtlCopyMemory(wname, e.BaseDllName.Buffer, wlen);
            }

            if (wlen <= 258 * sizeof(WCHAR) && !(wlen % sizeof(WCHAR)) &&
                MkmMatchW(ansi_name, wname, wlen)) {
                result = e.DllBase; __leave;
            }
            cur = e.InMemoryOrderLinks.Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { MkmSetFailcode(failcode, MKM_FAIL_MODULE_EXCEPTION, failmessage, "Exception while reading target PEB/LDR/module name list; target=%p; module=%.259s; exception=%s(0x%08lX); only already loaded modules are resolved.", target, ansi_name, MkmStatusName(GetExceptionCode()), static_cast<ULONG>(GetExceptionCode())); result = nullptr; }
    if (!result) MkmSetFailcode(failcode, MKM_FAIL_MODULE_NOT_FOUND, failmessage, "Requested module was not found in target InMemoryOrderModuleList (bounded to 512 entries); target=%p; module=%.259s; dependency loading is not performed; caller returns STATUS_DLL_NOT_FOUND(0xC0000135).", target, ansi_name);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑤-B  대상 프로세스에 로드된 모듈에서 export 함수 VA 해결
//        KeStackAttachProcess 상태에서 호출. depth = 포워딩 재귀 깊이.
// ═══════════════════════════════════════════════════════════════════════

// 상호 재귀(포워딩) 때문에 전방 선언
inline NTSTATUS MkmResolveExport(
    _In_     PEPROCESS  target,
    _In_     PVOID      mod_base_user,
    _In_opt_ PCSTR      func_name,       // nullptr → 서수로 해결
    _In_     USHORT     ordinal,
    _Out_    ULONGLONG* out_va,
    _In_     ULONG      depth,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr);

inline NTSTATUS MkmResolveExport(
    _In_     PEPROCESS  target,
    _In_     PVOID      mod_base_user,
    _In_opt_ PCSTR      func_name,
    _In_     USHORT     ordinal,
    _Out_    ULONGLONG* out_va,
    _In_     ULONG      depth,
    _Inout_ ULONG* failcode, PCHAR failmessage)
{
    *out_va = 0;
    if (!mod_base_user) return MkmFail(STATUS_INVALID_PARAMETER, failcode, MKM_FAIL_EXPORT_BASE, failmessage, "Export resolver module base is NULL; target=%p; symbol_pointer=%p; ordinal=%u; forward_depth=%lu.", target, func_name, ordinal, depth);
    if (depth > MKM_FWD_DEPTH) return MkmFail(STATUS_UNSUCCESSFUL, failcode, MKM_FAIL_EXPORT_DEPTH, failmessage, "Forwarded export recursion limit exceeded; module_base=%p; symbol=%.255s; ordinal=%u; depth=%lu; maximum=%u.", mod_base_user, func_name ? func_name : "<ordinal>", ordinal, depth, MKM_FWD_DEPTH); // 포워딩 깊이 초과

    PUCHAR base = static_cast<PUCHAR>(mod_base_user);

    // ── Phase 1: export 디렉터리 메타데이터 읽기 ─────────────────────
    ULONG export_rva = 0, export_sz = 0, image_size = 0;
    ULONG fn_rva = 0, nm_rva = 0, on_rva = 0;
    ULONG num_funcs = 0, num_names = 0, ord_base = 0;
    NTSTATUS st = STATUS_ENTRYPOINT_NOT_FOUND;

    __try {
        ProbeForRead(base, sizeof(HELPER_IMAGE_DOS_HEADER), 1);
        HELPER_IMAGE_DOS_HEADER dos; RtlCopyMemory(&dos, base, sizeof(dos));
        if (dos.e_magic != HELPER_IMAGE_DOS_SIGNATURE)
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_DOS_SIGNATURE, failmessage, "Loaded dependency DOS signature is invalid; module_base=%p; e_magic=0x%04X; expected=0x%04X; forward_depth=%lu.", base, dos.e_magic, HELPER_IMAGE_DOS_SIGNATURE, depth); __leave; }

        if (dos.e_lfanew <= 0 ||
            !MkmUserRange(reinterpret_cast<ULONGLONG>(base),
                static_cast<ULONGLONG>(dos.e_lfanew) + sizeof(HELPER_IMAGE_NT_HEADERS64)))
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_NT_RANGE, failmessage, "Loaded dependency NT header pointer/user range is invalid; module_base=%p; e_lfanew=%ld; nt_bytes=%llu; highest_user=%p.", base, dos.e_lfanew, static_cast<ULONGLONG>(sizeof(HELPER_IMAGE_NT_HEADERS64)), MmHighestUserAddress); __leave; }
        PUCHAR nt_ptr = base + static_cast<ULONG>(dos.e_lfanew);
        ProbeForRead(nt_ptr, sizeof(HELPER_IMAGE_NT_HEADERS64), sizeof(ULONG));
        HELPER_IMAGE_NT_HEADERS64 nth; RtlCopyMemory(&nth, nt_ptr, sizeof(nth));
        if (nth.Signature != HELPER_IMAGE_NT_SIGNATURE ||
            nth.OptionalHeader.Magic != HELPER_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_NT_SIGNATURE, failmessage, "Loaded dependency NT/optional signature mismatch; module_base=%p; nt_pointer=%p; signature=0x%08lX; optional_magic=0x%04X; expected_signature=0x%08lX; expected_magic=0x%04X.", base, nt_ptr, nth.Signature, nth.OptionalHeader.Magic, static_cast<ULONG>(HELPER_IMAGE_NT_SIGNATURE), HELPER_IMAGE_NT_OPTIONAL_HDR64_MAGIC); __leave; }
        image_size = nth.OptionalHeader.SizeOfImage;
        if (!image_size || image_size > MKM_MAX_SIZE ||
            !MkmRvaOk(static_cast<ULONG>(dos.e_lfanew), sizeof(nth), image_size) ||
            !MkmUserRange(reinterpret_cast<ULONGLONG>(base), image_size) ||
            nth.FileHeader.SizeOfOptionalHeader < sizeof(HELPER_IMAGE_OPTIONAL_HEADER64) ||
            nth.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_IMAGE_RANGE, failmessage, "Invalid loaded dependency image/NT/directory extent; module_base=%p; image_size=0x%lX; nt_offset=%ld; nt_bytes=%llu; optional_header_bytes=%u; required_optional_bytes=%llu; directory_count=%lu; image_limit=0x%llX.", base, image_size, dos.e_lfanew, static_cast<ULONGLONG>(sizeof(nth)), nth.FileHeader.SizeOfOptionalHeader, static_cast<ULONGLONG>(sizeof(HELPER_IMAGE_OPTIONAL_HEADER64)), nth.OptionalHeader.NumberOfRvaAndSizes, static_cast<ULONGLONG>(MKM_MAX_SIZE)); __leave; }

        export_rva = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        export_sz  = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!export_rva || !export_sz) { MkmSetFailcode(failcode, MKM_FAIL_EXPORT_DIRECTORY_MISSING, failmessage, "Loaded dependency has no export directory; module_base=%p; export_RVA=0x%lX; export_size=0x%lX; symbol=%.255s; ordinal=%u; result=STATUS_ENTRYPOINT_NOT_FOUND(0xC0000139).", base, export_rva, export_sz, func_name ? func_name : "<ordinal>", ordinal); __leave; } // st = STATUS_ENTRYPOINT_NOT_FOUND
        if (export_sz < sizeof(HELPER_IMAGE_EXPORT_DIRECTORY) ||
            !MkmRvaOk(export_rva, export_sz, image_size))
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_DIRECTORY_RANGE, failmessage, "Loaded dependency export directory extent is invalid; module_base=%p; export_RVA=0x%lX; export_size=0x%lX; minimum_directory_bytes=%llu; image_size=0x%lX.", base, export_rva, export_sz, static_cast<ULONGLONG>(sizeof(HELPER_IMAGE_EXPORT_DIRECTORY)), image_size); __leave; }

        PUCHAR ep = base + export_rva;
        ProbeForRead(ep, sizeof(HELPER_IMAGE_EXPORT_DIRECTORY), sizeof(ULONG));
        HELPER_IMAGE_EXPORT_DIRECTORY exp; RtlCopyMemory(&exp, ep, sizeof(exp));

        num_funcs = exp.NumberOfFunctions;
        num_names = exp.NumberOfNames;
        ord_base  = exp.Base;
        fn_rva    = exp.AddressOfFunctions;
        nm_rva    = exp.AddressOfNames;
        on_rva    = exp.AddressOfNameOrdinals;

        if (!num_funcs || num_funcs > MKM_MAX_EXPORTS || num_names > MKM_MAX_EXPORTS ||
            !MkmRvaOk(fn_rva, num_funcs * sizeof(ULONG), image_size) ||
            (num_names &&
             (!MkmRvaOk(nm_rva, num_names * sizeof(ULONG), image_size) ||
              !MkmRvaOk(on_rva, num_names * sizeof(USHORT), image_size))))
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_ARRAY_RANGE, failmessage, "Loaded dependency export arrays exceed validated image/count limits; module_base=%p; NumberOfFunctions=%lu; NumberOfNames=%lu; max_count=%u; AddressOfFunctions=0x%lX; AddressOfNames=0x%lX; AddressOfNameOrdinals=0x%lX; image_size=0x%lX; ordinal_base=%lu.", base, num_funcs, num_names, MKM_MAX_EXPORTS, fn_rva, nm_rva, on_rva, image_size, ord_base); __leave; }

        st = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { st = MkmFail(GetExceptionCode(), failcode, MKM_FAIL_EXPORT_HEADER_EXCEPTION, failmessage, "Exception during loaded dependency DOS/NT/export header ProbeForRead or copy; module_base=%p; export_RVA=0x%lX; export_size=0x%lX; image_size=0x%lX; symbol=%.255s; ordinal=%u; depth=%lu.", base, export_rva, export_sz, image_size, func_name ? func_name : "<ordinal>", ordinal, depth); }

    if (st == STATUS_ENTRYPOINT_NOT_FOUND) return st;
    if (!NT_SUCCESS(st))                   return st;

    // ── Phase 2: 세 export 배열을 커널 버퍼로 복사 ───────────────────
    auto* farr = static_cast<ULONG* >(MkmAlloc(static_cast<SIZE_T>(num_funcs) * sizeof(ULONG),  MKM_TAG_EXP));
    auto* narr = num_names ? static_cast<ULONG* >(MkmAlloc(static_cast<SIZE_T>(num_names) * sizeof(ULONG),  MKM_TAG_EXP)) : nullptr;
    auto* oarr = num_names ? static_cast<USHORT*>(MkmAlloc(static_cast<SIZE_T>(num_names) * sizeof(USHORT), MKM_TAG_EXP)) : nullptr;

    if (!farr || (num_names && (!narr || !oarr))) {
        MkmFree(farr, MKM_TAG_EXP); MkmFree(narr, MKM_TAG_EXP); MkmFree(oarr, MKM_TAG_EXP);
        return MkmFail(STATUS_INSUFFICIENT_RESOURCES, failcode, MKM_FAIL_EXPORT_ARRAY_ALLOC, failmessage, "ExAllocatePool2(PAGED, export arrays) returned NULL; functions=%lu; names=%lu; functions_bytes=%llu; names_bytes=%llu; ordinals_bytes=%llu; farr=%p; narr=%p; oarr=%p (released); tag=0x%08lX.", num_funcs, num_names, static_cast<ULONGLONG>(num_funcs) * sizeof(ULONG), static_cast<ULONGLONG>(num_names) * sizeof(ULONG), static_cast<ULONGLONG>(num_names) * sizeof(USHORT), farr, narr, oarr, static_cast<ULONG>(MKM_TAG_EXP));
    }

    __try {
        ProbeForRead(base + fn_rva, static_cast<SIZE_T>(num_funcs) * sizeof(ULONG), sizeof(ULONG));
        RtlCopyMemory(farr, base + fn_rva, static_cast<SIZE_T>(num_funcs) * sizeof(ULONG));
        if (num_names) {
            ProbeForRead(base + nm_rva, static_cast<SIZE_T>(num_names) * sizeof(ULONG), sizeof(ULONG));
            RtlCopyMemory(narr, base + nm_rva, static_cast<SIZE_T>(num_names) * sizeof(ULONG));
            ProbeForRead(base + on_rva, static_cast<SIZE_T>(num_names) * sizeof(USHORT), sizeof(USHORT));
            RtlCopyMemory(oarr, base + on_rva, static_cast<SIZE_T>(num_names) * sizeof(USHORT));
        }
        st = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        st = MkmFail(GetExceptionCode(), failcode, MKM_FAIL_EXPORT_ARRAY_EXCEPTION, failmessage, "Exception during loaded dependency export array ProbeForRead/copy; module_base=%p; functions_RVA=0x%lX; functions_count=%lu; names_RVA=0x%lX; ordinals_RVA=0x%lX; names_count=%lu; image_size=0x%lX.", base, fn_rva, num_funcs, nm_rva, on_rva, num_names, image_size);
        MkmFree(farr, MKM_TAG_EXP); MkmFree(narr, MKM_TAG_EXP); MkmFree(oarr, MKM_TAG_EXP);
        return st;
    }

    // ── Phase 3: 함수 RVA 탐색 ───────────────────────────────────────
    ULONG func_rva_out = 0;
    bool  found        = false;
    ULONG first_name_failure = 0;
    ULONG first_name_rva = 0, first_name_index = 0;
    NTSTATUS first_name_status = STATUS_SUCCESS;

    if (func_name)
    {
        // 이름으로 탐색 (export 이름 배열은 정렬되어 있음 — 선형 스캔 사용)
        for (ULONG i = 0; i < num_names && !found; ++i)
        {
            if (!narr[i]) continue;
            CHAR ename[256] = {};
            ULONG name_failcode = 0;
            st = MkmCopyExportString(base, narr[i], image_size, ename, sizeof(ename), &name_failcode);
            if (!NT_SUCCESS(st)) {
                if (!first_name_failure) {
                    first_name_failure = name_failcode;
                    first_name_rva = narr[i]; first_name_index = i; first_name_status = st;
                }
                continue;
            }

            if (MkmStrcmpA(ename, func_name) == 0 && oarr[i] < num_funcs) {
                func_rva_out = farr[oarr[i]];
                found = true;
            }
        }
    }
    else
    {
        // 서수로 탐색: 서수 베이스 차감 후 직접 인덱싱
        const ULONG idx = static_cast<ULONG>(ordinal) - ord_base;
        if (idx < num_funcs && farr[idx]) {
            func_rva_out = farr[idx];
            found = true;
        }
    }

    MkmFree(farr, MKM_TAG_EXP);
    MkmFree(narr, MKM_TAG_EXP);
    MkmFree(oarr, MKM_TAG_EXP);

    if (!found || !func_rva_out) {
        MkmSetFailcode(failcode, first_name_failure ? static_cast<MKM_FAIL_CODE>(first_name_failure) : MKM_FAIL_EXPORT_SYMBOL_NOT_FOUND, failmessage,
            "Export lookup found no matching usable symbol; module_base=%p; symbol=%.255s; ordinal=%u; ordinal_base=%lu; function_count=%lu; name_count=%lu; found=%u; function_RVA=0x%lX; first_name_probe_failcode=%lu; first_name_probe_reason=%s; first_name_probe_index=%lu; first_name_probe_RVA=0x%lX; probe_capacity=256; image_size=0x%lX; first_name_probe_status=%s(0x%08lX); operation=STATUS_ENTRYPOINT_NOT_FOUND(0xC0000139).",
            base, func_name ? func_name : "<ordinal>", ordinal, ord_base, num_funcs, num_names, found ? 1u : 0u, func_rva_out, first_name_failure, MkmExportStringFailureReason(first_name_failure), first_name_index, first_name_rva, image_size, MkmStatusName(first_name_status), static_cast<ULONG>(first_name_status));
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }
    if (!MkmRvaOk(func_rva_out, 1, image_size)) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_FUNCTION_RANGE, failmessage, "Resolved export function RVA is outside the dependency image; module_base=%p; function_RVA=0x%lX; image_size=0x%lX; symbol=%.255s; ordinal=%u.", base, func_rva_out, image_size, func_name ? func_name : "<ordinal>", ordinal);

    // ── Phase 4: 포워딩 익스포트 처리 ────────────────────────────────
    // RVA가 export 디렉터리 범위 내에 있으면 포워딩 문자열
    // 형식: "NTDLL.RtlAllocateHeap"  또는  "NTDLL.#123"
    if (func_rva_out >= export_rva && func_rva_out < export_rva + export_sz)
    {
        CHAR fwd[256] = {};
        st = MkmCopyExportString(base, func_rva_out, export_rva + export_sz,
            fwd, sizeof(fwd), failcode, failmessage);
        if (!NT_SUCCESS(st)) return st;

        PCHAR dot = MkmStrchr(fwd, '.');
        if (!dot || dot == fwd || !dot[1]) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_FORWARDER_SYNTAX, failmessage, "Invalid forwarded export syntax; module_base=%p; forwarder_RVA=0x%lX; forwarder=%.255s; expected MODULE.symbol or MODULE.#ordinal.", base, func_rva_out, fwd);
        *dot = '\0';

        CHAR fwd_mod[260]; MkmStrCopy(fwd_mod, fwd, sizeof(fwd_mod));
        MkmAppendDll(fwd_mod, sizeof(fwd_mod));  // "NTDLL" → "NTDLL.dll"
        PCHAR fwd_sym = dot + 1;

        PVOID fwd_base = MkmFindModule(target, fwd_mod, failcode, failmessage);
        if (!fwd_base) return STATUS_DLL_NOT_FOUND;

        if (fwd_sym[0] == '#') {
            // 포워딩 서수: "#123" → 123
            ULONG fwd_ord = 0;
            PCHAR p = fwd_sym + 1;
            if (!*p) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_FORWARDER_ORDINAL_EMPTY, failmessage, "Forwarded export ordinal is empty after #; forward_module=%.259s; forward_symbol=%.255s; source_module=%p; forwarder_RVA=0x%lX.", fwd_mod, fwd_sym, base, func_rva_out);
            for (; *p; ++p) {
                if (*p < '0' || *p > '9') return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_FORWARDER_ORDINAL_DIGIT, failmessage, "Forwarded export ordinal contains a non-decimal byte; forward_module=%.259s; forward_symbol=%.255s; byte_index=%llu; byte=0x%02X; accumulated_ordinal=%lu.", fwd_mod, fwd_sym, static_cast<ULONGLONG>(p - fwd_sym), static_cast<UCHAR>(*p), fwd_ord);
                fwd_ord = fwd_ord * 10 + static_cast<ULONG>(*p - '0');
                if (fwd_ord > MAXUSHORT) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_EXPORT_FORWARDER_ORDINAL_RANGE, failmessage, "Forwarded export ordinal exceeds USHORT range; forward_module=%.259s; forward_symbol=%.255s; accumulated_ordinal=%lu; maximum=%u.", fwd_mod, fwd_sym, fwd_ord, MAXUSHORT);
            }
            return MkmResolveExport(target, fwd_base, nullptr,
                static_cast<USHORT>(fwd_ord), out_va, depth + 1, failcode, failmessage);
        } else {
            return MkmResolveExport(target, fwd_base, fwd_sym, 0, out_va, depth + 1, failcode, failmessage);
        }
    }

    // 직접(비포워딩) 함수
    *out_va = reinterpret_cast<ULONGLONG>(base) + func_rva_out;
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑤-C  IAT 전체 해결 — local_img의 IAT 슬롯에 절대 VA를 기록
//        대상 프로세스에 한 번만 attach하여 모든 임포트 처리
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmResolveIAT(
    _In_ PEPROCESS target,
    _In_ PUCHAR    local_img,
    _In_ ULONG     img_sz,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    auto* dos = reinterpret_cast<PHELPER_IMAGE_DOS_HEADER>(local_img);
    auto* nth = reinterpret_cast<PHELPER_IMAGE_NT_HEADERS64>(local_img + dos->e_lfanew);

    if (nth->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return STATUS_SUCCESS;
    const ULONG imp_rva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const ULONG imp_sz  = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (!imp_rva || !imp_sz) return STATUS_SUCCESS;   // 임포트 없음
    if (imp_sz < sizeof(MKM_IMPORT_DESC) || !MkmRvaOk(imp_rva, imp_sz, img_sz))
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_DIRECTORY_RANGE, failmessage, "Import directory extent is invalid; import_RVA=0x%lX; import_size=0x%lX; image_size=0x%lX; descriptor_bytes=%llu.", imp_rva, imp_sz, img_sz, static_cast<ULONGLONG>(sizeof(MKM_IMPORT_DESC)));
    const ULONG headers_size = nth->OptionalHeader.SizeOfHeaders;

    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);   // 단 한 번 attach

    NTSTATUS st = STATUS_INVALID_IMAGE_FORMAT;
    for (ULONG offset = 0; offset <= imp_sz - sizeof(MKM_IMPORT_DESC);
         offset += sizeof(MKM_IMPORT_DESC))
    {
        const MKM_IMPORT_DESC desc = *reinterpret_cast<MKM_IMPORT_DESC*>(local_img + imp_rva + offset);
        if (!desc.OriginalFirstThunk && !desc.TimeDateStamp && !desc.ForwarderChain &&
            !desc.Name && !desc.FirstThunk) {
            st = STATUS_SUCCESS;
            break;
        }
        if (!desc.Name || !desc.FirstThunk || !MkmImageString(local_img, desc.Name, img_sz, 260))
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_DESCRIPTOR_NAME, failmessage, "Import descriptor name/IAT pointer is zero, outside image, or unterminated; descriptor_offset=0x%lX; Name_RVA=0x%lX; FirstThunk_RVA=0x%lX; OriginalFirstThunk_RVA=0x%lX; name_scan_limit=260; image_size=0x%lX.", offset, desc.Name, desc.FirstThunk, desc.OriginalFirstThunk, img_sz); break; }

        // Keep names stable even if a malformed IAT overlaps other image data.
        CHAR dll_name[260] = {};
        MkmStrCopy(dll_name, reinterpret_cast<PCHAR>(local_img + desc.Name), sizeof(dll_name));
        if (!dll_name[0]) { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_DLL_NAME_EMPTY, failmessage, "Import descriptor DLL name is empty; descriptor_offset=0x%lX; Name_RVA=0x%lX; FirstThunk_RVA=0x%lX.", offset, desc.Name, desc.FirstThunk); break; }

        CHAR resolved[260] = {};
        MkmStrCopy(resolved, dll_name, sizeof(resolved));
        if (MkmIsApiSet(dll_name)) {
            if (!MkmResolveApiSetAttached(target, dll_name, resolved, sizeof(resolved), failcode, failmessage)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[MKM] IAT: API set resolution failed: %s\n", dll_name);
                st = STATUS_DLL_NOT_FOUND;
                break;
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "[MKM] IAT: %s -> %s\n", dll_name, resolved);
        }
        PVOID mod_base = MkmFindModule(target, resolved, failcode, failmessage);
        if (!mod_base) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[MKM] IAT: module not in LDR: %s (from %s)\n", resolved, dll_name);
            st = STATUS_DLL_NOT_FOUND;
            break;
        }

        // 이름 정보는 OriginalFirstThunk(ILT)에서, 주소는 FirstThunk(IAT)에 씀
        const ULONG ilt_rva = desc.OriginalFirstThunk
                            ? desc.OriginalFirstThunk
                            : desc.FirstThunk;
        const ULONG iat_rva = desc.FirstThunk;

        if (iat_rva < headers_size || !MkmRvaOk(ilt_rva, sizeof(ULONGLONG), img_sz) ||
            !MkmRvaOk(iat_rva, sizeof(ULONGLONG), img_sz))
            { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_THUNK_RANGE, failmessage, "Import ILT/IAT range is invalid or IAT overlaps PE headers; module=%.259s; ILT_RVA=0x%lX; IAT_RVA=0x%lX; headers_size=0x%lX; image_size=0x%lX; required_slot_bytes=%llu.", dll_name, ilt_rva, iat_rva, headers_size, img_sz, static_cast<ULONGLONG>(sizeof(ULONGLONG))); break; }

        auto* ilt = reinterpret_cast<ULONGLONG*>(local_img + ilt_rva);
        auto* iat = reinterpret_cast<ULONGLONG*>(local_img + iat_rva);

        const ULONG ilt_count = (img_sz - ilt_rva) / sizeof(ULONGLONG);
        const ULONG iat_count = (img_sz - iat_rva) / sizeof(ULONGLONG);
        const ULONG thunk_count = ilt_count < iat_count ? ilt_count : iat_count;
        bool terminated = false;
        for (ULONG ti = 0; ti < thunk_count; ++ti)
        {
            const ULONGLONG thunk = ilt[ti];
            if (!thunk) { terminated = true; break; }
            ULONGLONG va = 0;

            if (thunk & MKM_ORDINAL_FLAG64)
            {
                if (thunk & ~(MKM_ORDINAL_FLAG64 | 0xFFFFULL))
                    { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_ORDINAL_BITS, failmessage, "Ordinal import thunk contains unsupported high bits; module=%.259s; thunk_index=%lu; thunk=0x%llX; allowed_mask=0x%llX; ILT_RVA=0x%lX; IAT_RVA=0x%lX.", dll_name, ti, thunk, MKM_ORDINAL_FLAG64 | 0xFFFFULL, ilt_rva, iat_rva); goto iat_done; }
                // 서수 임포트
                const USHORT ord = static_cast<USHORT>(thunk & 0xFFFF);
                st = MkmResolveExport(target, mod_base, nullptr, ord, &va, 0, failcode, failmessage);
            }
            else
            {
                // 이름 임포트: IBN 구조체의 Name 필드 (커널 버퍼 내)
                if (thunk > MAXULONG) { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_NAME_RVA, failmessage, "Named import thunk cannot be represented as a 32-bit RVA; module=%.259s; thunk_index=%lu; thunk=0x%llX; maximum_RVA=0x%lX.", dll_name, ti, thunk, static_cast<ULONG>(MAXULONG)); goto iat_done; }
                const ULONG ibn_rva = static_cast<ULONG>(thunk);
                if (!MkmRvaOk(ibn_rva, sizeof(USHORT) + 1, img_sz) ||
                    !MkmImageString(local_img, ibn_rva + sizeof(USHORT), img_sz))
                    { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_IMPORT_NAME, failmessage, "Import-by-name Hint/Name is outside image or lacks bounded NUL; module=%.259s; thunk_index=%lu; import_by_name_RVA=0x%lX; image_size=0x%lX; name_scan_limit=256.", dll_name, ti, ibn_rva, img_sz); goto iat_done; }
                CHAR fname[256] = {};
                MkmStrCopy(fname, reinterpret_cast<PCHAR>(local_img + ibn_rva + sizeof(USHORT)), sizeof(fname));
                if (!fname[0]) { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_SYMBOL_EMPTY, failmessage, "Import symbol name is empty; module=%.259s; thunk_index=%lu; import_by_name_RVA=0x%lX.", dll_name, ti, ibn_rva); goto iat_done; }
                st = MkmResolveExport(target, mod_base, fname, 0, &va, 0, failcode, failmessage);
            }

            if (!NT_SUCCESS(st)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[MKM] IAT: failed thunk[%lu] in %s — 0x%08lX\n",
                    ti, dll_name, static_cast<ULONG>(st));
                goto iat_done;
            }

            iat[ti] = va;   // IAT 슬롯에 해결된 VA 기록
        }
        if (!terminated) { st = MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_IAT_THUNK_TERMINATOR, failmessage, "Import thunk array has no zero terminator within both validated extents; module=%.259s; ILT_RVA=0x%lX; IAT_RVA=0x%lX; ILT_slots=%lu; IAT_slots=%lu; scanned_slots=%lu.", dll_name, ilt_rva, iat_rva, ilt_count, iat_count, thunk_count); break; }
        // A descriptor terminator inside the declared directory is mandatory.
        st = STATUS_INVALID_IMAGE_FORMAT;
    }

iat_done:
    if (st != STATUS_SUCCESS) MkmSetFailcode(failcode, MKM_FAIL_IAT_DESCRIPTOR_TERMINATOR, failmessage, "Import descriptor directory has no all-zero terminator inside its declared extent; import_RVA=0x%lX; import_size=0x%lX; image_size=0x%lX; returned=%s(0x%08lX).", imp_rva, imp_sz, img_sz, MkmStatusName(st), static_cast<ULONG>(st));
    KeUnstackDetachProcess(&apc);
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑥  베이스 재배치 (local image에 in-place 적용)
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmRelocate(
    _In_ PUCHAR    img,
    _In_ ULONG     img_sz,
    _In_ ULONGLONG preferred,   // PE 헤더의 ImageBase
    _In_ ULONGLONG actual, _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)      // 실제 원격 할당 주소
{
    const ULONGLONG delta = actual - preferred;
    if (!delta) return STATUS_SUCCESS;   // 선호 베이스 그대로 할당됨

    auto* dos = reinterpret_cast<PHELPER_IMAGE_DOS_HEADER>(img);
    auto* nth = reinterpret_cast<PHELPER_IMAGE_NT_HEADERS64>(img + dos->e_lfanew);

    if (nth->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC)
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_DIRECTORY_MISSING, failmessage, "Image moved away from preferred base but relocation directory entry is absent; preferred=0x%llX; actual=0x%llX; delta=0x%llX; NumberOfRvaAndSizes=%lu; required_directory_index=%u.", preferred, actual, delta, nth->OptionalHeader.NumberOfRvaAndSizes, IMAGE_DIRECTORY_ENTRY_BASERELOC);

    const ULONG reloc_rva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const ULONG reloc_sz  = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (!reloc_rva || reloc_sz < sizeof(MKM_BASE_RELOC) ||
        !MkmRvaOk(reloc_rva, reloc_sz, img_sz))
    {
        // .reloc 없음 + 베이스 변경 → 재배치 불가
        return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_DIRECTORY_RANGE, failmessage, "Image moved but relocation directory is missing/truncated/outside image; preferred=0x%llX; actual=0x%llX; delta=0x%llX; reloc_RVA=0x%lX; reloc_size=0x%lX; image_size=0x%lX; minimum_block_bytes=%llu.", preferred, actual, delta, reloc_rva, reloc_sz, img_sz, static_cast<ULONGLONG>(sizeof(MKM_BASE_RELOC)));
    }

    ULONG       offset = reloc_rva;
    const ULONG end    = reloc_rva + reloc_sz;

    while (offset < end)
    {
        if (end - offset < sizeof(MKM_BASE_RELOC)) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_BLOCK_HEADER, failmessage, "Relocation directory ends in a truncated block header; block_offset=0x%lX; directory_end=0x%lX; remaining=%lu; required=%llu; delta=0x%llX.", offset, end, end - offset, static_cast<ULONGLONG>(sizeof(MKM_BASE_RELOC)), delta);
        const MKM_BASE_RELOC blk = *reinterpret_cast<MKM_BASE_RELOC*>(img + offset);
        if (blk.SizeOfBlock < sizeof(MKM_BASE_RELOC) || blk.SizeOfBlock > end - offset ||
            (blk.SizeOfBlock - sizeof(MKM_BASE_RELOC)) % sizeof(USHORT))
            return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_BLOCK_SIZE, failmessage, "Relocation block size is too small, exceeds directory, or has an odd entry payload; block_offset=0x%lX; VirtualAddress=0x%lX; SizeOfBlock=%lu; remaining=%lu; minimum_block=%llu; entry_bytes=%llu.", offset, blk.VirtualAddress, blk.SizeOfBlock, end - offset, static_cast<ULONGLONG>(sizeof(MKM_BASE_RELOC)), static_cast<ULONGLONG>(sizeof(USHORT)));

        const ULONG count = (blk.SizeOfBlock - sizeof(MKM_BASE_RELOC)) / sizeof(USHORT);
        auto* entries = reinterpret_cast<USHORT*>(img + offset + sizeof(MKM_BASE_RELOC));

        for (ULONG e = 0; e < count; ++e)
        {
            const USHORT type = entries[e] >> 12;
            const USHORT off  = entries[e] & 0x0FFF;

            if (type == MKM_REL_ABSOLUTE) continue;   // 패딩
            if (type != MKM_REL_DIR64) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_TYPE, failmessage, "Unsupported relocation type; block_offset=0x%lX; block_RVA=0x%lX; entry_index=%lu; entry=0x%04X; type=%u; supported_types=ABSOLUTE(0)/DIR64(10); entry_offset=0x%X.", offset, blk.VirtualAddress, e, entries[e], type, off);

            if (blk.VirtualAddress > MAXULONG - off) return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_RVA_OVERFLOW, failmessage, "Relocation patch RVA addition overflows ULONG; block_offset=0x%lX; block_RVA=0x%lX; entry_index=%lu; entry_offset=0x%X; image_size=0x%lX.", offset, blk.VirtualAddress, e, off, img_sz);
            const ULONG patch_rva = blk.VirtualAddress + off;
            if (!MkmRvaOk(patch_rva, sizeof(ULONGLONG), img_sz))
                return MkmFail(STATUS_INVALID_IMAGE_FORMAT, failcode, MKM_FAIL_RELOCATE_PATCH_RANGE, failmessage, "Relocation DIR64 patch exceeds image extent; block_offset=0x%lX; entry_index=%lu; patch_RVA=0x%lX; patch_bytes=%llu; image_size=0x%lX; delta=0x%llX.", offset, e, patch_rva, static_cast<ULONGLONG>(sizeof(ULONGLONG)), img_sz, delta);

            auto* p = reinterpret_cast<ULONGLONG*>(img + patch_rva);
            *p += delta;
        }

        offset += blk.SizeOfBlock;
    }

    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑦  대상 프로세스에 SizeOfImage 크기 메모리 확보
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmAllocRemote(
    _In_  HANDLE    proc_h,
    _In_  ULONG     size,
    _In_  ULONGLONG preferred,
    _Out_ ULONGLONG* out_base,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    *out_base = 0;

    // 선호 베이스로 먼저 시도
    PVOID  va = reinterpret_cast<PVOID>(preferred);
    SIZE_T sz = size;
    NTSTATUS st = ZwAllocateVirtualMemory(proc_h, &va, 0, &sz,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    const NTSTATUS first_status = st;

    if (!NT_SUCCESS(st)) {
        // 선호 베이스 사용 중 → OS가 ASLR 주소 선택
        va = nullptr; sz = size;
        st = ZwAllocateVirtualMemory(proc_h, &va, 0, &sz,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    if (NT_SUCCESS(st)) *out_base = reinterpret_cast<ULONGLONG>(va);
    else MkmSetFailcode(failcode, MKM_FAIL_REMOTE_ALLOC_FALLBACK, failmessage, "ZwAllocateVirtualMemory failed at final allocation attempt; proc_h=%p; preferred_base=0x%llX; requested_size=%lu; first_status=%s(0x%08lX); fallback_requested_base=NULL; zero_bits=0; allocation_type=0x%lX; protection=PAGE_READWRITE(0x4); output_base=%p; output_size=%llu; returned=%s(0x%08lX).", proc_h, preferred, size, MkmStatusName(first_status), static_cast<ULONG>(first_status), static_cast<ULONG>(MEM_RESERVE | MEM_COMMIT), va, static_cast<ULONGLONG>(sz), MkmStatusName(st), static_cast<ULONG>(st));
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑧  local image → 대상 프로세스 원격 VA 기록
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmWriteRemote(
    _In_ PEPROCESS  target,
    _In_ ULONGLONG  remote_base,
    _In_ PUCHAR     local_img,
    _In_ ULONG      img_sz,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    NTSTATUS   st  = STATUS_SUCCESS;
    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);
    __try {
        ProbeForWrite(reinterpret_cast<PVOID>(remote_base), img_sz, 1);
        RtlCopyMemory(reinterpret_cast<PVOID>(remote_base), local_img, img_sz);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { st = MkmFail(GetExceptionCode(), failcode, MKM_FAIL_REMOTE_WRITE_EXCEPTION, failmessage, "Exception during ProbeForWrite(remote image) or RtlCopyMemory while attached; target=%p; destination=0x%llX; source=%p; bytes=%lu; probe_alignment=1.", target, remote_base, local_img, img_sz); }
    KeUnstackDetachProcess(&apc);
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑨  섹션 Characteristics → ZwProtectVirtualMemory
// ═══════════════════════════════════════════════════════════════════════

// Read-only query ABI: WDK ntddk.h ProcessMitigationPolicy=52,
// ProcessProtectionInformation=61, ProcessDynamicCodePolicy=2. The native
// mitigation query includes its policy selector (unlike the Win32 output-only
// PROCESS_MITIGATION_DYNAMIC_CODE_POLICY). The PHNT definitions document the
// selector + 4-byte flags and the one-byte PS_PROTECTION result:
// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
// No EPROCESS offsets, process policy setters, or protection changes are used.
struct MKM_DYNAMIC_CODE_QUERY
{
    ULONG Policy;
    ULONG Flags;
};
static_assert(sizeof(MKM_DYNAMIC_CODE_QUERY) == 8, "Native mitigation query ABI mismatch");
static_assert(FIELD_OFFSET(MKM_DYNAMIC_CODE_QUERY, Flags) == 4, "Mitigation flags offset mismatch");

struct MKM_PRE_PROTECT_SNAPSHOT
{
    MEMORY_BASIC_INFORMATION Page;
    SIZE_T PageReturnLength;
    NTSTATUS PageStatus;
    ULONG DynamicFlags;
    ULONG DynamicReturnLength;
    NTSTATUS DynamicStatus;
    bool DynamicPolicyValid;
    UCHAR ProtectionLevel;
    ULONG ProtectionReturnLength;
    NTSTATUS ProtectionStatus;
    bool FirstRegionCoversRequest;
    bool PageRangeValid;
};

inline void MkmCapturePreProtect(HANDLE proc_h, ULONGLONG requested_va,
    SIZE_T requested_size, MKM_PRE_PROTECT_SNAPSHOT* snapshot)
{
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    MKM_DYNAMIC_CODE_QUERY dynamic = { 2, 0 };
    snapshot->DynamicStatus = ZwQueryInformationProcess(proc_h,
        static_cast<PROCESSINFOCLASS>(52), &dynamic, sizeof(dynamic),
        &snapshot->DynamicReturnLength);
    snapshot->DynamicPolicyValid = NT_SUCCESS(snapshot->DynamicStatus) &&
        snapshot->DynamicReturnLength == sizeof(dynamic) && dynamic.Policy == 2;
    if (snapshot->DynamicPolicyValid)
        snapshot->DynamicFlags = dynamic.Flags;

    UCHAR protection = 0;
    snapshot->ProtectionStatus = ZwQueryInformationProcess(proc_h,
        static_cast<PROCESSINFOCLASS>(61), &protection, sizeof(protection),
        &snapshot->ProtectionReturnLength);
    if (NT_SUCCESS(snapshot->ProtectionStatus) &&
        snapshot->ProtectionReturnLength == sizeof(protection))
        snapshot->ProtectionLevel = protection;

    // Capture the first region last, immediately before the protection call.
    // This is a point-in-time observation, not a lock on the target's memory.
    snapshot->PageStatus = ZwQueryVirtualMemory(proc_h,
        reinterpret_cast<PVOID>(requested_va), MemoryBasicInformation,
        &snapshot->Page, sizeof(snapshot->Page), &snapshot->PageReturnLength);
    if (!NT_SUCCESS(snapshot->PageStatus) ||
        snapshot->PageReturnLength != sizeof(snapshot->Page)) return;

    const ULONGLONG base = reinterpret_cast<ULONGLONG>(snapshot->Page.BaseAddress);
    const ULONGLONG extent = static_cast<ULONGLONG>(snapshot->Page.RegionSize);
    const ULONGLONG maximum = ~static_cast<ULONGLONG>(0);
    snapshot->PageRangeValid = extent && base <= requested_va &&
        requested_va - base < extent && extent <= maximum - base;
    if (!snapshot->PageRangeValid || !requested_size ||
        requested_va > maximum - requested_size) return;
    const ULONGLONG raw_end = requested_va + requested_size;
    if (raw_end > maximum - (PAGE_SIZE - 1)) return;
    const ULONGLONG page_start = requested_va & ~static_cast<ULONGLONG>(PAGE_SIZE - 1);
    const ULONGLONG page_end = (raw_end + PAGE_SIZE - 1) & ~static_cast<ULONGLONG>(PAGE_SIZE - 1);
    snapshot->FirstRegionCoversRequest = base <= page_start &&
        page_end >= base && page_end - base <= extent;
}

inline PCSTR MkmMemoryStateName(ULONG state)
{
    switch (state) {
    case MEM_COMMIT: return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE: return "MEM_FREE";
    default: return "UNKNOWN_STATE";
    }
}
inline PCSTR MkmMemoryTypeName(ULONG type)
{
    switch (type) {
    case MEM_PRIVATE: return "MEM_PRIVATE";
    case MEM_MAPPED: return "MEM_MAPPED";
    case MEM_IMAGE: return "MEM_IMAGE";
    default: return "UNKNOWN_TYPE";
    }
}
inline PCSTR MkmProcessProtectionTypeName(UCHAR type)
{
    switch (type) {
    case 0: return "None";
    case 1: return "ProtectedLight/PPL";
    case 2: return "Protected";
    default: return "Unknown";
    }
}
inline PCSTR MkmProcessProtectionSignerName(UCHAR signer)
{
    switch (signer) {
    case 0: return "None";
    case 1: return "Authenticode";
    case 2: return "CodeGen";
    case 3: return "Antimalware";
    case 4: return "Lsa";
    case 5: return "Windows";
    case 6: return "WinTcb";
    case 7: return "WinSystem";
    case 8: return "App";
    default: return "Unknown";
    }
}

inline void MkmAppendDiagnostic(PCHAR message, PCSTR format, ...)
{
    if (!message) return;
    const ULONG used = MkmMessageLength(message);
    va_list args;
    va_start(args, format);
    const NTSTATUS formatted = RtlStringCbVPrintfA(message + used,
        MKM_FAILMESSAGE_BYTES - used, format, args);
    va_end(args);
    MkmFinishMessage(message, !NT_SUCCESS(formatted));
}

inline void MkmAppendPreProtect(PCHAR message, const MKM_PRE_PROTECT_SNAPSHOT& snapshot)
{
    if (!message) return;
    if (NT_SUCCESS(snapshot.PageStatus) &&
        snapshot.PageReturnLength == sizeof(snapshot.Page) && snapshot.PageRangeValid) {
        const auto& p = snapshot.Page;
        MkmAppendDiagnostic(message,
            "pre_page{q=0x%08lX,bytes=%llu,State=%s(0x%lX),Base=%p,RegionSize=0x%llX,first_region_only=1,covers_page_request=%u",
            static_cast<ULONG>(snapshot.PageStatus), static_cast<ULONGLONG>(snapshot.PageReturnLength),
            MkmMemoryStateName(p.State), p.State, p.BaseAddress, static_cast<ULONGLONG>(p.RegionSize),
            snapshot.FirstRegionCoversRequest ? 1u : 0u);
        if (p.State == MEM_FREE)
            MkmAppendDiagnostic(message, ",Type/Protect/AllocationProtect/AllocationBase=UNDEFINED(MEM_FREE)}; ");
        else if (p.State == MEM_RESERVE)
            MkmAppendDiagnostic(message,
                ",Type=%s(0x%lX),Protect=UNDEFINED(MEM_RESERVE),AllocationProtect=%s(0x%lX),AllocationBase=%p}; ",
                MkmMemoryTypeName(p.Type), p.Type, MkmProtectionName(p.AllocationProtect),
                p.AllocationProtect, p.AllocationBase);
        else
            MkmAppendDiagnostic(message,
                ",Type=%s(0x%lX),Protect=%s(0x%lX),AllocationProtect=%s(0x%lX),AllocationBase=%p}; ",
                MkmMemoryTypeName(p.Type), p.Type, MkmProtectionName(p.Protect), p.Protect,
                MkmProtectionName(p.AllocationProtect), p.AllocationProtect, p.AllocationBase);
    } else MkmAppendDiagnostic(message,
        "pre_page{UNAVAILABLE,q=%s(0x%08lX),bytes=%llu,required=%llu,range_valid=%u,first_region_only=1}; ",
        MkmStatusName(snapshot.PageStatus), static_cast<ULONG>(snapshot.PageStatus),
        static_cast<ULONGLONG>(snapshot.PageReturnLength), static_cast<ULONGLONG>(sizeof(snapshot.Page)),
        snapshot.PageRangeValid ? 1u : 0u);

    if (snapshot.DynamicPolicyValid)
        MkmAppendDiagnostic(message,
            "pre_dynamic{q=0x%08lX,bytes=%lu,Flags=0x%lX,ProhibitDynamicCode=%u,AllowThreadOptOut=%u,AllowRemoteDowngrade=%u,AuditProhibitDynamicCode=%u}; ",
            static_cast<ULONG>(snapshot.DynamicStatus), snapshot.DynamicReturnLength, snapshot.DynamicFlags,
            snapshot.DynamicFlags & 1u, (snapshot.DynamicFlags >> 1) & 1u,
            (snapshot.DynamicFlags >> 2) & 1u, (snapshot.DynamicFlags >> 3) & 1u);
    else MkmAppendDiagnostic(message,
        "pre_dynamic{UNAVAILABLE,q=%s(0x%08lX),bytes=%lu,required=8,payload_valid=0}; ",
        MkmStatusName(snapshot.DynamicStatus), static_cast<ULONG>(snapshot.DynamicStatus), snapshot.DynamicReturnLength);

    if (NT_SUCCESS(snapshot.ProtectionStatus) && snapshot.ProtectionReturnLength == sizeof(UCHAR)) {
        const UCHAR type = snapshot.ProtectionLevel & 7u;
        const UCHAR audit = (snapshot.ProtectionLevel >> 3) & 1u;
        const UCHAR signer = snapshot.ProtectionLevel >> 4;
        MkmAppendDiagnostic(message,
            "pre_protection{q=0x%08lX,bytes=%lu,Level=0x%02X,Type=%s(%u),Audit=%u,Signer=%s(%u)}; ",
            static_cast<ULONG>(snapshot.ProtectionStatus), snapshot.ProtectionReturnLength,
            static_cast<ULONG>(snapshot.ProtectionLevel), MkmProcessProtectionTypeName(type),
            static_cast<ULONG>(type), static_cast<ULONG>(audit), MkmProcessProtectionSignerName(signer),
            static_cast<ULONG>(signer));
    } else MkmAppendDiagnostic(message,
        "pre_protection{UNAVAILABLE,q=%s(0x%08lX),bytes=%lu,required=1}; ",
        MkmStatusName(snapshot.ProtectionStatus), static_cast<ULONG>(snapshot.ProtectionStatus), snapshot.ProtectionReturnLength);
}

inline NTSTATUS MkmFailProtection(NTSTATUS status, ULONG* failcode, MKM_FAIL_CODE code,
    PCHAR failmessage, PCSTR stage, HANDLE proc_h, ULONGLONG requested_va, SIZE_T requested_size,
    ULONG requested_protect, PVOID output_va, SIZE_T output_size, ULONG output_old_protect,
    const MKM_PRE_PROTECT_SNAPSHOT& snapshot, PHELPER_IMAGE_SECTION_HEADER section = nullptr,
    ULONG section_index = 0)
{
    // Diagnostic queries can fail independently. Only the protection operation
    // claims the primary failure, and all its earlier failure facts are preserved.
    if (!MkmClaimFailure(failcode, code, failmessage)) return status;
    if (!failmessage) return status;
    const NTSTATUS formatted = MkmPrint(failmessage, MKM_FAILMESSAGE_BYTES,
        "failcode=%lu; NTSTATUS=%s(0x%08lX); ZwProtectVirtualMemory(%s) failed; proc_h=%p; requested_VA=0x%llX; requested_size=%llu; requested_protect=%s(0x%lX); ",
        static_cast<ULONG>(code), MkmStatusName(status), static_cast<ULONG>(status), stage, proc_h,
        requested_va, static_cast<ULONGLONG>(requested_size), MkmProtectionName(requested_protect), requested_protect);
    MkmFinishMessage(failmessage, !NT_SUCCESS(formatted));
    if (section) MkmAppendDiagnostic(failmessage, "section_index=%lu; section_name=%.8s; ",
        section_index, reinterpret_cast<PCSTR>(section->Name));
    MkmAppendPreProtect(failmessage, snapshot);
    MkmAppendDiagnostic(failmessage,
        "output_VA=%p; output_size=%llu; output_old_protect=0x%lX(untrusted_on_failure)",
        output_va, static_cast<ULONGLONG>(output_size), output_old_protect);
    if (section) MkmAppendDiagnostic(failmessage,
        "; RVA=0x%lX; VirtualSize=0x%lX; RawSize=0x%lX; Characteristics=0x%lX",
        section->VirtualAddress, section->Misc.VirtualSize, section->SizeOfRawData, section->Characteristics);
    return status;
}

inline NTSTATUS MkmProtectSections(
    _In_ HANDLE                       proc_h,
    _In_ ULONGLONG                    remote_base,
    _In_ ULONG                        img_sz,
    _In_ ULONG                        headers_size,
    _In_ PHELPER_IMAGE_SECTION_HEADER sects,
    _In_ USHORT                       nsect,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    PVOID image_va = reinterpret_cast<PVOID>(remote_base);
    SIZE_T image_size = img_sz;
    ULONG prior_protection = 0;
    MKM_PRE_PROTECT_SNAPSHOT snapshot;
    MkmCapturePreProtect(proc_h, remote_base, image_size, &snapshot);
    NTSTATUS status = ZwProtectVirtualMemory(proc_h, &image_va, &image_size, PAGE_NOACCESS, &prior_protection);
    if (!NT_SUCCESS(status)) return MkmFailProtection(status, failcode, MKM_FAIL_PROTECT_IMAGE,
        failmessage, "image", proc_h, remote_base, img_sz, PAGE_NOACCESS,
        image_va, image_size, prior_protection, snapshot);
    image_va = reinterpret_cast<PVOID>(remote_base);
    image_size = headers_size;
    MkmCapturePreProtect(proc_h, remote_base, image_size, &snapshot);
    status = ZwProtectVirtualMemory(proc_h, &image_va, &image_size, PAGE_READONLY, &prior_protection);
    if (!NT_SUCCESS(status)) return MkmFailProtection(status, failcode, MKM_FAIL_PROTECT_HEADERS,
        failmessage, "headers", proc_h, remote_base, headers_size, PAGE_READONLY,
        image_va, image_size, prior_protection, snapshot);
    for (USHORT i = 0; i < nsect; ++i)
    {
        const auto& s = sects[i];
        const ULONG span = s.Misc.VirtualSize > s.SizeOfRawData ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (!span) continue;

        PVOID  va      = reinterpret_cast<PVOID>(remote_base + s.VirtualAddress);
        SIZE_T sz      = span;
        ULONG  protect = MkmSectProt(s.Characteristics);
        ULONG  old_p   = 0;

        MkmCapturePreProtect(proc_h, remote_base + s.VirtualAddress, sz, &snapshot);
        NTSTATUS st = ZwProtectVirtualMemory(proc_h, &va, &sz, protect, &old_p);
        if (!NT_SUCCESS(st)) return MkmFailProtection(st, failcode, MKM_FAIL_PROTECT_SECTION,
            failmessage, "section", proc_h, remote_base + s.VirtualAddress, span, protect,
            va, sz, old_p, snapshot, &sects[i], i);
    }
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  ⑪  DllMain 호출 — 39-byte x64 트램폴린 stub
//
//  Stub 레이아웃 (thread entry: RSP ≡ 8 mod 16 at entry):
//
//   +00  48 83 EC 28       sub  rsp, 0x28       ; shadow space + 정렬
//   +04  48 B9 [8]         mov  rcx, hModule    ; arg1 = 매핑된 베이스
//   +0E  BA 01 00 00 00    mov  edx, 1          ; arg2 = DLL_PROCESS_ATTACH
//   +13  45 33 C0          xor  r8d, r8d        ; arg3 = NULL
//   +16  48 B8 [8]         mov  rax, DllMain    ; 대상 VA
//   +20  FF D0             call rax
//   +22  48 83 C4 28       add  rsp, 0x28
//   +26  C3                ret
//
//  패치 오프셋: hModule @ +6,  DllMain @ +24
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmCallDllMain(
    _In_ PEPROCESS  owner,
    _In_ PEPROCESS  target,
    _In_ HANDLE     proc_h,
    _In_ ULONGLONG  remote_base,
    _In_ ULONGLONG  dll_main_va,
    _Out_ bool*    retain_image,
    _Inout_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    UNREFERENCED_PARAMETER(owner);
    *retain_image = false;
    if (!g_MkmCreateThread) return MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_DLL_MAIN_ROUTINE, failmessage, "RtlCreateUserThread routine is unavailable; target=%p; proc_h=%p; image_base=0x%llX; DllMain=0x%llX; no thread was created.", target, proc_h, remote_base, dll_main_va);

    // ── stub 구성 ──────────────────────────────────────────────────
    UCHAR stub[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 0x28
        0x48, 0xB9,                          // mov  rcx, imm64   (+6)
              0,0,0,0,0,0,0,0,
        0xBA, 0x01, 0x00, 0x00, 0x00,       // mov  edx, 1
        0x45, 0x33, 0xC0,                   // xor  r8d, r8d
        0x48, 0xB8,                          // mov  rax, imm64   (+24)
              0,0,0,0,0,0,0,0,
        0xFF, 0xD0,                          // call rax
        0x48, 0x83, 0xC4, 0x28,            // add  rsp, 0x28
        0xC3                                // ret
    };
    static_assert(sizeof(stub) == 39, "DllMain trampoline length mismatch");
    RtlCopyMemory(stub + 6, &remote_base, sizeof(remote_base));
    RtlCopyMemory(stub + 24, &dll_main_va, sizeof(dll_main_va));

    // MapDll holds process exit synchronization for this entire operation.
    PVOID  stub_va = nullptr;
    SIZE_T stub_sz = sizeof(stub);
    NTSTATUS st = ZwAllocateVirtualMemory(proc_h, &stub_va, 0, &stub_sz,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) return MkmFail(st, failcode, MKM_FAIL_DLL_MAIN_STUB_ALLOC, failmessage, "ZwAllocateVirtualMemory(DllMain stub) failed; proc_h=%p; requested_base=NULL; zero_bits=0; requested_size=%llu; allocation_type=0x%lX; protect=PAGE_READWRITE(0x4); output_base=%p; output_size=%llu; image_base=0x%llX; DllMain=0x%llX.", proc_h, static_cast<ULONGLONG>(sizeof(stub)), static_cast<ULONG>(MEM_RESERVE | MEM_COMMIT), stub_va, static_cast<ULONGLONG>(stub_sz), remote_base, dll_main_va);

    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);
    bool ok = false;
    __try {
        ProbeForWrite(stub_va, sizeof(stub), 1);
        RtlCopyMemory(stub_va, stub, sizeof(stub));
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { st = MkmFail(GetExceptionCode(), failcode, MKM_FAIL_DLL_MAIN_STUB_WRITE, failmessage, "Exception during ProbeForWrite/RtlCopyMemory for DllMain stub; target=%p; proc_h=%p; stub_base=%p; bytes=%llu; probe_alignment=1; image_base=0x%llX; DllMain=0x%llX.", target, proc_h, stub_va, static_cast<ULONGLONG>(sizeof(stub)), remote_base, dll_main_va); }
    KeUnstackDetachProcess(&apc);

    if (!ok) {
        SIZE_T z = 0; ZwFreeVirtualMemory(proc_h, &stub_va, &z, MEM_RELEASE);
        return st;
    }

    // Protect/flush must succeed before any target thread can execute the stub.
    ULONG old_protection = 0;
    SIZE_T protect_size = sizeof(stub);
    PVOID protect_base = stub_va;
    MKM_PRE_PROTECT_SNAPSHOT snapshot;
    MkmCapturePreProtect(proc_h, reinterpret_cast<ULONGLONG>(stub_va), protect_size, &snapshot);
    st = ZwProtectVirtualMemory(proc_h, &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protection);
    if (!NT_SUCCESS(st)) {
        MkmFailProtection(st, failcode, MKM_FAIL_DLL_MAIN_STUB_PROTECT, failmessage,
            "DllMain stub", proc_h, reinterpret_cast<ULONGLONG>(stub_va), sizeof(stub),
            PAGE_EXECUTE_READ, protect_base, protect_size, old_protection, snapshot);
        SIZE_T z = 0; ZwFreeVirtualMemory(proc_h, &stub_va, &z, MEM_RELEASE);
        return st;
    }
    st = g_MkmFlushCache(proc_h, stub_va, sizeof(stub));
    if (!NT_SUCCESS(st)) {
        MkmSetFailcode(failcode, MKM_FAIL_DLL_MAIN_STUB_FLUSH, failmessage, "ZwFlushInstructionCache(DllMain stub) failed; proc_h=%p; stub_base=%p; bytes=%llu; returned=%s(0x%08lX); thread not started.", proc_h, stub_va, static_cast<ULONGLONG>(sizeof(stub)), MkmStatusName(st), static_cast<ULONG>(st));
        SIZE_T z = 0; ZwFreeVirtualMemory(proc_h, &stub_va, &z, MEM_RELEASE);
        return st;
    }

    // 스레드 생성 (CREATE_SUSPENDED)
    HANDLE    thread_h  = nullptr;
    CLIENT_ID cid       = {};
    st = g_MkmCreateThread(proc_h, nullptr, TRUE,
        0, 0, 0, stub_va, nullptr, &thread_h, &cid);

    if (st != STATUS_SUCCESS || !thread_h) {
        // A returned handle, or success without a handle, cannot prove no thread exists.
        *retain_image = thread_h != nullptr || NT_SUCCESS(st);
        if (thread_h) ZwClose(thread_h);
        if (!*retain_image) {
            SIZE_T z = 0; ZwFreeVirtualMemory(proc_h, &stub_va, &z, MEM_RELEASE);
        }
        return MkmFail(NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st, failcode, MKM_FAIL_DLL_MAIN_THREAD_CREATE, failmessage, "RtlCreateUserThread failed or returned no usable handle; proc_h=%p; security=NULL; create_suspended=TRUE; stack_zero_bits=0; stack_reserve=0; stack_commit=0; start_address=%p; start_parameter=NULL; output_thread_handle=%p; output_pid=%p; output_tid=%p; API_return=%s(0x%08lX); retained_image=%u; image_base=0x%llX; DllMain=0x%llX.", proc_h, stub_va, thread_h, cid.UniqueProcess, cid.UniqueThread, MkmStatusName(st), static_cast<ULONG>(st), *retain_image ? 1u : 0u, remote_base, dll_main_va);
    }

    // Creation is irreversible: retain the image on every unproven/failed initialization.
    *retain_image = true;
    PETHREAD tobj = nullptr;
    st = ObReferenceObjectByHandle(thread_h, SYNCHRONIZE, *PsThreadType,
        KernelMode, reinterpret_cast<PVOID*>(&tobj), nullptr);
    if (!NT_SUCCESS(st)) {
        MkmSetFailcode(failcode, MKM_FAIL_DLL_MAIN_THREAD_REFERENCE, failmessage, "ObReferenceObjectByHandle(thread_handle=%p, desired_access=SYNCHRONIZE, type=Thread, mode=KernelMode) failed; output_thread=%p; returned=%s(0x%08lX); image/stub retained; suspended thread is not resumed.", thread_h, tobj, MkmStatusName(st), static_cast<ULONG>(st));
        ZwClose(thread_h); // Do not resume or free storage without a referenced thread.
        return st;
    }
    const PEPROCESS actual_thread_process = PsGetThreadProcess(tobj);
    const HANDLE actual_thread_id = PsGetThreadId(tobj);
    if (actual_thread_process != target || actual_thread_id != cid.UniqueThread) {
        ZwClose(thread_h);
        ObDereferenceObject(tobj);
        return MkmFail(STATUS_INVALID_HANDLE, failcode, MKM_FAIL_DLL_MAIN_THREAD_IDENTITY, failmessage, "Created thread identity mismatch; thread=%p; expected_process=%p; actual_process=%p; expected_tid=%p; actual_tid=%p; image/stub retained and thread not resumed.", tobj, target, actual_thread_process, cid.UniqueThread, actual_thread_id);
    }

    // Use a kernel handle to the referenced object so caller handle reuse cannot redirect resume.
    HANDLE resume_h = nullptr;
    st = ObOpenObjectByPointer(tobj, OBJ_KERNEL_HANDLE, nullptr,
        THREAD_SUSPEND_RESUME, *PsThreadType, KernelMode, &resume_h);
    ZwClose(thread_h);
    if (!NT_SUCCESS(st)) {
        MkmSetFailcode(failcode, MKM_FAIL_DLL_MAIN_RESUME_HANDLE, failmessage, "ObOpenObjectByPointer(thread=%p, attributes=OBJ_KERNEL_HANDLE, desired_access=THREAD_SUSPEND_RESUME, type=Thread, mode=KernelMode) failed; output_resume_handle=%p; returned=%s(0x%08lX); image/stub retained; thread not resumed.", tobj, resume_h, MkmStatusName(st), static_cast<ULONG>(st));
        ObDereferenceObject(tobj);
        return st;
    }
    st = ZwResumeThread(resume_h, nullptr);
    ZwClose(resume_h);
    if (!NT_SUCCESS(st)) {
        MkmSetFailcode(failcode, MKM_FAIL_DLL_MAIN_RESUME, failmessage, "ZwResumeThread(handle=%p, previous_suspend_count=NULL) failed; thread=%p; returned=%s(0x%08lX); image/stub retained.", resume_h, tobj, MkmStatusName(st), static_cast<ULONG>(st));
        ObDereferenceObject(tobj);
        return st;
    }

    // PETHREAD keeps the object alive after handle close. Only a signaled wait permits free.
    LARGE_INTEGER timeout;
    timeout.QuadPart = -50000000LL;
    st = KeWaitForSingleObject(tobj, Executive, KernelMode, FALSE, &timeout);
    if (st != STATUS_SUCCESS) {
        ObDereferenceObject(tobj);
        return MkmFail(st == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT :
            (NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st), failcode, MKM_FAIL_DLL_MAIN_WAIT, failmessage, "KeWaitForSingleObject(thread=%p, reason=Executive, mode=KernelMode, alertable=FALSE, timeout_100ns=%lld [5 seconds relative]) did not signal success; API_return=%s(0x%08lX); image_base=0x%llX; stub=%p; DllMain=0x%llX; image/stub retained because completion is unproven.", tobj, timeout.QuadPart, MkmStatusName(st), static_cast<ULONG>(st), remote_base, stub_va, dll_main_va);
    }

    HANDLE query_h = nullptr;
    st = ObOpenObjectByPointer(tobj, OBJ_KERNEL_HANDLE, nullptr,
        THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &query_h);
    if (!NT_SUCCESS(st)) MkmSetFailcode(failcode, MKM_FAIL_DLL_MAIN_QUERY_HANDLE, failmessage, "ObOpenObjectByPointer(completed_thread=%p, attributes=OBJ_KERNEL_HANDLE, desired_access=THREAD_QUERY_INFORMATION, type=Thread, mode=KernelMode) failed; query_handle=%p; returned=%s(0x%08lX); DllMain result unavailable.", tobj, query_h, MkmStatusName(st), static_cast<ULONG>(st));
    if (NT_SUCCESS(st)) {
        THREAD_BASIC_INFORMATION basic = {};
        ULONG returned_size = 0;
        st = ZwQueryInformationThread(query_h, ThreadBasicInformation,
            &basic, sizeof(basic), &returned_size);
        ZwClose(query_h);
        if (!NT_SUCCESS(st)) MkmSetFailcode(failcode, MKM_FAIL_DLL_MAIN_QUERY, failmessage, "ZwQueryInformationThread(query_handle=%p, class=ThreadBasicInformation, requested_bytes=%llu) failed; returned_bytes=%lu; returned=%s(0x%08lX); DllMain result unavailable.", query_h, static_cast<ULONGLONG>(sizeof(basic)), returned_size, MkmStatusName(st), static_cast<ULONG>(st));
        if (NT_SUCCESS(st)) {
            if (returned_size < sizeof(basic))
                st = MkmFail(STATUS_UNSUCCESSFUL, failcode, MKM_FAIL_DLL_MAIN_QUERY_SIZE, failmessage, "ZwQueryInformationThread succeeded but THREAD_BASIC_INFORMATION result is truncated; returned_bytes=%lu; required_bytes=%llu; query_handle=%p; ExitStatus=0x%08lX (not trusted).", returned_size, static_cast<ULONGLONG>(sizeof(basic)), query_h, static_cast<ULONG>(basic.ExitStatus));
            else if (!basic.ExitStatus)
                st = MkmFail(STATUS_DLL_INIT_FAILED, failcode, MKM_FAIL_DLL_MAIN_FALSE, failmessage, "Completed DllMain thread returned zero/FALSE; ExitStatus=0x%08lX; image_base=0x%llX; DllMain=0x%llX; thread_result_bytes=%lu; initialization failed.", static_cast<ULONG>(basic.ExitStatus), remote_base, dll_main_va, returned_size);
            else if (!NT_SUCCESS(basic.ExitStatus))
                st = MkmFail(basic.ExitStatus, failcode, MKM_FAIL_DLL_MAIN_EXIT_STATUS, failmessage, "Completed DllMain thread exit value has failing NTSTATUS bits; ExitStatus=%s(0x%08lX); image_base=0x%llX; DllMain=0x%llX; thread_result_bytes=%lu; exception vs DLL return cannot be distinguished from this value alone.", MkmStatusName(basic.ExitStatus), static_cast<ULONG>(basic.ExitStatus), remote_base, dll_main_va, returned_size);
            else
                st = STATUS_SUCCESS;
        }
    }
    ObDereferenceObject(tobj);

    // Completion is proven even if exit-status observation failed.
    const PVOID released_stub_base = stub_va;
    SIZE_T z = 0;
    const NTSTATUS free_st = ZwFreeVirtualMemory(proc_h, &stub_va, &z, MEM_RELEASE);
    if (st == STATUS_SUCCESS && !NT_SUCCESS(free_st)) st = MkmFail(free_st, failcode, MKM_FAIL_DLL_MAIN_STUB_FREE, failmessage, "ZwFreeVirtualMemory(completed DllMain stub) failed; proc_h=%p; requested_base=%p; requested_size=0; free_type=MEM_RELEASE; output_base=%p; output_size=%llu; image_base=0x%llX; DllMain completed.", proc_h, released_stub_base, stub_va, static_cast<ULONGLONG>(z), remote_base);
    if (st == STATUS_SUCCESS) *retain_image = false;
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
//  통합 오케스트레이터
// ═══════════════════════════════════════════════════════════════════════

inline NTSTATUS MkmMapDll(
    _In_  PEPROCESS  owner,
    _In_  ULONGLONG  target_pid,
    _In_  PCWSTR     image_path,
    _In_  BOOLEAN    only_mapping,
    _Out_ ULONGLONG* out_base,
    _Out_ ULONGLONG* out_entry,
    _Out_ ULONG* failcode, PCHAR failmessage = nullptr)
{
    *out_base = *out_entry = 0;
    *failcode = MKM_FAIL_SUCCESS;
    if (failmessage) RtlZeroMemory(failmessage, MKM_FAILMESSAGE_BYTES);
    if (!g_MkmReady) return MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_MAP_NOT_READY, failmessage, "MkmMapDll: required kernel routines are unavailable; ready=%u; target_pid=0x%llX; create_thread=%p; flush_cache=%p; acquire_exit=%p; release_exit=%p.", g_MkmReady ? 1u : 0u, target_pid, reinterpret_cast<PVOID>(g_MkmCreateThread), reinterpret_cast<PVOID>(g_MkmFlushCache), reinterpret_cast<PVOID>(g_MkmAcquireExit), reinterpret_cast<PVOID>(g_MkmReleaseExit));

    // 클린업 추적용 로컬
    PUCHAR    raw        = nullptr;  ULONG raw_sz = 0;
    PUCHAR    local_img  = nullptr;
    PEPROCESS target     = nullptr;
    HANDLE    proc_h     = nullptr;
    ULONGLONG remote_base = 0;
    ULONGLONG entry_va    = 0;
    bool retain_remote    = false;
    bool exit_acquired    = false;
    NTSTATUS  st          = STATUS_SUCCESS;

    PHELPER_IMAGE_NT_HEADERS64   nth   = nullptr;
    PHELPER_IMAGE_SECTION_HEADER sects = nullptr;
    PHELPER_IMAGE_SECTION_HEADER section_copy = nullptr;
    USHORT                       nsect = 0;

    do {
        // ①  디스크에서 파일 읽기
        st = MkmReadFile(image_path, &raw, &raw_sz, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        // ②  PE64 헤더 검증
        st = MkmParseHeaders(raw, raw_sz, &nth, &sects, &nsect, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        const ULONG     img_sz    = nth->OptionalHeader.SizeOfImage;
        const ULONG     headers_size = nth->OptionalHeader.SizeOfHeaders;
        const ULONGLONG preferred = nth->OptionalHeader.ImageBase;
        const ULONG     entry_rva = nth->OptionalHeader.AddressOfEntryPoint;

        // Imports/relocations mutate local_img; protection metadata must remain immutable.
        section_copy = static_cast<PHELPER_IMAGE_SECTION_HEADER>(
            MkmAlloc(static_cast<SIZE_T>(nsect) * sizeof(*sects), MKM_TAG_META));
        if (!section_copy) { st = MkmFail(STATUS_INSUFFICIENT_RESOURCES, failcode, MKM_FAIL_MAP_SECTION_METADATA_ALLOC, failmessage, "ExAllocatePool2(PAGED, section metadata) returned NULL; section_count=%u; bytes=%llu; tag=0x%08lX; raw=%p; raw_size=%lu.", nsect, static_cast<ULONGLONG>(nsect) * sizeof(*sects), static_cast<ULONG>(MKM_TAG_META), raw, raw_sz); break; }
        RtlCopyMemory(section_copy, sects, static_cast<SIZE_T>(nsect) * sizeof(*sects));

        // ③④  local image 구성
        st = MkmBuildLocalImage(raw, raw_sz, nth, sects, nsect, &local_img, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        // raw 버퍼 즉시 해제 (nth / sects 포인터 무효화됨)
        MkmFree(raw, MKM_TAG_RAW);
        raw = nullptr;
        nth = nullptr; sects = nullptr;

        // 대상 프로세스 획득
        st = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &target);
        if (!NT_SUCCESS(st)) { MkmSetFailcode(failcode, MKM_FAIL_MAP_PROCESS_LOOKUP, failmessage, "PsLookupProcessByProcessId(pid=0x%llX) failed; target=%p; returned=%s(0x%08lX).", target_pid, target, MkmStatusName(st), static_cast<ULONG>(st)); break; }

        if (PsGetProcessWow64Process(target) || target == PsInitialSystemProcess)
            { st = MkmFail(STATUS_NOT_SUPPORTED, failcode, MKM_FAIL_MAP_UNSUPPORTED_PROCESS, failmessage, "MkmMapDll target validation: WOW64 or initial system process is unsupported; pid=0x%llX; target=%p; wow64=%p; system_process=%p.", target_pid, target, PsGetProcessWow64Process(target), PsInitialSystemProcess); break; }

        st = ObOpenObjectByPointer(target, OBJ_KERNEL_HANDLE /*| OBJ_FORCE_ACCESS_CHECK*/, nullptr,
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION | 0x0002 /* PROCESS_CREATE_THREAD */,
            *PsProcessType, KernelMode, &proc_h);
        if (!NT_SUCCESS(st)) { MkmSetFailcode(failcode, MKM_FAIL_MAP_PROCESS_OPEN, failmessage, "ObOpenObjectByPointer(target=%p, attributes=OBJ_KERNEL_HANDLE, desired_access=0x%08lX, type=Process, access_mode=KernelMode) failed; proc_h=%p; returned=%s(0x%08lX).", target, static_cast<ULONG>(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | 0x0002), proc_h, MkmStatusName(st), static_cast<ULONG>(st)); break; }

        st = g_MkmAcquireExit(target);
        if (!NT_SUCCESS(st)) { MkmSetFailcode(failcode, MKM_FAIL_MAP_EXIT_SYNC, failmessage, "PsAcquireProcessExitSynchronization(target=%p, pid=0x%llX) failed; returned=%s(0x%08lX).", target, target_pid, MkmStatusName(st), static_cast<ULONG>(st)); break; }
        exit_acquired = true;

        // ⑤  IAT 해결 (local_img에 in-place 기록)
        st = MkmResolveIAT(target, local_img, img_sz, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        // ⑦  원격 메모리 할당 (⑥ 전에 실제 베이스 확정)
        st = MkmAllocRemote(proc_h, img_sz, preferred, &remote_base, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;
        if (!MkmUserRange(remote_base, img_sz)) { st = MkmFail(STATUS_INVALID_ADDRESS, failcode, MKM_FAIL_MAP_REMOTE_RANGE, failmessage, "Allocated remote image is outside the valid user address range; proc_h=%p; remote_base=0x%llX; image_size=0x%lX; highest_user=%p.", proc_h, remote_base, img_sz, MmHighestUserAddress); break; }
        entry_va = entry_rva ? remote_base + entry_rva : 0;

        // ⑥  재배치 적용 (local_img에 실제 remote_base 기준으로)
        st = MkmRelocate(local_img, img_sz, preferred, remote_base, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        // ⑧  local image → 원격 프로세스 VA 복사
        st = MkmWriteRemote(target, remote_base, local_img, img_sz, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        // ⑨  Apply the validated immutable section metadata.
        st = MkmProtectSections(proc_h, remote_base, img_sz, headers_size, section_copy, nsect, failcode, failmessage);
        if (!NT_SUCCESS(st)) break;

        // ⑩  I-cache flush
        st = g_MkmFlushCache(proc_h, reinterpret_cast<PVOID>(remote_base), img_sz);
        if (!NT_SUCCESS(st)) { MkmSetFailcode(failcode, MKM_FAIL_MAP_IMAGE_FLUSH, failmessage, "ZwFlushInstructionCache(proc_h=%p, base=0x%llX, size=0x%lX) failed; returned=%s(0x%08lX); DllMain has not been started.", proc_h, remote_base, img_sz, MkmStatusName(st), static_cast<ULONG>(st)); break; }

        // ⑪  DllMain 호출 (매핑 전용 요청이 아니고 entry point가 있을 때만)
        if (entry_va && !only_mapping) {
            st = MkmCallDllMain(owner, target, proc_h, remote_base, entry_va, &retain_remote, failcode, failmessage);
            if (st != STATUS_SUCCESS) break;
        }

        *out_base  = remote_base;
        *out_entry = entry_va;

    } while (false);

    // ── 실패 시 원격 VA 해제 ─────────────────────────────────────────
    if (st != STATUS_SUCCESS && remote_base && proc_h) {
        if (!retain_remote) {
            PVOID tmp = reinterpret_cast<PVOID>(remote_base);
            SIZE_T z = 0;
            const NTSTATUS free_st = ZwFreeVirtualMemory(proc_h, &tmp, &z, MEM_RELEASE);
            if (!NT_SUCCESS(free_st)) {
                // Cleanup failure must not hide a surviving allocation from the caller.
                retain_remote = true;
                MkmSetFailcode(failcode, MKM_FAIL_MAP_REMOTE_CLEANUP, failmessage, "ZwFreeVirtualMemory cleanup failed; proc_h=%p; requested_base=0x%llX; requested_size=0; free_type=MEM_RELEASE; output_base=%p; output_size=%llu; returned=%s(0x%08lX); remote allocation retained.", proc_h, remote_base, tmp, static_cast<ULONGLONG>(z), MkmStatusName(free_st), static_cast<ULONG>(free_st));
                st = free_st;
            }
        }
        if (retain_remote) {
            *out_base = remote_base;
            *out_entry = entry_va;
        }
    }

    if (exit_acquired) g_MkmReleaseExit(target);
    if (proc_h)   ZwClose(proc_h);
    if (target)   ObDereferenceObject(target);
    MkmFree(local_img, MKM_TAG_IMG);
    MkmFree(section_copy, MKM_TAG_META);
    MkmFree(raw,       MKM_TAG_RAW);   // 정상 경로에서는 null

    if (st != STATUS_SUCCESS) MkmSetFailcode(failcode, MKM_FAIL_MAP_FINAL_STATUS, failmessage, "MkmMapDll ended without an earlier diagnostic; pid=0x%llX; remote_base=0x%llX; entry=0x%llX; retained=%u; returned=%s(0x%08lX).", target_pid, remote_base, entry_va, retain_remote ? 1u : 0u, MkmStatusName(st), static_cast<ULONG>(st));
    if (st == STATUS_SUCCESS) {
        *failcode = MKM_FAIL_SUCCESS;
        if (failmessage) RtlZeroMemory(failmessage, MKM_FAILMESSAGE_BYTES);
    } else {
        MkmAppendResult(failmessage, st);
        MkmAppendImagePath(failmessage, image_path);
    }
    return st;
}

// ═══════════════════════════════════════════════════════════════════════
//  IOCTL 0x878 진입점
//  ioctl_helper::DeviceControlRoutineImpl에서 rundown 보호 획득 후 호출됨
// ═══════════════════════════════════════════════════════════════════════

// Complete a well-sized METHOD_BUFFERED packet even on operation/validation failure.
// The transport succeeds; ResultStatus/failcode/failmessage describe the operation.
inline NTSTATUS MkmReply(PMANUAL_MAP_REQUEST buffer, MANUAL_MAP_REQUEST& request,
    ULONG_PTR* returned, NTSTATUS status, ULONG failcode,
    ULONGLONG mapped_base = 0, ULONGLONG entry_point = 0, PCHAR failmessage = nullptr)
{
    request.ResultStatus = status;
    request.MappedBase = mapped_base;
    request.EntryPoint = entry_point;
    request.failcode = failcode;
    if (status == STATUS_SUCCESS) RtlZeroMemory(request.failmessage, MKM_FAILMESSAGE_BYTES);
    else if (failmessage && failmessage != request.failmessage)
        RtlCopyMemory(request.failmessage, failmessage, MKM_FAILMESSAGE_BYTES);
    else if (!failmessage) {
        RtlZeroMemory(request.failmessage, MKM_FAILMESSAGE_BYTES);
        MkmPrint(request.failmessage, MKM_FAILMESSAGE_BYTES,
            "failcode=%lu; NTSTATUS=%s(0x%08lX); Mapper returned failure without detail.",
            failcode, MkmStatusName(status), static_cast<ULONG>(status));
    }
    MkmFinishMessage(request.failmessage, false);
    RtlCopyMemory(buffer, &request, sizeof(request));
    *returned = sizeof(request);
    return STATUS_SUCCESS;
}

inline NTSTATUS MkmReplyFailure(PMANUAL_MAP_REQUEST buffer, MANUAL_MAP_REQUEST& request,
    ULONG_PTR* returned, NTSTATUS status, MKM_FAIL_CODE code, PCSTR format, ...)
{
    RtlZeroMemory(request.failmessage, MKM_FAILMESSAGE_BYTES);
    va_list args;
    va_start(args, format);
    MkmFormatFailureV(request.failmessage, code, true, status, format, args);
    va_end(args);
    return MkmReply(buffer, request, returned, status, static_cast<ULONG>(code),
        0, 0, request.failmessage);
}

inline NTSTATUS Request(_In_ PIRP irp, _Out_ ULONG_PTR* returned)
{
    // There is no writable response for a missing IRP/output length or wrong buffer size.
    if (!returned) return STATUS_INVALID_PARAMETER;
    *returned = 0;
    if (!irp) return STATUS_INVALID_PARAMETER;
    const auto* stack = IoGetCurrentIrpStackLocation(irp);
    auto* buffer = static_cast<MANUAL_MAP_REQUEST*>(irp->AssociatedIrp.SystemBuffer);
    if (!buffer || stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(MANUAL_MAP_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(MANUAL_MAP_REQUEST))
        return STATUS_INVALID_PARAMETER;

    MANUAL_MAP_REQUEST request;
    RtlCopyMemory(&request, buffer, sizeof(request));
    if (!g_MkmReady)
        return MkmReplyFailure(buffer, request, returned, STATUS_NOT_SUPPORTED, MKM_FAIL_REQUEST_NOT_READY,
            "IOCTL_MANUAL_MAP unavailable; ready=%u; create_thread=%p; flush_cache=%p; acquire_exit=%p; release_exit=%p.",
            g_MkmReady ? 1u : 0u, reinterpret_cast<PVOID>(g_MkmCreateThread), reinterpret_cast<PVOID>(g_MkmFlushCache), reinterpret_cast<PVOID>(g_MkmAcquireExit), reinterpret_cast<PVOID>(g_MkmReleaseExit));
    const KIRQL irql = KeGetCurrentIrql();
    if (irql != PASSIVE_LEVEL)
        return MkmReplyFailure(buffer, request, returned, STATUS_NOT_SUPPORTED, MKM_FAIL_REQUEST_IRQL,
            "IOCTL requires PASSIVE_LEVEL; actual_IRQL=%u; required_IRQL=%u.", irql, static_cast<ULONG>(PASSIVE_LEVEL));
    if (irp->RequestorMode != UserMode)
        return MkmReplyFailure(buffer, request, returned, STATUS_ACCESS_DENIED, MKM_FAIL_REQUEST_REQUESTOR_MODE,
            "IOCTL requires UserMode requestor; RequestorMode=%u; expected=%u.", static_cast<ULONG>(irp->RequestorMode), static_cast<ULONG>(UserMode));
    if (IoIs32bitProcess(irp))
        return MkmReplyFailure(buffer, request, returned, STATUS_NOT_SUPPORTED, MKM_FAIL_REQUEST_WOW64,
            "IOCTL rejects WOW64/32-bit caller; IoIs32bitProcess=TRUE; native x64 caller is required.");
    if (!stack->FileObject || stack->FileObject->FsContext2)
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_HANDLE, MKM_FAIL_REQUEST_FILE_HANDLE,
            "IOCTL file handle is missing or cleanup has begun; FileObject=%p; FsContext2=%p (read only if FileObject is present).",
            stack->FileObject, stack->FileObject ? stack->FileObject->FsContext2 : nullptr);
    if (request.Version != MKM_VERSION)
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_PARAMETER, MKM_FAIL_REQUEST_VERSION,
            "Manual-map wire protocol version mismatch; actual=%lu; required=%lu; packet_bytes=%llu.", request.Version, MKM_VERSION, static_cast<ULONGLONG>(sizeof(request)));
    if (request.OnlyMapping > TRUE)
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_PARAMETER, MKM_FAIL_REQUEST_ONLY_MAPPING,
            "OnlyMapping must be FALSE (0) or TRUE (1); actual=0x%02X.", static_cast<unsigned int>(request.OnlyMapping));
    ULONG reserved_nonzero = RTL_NUMBER_OF(request.Reserved);
    for (ULONG i = 0; i < RTL_NUMBER_OF(request.Reserved); ++i) {
        if (request.Reserved[i]) { reserved_nonzero = i; break; }
    }
    if (reserved_nonzero != RTL_NUMBER_OF(request.Reserved))
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_PARAMETER, MKM_FAIL_REQUEST_RESERVED,
            "Reserved request bytes must be zero; first_nonzero_index=%lu; actual=0x%02X.",
            reserved_nonzero, static_cast<unsigned int>(request.Reserved[reserved_nonzero]));
    if (!request.ProcessId || request.ProcessId > MAXULONG_PTR)
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_PARAMETER, MKM_FAIL_REQUEST_PROCESS_ID,
            "Target ProcessId is zero or exceeds ULONG_PTR; actual=0x%llX; maximum=0x%llX.", request.ProcessId, static_cast<ULONGLONG>(MAXULONG_PTR));
    ULONG message_input_nonzero = MKM_FAILMESSAGE_BYTES;
    for (ULONG i = 0; i < MKM_FAILMESSAGE_BYTES; ++i) {
        if (request.failmessage[i]) { message_input_nonzero = i; break; }
    }
    if (request.MappedBase || request.EntryPoint || request.failcode || message_input_nonzero != MKM_FAILMESSAGE_BYTES)
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_PARAMETER, MKM_FAIL_REQUEST_OUTPUT_FIELDS,
            "Output fields must be zero on input; MappedBase=0x%llX; EntryPoint=0x%llX; failcode=%lu; failmessage_first_nonzero_index=%lu (1024 means none); first_nonzero_byte=0x%02X.",
            request.MappedBase, request.EntryPoint, request.failcode, message_input_nonzero,
            message_input_nonzero < MKM_FAILMESSAGE_BYTES ? static_cast<UCHAR>(request.failmessage[message_input_nonzero]) : 0u);

    bool terminated = false;
    ULONG path_chars = 0;
    for (; path_chars < MKM_MAX_PATH; ++path_chars)
        if (!request.ImagePath[path_chars]) { terminated = true; break; }
    if (!terminated || request.ImagePath[0] != L'\\')
        return MkmReplyFailure(buffer, request, returned, STATUS_INVALID_PARAMETER, MKM_FAIL_REQUEST_IMAGE_PATH,
            "ImagePath must be NUL-terminated NT absolute path beginning with backslash; terminated=%u; scanned_chars=%lu; capacity=%u; first_utf16=0x%04X.",
            terminated ? 1u : 0u, path_chars, MKM_MAX_PATH, static_cast<USHORT>(request.ImagePath[0]));
    PEPROCESS owner = IoGetRequestorProcess(irp);
    PEPROCESS current = PsGetCurrentProcess();
    if (!owner || owner != current)
        return MkmReplyFailure(buffer, request, returned, STATUS_ACCESS_DENIED, MKM_FAIL_REQUEST_OWNER,
            "Requestor process must exist and match current process; owner=%p; current=%p; target_pid=0x%llX.", owner, current, request.ProcessId);

    // Packed fields are unaligned; helpers only receive naturally aligned output locals.
    ULONGLONG mapped_base = 0, entry_point = 0;
    ULONG failcode = MKM_FAIL_SUCCESS;
    const NTSTATUS status = MkmMapDll(owner, request.ProcessId, request.ImagePath, request.OnlyMapping,
        &mapped_base, &entry_point, &failcode, request.failmessage);
    return MkmReply(buffer, request, returned, status, failcode, mapped_base, entry_point, request.failmessage);
}

} } // namespace helper::manual_map
