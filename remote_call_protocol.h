#pragma once

// Include ntifs.h (kernel) or windows.h/winioctl.h (client) before this file.
// Values are wire-format integers, never caller-owned pointers to packet data.
#define IOCTL_HELPER_CREATE_FUNCTION_CALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HELPER_QUERY_FUNCTION_CALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HELPER_RELEASE_FUNCTION_CALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define FUNCTION_CALL_PROTOCOL_VERSION 1UL
#define FUNCTION_CALL_MAX_WAIT_MS 1000UL
#define FUNCTION_CALL_MAX_RECORDS 128UL
#define FUNCTION_CALL_MAX_RECORDS_PER_FILE 32UL

#pragma pack(push, 8)
typedef struct _CREATE_FUNCTION_CALL_REQUEST
{
    ULONG StructSize;
    ULONG Version;
    ULONG ProcessId;
    ULONG Flags;                  // Reserved: must be zero.
    ULONGLONG ProcessStartKey;     // Required, from process information IOCTL.
    ULONGLONG FunctionAddress;     // Start routine in the TARGET address space.
    ULONGLONG Parameter;           // One raw machine-word argument; not dereferenced.
    ULONG WaitMilliseconds;       // 0 = poll; at most FUNCTION_CALL_MAX_WAIT_MS.
    NTSTATUS ResultStatus;         // Creation status, NOT the function result.
    ULONGLONG CallId;              // Opaque token owned by this device file.
    ULONGLONG ThreadId;
    ULONG ThreadCreated;           // Even a later observation error must not trigger retry.
    ULONG Completed;               // Based on thread signaling, not ExitStatus == 259.
    NTSTATUS WaitStatus;
    NTSTATUS ExitStatus;           // 32-bit thread exit value; valid only when completed
    NTSTATUS QueryStatus;          // and QueryStatus == STATUS_SUCCESS.
    ULONG Reserved;               // Must be zero.
} CREATE_FUNCTION_CALL_REQUEST;

typedef struct _QUERY_FUNCTION_CALL_REQUEST
{
    ULONG StructSize;
    ULONG Version;
    ULONGLONG CallId;
    ULONG WaitMilliseconds;
    NTSTATUS ResultStatus;
    ULONGLONG ProcessId;
    ULONGLONG ProcessStartKey;
    ULONGLONG ThreadId;
    ULONGLONG FunctionAddress;
    ULONGLONG Parameter;
    ULONGLONG CreatedAtTime;       // Windows system time, 100 ns units.
    ULONG ThreadCreated;
    ULONG Completed;
    NTSTATUS WaitStatus;
    NTSTATUS ExitStatus;
    NTSTATUS QueryStatus;
    ULONG Reserved;
} QUERY_FUNCTION_CALL_REQUEST;

typedef struct _RELEASE_FUNCTION_CALL_REQUEST
{
    ULONG StructSize;
    ULONG Version;
    ULONGLONG CallId;
    NTSTATUS ResultStatus;
    ULONG Reserved;
} RELEASE_FUNCTION_CALL_REQUEST;
#pragma pack(pop)

static_assert(sizeof(CREATE_FUNCTION_CALL_REQUEST) == 88, "function-call create ABI");
static_assert(sizeof(QUERY_FUNCTION_CALL_REQUEST) == 96, "function-call query ABI");
static_assert(sizeof(RELEASE_FUNCTION_CALL_REQUEST) == 24, "function-call release ABI");
