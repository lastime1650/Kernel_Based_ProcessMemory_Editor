#pragma once

// Include ntifs.h or windows.h/winioctl.h before this shared wire protocol.
#include <stddef.h>

#define IOCTL_HELPER_QUERY_OB_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HELPER_REGISTER_OB_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HELPER_UNREGISTER_OB_CALLBACKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x829, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define OB_CALLBACK_STATUS_VERSION 2UL
#define OB_CALLBACK_ALTITUDE_CHARS 16UL

#define OB_CALLBACK_STATE_NOT_INITIALIZED 0UL
#define OB_CALLBACK_STATE_REGISTERING 1UL
#define OB_CALLBACK_STATE_REGISTERED 2UL
#define OB_CALLBACK_STATE_FAILED 3UL
#define OB_CALLBACK_STATE_UNREGISTERED 4UL
#define OB_CALLBACK_STATE_UNREGISTERING 5UL

#define OB_CALLBACK_STAGE_NONE 0UL
#define OB_CALLBACK_STAGE_RESOLVE_ROUTINES 1UL
#define OB_CALLBACK_STAGE_FORMAT_ALTITUDE 2UL
#define OB_CALLBACK_STAGE_REGISTER_CALLBACKS 3UL
#define OB_CALLBACK_STAGE_ALTITUDE_EXHAUSTED 4UL
#define OB_CALLBACK_STAGE_VALIDATE_CONFIGURATION 5UL
#define OB_CALLBACK_STAGE_CREATE_WORKER 6UL
#define OB_CALLBACK_STAGE_CANCELLED 7UL

#pragma pack(push, 8)
typedef struct _OB_CALLBACK_STATUS_REQUEST {
    ULONG StructSize;
    ULONG Version;
    NTSTATUS ResultStatus;                 // Query result, independent of registration.
    NTSTATUS RegistrationStatus;
    ULONG State;
    ULONG FailureStage;
    ULONGLONG RegistrationAttempts;
    LONGLONG MinimumAltitude;              // -1 when unregistered; otherwise ULONG range.
    LONGLONG MaximumAltitude;
    ULONG MaximumFraction;
    ULONG LastWhole;
    ULONG LastFraction;
    ULONG RegisterRoutineResolved;
    ULONG UnregisterRoutineResolved;
    ULONG CallbackVersion;
    ULONG OperationCount;
    ULONG ProcessOperations;
    ULONG ThreadOperations;
    ULONG PreOperationEnabled;
    ULONG PostOperationEnabled;
    ULONG ObserveOnly;
    ULONG DynamicResolution;
    ULONG HandlerAddressValid;
    ULONG WorkerActive;
    ULONG Reserved;
    ULONGLONG HandlerAddress;              // Own PRE callback only, zero when inactive.
    ULONGLONG RegistrationGeneration;
    LONGLONG LastRequestedMinimumAltitude; // Historical request, separate from active settings.
    LONGLONG LastRequestedMaximumAltitude;
    ULONG LastRequestedMaximumFraction;
    ULONG Reserved2;
    WCHAR RegisteredAltitude[OB_CALLBACK_ALTITUDE_CHARS]; // "-1" when inactive.
    WCHAR LastAttemptAltitude[OB_CALLBACK_ALTITUDE_CHARS];
} OB_CALLBACK_STATUS_REQUEST, *POB_CALLBACK_STATUS_REQUEST;

typedef struct _OB_CALLBACK_CONTROL_REQUEST {
    ULONG StructSize;
    ULONG Version;
    NTSTATUS ResultStatus;                 // SUCCESS accepts registration; query tracks completion.
    ULONG MinimumAltitude;
    ULONG MaximumAltitude;
    ULONG MaximumFraction;
    ULONG Reserved[2];
} OB_CALLBACK_CONTROL_REQUEST, *POB_CALLBACK_CONTROL_REQUEST;
#pragma pack(pop)

static_assert(sizeof(OB_CALLBACK_STATUS_REQUEST) == 216, "OB callback status V2 ABI");
static_assert(offsetof(OB_CALLBACK_STATUS_REQUEST, HandlerAddress) == 112, "OB handler offset");
static_assert(offsetof(OB_CALLBACK_STATUS_REQUEST, RegisteredAltitude) == 152, "OB altitude offset");
static_assert(offsetof(OB_CALLBACK_STATUS_REQUEST, LastAttemptAltitude) == 184, "OB last altitude offset");
static_assert(sizeof(OB_CALLBACK_CONTROL_REQUEST) == 32, "OB callback control V2 ABI");
