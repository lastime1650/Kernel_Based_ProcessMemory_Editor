#pragma once

#include <ntifs.h>
#include "ob_callbacks_protocol.h"

namespace helper { namespace ob_callbacks {

using FnObRegisterCallbacks = NTSTATUS (NTAPI*)(POB_CALLBACK_REGISTRATION, PVOID*);
using FnObUnRegisterCallbacks = VOID (NTAPI*)(PVOID);

static FnObRegisterCallbacks g_ObRegisterCallbacks = nullptr;
static FnObUnRegisterCallbacks g_ObUnRegisterCallbacks = nullptr;
static PVOID volatile g_RegistrationHandle = nullptr;

static constexpr ULONG kMaximumFraction = 1000;
static constexpr ULONG kAltitudeBufferChars = OB_CALLBACK_ALTITUDE_CHARS;
static WCHAR g_RegisteredAltitude[kAltitudeBufferChars] = {};
static KSPIN_LOCK g_DiagnosticsLock;
static OB_CALLBACK_STATUS_REQUEST g_Diagnostics = {};
static bool g_DiagnosticsInitialized = false;
// KMUTEX keeps registration and thread creation at PASSIVE_LEVEL. Queries use only the spinlock.
static KMUTEX g_ControlMutex;
static HANDLE g_WorkerHandle = nullptr;
static bool g_WorkerActive = false;
static bool g_Stopping = false;
static volatile LONG g_CancelRequested = 0;

class ControlLock {
public:
    ControlLock() { KeWaitForSingleObject(&g_ControlMutex, Executive, KernelMode, FALSE, nullptr); }
    ~ControlLock() { KeReleaseMutex(&g_ControlMutex, FALSE); }
    ControlLock(const ControlLock&) = delete;
    ControlLock& operator=(const ControlLock&) = delete;
};

inline VOID ClearActiveSettings(OB_CALLBACK_STATUS_REQUEST& snapshot)
{
    snapshot.MinimumAltitude = -1;
    snapshot.MaximumAltitude = -1;
    snapshot.MaximumFraction = 0;
    snapshot.HandlerAddress = 0;
    snapshot.HandlerAddressValid = 0;
    for (auto& character : snapshot.RegisteredAltitude) character = L'\0';
    snapshot.RegisteredAltitude[0] = L'-';
    snapshot.RegisteredAltitude[1] = L'1';
}

inline OB_CALLBACK_STATUS_REQUEST MakeDiagnostics(
    LONGLONG minimum, LONGLONG maximum, ULONG maximum_fraction)
{
    OB_CALLBACK_STATUS_REQUEST snapshot = {};
    snapshot.StructSize = sizeof(snapshot);
    snapshot.Version = OB_CALLBACK_STATUS_VERSION;
    snapshot.ResultStatus = STATUS_SUCCESS;
    snapshot.RegistrationStatus = STATUS_SUCCESS;
    snapshot.State = OB_CALLBACK_STATE_UNREGISTERED;
    ClearActiveSettings(snapshot);
    snapshot.MinimumAltitude = minimum;
    snapshot.MaximumAltitude = maximum;
    snapshot.MaximumFraction = maximum_fraction;
    snapshot.LastRequestedMinimumAltitude = -1;
    snapshot.LastRequestedMaximumAltitude = -1;
    snapshot.CallbackVersion = OB_FLT_REGISTRATION_VERSION;
    snapshot.OperationCount = 2;
    snapshot.ProcessOperations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    snapshot.ThreadOperations = snapshot.ProcessOperations;
    snapshot.PreOperationEnabled = 1;
    snapshot.ObserveOnly = 1;
    snapshot.DynamicResolution = 1;
    return snapshot;
}

// DriverEntry prepares diagnostics before publishing the control device.
inline VOID PrepareDiagnostics()
{
    KeInitializeSpinLock(&g_DiagnosticsLock);
    KeInitializeMutex(&g_ControlMutex, 0);
    g_Diagnostics = MakeDiagnostics(-1, -1, 0);
    g_DiagnosticsInitialized = true;
}

inline VOID PublishDiagnostics(const OB_CALLBACK_STATUS_REQUEST& snapshot)
{
    KIRQL previous_irql;
    KeAcquireSpinLock(&g_DiagnosticsLock, &previous_irql);
    g_Diagnostics = snapshot;
    KeReleaseSpinLock(&g_DiagnosticsLock, previous_irql);
}

inline VOID CopyAltitude(WCHAR* destination, const WCHAR* source)
{
    for (ULONG index = 0; index < kAltitudeBufferChars; ++index)
        destination[index] = source[index];
}

inline OB_CALLBACK_STATUS_REQUEST ReadDiagnostics()
{
    KIRQL previous_irql;
    KeAcquireSpinLock(&g_DiagnosticsLock, &previous_irql);
    const auto snapshot = g_Diagnostics;
    KeReleaseSpinLock(&g_DiagnosticsLock, previous_irql);
    return snapshot;
}

inline NTSTATUS QueryDiagnostics(POB_CALLBACK_STATUS_REQUEST request)
{
    if (!request || request->StructSize != sizeof(*request) ||
        request->Version != OB_CALLBACK_STATUS_VERSION)
        return STATUS_INVALID_PARAMETER;
    if (!g_DiagnosticsInitialized) return STATUS_DEVICE_NOT_READY;

    *request = ReadDiagnostics();
    return STATUS_SUCCESS;
}

// Keep the requested decimal spelling; floating-point conversion would lose trailing digits.
inline NTSTATUS FormatAltitude(
    ULONG whole, ULONG fraction, PWCHAR buffer, USHORT buffer_bytes,
    PUNICODE_STRING altitude)
{
    if (!altitude) return STATUS_INVALID_PARAMETER;
    *altitude = {};
    if (!buffer || buffer_bytes < sizeof(WCHAR) ||
        buffer_bytes % sizeof(WCHAR) != 0 || fraction > kMaximumFraction)
        return STATUS_INVALID_PARAMETER;

    altitude->Buffer = buffer;
    altitude->MaximumLength = buffer_bytes;
    buffer[0] = L'\0';
    NTSTATUS status = RtlIntegerToUnicodeString(whole, 10, altitude);
    if (!NT_SUCCESS(status)) return status;
    if (altitude->Length > buffer_bytes - sizeof(WCHAR))
        return STATUS_BUFFER_OVERFLOW;
    buffer[altitude->Length / sizeof(WCHAR)] = L'\0';
    if (fraction == 0) return STATUS_SUCCESS;

    // Reserve the separator and terminator before converting the fractional counter.
    if (buffer_bytes - altitude->Length < 2 * sizeof(WCHAR))
        return STATUS_BUFFER_OVERFLOW;
    const USHORT whole_length = altitude->Length;
    buffer[whole_length / sizeof(WCHAR)] = L'.';
    UNICODE_STRING suffix = {};
    suffix.Buffer = buffer + whole_length / sizeof(WCHAR) + 1;
    suffix.MaximumLength = static_cast<USHORT>(buffer_bytes - whole_length - sizeof(WCHAR));
    status = RtlIntegerToUnicodeString(fraction, 10, &suffix);
    if (!NT_SUCCESS(status)) return status;
    if (suffix.Length > suffix.MaximumLength - sizeof(WCHAR))
        return STATUS_BUFFER_OVERFLOW;
    altitude->Length = static_cast<USHORT>(whole_length + sizeof(WCHAR) + suffix.Length);
    buffer[altitude->Length / sizeof(WCHAR)] = L'\0';
    return STATUS_SUCCESS;
}

// PRE observes requested rights; it does not report the final handle result.
inline OB_PREOP_CALLBACK_STATUS NTAPI PreOperation(
    _In_ PVOID registration_context,
    _Inout_ POB_PRE_OPERATION_INFORMATION information)
{
    UNREFERENCED_PARAMETER(registration_context);
    if (!information || !information->Object || !information->Parameters)
        return OB_PREOP_SUCCESS;

    PCSTR object_name = nullptr;
    HANDLE object_pid = nullptr;
    HANDLE object_tid = nullptr;
    if (information->ObjectType == *PsProcessType) {
        object_name = "process";
        object_pid = PsGetProcessId(static_cast<PEPROCESS>(information->Object));
    } else if (information->ObjectType == *PsThreadType) {
        object_name = "thread";
        PETHREAD thread = static_cast<PETHREAD>(information->Object);
        object_pid = PsGetProcessId(PsGetThreadProcess(thread));
        object_tid = PsGetThreadId(thread);
    } else {
        return OB_PREOP_SUCCESS;
    }

    PCSTR operation_name = nullptr;
    ACCESS_MASK desired_access = 0;
    ACCESS_MASK original_access = 0;
    HANDLE source_pid = nullptr;
    HANDLE destination_pid = nullptr;
    if (information->Operation == OB_OPERATION_HANDLE_CREATE) {
        operation_name = "create";
        desired_access = information->Parameters->CreateHandleInformation.DesiredAccess;
        original_access = information->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else if (information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        operation_name = "duplicate";
        const auto& duplicate = information->Parameters->DuplicateHandleInformation;
        desired_access = duplicate.DesiredAccess;
        original_access = duplicate.OriginalDesiredAccess;
        if (duplicate.SourceProcess)
            source_pid = PsGetProcessId(static_cast<PEPROCESS>(duplicate.SourceProcess));
        if (duplicate.TargetProcess)
            destination_pid = PsGetProcessId(static_cast<PEPROCESS>(duplicate.TargetProcess));
    } else {
        return OB_PREOP_SUCCESS;
    }

    // No handles, pool allocations, deferred work or access-mask writes in this callback.
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[OB] PRE %s %s caller_pid=%p caller_tid=%p object_pid=%p object_tid=%p "
        "kernel=%lu desired=0x%08lX original=0x%08lX source_pid=%p destination_pid=%p\n",
        operation_name, object_name, PsGetCurrentProcessId(), PsGetCurrentThreadId(),
        object_pid, object_tid, static_cast<ULONG>(information->KernelHandle),
        desired_access, original_access, source_pid, destination_pid);
    return OB_PREOP_SUCCESS;
}

// Runs only on our system thread; it never retains an IRP or a user buffer.
inline NTSTATUS RegisterLoop(OB_CALLBACK_STATUS_REQUEST& snapshot, PVOID* completed_handle)
{
    *completed_handle = nullptr;
    UNICODE_STRING register_name;
    UNICODE_STRING unregister_name;
    RtlInitUnicodeString(&register_name, L"ObRegisterCallbacks");
    RtlInitUnicodeString(&unregister_name, L"ObUnRegisterCallbacks");
    PVOID register_address = MmGetSystemRoutineAddress(&register_name);
    PVOID unregister_address = MmGetSystemRoutineAddress(&unregister_name);
    snapshot.RegisterRoutineResolved = register_address ? 1 : 0;
    snapshot.UnregisterRoutineResolved = unregister_address ? 1 : 0;
    if (!register_address || !unregister_address) {
        g_ObRegisterCallbacks = nullptr;
        g_ObUnRegisterCallbacks = nullptr;
        snapshot.State = OB_CALLBACK_STATE_FAILED;
        snapshot.FailureStage = OB_CALLBACK_STAGE_RESOLVE_ROUTINES;
        snapshot.RegistrationStatus = STATUS_PROCEDURE_NOT_FOUND;
        PublishDiagnostics(snapshot);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[OB] Registration unavailable: required system routine missing\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    g_ObRegisterCallbacks = reinterpret_cast<FnObRegisterCallbacks>(register_address);
    g_ObUnRegisterCallbacks = reinterpret_cast<FnObUnRegisterCallbacks>(unregister_address);
    PublishDiagnostics(snapshot);

    struct RegistrationBuffer {
        OB_CALLBACK_REGISTRATION Registration;
        OB_OPERATION_REGISTRATION Operations[2];
    } callbacks = {};
    callbacks.Registration.Version = OB_FLT_REGISTRATION_VERSION;
    callbacks.Registration.OperationRegistrationCount = RTL_NUMBER_OF(callbacks.Operations);
    callbacks.Registration.OperationRegistration = callbacks.Operations;
    callbacks.Operations[0].ObjectType = PsProcessType;
    callbacks.Operations[1].ObjectType = PsThreadType;
    for (auto& operation : callbacks.Operations) {
        operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation.PreOperation = PreOperation;
    }

    WCHAR altitude_buffer[kAltitudeBufferChars] = {};
    // Explicit last-whole break prevents ULONG_MAX from wrapping to zero.
    for (ULONG whole = static_cast<ULONG>(snapshot.MinimumAltitude); ; ++whole) {
        for (ULONG fraction = 0; fraction <= snapshot.MaximumFraction; ++fraction) {
            if (InterlockedCompareExchange(&g_CancelRequested, 0, 0))
                return STATUS_CANCELLED;
            snapshot.LastWhole = whole;
            snapshot.LastFraction = fraction;
            NTSTATUS status = FormatAltitude(whole, fraction, altitude_buffer,
                static_cast<USHORT>(sizeof(altitude_buffer)), &callbacks.Registration.Altitude);
            if (!NT_SUCCESS(status)) {
                snapshot.State = OB_CALLBACK_STATE_FAILED;
                snapshot.FailureStage = OB_CALLBACK_STAGE_FORMAT_ALTITUDE;
                snapshot.RegistrationStatus = status;
                for (auto& character : snapshot.LastAttemptAltitude) character = L'\0';
                PublishDiagnostics(snapshot);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[OB] Altitude conversion failed: 0x%08lX\n", static_cast<ULONG>(status));
                return status;
            }

            PVOID registration_handle = nullptr;
            ++snapshot.RegistrationAttempts;
            CopyAltitude(snapshot.LastAttemptAltitude, altitude_buffer);
            PublishDiagnostics(snapshot);
            status = g_ObRegisterCallbacks(&callbacks.Registration, &registration_handle);
            snapshot.RegistrationStatus = status;
            if (NT_SUCCESS(status)) {
                if (!registration_handle) {
                    snapshot.State = OB_CALLBACK_STATE_FAILED;
                    snapshot.FailureStage = OB_CALLBACK_STAGE_REGISTER_CALLBACKS;
                    snapshot.RegistrationStatus = STATUS_UNSUCCESSFUL;
                    return STATUS_UNSUCCESSFUL;
                }
                *completed_handle = registration_handle;
                snapshot.State = OB_CALLBACK_STATE_REGISTERED;
                CopyAltitude(snapshot.RegisteredAltitude, altitude_buffer);
                return status;
            }
            // A different altitude cannot repair signature, parameter or resource failures.
            if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
                snapshot.State = OB_CALLBACK_STATE_FAILED;
                snapshot.FailureStage = OB_CALLBACK_STAGE_REGISTER_CALLBACKS;
                PublishDiagnostics(snapshot);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[OB] Registration failed: altitude=%ws attempts=%llu status=0x%08lX\n",
                    altitude_buffer, snapshot.RegistrationAttempts, static_cast<ULONG>(status));
                return status;
            }
            PublishDiagnostics(snapshot);
            // Yield periodically during a long collision scan; cancellation is checked every attempt.
            if ((snapshot.RegistrationAttempts & 255ULL) == 0) {
                LARGE_INTEGER delay;
                delay.QuadPart = -10000; // 1 ms, relative.
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        }
        if (whole == static_cast<ULONG>(snapshot.MaximumAltitude)) break;
    }
    snapshot.State = OB_CALLBACK_STATE_FAILED;
    snapshot.FailureStage = OB_CALLBACK_STAGE_ALTITUDE_EXHAUSTED;
    PublishDiagnostics(snapshot);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[OB] Altitude candidates exhausted: last=%ws attempts=%llu status=0x%08lX\n",
        altitude_buffer, snapshot.RegistrationAttempts, static_cast<ULONG>(STATUS_FLT_INSTANCE_ALTITUDE_COLLISION));
    return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
}

inline VOID NTAPI RegistrationWorker(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    OB_CALLBACK_STATUS_REQUEST snapshot;
    {
        ControlLock lock;
        snapshot = ReadDiagnostics();
    }
    PVOID registration_handle = nullptr;
    NTSTATUS status = RegisterLoop(snapshot, &registration_handle);
    {
        ControlLock lock;
        if (g_Stopping || InterlockedCompareExchange(&g_CancelRequested, 0, 0) ||
            status == STATUS_CANCELLED) {
            if (registration_handle) g_ObUnRegisterCallbacks(registration_handle);
            ClearActiveSettings(snapshot);
            snapshot.State = OB_CALLBACK_STATE_UNREGISTERED;
            snapshot.RegistrationStatus = STATUS_CANCELLED;
            snapshot.FailureStage = OB_CALLBACK_STAGE_CANCELLED;
            status = STATUS_CANCELLED;
        } else if (NT_SUCCESS(status)) {
            g_RegistrationHandle = registration_handle;
            CopyAltitude(g_RegisteredAltitude, snapshot.RegisteredAltitude);
            // This is our nonpaged PRE entry point. The driver stays loaded until Shutdown joins
            // the worker and ObUnRegisterCallbacks drains callbacks; no speculative VA probe needed.
            snapshot.HandlerAddress = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(&PreOperation));
            snapshot.HandlerAddressValid = 1;
        }
        g_WorkerActive = false;
        snapshot.WorkerActive = 0;
        PublishDiagnostics(snapshot);
    }
    // No access to controller state after releasing the lock: reaping under that lock is safe.
    PsTerminateSystemThread(status);
}

inline bool ValidControlPacket(POB_CALLBACK_CONTROL_REQUEST request)
{
    return request && request->StructSize == sizeof(*request) &&
        request->Version == OB_CALLBACK_STATUS_VERSION &&
        !request->Reserved[0] && !request->Reserved[1];
}

// Called with the controller lock only after WorkerActive becomes false.
inline VOID ReapFinishedWorker()
{
    if (g_WorkerHandle) {
        ZwWaitForSingleObject(g_WorkerHandle, FALSE, nullptr);
        ZwClose(g_WorkerHandle);
        g_WorkerHandle = nullptr;
    }
}

inline NTSTATUS RequestRegistration(POB_CALLBACK_CONTROL_REQUEST request)
{
    if (!ValidControlPacket(request) || request->MinimumAltitude > request->MaximumAltitude ||
        request->MaximumFraction > kMaximumFraction) return STATUS_INVALID_PARAMETER;
    if (!g_DiagnosticsInitialized) return STATUS_DEVICE_NOT_READY;
    ControlLock lock;
    if (g_Stopping) return STATUS_DELETE_PENDING;
    if (g_WorkerActive || g_RegistrationHandle) return STATUS_DEVICE_BUSY;
    ReapFinishedWorker();
    const auto previous = ReadDiagnostics();
    auto snapshot = MakeDiagnostics(request->MinimumAltitude, request->MaximumAltitude,
        request->MaximumFraction);
    snapshot.State = OB_CALLBACK_STATE_REGISTERING;
    snapshot.RegistrationStatus = STATUS_PENDING;
    snapshot.RegistrationGeneration = previous.RegistrationGeneration + 1;
    snapshot.LastRequestedMinimumAltitude = request->MinimumAltitude;
    snapshot.LastRequestedMaximumAltitude = request->MaximumAltitude;
    snapshot.LastRequestedMaximumFraction = request->MaximumFraction;
    snapshot.WorkerActive = 1;
    g_WorkerActive = true;
    InterlockedExchange(&g_CancelRequested, 0);
    PublishDiagnostics(snapshot);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS status = PsCreateSystemThread(&g_WorkerHandle, SYNCHRONIZE, &attributes,
        nullptr, nullptr, RegistrationWorker, nullptr);
    if (!NT_SUCCESS(status)) {
        g_WorkerHandle = nullptr;
        g_WorkerActive = false;
        snapshot.State = OB_CALLBACK_STATE_FAILED;
        snapshot.FailureStage = OB_CALLBACK_STAGE_CREATE_WORKER;
        snapshot.RegistrationStatus = status;
        snapshot.WorkerActive = 0;
        PublishDiagnostics(snapshot);
    }
    return status;
}

inline NTSTATUS RequestUnregistration(POB_CALLBACK_CONTROL_REQUEST request)
{
    if (!ValidControlPacket(request) || request->MinimumAltitude || request->MaximumAltitude ||
        request->MaximumFraction) return STATUS_INVALID_PARAMETER;
    if (!g_DiagnosticsInitialized) return STATUS_DEVICE_NOT_READY;
    ControlLock lock;
    if (g_Stopping) return STATUS_DELETE_PENDING;
    if (g_WorkerActive) return STATUS_DEVICE_BUSY;
    if (!g_RegistrationHandle) return STATUS_INVALID_DEVICE_STATE;
    ReapFinishedWorker();
    auto snapshot = ReadDiagnostics();
    snapshot.State = OB_CALLBACK_STATE_UNREGISTERING;
    PublishDiagnostics(snapshot);
    g_ObUnRegisterCallbacks(g_RegistrationHandle);
    g_RegistrationHandle = nullptr;
    for (auto& character : g_RegisteredAltitude) character = L'\0';
    ClearActiveSettings(snapshot);
    snapshot.State = OB_CALLBACK_STATE_UNREGISTERED;
    snapshot.RegistrationStatus = STATUS_SUCCESS;
    snapshot.FailureStage = OB_CALLBACK_STAGE_NONE;
    PublishDiagnostics(snapshot);
    return STATUS_SUCCESS;
}

// DriverUnload calls this after draining IOCTL handlers, so no new control operation can enter.
inline VOID Shutdown()
{
    if (!g_DiagnosticsInitialized) return;
    HANDLE worker_handle;
    {
        ControlLock lock;
        g_Stopping = true;
        InterlockedExchange(&g_CancelRequested, 1);
        worker_handle = g_WorkerHandle;
    }
    // Do not hold the mutex here: an active worker needs it to publish its final state and exit.
    if (worker_handle) ZwWaitForSingleObject(worker_handle, FALSE, nullptr);
    {
        ControlLock lock;
        if (g_WorkerHandle) {
            ZwClose(g_WorkerHandle);
            g_WorkerHandle = nullptr;
        }
        if (g_RegistrationHandle) {
            g_ObUnRegisterCallbacks(g_RegistrationHandle);
            g_RegistrationHandle = nullptr;
        }
        for (auto& character : g_RegisteredAltitude) character = L'\0';
        auto snapshot = ReadDiagnostics();
        ClearActiveSettings(snapshot);
        snapshot.State = OB_CALLBACK_STATE_UNREGISTERED;
        snapshot.WorkerActive = 0;
        PublishDiagnostics(snapshot);
    }
}

} } // namespace helper::ob_callbacks
