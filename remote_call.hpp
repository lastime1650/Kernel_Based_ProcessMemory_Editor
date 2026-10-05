#pragma once

#include "remote_call_protocol.h"

namespace helper
{
    namespace remote_call
    {
        // Native export: not a documented WDK DDI. Resolve by name and fail
        // closed when unavailable; never scan/patch kernel memory or SSDT.
        using CREATE_USER_THREAD = decltype(&RtlCreateUserThread);

        struct RECORD
        {
            PFILE_OBJECT Owner;
            PETHREAD Thread; // Referenced object, independent of TID reuse.
            ULONGLONG CallId;
            ULONGLONG ProcessId;
            ULONGLONG ProcessStartKey;
            ULONGLONG ThreadId;
            ULONGLONG FunctionAddress;
            ULONGLONG Parameter;
            ULONGLONG CreatedAtTime;
        };
        struct STATE
        {
            KMUTEX Mutex;
            CREATE_USER_THREAD CreateThread;
            ULONGLONG NextId;
            RECORD Records[FUNCTION_CALL_MAX_RECORDS];
        };
        inline STATE& State()
        {
            static STATE state = {};
            return state;
        }
        inline VOID Lock() { KeWaitForSingleObject(&State().Mutex, Executive, KernelMode, FALSE, nullptr); }
        inline VOID Unlock() { KeReleaseMutex(&State().Mutex, FALSE); }
        inline VOID Initialize()
        {
            auto& state = State();
            RtlZeroMemory(&state, sizeof(state));
            KeInitializeMutex(&state.Mutex, 0);
            UNICODE_STRING name;
            RtlInitUnicodeString(&name, L"RtlCreateUserThread");
            state.CreateThread = reinterpret_cast<CREATE_USER_THREAD>(MmGetSystemRoutineAddress(&name));
        }
        inline bool IsClosed(PFILE_OBJECT owner)
        {
            return !owner || owner->FsContext2 != nullptr;
        }
        inline VOID CleanupFile(PFILE_OBJECT owner)
        {
            if (!owner) return;
            Lock();
            // This driver reserves FsContext2 for its cleanup marker. Holding
            // the same mutex as creation prevents insertion after cleanup.
            owner->FsContext2 = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(1));
            for (auto& record : State().Records)
            {
                if (record.Owner == owner)
                {
                    PETHREAD thread = record.Thread;
                    RtlZeroMemory(&record, sizeof(record));
                    if (thread) ObDereferenceObject(thread);
                }
            }
            Unlock();
        }
        inline VOID Shutdown()
        {
            // Called only after request rundown. User threads execute no code
            // in this driver, so there is no need to wait for/terminate them.
            Lock();
            for (auto& record : State().Records)
            {
                PETHREAD thread = record.Thread;
                RtlZeroMemory(&record, sizeof(record));
                if (thread) ObDereferenceObject(thread);
            }
            Unlock();
        }

        inline VOID Observe(PETHREAD thread, ULONG wait_ms, PULONG completed,
            NTSTATUS* wait_status, NTSTATUS* exit_status, NTSTATUS* query_status)
        {
            *completed = 0;
            *exit_status = STATUS_PENDING;
            *query_status = STATUS_PENDING;
            LARGE_INTEGER timeout;
            timeout.QuadPart = -static_cast<LONGLONG>(wait_ms) * 10000LL;
            *wait_status = KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, &timeout);
            // STATUS_TIMEOUT is nonnegative. NT_SUCCESS is not completion.
            if (*wait_status != STATUS_SUCCESS) return;
            *completed = 1;
            HANDLE handle = nullptr;
            *query_status = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, nullptr,
                0x0040 /* THREAD_QUERY_INFORMATION */, *PsThreadType, KernelMode, &handle);
            if (!NT_SUCCESS(*query_status)) return;
            THREAD_BASIC_INFORMATION basic = {};
            *query_status = ZwQueryInformationThread(handle, static_cast<THREADINFOCLASS>(0),
                &basic, sizeof(basic), nullptr);
            if (NT_SUCCESS(*query_status)) *exit_status = basic.ExitStatus;
            ZwClose(handle);
        }

        inline NTSTATUS Create(PFILE_OBJECT owner, CREATE_FUNCTION_CALL_REQUEST* request)
        {
            const ULONG reserved = request->Reserved;
            request->ResultStatus = STATUS_UNSUCCESSFUL;
            request->CallId = request->ThreadId = 0;
            request->ThreadCreated = request->Completed = 0;
            request->WaitStatus = request->ExitStatus = request->QueryStatus = STATUS_PENDING;
            request->Reserved = 0;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            if (request->StructSize != sizeof(*request) ||
                request->Version != FUNCTION_CALL_PROTOCOL_VERSION || request->Flags || reserved ||
                !owner || !request->ProcessId || !request->ProcessStartKey ||
                request->WaitMilliseconds > FUNCTION_CALL_MAX_WAIT_MS ||
                !request->FunctionAddress || request->FunctionAddress > reinterpret_cast<ULONG_PTR>(MmHighestUserAddress))
                return STATUS_INVALID_PARAMETER;
#if !defined(_AMD64_)
            return STATUS_NOT_SUPPORTED;
#else
            if (!State().CreateThread) return STATUS_NOT_SUPPORTED;
            PEPROCESS process = nullptr;
            NTSTATUS status = PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ProcessId)), &process);
            if (!NT_SUCCESS(status)) return status;
            HANDLE process_handle = nullptr;
            HANDLE thread_handle = nullptr;
            PETHREAD thread = nullptr;
            bool locked = false;
            do
            {
                if (process == PsInitialSystemProcess || PsGetProcessWow64Process(process))
                { status = STATUS_NOT_SUPPORTED; break; }
                if (PsGetProcessStartKey(process) != request->ProcessStartKey)
                { status = STATUS_INVALID_CID; break; }
                if (PsGetProcessExitStatus(process) != STATUS_PENDING)
                { status = STATUS_PROCESS_IS_TERMINATING; break; }
                status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr,
                    0x0002 /* PROCESS_CREATE_THREAD */ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                    PROCESS_VM_READ | PROCESS_VM_WRITE, *PsProcessType, KernelMode, &process_handle);
                if (!NT_SUCCESS(status)) break;
                MEMORY_BASIC_INFORMATION memory = {};
                status = ZwQueryVirtualMemory(process_handle, reinterpret_cast<PVOID>(request->FunctionAddress),
                    MemoryBasicInformation, &memory, sizeof(memory), nullptr);
                if (!NT_SUCCESS(status)) break;
                const ULONG executable = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                if (memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
                    !(memory.Protect & executable))
                { status = STATUS_ACCESS_VIOLATION; break; }
                Lock(); locked = true;
                if (IsClosed(owner)) { status = STATUS_DELETE_PENDING; break; }
                RECORD* slot = nullptr;
                ULONG owned = 0;
                for (auto& record : State().Records)
                {
                    if (!record.Thread && !slot) slot = &record;
                    if (record.Owner == owner) ++owned;
                }
                if (!slot || owned >= FUNCTION_CALL_MAX_RECORDS_PER_FILE)
                { status = STATUS_QUOTA_EXCEEDED; break; }
                // Reserve a non-repeating ID before the irreversible create.
                if (State().NextId == ~static_cast<ULONGLONG>(0))
                { status = STATUS_INTEGER_OVERFLOW; break; }
                const ULONGLONG call_id = ++State().NextId;
                CLIENT_ID client_id = {};
                // The ntoskrnl RtlCreateUserThread wrapper creates a private
                // kernel handle (OBJ_KERNEL_HANDLE), unlike its ntdll counterpart.
                // No process attachment or PreviousMode modification is used.
                status = State().CreateThread(process_handle, nullptr, FALSE, 0, 0, 0,
                    reinterpret_cast<PUSER_THREAD_START_ROUTINE>(request->FunctionAddress),
                    reinterpret_cast<PVOID>(request->Parameter), &thread_handle, &client_id);
                if (!NT_SUCCESS(status)) break;
                request->ThreadCreated = 1;
                request->ThreadId = reinterpret_cast<ULONG_PTR>(client_id.UniqueThread);
                status = ObReferenceObjectByHandle(thread_handle, SYNCHRONIZE, *PsThreadType,
                    KernelMode, reinterpret_cast<PVOID*>(&thread), nullptr);
                if (!NT_SUCCESS(status)) break; // Already created: never automatically retry.
                request->ThreadId = reinterpret_cast<ULONG_PTR>(PsGetThreadId(thread));
                slot->Owner = owner;
                slot->Thread = thread; // Transfer this reference to the record.
                slot->CallId = request->CallId = call_id;
                slot->ProcessId = request->ProcessId;
                slot->ProcessStartKey = request->ProcessStartKey;
                slot->ThreadId = request->ThreadId;
                slot->FunctionAddress = request->FunctionAddress;
                slot->Parameter = request->Parameter;
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                slot->CreatedAtTime = now.QuadPart;
                // A separate reference keeps observation safe if cleanup runs.
                ObReferenceObject(thread);
                Unlock(); locked = false;
                Observe(thread, request->WaitMilliseconds, &request->Completed,
                    &request->WaitStatus, &request->ExitStatus, &request->QueryStatus);
                ObDereferenceObject(thread);
                status = STATUS_SUCCESS;
            } while (false);
            if (locked) Unlock();
            if (thread_handle) ZwClose(thread_handle);
            if (process_handle) ZwClose(process_handle);
            ObDereferenceObject(process);
            return status;
#endif
        }

        inline NTSTATUS Query(PFILE_OBJECT owner, QUERY_FUNCTION_CALL_REQUEST* request)
        {
            const ULONG reserved = request->Reserved;
            request->ProcessId = request->ProcessStartKey = request->ThreadId = 0;
            request->FunctionAddress = request->Parameter = request->CreatedAtTime = 0;
            request->ThreadCreated = request->Completed = 0;
            request->WaitStatus = request->ExitStatus = request->QueryStatus = STATUS_PENDING;
            request->Reserved = 0;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            if (!owner || !request->CallId || request->StructSize != sizeof(*request) ||
                request->Version != FUNCTION_CALL_PROTOCOL_VERSION || reserved ||
                request->WaitMilliseconds > FUNCTION_CALL_MAX_WAIT_MS)
                return STATUS_INVALID_PARAMETER;
            RECORD snapshot = {};
            Lock();
            if (IsClosed(owner)) { Unlock(); return STATUS_DELETE_PENDING; }
            for (auto& record : State().Records)
            {
                if (record.Owner == owner && record.CallId == request->CallId)
                {
                    snapshot = record;
                    ObReferenceObject(snapshot.Thread);
                    break;
                }
            }
            Unlock();
            if (!snapshot.Thread) return STATUS_NOT_FOUND;
            request->ProcessId = snapshot.ProcessId;
            request->ProcessStartKey = snapshot.ProcessStartKey;
            request->ThreadId = snapshot.ThreadId;
            request->FunctionAddress = snapshot.FunctionAddress;
            request->Parameter = snapshot.Parameter;
            request->CreatedAtTime = snapshot.CreatedAtTime;
            request->ThreadCreated = 1;
            Observe(snapshot.Thread, request->WaitMilliseconds, &request->Completed,
                &request->WaitStatus, &request->ExitStatus, &request->QueryStatus);
            ObDereferenceObject(snapshot.Thread);
            if (request->WaitStatus != STATUS_SUCCESS && request->WaitStatus != STATUS_TIMEOUT)
                return request->WaitStatus;
            return request->Completed ? request->QueryStatus : STATUS_SUCCESS;
        }

        inline NTSTATUS Release(PFILE_OBJECT owner, RELEASE_FUNCTION_CALL_REQUEST* request)
        {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
            if (!owner || !request->CallId || request->StructSize != sizeof(*request) ||
                request->Version != FUNCTION_CALL_PROTOCOL_VERSION || request->Reserved)
                return STATUS_INVALID_PARAMETER;
            PETHREAD thread = nullptr;
            Lock();
            if (IsClosed(owner)) { Unlock(); return STATUS_DELETE_PENDING; }
            for (auto& record : State().Records)
            {
                if (record.Owner == owner && record.CallId == request->CallId)
                {
                    thread = record.Thread;
                    RtlZeroMemory(&record, sizeof(record));
                    break;
                }
            }
            Unlock();
            if (!thread) return STATUS_NOT_FOUND;
            ObDereferenceObject(thread);
            // Releasing tracking does not terminate the thread or free its argument.
            return STATUS_SUCCESS;
        }

        _Dispatch_type_(IRP_MJ_CREATE)
        _Dispatch_type_(IRP_MJ_CLEANUP)
        _Dispatch_type_(IRP_MJ_CLOSE)
        inline DRIVER_DISPATCH FileRoutine;
        inline NTSTATUS FileRoutine(PDEVICE_OBJECT device, PIRP irp)
        {
            UNREFERENCED_PARAMETER(device);
            auto stack = IoGetCurrentIrpStackLocation(irp);
            NTSTATUS status = STATUS_SUCCESS;
            bool critical = false;
            bool acquired = false;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) status = STATUS_INVALID_DEVICE_STATE;
            else
            {
                KeEnterCriticalRegion();
                critical = true;
                acquired = ExAcquireRundownProtection(&helper::lifecycle::Requests()) != FALSE;
                if (!acquired) status = STATUS_DELETE_PENDING;
                else if (!stack->FileObject) status = STATUS_INVALID_PARAMETER;
                else
                {
                    if (stack->MajorFunction == IRP_MJ_CREATE)
                        stack->FileObject->FsContext2 = nullptr;
                    else CleanupFile(stack->FileObject);
                }
            }
            irp->IoStatus.Status = status;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            if (acquired) ExReleaseRundownProtection(&helper::lifecycle::Requests());
            if (critical) KeLeaveCriticalRegion();
            return status;
        }
    }
}
