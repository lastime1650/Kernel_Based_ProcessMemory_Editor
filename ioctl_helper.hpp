#pragma once

#include "helper.hpp"
#include "remote_call.hpp"


namespace helper
{
    namespace ioctl_helper
    {
        //
        // ============================================================
        // IOCTL definitions
        //
        // Private/Vendor function range:
        //
        //      0x800 ~
        //
        // METHOD_BUFFERED:
        //
        //      Input / Output = Irp->AssociatedIrp.SystemBuffer
        // ============================================================
        //

#define IOCTL_HELPER_PROCESS_INFORMATION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_ALLOC_VIRTUAL_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_FREE_VIRTUAL_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_COPY_PROCESS_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_SCAN_VALUE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_READ_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_READ_STRING_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_READ_PROCESS_INFORMATION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_FREE_LINKED_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_FREE_STRING_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//
// ============================================================
// HWBP IOCTL
// ============================================================
//

#define IOCTL_HELPER_SET_HARDWARE_BREAKPOINT \
    CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x80A, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS \
    )

#define IOCTL_HELPER_QUERY_HARDWARE_BREAKPOINT \
    CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x80B, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS \
    )

#define IOCTL_HELPER_REMOVE_HARDWARE_BREAKPOINT \
    CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x80C, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS \
    )

#define IOCTL_HELPER_FREE_HARDWARE_BREAKPOINT_RESULT \
    CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x80D, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS \
    )

// ============================================================
// REGISTER DLL (DLL INJECTION)
// ============================================================

#define IOCTL_HELPER_REGISTER_DLL \
    CTL_CODE( \
        FILE_DEVICE_UNKNOWN, \
        0x80E, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS \
    )

#define IOCTL_HELPER_WRITE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_PROTECT_VIRTUAL_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_PATTERN_SCAN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_ENUMERATE_THREADS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_SUSPEND_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_RESUME_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_GET_THREAD_CONTEXT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_SET_THREAD_CONTEXT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_EVENT_MONITOR_CONTROL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_POLL_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_GET_DRIVER_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_QUERY_PROCESS_EXTENDED \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_QUERY_PROCESS_HANDLES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_QUERY_PROCESS_TOKEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81C, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_QUERY_THREAD_INFO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81D, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_SET_THREAD_PRIORITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81E, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_SET_THREAD_AFFINITY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81F, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_TERMINATE_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_SET_THREAD_HIDE_FROM_DEBUGGER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


        //
        // ============================================================
        // PROCESS INFORMATION
        // ============================================================
        //

        typedef struct _PROCESS_INFORMATION_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG ProcessIdResult;
            ULONGLONG ParentProcessId;

            ULONGLONG PebBaseAddress;

            NTSTATUS ExitStatus;

            ULONGLONG AffinityMask;

            LONG BasePriority;

            ULONGLONG ProcessStartKey;

            BOOLEAN IsProtectedProcess;

            WCHAR ImagePath[512];

        } PROCESS_INFORMATION_REQUEST,
            * PPROCESS_INFORMATION_REQUEST;



        //
        // ============================================================
        // ALLOC USER VIRTUAL MEMORY
        // ============================================================
        //

        typedef struct _ALLOC_VIRTUAL_MEMORY_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;

            ULONGLONG Size;

            ULONG Protect;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG AllocatedAddress;

        } ALLOC_VIRTUAL_MEMORY_REQUEST,
            * PALLOC_VIRTUAL_MEMORY_REQUEST;



        //
        // ============================================================
        // FREE USER VIRTUAL MEMORY
        // ============================================================
        //

        typedef struct _FREE_VIRTUAL_MEMORY_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;

            ULONGLONG Address;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

        } FREE_VIRTUAL_MEMORY_REQUEST,
            * PFREE_VIRTUAL_MEMORY_REQUEST;



        //
        // ============================================================
        // COPY PROCESS MEMORY
        // ============================================================
        //

        typedef struct _COPY_PROCESS_MEMORY_REQUEST
        {
            //
            // INPUT
            //
            ULONG SourceProcessId;

            ULONGLONG SourceAddress;

            ULONG DestinationProcessId;

            ULONGLONG DestinationAddress;

            ULONGLONG Size;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG CopiedSize;

        } COPY_PROCESS_MEMORY_REQUEST,
            * PCOPY_PROCESS_MEMORY_REQUEST;



        //
        // ============================================================
        // SCAN VALUE
        //
        // SourceValueAddress belongs to the IOCTL requester process.
        //
        // ResultListAddress also belongs to requester process.
        // ============================================================
        //

        typedef struct _SCAN_VALUE_PROCESS_REQUEST
        {
            //
            // INPUT
            //
            ULONG TargetProcessId;

            ULONGLONG SourceValueAddress;

            ULONGLONG SourceValueSize;

            ULONG PageProtect;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG ResultListAddress;

        } SCAN_VALUE_PROCESS_REQUEST,
            * PSCAN_VALUE_PROCESS_REQUEST;



        //
        // ============================================================
        // READ PROCESS
        //
        // Output DumpedAddress belongs to IOCTL requester process.
        // ============================================================
        //

        typedef struct _READ_PROCESS_REQUEST
        {
            //
            // INPUT
            //
            ULONG TargetProcessId;

            ULONGLONG ReadAddress;

            ULONGLONG Size;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG DumpedAddress;

        } READ_PROCESS_REQUEST,
            * PREAD_PROCESS_REQUEST;



        //
        // ============================================================
        // READ STRING PROCESS
        // ============================================================
        //

        typedef struct _READ_STRING_PROCESS_REQUEST
        {
            //
            // INPUT
            //
            ULONG TargetProcessId;

            ULONGLONG MinimumCharacterCount;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG ResultListAddress;

        } READ_STRING_PROCESS_REQUEST,
            * PREAD_STRING_PROCESS_REQUEST;



        //
        // ============================================================
        // READ PROCESS MEMORY INFORMATION
        // ============================================================
        //

        typedef struct _READ_PROCESS_INFORMATION_REQUEST
        {
            //
            // INPUT
            //
            ULONG TargetProcessId;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONGLONG ResultListAddress;

        } READ_PROCESS_INFORMATION_REQUEST,
            * PREAD_PROCESS_INFORMATION_REQUEST;



        //
        // ============================================================
        // FREE GENERIC USERMODE LINKED LIST
        // ============================================================
        //

        typedef struct _FREE_LINKED_LIST_REQUEST
        {
            //
            // INPUT
            //
            ULONGLONG FirstNodeAddress;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

        } FREE_LINKED_LIST_REQUEST,
            * PFREE_LINKED_LIST_REQUEST;



        //
        // ============================================================
        // FREE STRING RESULT LIST
        //
        // ReadStringProcess has an additional DumpedAddress allocation
        // for every node, so generic FreeLinkedList() alone is not enough.
        // ============================================================
        //

        typedef struct _FREE_STRING_LIST_REQUEST
        {
            //
            // INPUT
            //
            ULONGLONG FirstNodeAddress;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

        } FREE_STRING_LIST_REQUEST,
            * PFREE_STRING_LIST_REQUEST;

        //
// ============================================================
// HWBP SET
// ============================================================
//

        typedef struct _IOCTL_HWBP_SET_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;

            ULONG Reserved;

            ULONGLONG Address;

            //
            // helper::process::HARDWARE_BREAKPOINT_TYPE
            //
            ULONG Type;

            //
            // helper::process::HARDWARE_BREAKPOINT_LENGTH
            //
            ULONG Length;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONG Reserved2;

            //
            // Requestor Process User VA.
            //
            ULONGLONG FirstResultNode;

            ULONG AppliedThreadCount;

            ULONG FailedThreadCount;

        } IOCTL_HWBP_SET_REQUEST,
            * PIOCTL_HWBP_SET_REQUEST;



        //
        // ============================================================
        // HWBP QUERY
        // ============================================================
        //

        typedef struct _IOCTL_HWBP_QUERY_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;

            ULONG Reserved;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONG Reserved2;

            ULONGLONG FirstResultNode;

            ULONG ThreadCount;

            ULONG BreakpointCount;

        } IOCTL_HWBP_QUERY_REQUEST,
            * PIOCTL_HWBP_QUERY_REQUEST;



        //
        // ============================================================
        // HWBP REMOVE
        // ============================================================
        //

        typedef struct _IOCTL_HWBP_REMOVE_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;

            ULONG Reserved;

            //
            // SetHardwareBreakpoint()에서 반환받은
            // Requestor Process User VA.
            //
            ULONGLONG FirstResultNode;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONG RemovedThreadCount;

            ULONG FailedThreadCount;

            ULONG Reserved2;

        } IOCTL_HWBP_REMOVE_REQUEST,
            * PIOCTL_HWBP_REMOVE_REQUEST;



        //
        // ============================================================
        // HWBP RESULT FREE
        // ============================================================
        //

        typedef struct _IOCTL_HWBP_FREE_RESULT_REQUEST
        {
            //
            // INPUT
            //
            ULONGLONG FirstResultNode;


            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            ULONG Reserved;

        } IOCTL_HWBP_FREE_RESULT_REQUEST,
            * PIOCTL_HWBP_FREE_RESULT_REQUEST;

        //
// ============================================================
// REGISTER DLL REQUEST
// ============================================================
//

        typedef struct _REGISTER_DLL_REQUEST
        {
            //
            // INPUT
            //
            ULONG ProcessId;

            //
            // ANSI 경로 문자열 입력 (호출측에서 전달)
            //
            CHAR DllPath[520];

            //
            // OUTPUT
            //
            NTSTATUS ResultStatus;

            BOOLEAN TargetIsWow64;
            BOOLEAN Kernel32Found;
            BOOLEAN LoadLibraryFound;

            ULONGLONG Kernel32Base;
            ULONGLONG Kernel32Size;

            ULONGLONG LoadLibraryAddress;

        } REGISTER_DLL_REQUEST, * PREGISTER_DLL_REQUEST;

        // ============================================================
        // 0x80F: WRITE PROCESS MEMORY
        // ============================================================

        typedef struct _WRITE_PROCESS_REQUEST
        {
            ULONG ProcessId;
            ULONGLONG TargetAddress;
            ULONGLONG Size;
            UCHAR Buffer[4096];
            ULONGLONG UserBufferAddress;

            NTSTATUS ResultStatus;
            ULONGLONG BytesWritten;
        } WRITE_PROCESS_REQUEST, *PWRITE_PROCESS_REQUEST;

        // ============================================================
        // 0x810: PROTECT VIRTUAL MEMORY
        // ============================================================

        typedef struct _PROTECT_VIRTUAL_MEMORY_REQUEST
        {
            ULONG ProcessId;
            ULONGLONG BaseAddress;
            ULONGLONG RegionSize;
            ULONG NewProtect;

            NTSTATUS ResultStatus;
            ULONG OldProtect;
            ULONGLONG ResultBaseAddress;
            ULONGLONG ResultRegionSize;
        } PROTECT_VIRTUAL_MEMORY_REQUEST, *PPROTECT_VIRTUAL_MEMORY_REQUEST;

        // ============================================================
        // 0x811: PATTERN SCAN (AOB WILDCARD)
        // ============================================================

        typedef struct _PATTERN_SCAN_REQUEST
        {
            ULONG ProcessId;
            ULONGLONG StartAddress;
            ULONGLONG ScanLength;
            ULONG PatternLength;
            UCHAR Pattern[256];
            CHAR Mask[256];
            ULONG PageProtect;

            NTSTATUS ResultStatus;
            ULONGLONG FoundAddress;
            ULONG MatchesCount;
        } PATTERN_SCAN_REQUEST, *PPATTERN_SCAN_REQUEST;

        // ============================================================
        // 0x812: ENUMERATE THREADS
        // ============================================================

        typedef struct _THREAD_SNAPSHOT_INFO
        {
            ULONGLONG ThreadId;
            ULONGLONG StartAddress;
            ULONG Priority;
            LONG BasePriority;
            ULONG State;
            ULONG WaitReason;
            ULONG ContextSwitches;
        } THREAD_SNAPSHOT_INFO, *PTHREAD_SNAPSHOT_INFO;

        typedef struct _ENUMERATE_THREADS_REQUEST
        {
            ULONG ProcessId;
            ULONG MaxThreads;

            NTSTATUS ResultStatus;
            ULONG ThreadCount;
            THREAD_SNAPSHOT_INFO Threads[64];
        } ENUMERATE_THREADS_REQUEST, *PENUMERATE_THREADS_REQUEST;

        // ============================================================
        // 0x813 & 0x814: SUSPEND / RESUME THREAD
        // ============================================================

        typedef struct _THREAD_CONTROL_REQUEST
        {
            ULONG ThreadId;

            NTSTATUS ResultStatus;
            ULONG PreviousSuspendCount;
        } THREAD_CONTROL_REQUEST, *PTHREAD_CONTROL_REQUEST;

        // ============================================================
        // 0x815 & 0x816: GET / SET THREAD CONTEXT (REGISTERS)
        // ============================================================

        typedef struct _THREAD_REGISTERS_REQUEST
        {
            ULONG ThreadId;

            NTSTATUS ResultStatus;
            ULONGLONG Rip;
            ULONGLONG Rsp;
            ULONGLONG Rbp;
            ULONGLONG Rax;
            ULONGLONG Rbx;
            ULONGLONG Rcx;
            ULONGLONG Rdx;
            ULONGLONG Rsi;
            ULONGLONG Rdi;
            ULONGLONG R8;
            ULONGLONG R9;
            ULONGLONG R10;
            ULONGLONG R11;
            ULONGLONG R12;
            ULONGLONG R13;
            ULONGLONG R14;
            ULONGLONG R15;
            ULONG EFlags;
        } THREAD_REGISTERS_REQUEST, *PTHREAD_REGISTERS_REQUEST;

        // ============================================================
        // 0x817: EVENT MONITOR CONTROL
        // ============================================================

        typedef struct _EVENT_MONITOR_CONTROL_REQUEST
        {
            BOOLEAN EnableProcessMonitor;
            BOOLEAN EnableImageLoadMonitor;

            NTSTATUS ResultStatus;
            BOOLEAN ProcessMonitorActive;
            BOOLEAN ImageMonitorActive;
        } EVENT_MONITOR_CONTROL_REQUEST, *PEVENT_MONITOR_CONTROL_REQUEST;

        // ============================================================
        // 0x818: POLL EVENTS
        // ============================================================

        // Wire layout retained for existing clients; notification callbacks are removed.
        typedef struct _KERNEL_MONITOR_EVENT
        {
            ULONG EventType;
            LARGE_INTEGER Timestamp;
            ULONG ProcessId;
            ULONG ParentProcessId;
            ULONG CreatingThreadId;
            ULONGLONG ImageBase;
            ULONGLONG ImageSize;
            WCHAR ImageName[260];
            WCHAR CommandLine[260];
        } KERNEL_MONITOR_EVENT, *PKERNEL_MONITOR_EVENT;

        typedef struct _POLL_EVENTS_REQUEST
        {
            ULONG MaxEventsToRead;

            NTSTATUS ResultStatus;
            ULONG EventsReturned;
            ULONG EventsRemaining;
            KERNEL_MONITOR_EVENT Events[16];
        } POLL_EVENTS_REQUEST, *PPOLL_EVENTS_REQUEST;

        // ============================================================
        // 0x819: DRIVER STATUS
        // ============================================================

        typedef struct _DRIVER_STATUS_REQUEST
        {
            NTSTATUS ResultStatus;
            ULONG MajorVersion;
            ULONG MinorVersion;
            ULONG BuildNumber;
            LARGE_INTEGER DriverStartTime;
            ULONGLONG TotalIoctlRequests;
            BOOLEAN EventMonitorActive;
            ULONG QueuedEventCount;
        } DRIVER_STATUS_REQUEST, *PDRIVER_STATUS_REQUEST;

        // ============================================================
        // 0x81A: QUERY PROCESS EXTENDED INFO
        // ============================================================

        typedef struct _PROCESS_EXTENDED_INFO_REQUEST
        {
            ULONGLONG ProcessId;
            NTSTATUS ResultStatus;
            helper::process::PROCESS_EXTENDED_INFO Info;
        } PROCESS_EXTENDED_INFO_REQUEST, *PPROCESS_EXTENDED_INFO_REQUEST;

        // ============================================================
        // 0x81B: QUERY PROCESS HANDLES
        // ============================================================

        typedef struct _PROCESS_HANDLES_REQUEST
        {
            ULONGLONG ProcessId;
            NTSTATUS ResultStatus;
            ULONG MaxHandles;
            ULONG ReturnedHandleCount;
            helper::process::PROCESS_HANDLE_ENTRY Handles[128];
        } PROCESS_HANDLES_REQUEST, *PPROCESS_HANDLES_REQUEST;

        // ============================================================
        // 0x81C: QUERY PROCESS TOKEN
        // ============================================================

        typedef struct _PROCESS_TOKEN_INFO_REQUEST
        {
            ULONGLONG ProcessId;
            NTSTATUS ResultStatus;
            helper::process::PROCESS_TOKEN_INFO TokenInfo;
        } PROCESS_TOKEN_INFO_REQUEST, *PPROCESS_TOKEN_INFO_REQUEST;

        // ============================================================
        // 0x81D: QUERY THREAD INFO
        // ============================================================

        typedef struct _THREAD_INFO_REQUEST
        {
            ULONGLONG ThreadId;
            NTSTATUS ResultStatus;
            helper::process::THREAD_EXTENDED_INFO ThreadInfo;
        } THREAD_INFO_REQUEST, *PTHREAD_INFO_REQUEST;

        // ============================================================
        // 0x81E: SET THREAD PRIORITY
        // ============================================================

        typedef struct _THREAD_PRIORITY_REQUEST
        {
            ULONGLONG ThreadId;
            LONG Priority;
            NTSTATUS ResultStatus;
        } THREAD_PRIORITY_REQUEST, *PTHREAD_PRIORITY_REQUEST;

        // ============================================================
        // 0x81F: SET THREAD AFFINITY
        // ============================================================

        typedef struct _THREAD_AFFINITY_REQUEST
        {
            ULONGLONG ThreadId;
            ULONGLONG AffinityMask;
            NTSTATUS ResultStatus;
        } THREAD_AFFINITY_REQUEST, *PTHREAD_AFFINITY_REQUEST;

        // ============================================================
        // 0x820: TERMINATE THREAD
        // ============================================================

        typedef struct _THREAD_TERMINATE_REQUEST
        {
            ULONGLONG ThreadId;
            NTSTATUS ExitStatus;
            NTSTATUS ResultStatus;
        } THREAD_TERMINATE_REQUEST, *PTHREAD_TERMINATE_REQUEST;

        // ============================================================
        // 0x821: SET THREAD HIDE FROM DEBUGGER
        // ============================================================

        typedef struct _THREAD_HIDE_REQUEST
        {
            ULONGLONG ThreadId;
            NTSTATUS ResultStatus;
        } THREAD_HIDE_REQUEST, *PTHREAD_HIDE_REQUEST;


        //
        // ============================================================
        // Internal
        //
        // PID -> kernel HANDLE with requested access rights
        // ============================================================
        //

        inline NTSTATUS OpenProcessHandleByPid(
            _In_ ULONG pid,
            _In_ ACCESS_MASK desired_access,
            _Out_ PHANDLE process_handle
        )
        {
            if (
                pid == 0 ||
                process_handle == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            *process_handle =
                nullptr;


            PEPROCESS process =
                nullptr;


            NTSTATUS status =
                PsLookupProcessByProcessId(
                    reinterpret_cast<HANDLE>(
                        static_cast<ULONG_PTR>(pid)
                        ),
                    &process
                );


            if (!NT_SUCCESS(status))
                return status;


            status =
                ObOpenObjectByPointer(
                    process,
                    OBJ_KERNEL_HANDLE,
                    nullptr,
                    desired_access,
                    *PsProcessType,
                    KernelMode,
                    process_handle
                );


            ObDereferenceObject(
                process
            );


            return status;
        }



        //
        // ============================================================
        // Open the process which actually issued this IOCTL.
        //
        // Do NOT trust a RequestProcessId supplied by user-mode.
        // ============================================================
        //

        inline NTSTATUS OpenRequestorProcessHandle(
            _In_ PIRP irp,
            _In_ ACCESS_MASK desired_access,
            _Out_ PHANDLE process_handle
        )
        {
            if (
                irp == nullptr ||
                process_handle == nullptr
                )
            {
                return STATUS_INVALID_PARAMETER;
            }


            *process_handle =
                nullptr;


            PEPROCESS request_process =
                IoGetRequestorProcess(
                    irp
                );


            if (request_process == nullptr)
                return STATUS_INVALID_CID;


            return ObOpenObjectByPointer(
                request_process,
                OBJ_KERNEL_HANDLE,
                nullptr,
                desired_access,
                *PsProcessType,
                KernelMode,
                process_handle
            );
        }



        //
        // ============================================================
        // User VA validation
        //
        // IOCTL caller cannot use this interface to supply a raw
        // kernel virtual address.
        // ============================================================
        //

        inline BOOLEAN IsValidUserRange(
            _In_ ULONGLONG address,
            _In_ ULONGLONG size
        )
        {
            if (
                address == 0 ||
                size == 0
                )
            {
                return FALSE;
            }


            if (
                address >
                static_cast<ULONGLONG>(
                    MAXULONG_PTR
                    ) ||
                size >
                static_cast<ULONGLONG>(
                    MAXSIZE_T
                    )
                )
            {
                return FALSE;
            }


            ULONGLONG end_address =
                address + size - 1;


            if (end_address < address)
                return FALSE;


            if (
                end_address >
                reinterpret_cast<ULONGLONG>(
                    MmHighestUserAddress
                    )
                )
            {
                return FALSE;
            }


            return TRUE;
        }



        //
        // ============================================================
        // METHOD_BUFFERED packet validator
        // ============================================================
        //

        template<typename T>
        inline T* GetPacket(
            _In_ PIRP irp,
            _In_ PIO_STACK_LOCATION stack
        )
        {
            if (
                irp == nullptr ||
                stack == nullptr
                )
            {
                return nullptr;
            }


            if (
                irp->AssociatedIrp.SystemBuffer ==
                nullptr
                )
            {
                return nullptr;
            }


            if (
                stack->Parameters.DeviceIoControl
                .InputBufferLength <
                sizeof(T) ||
                stack->Parameters.DeviceIoControl
                .OutputBufferLength <
                sizeof(T)
                )
            {
                return nullptr;
            }


            return static_cast<T*>(
                irp->AssociatedIrp.SystemBuffer
                );
        }



        //
        // ============================================================
        // Free ReadStringProcess result
        //
        // Every node contains:
        //
        // READ_STRING_INFORMATION
        //      └─ DumpedAddress -> additional user allocation
        //
        // Therefore:
        //
        // 1. free all DumpedAddress
        // 2. FreeLinkedList()
        // ============================================================
        //

        inline NTSTATUS FreeStringResultList(HANDLE request_process_handle, PVOID first_node_address)
        {
            return helper::read::process::FreeStringResultList(request_process_handle, first_node_address);
        }


        //
        // ============================================================
        // DeviceControlRoutine
        // ============================================================
        //

        inline NTSTATUS DeviceControlRoutineImpl(
            _In_ PDEVICE_OBJECT device_object,
            _Inout_ PIRP irp
        )
        {
            UNREFERENCED_PARAMETER(
                device_object
            );


            if (irp == nullptr)
                return STATUS_INVALID_PARAMETER;


            //
            // All current high-level helpers are designed
            // around PASSIVE_LEVEL.
            //
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            {
                irp->IoStatus.Status =
                    STATUS_INVALID_DEVICE_STATE;

                irp->IoStatus.Information =
                    0;


                IoCompleteRequest(
                    irp,
                    IO_NO_INCREMENT
                );


                return STATUS_INVALID_DEVICE_STATE;
            }


            PIO_STACK_LOCATION stack =
                IoGetCurrentIrpStackLocation(
                    irp
                );


            ULONG ioctl_code =
                stack->Parameters.DeviceIoControl
                .IoControlCode;


            NTSTATUS status =
                STATUS_INVALID_DEVICE_REQUEST;


            ULONG_PTR information =
                0;

            helper::diagnostics::IncrementIoctlCount();



            //
            // ========================================================
            // 0x800
            //
            // SearchActiveProcessInformation
            // ========================================================
            //

            if (
                ioctl_code ==
                IOCTL_HELPER_PROCESS_INFORMATION
                )
            {
                auto request =
                    GetPacket<
                    PROCESS_INFORMATION_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    helper::process::
                        ACTIVE_PROCESS_INFORMATION
                        process_information = {};


                    status =
                        helper::process::
                        SearchActiveProcessInformation(
                            reinterpret_cast<HANDLE>(
                                static_cast<ULONG_PTR>(
                                    request->ProcessId
                                    )
                                ),
                            &process_information
                        );


                    request->ResultStatus =
                        status;


                    if (NT_SUCCESS(status))
                    {
                        request->ProcessIdResult =
                            reinterpret_cast<ULONGLONG>(
                                process_information.ProcessId
                                );


                        request->ParentProcessId =
                            reinterpret_cast<ULONGLONG>(
                                process_information.ParentProcessId
                                );


                        request->PebBaseAddress =
                            reinterpret_cast<ULONGLONG>(
                                process_information.PebBaseAddress
                                );


                        request->ExitStatus =
                            process_information.ExitStatus;


                        request->AffinityMask =
                            static_cast<ULONGLONG>(
                                process_information.AffinityMask
                                );


                        request->BasePriority =
                            static_cast<LONG>(
                                process_information.BasePriority
                                );


                        request->ProcessStartKey =
                            process_information.ProcessStartKey;


                        request->IsProtectedProcess =
                            process_information.IsProtectedProcess;


                        RtlZeroMemory(
                            request->ImagePath,
                            sizeof(
                                request->ImagePath
                                )
                        );


                        if (
                            process_information.ImageFileName !=
                            nullptr &&
                            process_information.ImageFileName->Buffer !=
                            nullptr
                            )
                        {
                            USHORT character_count =
                                process_information.ImageFileName->Length /
                                sizeof(WCHAR);


                            if (
                                character_count >=
                                RTL_NUMBER_OF(
                                    request->ImagePath
                                )
                                )
                            {
                                character_count =
                                    RTL_NUMBER_OF(
                                        request->ImagePath
                                    ) - 1;
                            }


                            RtlCopyMemory(
                                request->ImagePath,
                                process_information.ImageFileName->Buffer,
                                static_cast<SIZE_T>(
                                    character_count
                                    ) * sizeof(WCHAR)
                            );


                            request->ImagePath[
                                character_count
                            ] = L'\0';
                        }


                        helper::process::
                            FreeActiveProcessInformation(
                                &process_information
                            );


                        information =
                            sizeof(*request);
                    }
                }
            }



            //
            // ========================================================
            // 0x801
            //
            // allocate::usermode::AllocVirtualMemory
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_ALLOC_VIRTUAL_MEMORY
                )
            {
                auto request =
                    GetPacket<
                    ALLOC_VIRTUAL_MEMORY_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else if (
                    request->Size == 0 ||
                    request->Size >
                    static_cast<ULONGLONG>(
                        MAXSIZE_T
                        )
                    )
                {
                    status =
                        STATUS_INVALID_PARAMETER;

                    request->ResultStatus =
                        status;
                }
                else
                {
                    HANDLE process_handle =
                        nullptr;


                    status =
                        OpenProcessHandleByPid(
                            request->ProcessId,
                            PROCESS_VM_OPERATION,
                            &process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        PVOID allocated_address =
                            nullptr;


                        status =
                            helper::allocate::usermode::
                            AllocVirtualMemory(
                                process_handle,
                                static_cast<SIZE_T>(
                                    request->Size
                                    ),
                                request->Protect,
                                &allocated_address
                            );


                        request->AllocatedAddress =
                            reinterpret_cast<ULONGLONG>(
                                allocated_address
                                );


                        ZwClose(
                            process_handle
                        );
                    }


                    request->ResultStatus =
                        status;


                    if (NT_SUCCESS(status))
                    {
                        information =
                            sizeof(*request);
                    }
                }
            }



            //
            // ========================================================
            // 0x802
            //
            // FreeVirtualMemory
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_FREE_VIRTUAL_MEMORY
                )
            {
                auto request =
                    GetPacket<
                    FREE_VIRTUAL_MEMORY_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    HANDLE process_handle =
                        nullptr;


                    status =
                        OpenProcessHandleByPid(
                            request->ProcessId,
                            PROCESS_VM_OPERATION,
                            &process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            helper::allocate::usermode::
                            FreeVirtualMemory(
                                process_handle,
                                reinterpret_cast<PVOID>(
                                    request->Address
                                    )
                            );


                        ZwClose(
                            process_handle
                        );
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x803
            //
            // CopyProcessMemory
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_COPY_PROCESS_MEMORY
                )
            {
                auto request =
                    GetPacket<
                    COPY_PROCESS_MEMORY_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else if (
                    !IsValidUserRange(
                        request->SourceAddress,
                        request->Size
                    ) ||
                    !IsValidUserRange(
                        request->DestinationAddress,
                        request->Size
                    )
                    )
                {
                    status =
                        STATUS_INVALID_PARAMETER;

                    request->ResultStatus =
                        status;
                }
                else
                {
                    HANDLE source_handle =
                        nullptr;

                    HANDLE destination_handle =
                        nullptr;


                    status =
                        OpenProcessHandleByPid(
                            request->SourceProcessId,
                            PROCESS_VM_READ,
                            &source_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            OpenProcessHandleByPid(
                                request->DestinationProcessId,
                                PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION,
                                &destination_handle
                            );
                    }


                    SIZE_T copied_size =
                        0;


                    if (
                        source_handle != nullptr &&
                        destination_handle != nullptr
                        )
                    {
                        status =
                            helper::Copy::usermode::
                            CopyProcessMemory(
                                source_handle,
                                reinterpret_cast<PVOID>(
                                    request->SourceAddress
                                    ),
                                destination_handle,
                                reinterpret_cast<PVOID>(
                                    request->DestinationAddress
                                    ),
                                static_cast<SIZE_T>(
                                    request->Size
                                    ),
                                &copied_size
                            );
                    }


                    if (destination_handle != nullptr)
                        ZwClose(destination_handle);

                    if (source_handle != nullptr)
                        ZwClose(source_handle);


                    request->CopiedSize =
                        static_cast<ULONGLONG>(
                            copied_size
                            );


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x804
            //
            // ScanValueProcess
            //
            // SourceValue is restricted to requester User VA.
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_SCAN_VALUE_PROCESS
                )
            {
                auto request =
                    GetPacket<
                    SCAN_VALUE_PROCESS_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else if (
                    !IsValidUserRange(
                        request->SourceValueAddress,
                        request->SourceValueSize
                    )
                    )
                {
                    status =
                        STATUS_INVALID_PARAMETER;

                    request->ResultStatus =
                        status;
                }
                else
                {
                    HANDLE request_process_handle =
                        nullptr;

                    HANDLE target_process_handle =
                        nullptr;


                    status =
                        OpenRequestorProcessHandle(
                            irp,
                            PROCESS_VM_READ |
                            PROCESS_VM_WRITE |
                            PROCESS_VM_OPERATION |
                            PROCESS_QUERY_INFORMATION,
                            &request_process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            OpenProcessHandleByPid(
                                request->TargetProcessId,
                                PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_READ,
                                &target_process_handle
                            );
                    }


                    PVOID list_address =
                        nullptr;


                    if (
                        request_process_handle !=
                        nullptr &&
                        target_process_handle !=
                        nullptr
                        )
                    {
                        list_address =
                            helper::scan::process::
                            ScanValueProcess(
                                request_process_handle,
                                reinterpret_cast<PVOID>(
                                    request->SourceValueAddress
                                    ),
                                request->SourceValueSize,
                                request->PageProtect,
                                target_process_handle,
                                &status
                            );


                        //
                        // ScanValueProcess propagates its failure status.
                        // The result pointer remains null on atomic quota failure.
                        //
                    }


                    if (target_process_handle != nullptr)
                        ZwClose(target_process_handle);

                    if (request_process_handle != nullptr)
                        ZwClose(request_process_handle);


                    request->ResultListAddress =
                        reinterpret_cast<ULONGLONG>(
                            list_address
                            );


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x805
            //
            // ReadProcess
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_READ_PROCESS
                )
            {
                auto request =
                    GetPacket<
                    READ_PROCESS_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else if (
                    !IsValidUserRange(
                        request->ReadAddress,
                        request->Size
                    )
                    )
                {
                    status =
                        STATUS_INVALID_PARAMETER;

                    request->ResultStatus =
                        status;
                }
                else
                {
                    HANDLE request_process_handle =
                        nullptr;

                    HANDLE target_process_handle =
                        nullptr;


                    status =
                        OpenRequestorProcessHandle(
                            irp,
                            PROCESS_VM_WRITE |
                            PROCESS_VM_OPERATION,
                            &request_process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            OpenProcessHandleByPid(
                                request->TargetProcessId,
                                PROCESS_VM_READ,
                                &target_process_handle
                            );
                    }


                    PUCHAR dumped_address =
                        nullptr;


                    if (
                        request_process_handle !=
                        nullptr &&
                        target_process_handle !=
                        nullptr
                        )
                    {
                        status =
                            helper::read::process::
                            ReadProcess(
                                request_process_handle,
                                target_process_handle,
                                reinterpret_cast<PVOID>(
                                    request->ReadAddress
                                    ),
                                request->Size,
                                &dumped_address
                            );
                    }


                    if (target_process_handle != nullptr)
                        ZwClose(target_process_handle);

                    if (request_process_handle != nullptr)
                        ZwClose(request_process_handle);


                    request->DumpedAddress =
                        reinterpret_cast<ULONGLONG>(
                            dumped_address
                            );


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x806
            //
            // ReadStringProcess
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_READ_STRING_PROCESS
                )
            {
                auto request =
                    GetPacket<
                    READ_STRING_PROCESS_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    HANDLE request_process_handle =
                        nullptr;

                    HANDLE target_process_handle =
                        nullptr;


                    status =
                        OpenRequestorProcessHandle(
                            irp,
                            PROCESS_VM_READ |
                            PROCESS_VM_WRITE |
                            PROCESS_VM_OPERATION,
                            &request_process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            OpenProcessHandleByPid(
                                request->TargetProcessId,
                                PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_READ,
                                &target_process_handle
                            );
                    }


                    PVOID list_address =
                        nullptr;


                    if (
                        request_process_handle !=
                        nullptr &&
                        target_process_handle !=
                        nullptr
                        )
                    {
                        list_address =
                            helper::read::process::
                            ReadStringProcess(
                                request_process_handle,
                                target_process_handle,
                                static_cast<SIZE_T>(
                                    request->MinimumCharacterCount
                                    ),
                                &status
                            );


                    }


                    if (target_process_handle != nullptr)
                        ZwClose(target_process_handle);

                    if (request_process_handle != nullptr)
                        ZwClose(request_process_handle);


                    request->ResultListAddress =
                        reinterpret_cast<ULONGLONG>(
                            list_address
                            );


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x807
            //
            // ReadProcessInformation
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_READ_PROCESS_INFORMATION
                )
            {
                auto request =
                    GetPacket<
                    READ_PROCESS_INFORMATION_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    HANDLE request_process_handle =
                        nullptr;

                    HANDLE target_process_handle =
                        nullptr;


                    status =
                        OpenRequestorProcessHandle(
                            irp,
                            PROCESS_VM_WRITE |
                            PROCESS_VM_OPERATION,
                            &request_process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            OpenProcessHandleByPid(
                                request->TargetProcessId,
                                PROCESS_QUERY_INFORMATION,
                                &target_process_handle
                            );
                    }


                    PVOID list_address =
                        nullptr;


                    if (
                        request_process_handle !=
                        nullptr &&
                        target_process_handle !=
                        nullptr
                        )
                    {
                        status =
                            helper::read::process::
                            ReadProcessInformation(
                                request_process_handle,
                                target_process_handle,
                                &list_address
                            );
                    }


                    if (target_process_handle != nullptr)
                        ZwClose(target_process_handle);

                    if (request_process_handle != nullptr)
                        ZwClose(request_process_handle);


                    request->ResultListAddress =
                        reinterpret_cast<ULONGLONG>(
                            list_address
                            );


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x808
            //
            // Generic user linked-list free
            //
            // ScanValueProcess
            // ReadProcessInformation
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_FREE_LINKED_LIST
                )
            {
                auto request =
                    GetPacket<
                    FREE_LINKED_LIST_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    HANDLE request_process_handle =
                        nullptr;


                    status =
                        OpenRequestorProcessHandle(
                            irp,
                            PROCESS_VM_OPERATION,
                            &request_process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            helper::linkedlist::usermode::
                            FreeLinkedList(
                                request_process_handle,
                                reinterpret_cast<PVOID>(
                                    request->FirstNodeAddress
                                    )
                            );


                        ZwClose(
                            request_process_handle
                        );
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }



            //
            // ========================================================
            // 0x809
            //
            // ReadStringProcess list free
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_FREE_STRING_LIST
                )
            {
                auto request =
                    GetPacket<
                    FREE_STRING_LIST_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    HANDLE request_process_handle =
                        nullptr;


                    status =
                        OpenRequestorProcessHandle(
                            irp,
                            PROCESS_VM_READ |
                            PROCESS_VM_OPERATION,
                            &request_process_handle
                        );


                    if (NT_SUCCESS(status))
                    {
                        status =
                            FreeStringResultList(
                                request_process_handle,
                                reinterpret_cast<PVOID>(
                                    request->FirstNodeAddress
                                    )
                            );


                        ZwClose(
                            request_process_handle
                        );
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }


            //
// ========================================================
// 0x80A
//
// SetHardwareBreakpoint
// ========================================================
//

            else if (
                ioctl_code ==
                IOCTL_HELPER_SET_HARDWARE_BREAKPOINT
            )
            {
                //__debugbreak();

                auto request =
                    GetPacket<
                    IOCTL_HWBP_SET_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    //
                    // Initialize OUTPUT.
                    //
                    request->ResultStatus =
                        STATUS_UNSUCCESSFUL;

                    request->FirstResultNode =
                        0;

                    request->AppliedThreadCount =
                        0;

                    request->FailedThreadCount =
                        0;


                    if (
                        request->ProcessId == 0 ||
                        request->Address == 0
                        )
                    {
                        status =
                            STATUS_INVALID_PARAMETER;
                    }
                    else
                    {
                        HANDLE request_process_handle =
                            nullptr;

                        HANDLE target_process_handle =
                            nullptr;


                        //
                        // Result linked-list belongs to the actual
                        // DeviceIoControl requester.
                        //
                        status =
                            OpenRequestorProcessHandle(
                                irp,

                                PROCESS_VM_READ |
                                PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION,

                                &request_process_handle
                            );


                        if (NT_SUCCESS(status))
                        {
                            //
                            // Only obtain the target process using the PID
                            // supplied by UserMode.
                            //
                            status =
                                OpenProcessHandleByPid(
                                    request->ProcessId,

                                    PROCESS_QUERY_INFORMATION,

                                    &target_process_handle
                                );
                        }


                        if (
                            request_process_handle != nullptr &&
                            target_process_handle != nullptr
                            )
                        {
                            PVOID first_result_node =
                                nullptr;


                            ULONG applied_count =
                                0;

                            ULONG failed_count =
                                0;


                            status =
                                helper::process::
                                SetHardwareBreakpoint(
                                    request_process_handle,

                                    target_process_handle,

                                    reinterpret_cast<PVOID>(
                                        static_cast<ULONG_PTR>(
                                            request->Address
                                            )
                                        ),

                                    static_cast<
                                    helper::process::hwbp_internal::
                                    HARDWARE_BREAKPOINT_TYPE
                                    >(
                                        request->Type
                                        ),

                                    static_cast<
                                    helper::process::hwbp_internal::
                                    HARDWARE_BREAKPOINT_LENGTH
                                    >(
                                        request->Length
                                        ),

                                    &first_result_node,

                                    &applied_count,

                                    &failed_count
                                );


                            request->FirstResultNode =
                                reinterpret_cast<ULONGLONG>(
                                    first_result_node
                                    );


                            request->AppliedThreadCount =
                                applied_count;


                            request->FailedThreadCount =
                                failed_count;
                        }


                        if (target_process_handle != nullptr)
                        {
                            ZwClose(
                                target_process_handle
                            );
                        }


                        if (request_process_handle != nullptr)
                        {
                            ZwClose(
                                request_process_handle
                            );
                        }
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);
                }
            }

            //
            // ========================================================
            // 0x80B
            //
            // QueryHardwareBreakpoints
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_QUERY_HARDWARE_BREAKPOINT
            )
            {
                //__debugbreak();

                auto request =
                    GetPacket<
                    IOCTL_HWBP_QUERY_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus =
                        STATUS_UNSUCCESSFUL;

                    request->FirstResultNode =
                        0;

                    request->ThreadCount =
                        0;

                    request->BreakpointCount =
                        0;


                    if (request->ProcessId == 0)
                    {
                        status =
                            STATUS_INVALID_PARAMETER;
                    }
                    else
                    {
                        HANDLE request_process_handle =
                            nullptr;

                        HANDLE target_process_handle =
                            nullptr;


                        status =
                            OpenRequestorProcessHandle(
                                irp,

                                PROCESS_VM_READ |
                                PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION,

                                &request_process_handle
                            );


                        if (NT_SUCCESS(status))
                        {
                            status =
                                OpenProcessHandleByPid(
                                    request->ProcessId,

                                    PROCESS_QUERY_INFORMATION,

                                    &target_process_handle
                                );
                        }


                        if (
                            request_process_handle != nullptr &&
                            target_process_handle != nullptr
                            )
                        {
                            PVOID first_result_node =
                                nullptr;


                            ULONG thread_count =
                                0;

                            ULONG breakpoint_count =
                                0;


                            status =
                                helper::process::
                                QueryHardwareBreakpoints(
                                    request_process_handle,

                                    target_process_handle,

                                    &first_result_node,

                                    &thread_count,

                                    &breakpoint_count
                                );


                            request->FirstResultNode =
                                reinterpret_cast<ULONGLONG>(
                                    first_result_node
                                    );


                            request->ThreadCount =
                                thread_count;


                            request->BreakpointCount =
                                breakpoint_count;
                        }


                        if (target_process_handle != nullptr)
                        {
                            ZwClose(
                                target_process_handle
                            );
                        }


                        if (request_process_handle != nullptr)
                        {
                            ZwClose(
                                request_process_handle
                            );
                        }
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);

                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x80C
            //
            // RemoveHardwareBreakpoint
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_REMOVE_HARDWARE_BREAKPOINT
                )
            {
                //__debugbreak();

                auto request =
                    GetPacket<
                    IOCTL_HWBP_REMOVE_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus =
                        STATUS_UNSUCCESSFUL;

                    request->RemovedThreadCount =
                        0;

                    request->FailedThreadCount =
                        0;


                    if (
                        request->ProcessId == 0 ||
                        request->FirstResultNode == 0
                        )
                    {
                        status =
                            STATUS_INVALID_PARAMETER;
                    }
                    else
                    {
                        //
                        // Result list pointer must be UserMode VA.
                        //
                        if (
                            !IsValidUserRange(
                                request->FirstResultNode,
                                sizeof(
                                    helper::linkedlist::
                                    LINKED_LIST_NODE
                                    )
                            )
                            )
                        {
                            status =
                                STATUS_INVALID_PARAMETER;
                        }
                        else
                        {
                            HANDLE request_process_handle =
                                nullptr;

                            HANDLE target_process_handle =
                                nullptr;


                            status =
                                OpenRequestorProcessHandle(
                                    irp,

                                    PROCESS_VM_READ |
                                    PROCESS_VM_OPERATION,

                                    &request_process_handle
                                );


                            if (NT_SUCCESS(status))
                            {
                                status =
                                    OpenProcessHandleByPid(
                                        request->ProcessId,

                                        PROCESS_QUERY_INFORMATION,

                                        &target_process_handle
                                    );
                            }


                            if (
                                request_process_handle != nullptr &&
                                target_process_handle != nullptr
                                )
                            {
                                ULONG removed_count =
                                    0;

                                ULONG failed_count =
                                    0;


                                status =
                                    helper::process::
                                    RemoveHardwareBreakpoint(
                                        request_process_handle,

                                        target_process_handle,

                                        reinterpret_cast<PVOID>(
                                            static_cast<ULONG_PTR>(
                                                request->FirstResultNode
                                                )
                                            ),

                                        &removed_count,

                                        &failed_count
                                    );


                                request->RemovedThreadCount =
                                    removed_count;


                                request->FailedThreadCount =
                                    failed_count;
                            }


                            if (target_process_handle != nullptr)
                            {
                                ZwClose(
                                    target_process_handle
                                );
                            }


                            if (request_process_handle != nullptr)
                            {
                                ZwClose(
                                    request_process_handle
                                );
                            }
                        }
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);

                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x80D
            //
            // FreeHardwareBreakpointResult
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_FREE_HARDWARE_BREAKPOINT_RESULT
            )
            {
                //__debugbreak();

                auto request =
                    GetPacket<
                    IOCTL_HWBP_FREE_RESULT_REQUEST
                    >(
                        irp,
                        stack
                    );


                if (request == nullptr)
                {
                    status =
                        STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus =
                        STATUS_UNSUCCESSFUL;


                    if (request->FirstResultNode == 0)
                    {
                        //
                        // nullptr free is harmless.
                        //
                        status =
                            STATUS_SUCCESS;
                    }
                    else if (
                        !IsValidUserRange(
                            request->FirstResultNode,
                            sizeof(
                                helper::linkedlist::
                                LINKED_LIST_NODE
                                )
                        )
                        )
                    {
                        status =
                            STATUS_INVALID_PARAMETER;
                    }
                    else
                    {
                        HANDLE request_process_handle =
                            nullptr;


                        status =
                            OpenRequestorProcessHandle(
                                irp,

                                PROCESS_VM_READ |
                                PROCESS_VM_OPERATION,

                                &request_process_handle
                            );


                        if (NT_SUCCESS(status))
                        {
                            status =
                                helper::process::
                                FreeHardwareBreakpointResult(
                                    request_process_handle,

                                    reinterpret_cast<PVOID>(
                                        static_cast<ULONG_PTR>(
                                            request->FirstResultNode
                                            )
                                        )
                                );


                            ZwClose(
                                request_process_handle
                            );


                            if (NT_SUCCESS(status))
                            {
                                request->FirstResultNode =
                                    0;
                            }
                        }
                    }


                    request->ResultStatus =
                        status;


                    information =
                        sizeof(*request);

                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x80E
            //
            // DllRegister (ANSI to UNICODE_STRING -> Free)
            // ========================================================
            //

            else if (
                ioctl_code ==
                IOCTL_HELPER_REGISTER_DLL
            )
                {
                    //__debugbreak();

                    auto request =
                        GetPacket<
                        REGISTER_DLL_REQUEST
                        >(
                            irp,
                            stack
                        );

                    if (request == nullptr)
                    {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        request->ResultStatus = STATUS_UNSUCCESSFUL;
                        request->TargetIsWow64 = FALSE;
                        request->Kernel32Found = FALSE;
                        request->LoadLibraryFound = FALSE;
                        request->Kernel32Base = 0;
                        request->Kernel32Size = 0;
                        request->LoadLibraryAddress = 0;

                        // Null-termination 안전 보장
                        request->DllPath[sizeof(request->DllPath) - 1] = '\0';

                        if (request->ProcessId == 0 || request->DllPath[0] == '\0')
                        {
                            status = STATUS_INVALID_PARAMETER;
                        }
                        else
                        {
                            //
                            // 1. ANSI 문자열을 UNICODE_STRING 지역변수로 변환
                            //
                            request->DllPath[sizeof(request->DllPath) - 1] = '\0';
                            ANSI_STRING ansi_path = {};
                            UNICODE_STRING unicode_path = {};

                            RtlInitAnsiString(
                                &ansi_path,
                                request->DllPath
                            );

                            // AllocateDestinationString = TRUE: 커널 풀 메모리 할당
                            status = RtlAnsiStringToUnicodeString(
                                &unicode_path,
                                &ansi_path,
                                TRUE
                            );

                            if (!NT_SUCCESS(status))
                            {
                                request->ResultStatus = status;
                            }
                            else
                            {
                                HANDLE target_process_handle = nullptr;

                                //
                                // 2. 대상 프로세스 핸들 획득
                                //
                                status = OpenProcessHandleByPid(
                                    request->ProcessId,
                                    PROCESS_ALL_ACCESS,
                                    &target_process_handle
                                );

                                if (NT_SUCCESS(status))
                                {
                                    helper::process::DLL_REGISTER_INFORMATION register_info = {};

                                    //
                                    // 3. DllRegister 호출 (유니코드 경로 전달)
                                    //
                                    status = helper::process::DllRegister(
                                        target_process_handle,
                                        &unicode_path,
                                        &register_info
                                    );

                                    //
                                    // 4. 결과 채우기
                                    //
                                    request->TargetIsWow64 = register_info.TargetIsWow64;
                                    request->Kernel32Found = register_info.Kernel32Found;
                                    request->LoadLibraryFound = register_info.LoadLibraryFound;
                                    request->Kernel32Base = reinterpret_cast<ULONGLONG>(register_info.Kernel32Base);
                                    request->Kernel32Size = static_cast<ULONGLONG>(register_info.Kernel32Size);
                                    request->LoadLibraryAddress = reinterpret_cast<ULONGLONG>(register_info.LoadLibraryAddress);

                                    ZwClose(target_process_handle);
                                }

                                //
                                // 5. 할당된 UNICODE_STRING 해제 (메모리 누수 방지)
                                //
                                RtlFreeUnicodeString(&unicode_path);
                            }
                        }

                        request->ResultStatus = status;
                        information = sizeof(*request);
                    }
                }

            //
            // ========================================================
            // 0x80F: WriteProcessMemory
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_WRITE_PROCESS)
            {
                auto request = GetPacket<WRITE_PROCESS_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus = STATUS_UNSUCCESSFUL;
                    request->BytesWritten = 0;

                    if (!IsValidUserRange(request->TargetAddress, request->Size) ||
                        (request->Size > sizeof(request->Buffer) &&
                            !IsValidUserRange(request->UserBufferAddress, request->Size)))
                    {
                        request->ResultStatus = STATUS_INVALID_PARAMETER;
                    }
                    else
                    {
                        HANDLE target_process_handle = nullptr;
                        status = OpenProcessHandleByPid(request->ProcessId,
                            PROCESS_VM_WRITE | PROCESS_VM_OPERATION, &target_process_handle);
                        if (NT_SUCCESS(status))
                        {
                            PVOID alloc_buf = nullptr;
                            PVOID src_buffer = request->Buffer;
                            if (request->Size > sizeof(request->Buffer))
                            {
                                src_buffer = nullptr;
                                alloc_buf = helper::allocate::kernelmode::AllocateKernelMemory(
                                    static_cast<SIZE_T>(request->Size));
                                if (!alloc_buf) status = STATUS_INSUFFICIENT_RESOURCES;
                                else
                                {
                                    PEPROCESS requestor = IoGetRequestorProcess(irp);
                                    SIZE_T local_read = 0;
                                    status = requestor ? MmCopyVirtualMemory(requestor,
                                        reinterpret_cast<PVOID>(request->UserBufferAddress),
                                        PsGetCurrentProcess(), alloc_buf,
                                        static_cast<SIZE_T>(request->Size), KernelMode, &local_read)
                                        : STATUS_INVALID_CID;
                                    if (NT_SUCCESS(status) && local_read == request->Size)
                                        src_buffer = alloc_buf;
                                    else if (NT_SUCCESS(status)) status = STATUS_PARTIAL_COPY;
                                }
                            }
                            if (src_buffer)
                            {
                                SIZE_T written = 0;
                                status = helper::Copy::usermode::WriteProcessMemory(
                                    target_process_handle,
                                    reinterpret_cast<PVOID>(request->TargetAddress), src_buffer,
                                    static_cast<SIZE_T>(request->Size), &written);
                                request->BytesWritten = written;
                            }
                            if (alloc_buf) helper::allocate::kernelmode::FreeKernelMemory(alloc_buf);
                            ZwClose(target_process_handle);
                        }
                        request->ResultStatus = status;
                    }

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x810: ProtectVirtualMemory
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_PROTECT_VIRTUAL_MEMORY)
            {
                auto request = GetPacket<PROTECT_VIRTUAL_MEMORY_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus = STATUS_UNSUCCESSFUL;
                    request->OldProtect = 0;
                    request->ResultBaseAddress = request->BaseAddress;
                    request->ResultRegionSize = request->RegionSize;

                    HANDLE target_process_handle = nullptr;
                    status = OpenProcessHandleByPid(
                        request->ProcessId,
                        PROCESS_VM_OPERATION,
                        &target_process_handle
                    );

                    if (NT_SUCCESS(status))
                    {
                        PVOID base_addr = reinterpret_cast<PVOID>(request->BaseAddress);
                        SIZE_T reg_size = static_cast<SIZE_T>(request->RegionSize);
                        ULONG old_protect = 0;

                        status = helper::allocate::usermode::ProtectVirtualMemory(
                            target_process_handle,
                            &base_addr,
                            &reg_size,
                            request->NewProtect,
                            &old_protect
                        );

                        request->ResultStatus = status;
                        request->OldProtect = old_protect;
                        request->ResultBaseAddress = reinterpret_cast<ULONGLONG>(base_addr);
                        request->ResultRegionSize = static_cast<ULONGLONG>(reg_size);

                        ZwClose(target_process_handle);
                    }
                    else
                    {
                        request->ResultStatus = status;
                    }

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x811: PatternScan
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_PATTERN_SCAN)
            {
                auto request = GetPacket<PATTERN_SCAN_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus = STATUS_UNSUCCESSFUL;
                    request->FoundAddress = 0;
                    request->MatchesCount = 0;

                    if (request->PatternLength > 0 && request->PatternLength <= sizeof(request->Pattern))
                    {
                        HANDLE target_process_handle = nullptr;
                        status = OpenProcessHandleByPid(
                            request->ProcessId,
                            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                            &target_process_handle
                        );

                        if (NT_SUCCESS(status))
                        {
                            PVOID first_match = nullptr;
                            ULONG matches = 0;

                            const CHAR* mask_ptr = (request->Mask[0] != '\0') ? request->Mask : nullptr;

                            status = helper::scan::process::ScanPatternProcess(
                                target_process_handle,
                                reinterpret_cast<PVOID>(request->StartAddress),
                                static_cast<SIZE_T>(request->ScanLength),
                                request->Pattern,
                                mask_ptr,
                                static_cast<SIZE_T>(request->PatternLength),
                                request->PageProtect,
                                &first_match,
                                &matches
                            );

                            request->ResultStatus = status;
                            request->FoundAddress = reinterpret_cast<ULONGLONG>(first_match);
                            request->MatchesCount = matches;

                            ZwClose(target_process_handle);
                        }
                        else
                        {
                            request->ResultStatus = status;
                        }
                    }
                    else
                    {
                        status = STATUS_INVALID_PARAMETER;
                        request->ResultStatus = status;
                    }

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x812: EnumerateThreads
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_ENUMERATE_THREADS)
            {
                auto request = GetPacket<ENUMERATE_THREADS_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus = STATUS_UNSUCCESSFUL;
                    request->ThreadCount = 0;
                    RtlZeroMemory(request->Threads, sizeof(request->Threads));

                    ULONG max_allowed = 64;
                    if (request->MaxThreads > 0 && request->MaxThreads < max_allowed)
                        max_allowed = request->MaxThreads;

                    helper::process::THREAD_ENTRY_INFO thread_entries[64] = {};
                    ULONG retrieved_count = 0;

                    status = helper::process::EnumerateThreads(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ProcessId)),
                        thread_entries,
                        max_allowed,
                        &retrieved_count
                    );

                    request->ResultStatus = status;
                    request->ThreadCount = retrieved_count;

                    for (ULONG i = 0; i < retrieved_count; ++i)
                    {
                        request->Threads[i].ThreadId = reinterpret_cast<ULONGLONG>(thread_entries[i].ThreadId);
                        request->Threads[i].StartAddress = reinterpret_cast<ULONGLONG>(thread_entries[i].StartAddress);
                        request->Threads[i].Priority = static_cast<ULONG>(thread_entries[i].Priority);
                        request->Threads[i].BasePriority = thread_entries[i].BasePriority;
                        request->Threads[i].State = thread_entries[i].State;
                        request->Threads[i].WaitReason = thread_entries[i].WaitReason;
                        request->Threads[i].ContextSwitches = thread_entries[i].ContextSwitches;
                    }

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x813: SuspendThread
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_SUSPEND_THREAD)
            {
                auto request = GetPacket<THREAD_CONTROL_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    ULONG prev_count = 0;
                    status = helper::process::SuspendThread(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        &prev_count
                    );

                    request->ResultStatus = status;
                    request->PreviousSuspendCount = prev_count;

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x814: ResumeThread
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_RESUME_THREAD)
            {
                auto request = GetPacket<THREAD_CONTROL_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    ULONG prev_count = 0;
                    status = helper::process::ResumeThread(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        &prev_count
                    );

                    request->ResultStatus = status;
                    request->PreviousSuspendCount = prev_count;

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x815: GetThreadContext
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_GET_THREAD_CONTEXT)
            {
                auto request = GetPacket<THREAD_REGISTERS_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

                    status = helper::process::GetThreadContext(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        &ctx
                    );

                    request->ResultStatus = status;
                    if (NT_SUCCESS(status))
                    {
                        request->Rip = ctx.Rip;
                        request->Rsp = ctx.Rsp;
                        request->Rbp = ctx.Rbp;
                        request->Rax = ctx.Rax;
                        request->Rbx = ctx.Rbx;
                        request->Rcx = ctx.Rcx;
                        request->Rdx = ctx.Rdx;
                        request->Rsi = ctx.Rsi;
                        request->Rdi = ctx.Rdi;
                        request->R8 = ctx.R8;
                        request->R9 = ctx.R9;
                        request->R10 = ctx.R10;
                        request->R11 = ctx.R11;
                        request->R12 = ctx.R12;
                        request->R13 = ctx.R13;
                        request->R14 = ctx.R14;
                        request->R15 = ctx.R15;
                        request->EFlags = ctx.EFlags;
                    }

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x816: SetThreadContext
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_SET_THREAD_CONTEXT)
            {
                auto request = GetPacket<THREAD_REGISTERS_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

                    status = helper::process::GetThreadContext(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        &ctx
                    );

                    if (NT_SUCCESS(status))
                    {
                        ctx.Rip = request->Rip;
                        ctx.Rsp = request->Rsp;
                        ctx.Rbp = request->Rbp;
                        ctx.Rax = request->Rax;
                        ctx.Rbx = request->Rbx;
                        ctx.Rcx = request->Rcx;
                        ctx.Rdx = request->Rdx;
                        ctx.Rsi = request->Rsi;
                        ctx.Rdi = request->Rdi;
                        ctx.R8 = request->R8;
                        ctx.R9 = request->R9;
                        ctx.R10 = request->R10;
                        ctx.R11 = request->R11;
                        ctx.R12 = request->R12;
                        ctx.R13 = request->R13;
                        ctx.R14 = request->R14;
                        ctx.R15 = request->R15;
                        ctx.EFlags = request->EFlags;

                        status = helper::process::SetThreadContext(
                            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                            &ctx
                        );
                    }

                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x817: EventMonitorControl
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_EVENT_MONITOR_CONTROL)
            {
                auto request = GetPacket<EVENT_MONITOR_CONTROL_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ProcessMonitorActive = FALSE;
                    request->ImageMonitorActive = FALSE;
                    request->ResultStatus = (request->EnableProcessMonitor || request->EnableImageLoadMonitor)
                        ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x818: PollEvents
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_POLL_EVENTS)
            {
                auto request = GetPacket<POLL_EVENTS_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus = STATUS_SUCCESS;
                    request->EventsReturned = 0;
                    request->EventsRemaining = 0;
                    RtlZeroMemory(request->Events, sizeof(request->Events));

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x819: GetDriverStatus
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_GET_DRIVER_STATUS)
            {
                auto request = GetPacket<DRIVER_STATUS_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    request->ResultStatus = STATUS_SUCCESS;
                    request->MajorVersion = 2;
                    request->MinorVersion = 3;
                    request->BuildNumber = 20261004;
                    request->DriverStartTime = helper::diagnostics::DriverStartTime();
                    request->TotalIoctlRequests = static_cast<ULONGLONG>(InterlockedCompareExchange64(helper::diagnostics::TotalIoctlCount(), 0, 0));

                    request->EventMonitorActive = FALSE;
                    request->QueuedEventCount = 0;

                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x81A: QueryProcessExtended
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_QUERY_PROCESS_EXTENDED)
            {
                auto request = GetPacket<PROCESS_EXTENDED_INFO_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::QueryProcessExtended(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ProcessId)),
                        &request->Info
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x81B: QueryProcessHandles
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_QUERY_PROCESS_HANDLES)
            {
                auto request = GetPacket<PROCESS_HANDLES_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    ULONG max_handles = 128;
                    if (request->MaxHandles > 0 && request->MaxHandles < max_handles)
                        max_handles = request->MaxHandles;

                    ULONG returned_count = 0;
                    status = helper::process::QueryProcessHandles(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ProcessId)),
                        request->Handles,
                        max_handles,
                        &returned_count
                    );
                    request->ResultStatus = status;
                    request->ReturnedHandleCount = returned_count;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x81C: QueryProcessToken
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_QUERY_PROCESS_TOKEN)
            {
                auto request = GetPacket<PROCESS_TOKEN_INFO_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::QueryProcessToken(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ProcessId)),
                        &request->TokenInfo
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x81D: QueryThreadInfo
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_QUERY_THREAD_INFO)
            {
                auto request = GetPacket<THREAD_INFO_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::QueryThreadExtended(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        &request->ThreadInfo
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x81E: SetThreadPriority
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_SET_THREAD_PRIORITY)
            {
                auto request = GetPacket<THREAD_PRIORITY_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::SetThreadPriority(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        request->Priority
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x81F: SetThreadAffinity
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_SET_THREAD_AFFINITY)
            {
                auto request = GetPacket<THREAD_AFFINITY_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::SetThreadAffinity(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        request->AffinityMask
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x820: TerminateThread
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_TERMINATE_THREAD)
            {
                auto request = GetPacket<THREAD_TERMINATE_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::TerminateThread(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId)),
                        request->ExitStatus
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // ========================================================
            // 0x821: SetThreadHideFromDebugger
            // ========================================================
            //
            else if (ioctl_code == IOCTL_HELPER_SET_THREAD_HIDE_FROM_DEBUGGER)
            {
                auto request = GetPacket<THREAD_HIDE_REQUEST>(irp, stack);
                if (request == nullptr)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    status = helper::process::SetThreadHideFromDebugger(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(request->ThreadId))
                    );
                    request->ResultStatus = status;
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            //
            // Function execution in a target user thread. Each tracking token
            // is scoped to the device FILE_OBJECT that created it.
            //
            else if (ioctl_code == IOCTL_HELPER_CREATE_FUNCTION_CALL)
            {
                auto request = GetPacket<CREATE_FUNCTION_CALL_REQUEST>(irp, stack);
                if (!request) status = STATUS_BUFFER_TOO_SMALL;
                else
                {
                    request->ResultStatus = helper::remote_call::Create(stack->FileObject, request);
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }
            else if (ioctl_code == IOCTL_HELPER_QUERY_FUNCTION_CALL)
            {
                auto request = GetPacket<QUERY_FUNCTION_CALL_REQUEST>(irp, stack);
                if (!request) status = STATUS_BUFFER_TOO_SMALL;
                else
                {
                    request->ResultStatus = helper::remote_call::Query(stack->FileObject, request);
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }
            else if (ioctl_code == IOCTL_HELPER_RELEASE_FUNCTION_CALL)
            {
                auto request = GetPacket<RELEASE_FUNCTION_CALL_REQUEST>(irp, stack);
                if (!request) status = STATUS_BUFFER_TOO_SMALL;
                else
                {
                    request->ResultStatus = helper::remote_call::Release(stack->FileObject, request);
                    information = sizeof(*request);
                    status = STATUS_SUCCESS;
                }
            }

            // Unknown IOCTL
            //
            else
            {
                status =
                    STATUS_INVALID_DEVICE_REQUEST;

                information =
                    0;
            }



            //
            // ========================================================
            // Complete IRP
            // ========================================================
            //

            irp->IoStatus.Status =
                status;


            irp->IoStatus.Information =
                information;


            IoCompleteRequest(
                irp,
                IO_NO_INCREMENT
            );


            return status;
        }
        // Keep dispatch code and deferred cleanup alive until all requests
        // finish. Release only after completion, including exceptional exits.
        _Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
        inline DRIVER_DISPATCH DeviceControlRoutine;

        inline NTSTATUS DeviceControlRoutine(PDEVICE_OBJECT device_object, PIRP irp)
        {
            if (!irp) return STATUS_INVALID_PARAMETER;
            if (KeGetCurrentIrql() != PASSIVE_LEVEL)
                return DeviceControlRoutineImpl(device_object, irp);
            KeEnterCriticalRegion();
            if (!ExAcquireRundownProtection(&helper::lifecycle::Requests()))
            {
                irp->IoStatus.Status = STATUS_DELETE_PENDING;
                irp->IoStatus.Information = 0;
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                KeLeaveCriticalRegion();
                return STATUS_DELETE_PENDING;
            }
            NTSTATUS status;
            __try
            {
                helper::process::ReapDllCleanup();
                status = DeviceControlRoutineImpl(device_object, irp);
            }
            __finally
            {
                ExReleaseRundownProtection(&helper::lifecycle::Requests());
                KeLeaveCriticalRegion();
            }
            return status;
        }
    }
}

