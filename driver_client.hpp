#pragma once

#include <windows.h>
#include <winioctl.h>
#include "remote_call_protocol.h"
#include <iostream>
#include <vector>
#include <string>

//
// ============================================================
// Driver Device & IOCTL Codes
// ============================================================
//

#define DRIVER_DEVICE_NAME L"\\\\.\\MyDriver"

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

#define IOCTL_HELPER_SET_HARDWARE_BREAKPOINT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_QUERY_HARDWARE_BREAKPOINT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_REMOVE_HARDWARE_BREAKPOINT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_FREE_HARDWARE_BREAKPOINT_RESULT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_HELPER_REGISTER_DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

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
// IOCTL Data Structures
// ============================================================
//

namespace KernelClient
{
#pragma pack(push, 8)

    typedef struct _PROCESS_INFORMATION_REQUEST
    {
        ULONG ProcessId;
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
    } PROCESS_INFORMATION_REQUEST;

    typedef struct _ALLOC_VIRTUAL_MEMORY_REQUEST
    {
        ULONG ProcessId;
        ULONGLONG Size;
        ULONG Protect;
        NTSTATUS ResultStatus;
        ULONGLONG AllocatedAddress;
    } ALLOC_VIRTUAL_MEMORY_REQUEST;

    typedef struct _FREE_VIRTUAL_MEMORY_REQUEST
    {
        ULONG ProcessId;
        ULONGLONG Address;
        NTSTATUS ResultStatus;
    } FREE_VIRTUAL_MEMORY_REQUEST;

    typedef struct _WRITE_PROCESS_REQUEST
    {
        ULONG ProcessId;
        ULONGLONG TargetAddress;
        ULONGLONG Size;
        UCHAR Buffer[4096];
        ULONGLONG UserBufferAddress;
        NTSTATUS ResultStatus;
        ULONGLONG BytesWritten;
    } WRITE_PROCESS_REQUEST;

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
    } PROTECT_VIRTUAL_MEMORY_REQUEST;

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
    } PATTERN_SCAN_REQUEST;

    typedef struct _THREAD_SNAPSHOT_INFO
    {
        ULONGLONG ThreadId;
        ULONGLONG StartAddress;
        ULONG Priority;
        LONG BasePriority;
        ULONG State;
        ULONG WaitReason;
        ULONG ContextSwitches;
    } THREAD_SNAPSHOT_INFO;

    typedef struct _ENUMERATE_THREADS_REQUEST
    {
        ULONG ProcessId;
        ULONG MaxThreads;
        NTSTATUS ResultStatus;
        ULONG ThreadCount;
        THREAD_SNAPSHOT_INFO Threads[64];
    } ENUMERATE_THREADS_REQUEST;

    typedef struct _THREAD_CONTROL_REQUEST
    {
        ULONG ThreadId;
        NTSTATUS ResultStatus;
        ULONG PreviousSuspendCount;
    } THREAD_CONTROL_REQUEST;

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
    } THREAD_REGISTERS_REQUEST;

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
    } KERNEL_MONITOR_EVENT;

    typedef struct _EVENT_MONITOR_CONTROL_REQUEST
    {
        BOOLEAN EnableProcessMonitor;
        BOOLEAN EnableImageLoadMonitor;
        NTSTATUS ResultStatus;
        BOOLEAN ProcessMonitorActive;
        BOOLEAN ImageMonitorActive;
    } EVENT_MONITOR_CONTROL_REQUEST;

    typedef struct _POLL_EVENTS_REQUEST
    {
        ULONG MaxEventsToRead;
        NTSTATUS ResultStatus;
        ULONG EventsReturned;
        ULONG EventsRemaining;
        KERNEL_MONITOR_EVENT Events[16];
    } POLL_EVENTS_REQUEST;

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
    } DRIVER_STATUS_REQUEST;

    typedef struct _PROCESS_EXTENDED_INFO
    {
        ULONGLONG ProcessId;
        ULONGLONG ParentProcessId;
        ULONGLONG PebBaseAddress;
        ULONGLONG AffinityMask;
        LONG BasePriority;
        NTSTATUS ExitStatus;
        ULONG SessionId;
        ULONG HandleCount;
        ULONG ThreadCount;
        ULONG IsWow64;
        ULONG IsProtectedProcess;

        LARGE_INTEGER CreateTime;
        LARGE_INTEGER ExitTime;
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;

        ULONGLONG PeakVirtualSize;
        ULONGLONG VirtualSize;
        ULONG PageFaultCount;
        ULONGLONG PeakWorkingSetSize;
        ULONGLONG WorkingSetSize;
        ULONGLONG QuotaPagedPoolUsage;
        ULONGLONG QuotaNonPagedPoolUsage;
        ULONGLONG PagefileUsage;
        ULONGLONG PeakPagefileUsage;
        ULONGLONG PrivateUsage;

        WCHAR ImageFileName[260];
        WCHAR CommandLine[512];
    } PROCESS_EXTENDED_INFO;

    typedef struct _PROCESS_EXTENDED_INFO_REQUEST
    {
        ULONGLONG ProcessId;
        NTSTATUS ResultStatus;
        PROCESS_EXTENDED_INFO Info;
    } PROCESS_EXTENDED_INFO_REQUEST;

    typedef struct _PROCESS_HANDLE_ENTRY
    {
        ULONGLONG HandleValue;
        ULONG ObjectTypeIndex;
        ULONG GrantedAccess;
        ULONGLONG ObjectPointer;
    } PROCESS_HANDLE_ENTRY;

    typedef struct _PROCESS_HANDLES_REQUEST
    {
        ULONGLONG ProcessId;
        NTSTATUS ResultStatus;
        ULONG MaxHandles;
        ULONG ReturnedHandleCount;
        PROCESS_HANDLE_ENTRY Handles[128];
    } PROCESS_HANDLES_REQUEST;

    typedef struct _PROCESS_TOKEN_INFO
    {
        ULONGLONG ProcessId;
        ULONG TokenType;
        ULONG ElevationType;
        ULONG IsElevated;
        ULONG IntegrityLevel;
        ULONG SessionId;
        ULONG PrivilegeCount;
        ULONGLONG EnabledPrivilegesMask;
    } PROCESS_TOKEN_INFO;

    typedef struct _PROCESS_TOKEN_INFO_REQUEST
    {
        ULONGLONG ProcessId;
        NTSTATUS ResultStatus;
        PROCESS_TOKEN_INFO TokenInfo;
    } PROCESS_TOKEN_INFO_REQUEST;

    typedef struct _THREAD_EXTENDED_INFO
    {
        ULONGLONG ProcessId;
        ULONGLONG ThreadId;
        NTSTATUS ExitStatus;
        ULONGLONG TebBaseAddress;
        ULONGLONG StartAddress;
        ULONGLONG Win32StartAddress;
        LONG Priority;
        LONG BasePriority;
        ULONGLONG AffinityMask;
        ULONG State;
        ULONG WaitReason;
        ULONG SuspendCount;
        ULONG ContextSwitches;

        LARGE_INTEGER CreateTime;
        LARGE_INTEGER ExitTime;
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
    } THREAD_EXTENDED_INFO;

    typedef struct _THREAD_INFO_REQUEST
    {
        ULONGLONG ThreadId;
        NTSTATUS ResultStatus;
        THREAD_EXTENDED_INFO ThreadInfo;
    } THREAD_INFO_REQUEST;

    typedef struct _THREAD_PRIORITY_REQUEST
    {
        ULONGLONG ThreadId;
        LONG Priority;
        NTSTATUS ResultStatus;
    } THREAD_PRIORITY_REQUEST;

    typedef struct _THREAD_AFFINITY_REQUEST
    {
        ULONGLONG ThreadId;
        ULONGLONG AffinityMask;
        NTSTATUS ResultStatus;
    } THREAD_AFFINITY_REQUEST;

    typedef struct _THREAD_TERMINATE_REQUEST
    {
        ULONGLONG ThreadId;
        NTSTATUS ExitStatus;
        NTSTATUS ResultStatus;
    } THREAD_TERMINATE_REQUEST;

    typedef struct _THREAD_HIDE_REQUEST
    {
        ULONGLONG ThreadId;
        NTSTATUS ResultStatus;
    } THREAD_HIDE_REQUEST;

#pragma pack(pop)

    //
    // Driver Interface Helper Class
    //
    class DriverConnection
    {
    private:
        HANDLE m_deviceHandle;

    public:
        DriverConnection() : m_deviceHandle(INVALID_HANDLE_VALUE) {}
        ~DriverConnection() { Close(); }

        bool Open()
        {
            if (m_deviceHandle != INVALID_HANDLE_VALUE)
                return true;

            m_deviceHandle = CreateFileW(
                DRIVER_DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            return (m_deviceHandle != INVALID_HANDLE_VALUE);
        }

        void Close()
        {
            if (m_deviceHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(m_deviceHandle);
                m_deviceHandle = INVALID_HANDLE_VALUE;
            }
        }

        bool IsConnected() const { return m_deviceHandle != INVALID_HANDLE_VALUE; }

        HANDLE GetHandle() const { return m_deviceHandle; }

        //
        // Quick diagnostics
        //
        bool GetStatus(DRIVER_STATUS_REQUEST& statusOut)
        {
            if (!Open()) return false;
            DWORD bytes = 0;
            return DeviceIoControl(
                m_deviceHandle,
                IOCTL_HELPER_GET_DRIVER_STATUS,
                &statusOut, sizeof(statusOut),
                &statusOut, sizeof(statusOut),
                &bytes, nullptr
            );
        }

        //
        // Memory write
        //
        bool WriteMemory(ULONG pid, ULONGLONG targetAddr, const void* buffer, SIZE_T size, ULONGLONG* written = nullptr)
        {
            if (!Open() || !buffer || size == 0) return false;

            WRITE_PROCESS_REQUEST req = {};
            req.ProcessId = pid;
            req.TargetAddress = targetAddr;
            req.Size = size;

            if (size <= sizeof(req.Buffer))
            {
                memcpy(req.Buffer, buffer, size);
            }
            else
            {
                req.UserBufferAddress = reinterpret_cast<ULONGLONG>(buffer);
            }

            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(
                m_deviceHandle,
                IOCTL_HELPER_WRITE_PROCESS,
                &req, sizeof(req),
                &req, sizeof(req),
                &bytes, nullptr
            );

            if (written) *written = req.BytesWritten;
            return (ok && req.ResultStatus >= 0);
        }

        //
        // VirtualProtect
        //
        bool ProtectMemory(ULONG pid, ULONGLONG baseAddr, ULONGLONG regionSize, ULONG newProtect, ULONG* oldProtect = nullptr)
        {
            if (!Open()) return false;

            PROTECT_VIRTUAL_MEMORY_REQUEST req = {};
            req.ProcessId = pid;
            req.BaseAddress = baseAddr;
            req.RegionSize = regionSize;
            req.NewProtect = newProtect;

            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(
                m_deviceHandle,
                IOCTL_HELPER_PROTECT_VIRTUAL_MEMORY,
                &req, sizeof(req),
                &req, sizeof(req),
                &bytes, nullptr
            );

            if (oldProtect) *oldProtect = req.OldProtect;
            return (ok && req.ResultStatus >= 0);
        }

        //
        // AOB Pattern Scanner
        //
        ULONGLONG PatternScan(ULONG pid, ULONGLONG startAddr, ULONGLONG length, const unsigned char* pattern, const char* mask, ULONG patternLen, ULONG pageProtect = 0)
        {
            if (!Open() || !pattern || patternLen == 0) return 0;

            PATTERN_SCAN_REQUEST req = {};
            req.ProcessId = pid;
            req.StartAddress = startAddr;
            req.ScanLength = length;
            req.PatternLength = patternLen;
            req.PageProtect = pageProtect;

            if (patternLen > sizeof(req.Pattern)) patternLen = sizeof(req.Pattern);
            memcpy(req.Pattern, pattern, patternLen);
            if (mask) strncpy_s(req.Mask, mask, sizeof(req.Mask) - 1);

            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(
                m_deviceHandle,
                IOCTL_HELPER_PATTERN_SCAN,
                &req, sizeof(req),
                &req, sizeof(req),
                &bytes, nullptr
            );

            return (ok && req.ResultStatus >= 0) ? req.FoundAddress : 0;
        }

        //
        // Thread control
        //
        bool SuspendThread(ULONG tid, ULONG* prevSuspendCount = nullptr)
        {
            if (!Open()) return false;
            THREAD_CONTROL_REQUEST req = { tid, 0, 0 };
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_SUSPEND_THREAD, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            if (prevSuspendCount) *prevSuspendCount = req.PreviousSuspendCount;
            return (ok && req.ResultStatus >= 0);
        }

        bool ResumeThread(ULONG tid, ULONG* prevSuspendCount = nullptr)
        {
            if (!Open()) return false;
            THREAD_CONTROL_REQUEST req = { tid, 0, 0 };
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_RESUME_THREAD, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            if (prevSuspendCount) *prevSuspendCount = req.PreviousSuspendCount;
            return (ok && req.ResultStatus >= 0);
        }

        //
        // Process Introspection
        //
        bool QueryProcessExtended(ULONGLONG pid, PROCESS_EXTENDED_INFO& infoOut)
        {
            if (!Open()) return false;
            PROCESS_EXTENDED_INFO_REQUEST req = {};
            req.ProcessId = pid;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_QUERY_PROCESS_EXTENDED, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            if (ok && req.ResultStatus >= 0)
            {
                infoOut = req.Info;
                return true;
            }
            return false;
        }

        bool QueryProcessHandles(ULONGLONG pid, std::vector<PROCESS_HANDLE_ENTRY>& handlesOut, ULONG maxHandles = 128)
        {
            if (!Open()) return false;
            PROCESS_HANDLES_REQUEST req = {};
            req.ProcessId = pid;
            req.MaxHandles = maxHandles;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_QUERY_PROCESS_HANDLES, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            if (ok && req.ResultStatus >= 0)
            {
                ULONG count = (req.ReturnedHandleCount <= 128) ? req.ReturnedHandleCount : 128;
                handlesOut.assign(req.Handles, req.Handles + count);
                return true;
            }
            return false;
        }

        bool QueryProcessToken(ULONGLONG pid, PROCESS_TOKEN_INFO& tokenOut)
        {
            if (!Open()) return false;
            PROCESS_TOKEN_INFO_REQUEST req = {};
            req.ProcessId = pid;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_QUERY_PROCESS_TOKEN, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            if (ok && req.ResultStatus >= 0)
            {
                tokenOut = req.TokenInfo;
                return true;
            }
            return false;
        }

        //
        // Thread Introspection & Manipulation
        //
        bool QueryThreadInfo(ULONGLONG tid, THREAD_EXTENDED_INFO& infoOut)
        {
            if (!Open()) return false;
            THREAD_INFO_REQUEST req = {};
            req.ThreadId = tid;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_QUERY_THREAD_INFO, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            if (ok && req.ResultStatus >= 0)
            {
                infoOut = req.ThreadInfo;
                return true;
            }
            return false;
        }

        bool SetThreadPriority(ULONGLONG tid, LONG priority)
        {
            if (!Open()) return false;
            THREAD_PRIORITY_REQUEST req = {};
            req.ThreadId = tid;
            req.Priority = priority;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_SET_THREAD_PRIORITY, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            return (ok && req.ResultStatus >= 0);
        }

        bool SetThreadAffinity(ULONGLONG tid, ULONGLONG affinityMask)
        {
            if (!Open()) return false;
            THREAD_AFFINITY_REQUEST req = {};
            req.ThreadId = tid;
            req.AffinityMask = affinityMask;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_SET_THREAD_AFFINITY, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            return (ok && req.ResultStatus >= 0);
        }

        bool TerminateThread(ULONGLONG tid, NTSTATUS exitStatus = 0)
        {
            if (!Open()) return false;
            THREAD_TERMINATE_REQUEST req = {};
            req.ThreadId = tid;
            req.ExitStatus = exitStatus;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_TERMINATE_THREAD, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            return (ok && req.ResultStatus >= 0);
        }

        bool SetThreadHideFromDebugger(ULONGLONG tid)
        {
            if (!Open()) return false;
            THREAD_HIDE_REQUEST req = {};
            req.ThreadId = tid;
            DWORD bytes = 0;
            BOOL ok = DeviceIoControl(m_deviceHandle, IOCTL_HELPER_SET_THREAD_HIDE_FROM_DEBUGGER, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr);
            return (ok && req.ResultStatus >= 0);
        }
    };
}
