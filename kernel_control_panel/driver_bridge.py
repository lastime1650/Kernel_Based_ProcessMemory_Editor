"""
SampleKernel1 Windows Kernel Driver Communication Bridge (Python3)
Connects to \\\\.\\MyDriver via Windows DeviceIoControl and provides complete coverage
for all 37 IOCTLs (0x800 to 0x824).
"""

import ctypes
from ctypes import wintypes
import struct
import datetime
import threading
from typing import Optional, Dict, Any, List, Tuple

# Windows API Constants & Types
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

# IOCTL Calculation Helper
def CTL_CODE(device_type: int, function: int, method: int, access: int) -> int:
    return ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)

FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2
FILE_ANY_ACCESS = 0
RW_ACCESS = FILE_READ_ACCESS | FILE_WRITE_ACCESS

# All 37 IOCTL Codes
IOCTL_HELPER_PROCESS_INFORMATION         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_ALLOC_VIRTUAL_MEMORY        = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_FREE_VIRTUAL_MEMORY         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_COPY_PROCESS_MEMORY         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SCAN_VALUE_PROCESS          = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_READ_PROCESS                = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_READ_STRING_PROCESS         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_READ_PROCESS_INFORMATION    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_FREE_LINKED_LIST            = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_FREE_STRING_LIST            = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SET_HARDWARE_BREAKPOINT     = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_QUERY_HARDWARE_BREAKPOINT   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_REMOVE_HARDWARE_BREAKPOINT  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_FREE_HARDWARE_BREAKPOINT_RESULT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_REGISTER_DLL                = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_WRITE_PROCESS               = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_PROTECT_VIRTUAL_MEMORY      = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_PATTERN_SCAN                = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_ENUMERATE_THREADS           = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SUSPEND_THREAD              = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_RESUME_THREAD               = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_GET_THREAD_CONTEXT          = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SET_THREAD_CONTEXT          = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_EVENT_MONITOR_CONTROL       = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_POLL_EVENTS                 = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_GET_DRIVER_STATUS           = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_QUERY_PROCESS_EXTENDED      = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81A, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_QUERY_PROCESS_HANDLES       = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81B, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_QUERY_PROCESS_TOKEN         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81C, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_QUERY_THREAD_INFO           = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81D, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SET_THREAD_PRIORITY         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81E, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SET_THREAD_AFFINITY         = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81F, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_TERMINATE_THREAD            = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_SET_THREAD_HIDE_FROM_DEBUGGER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_CREATE_FUNCTION_CALL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_QUERY_FUNCTION_CALL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, RW_ACCESS)
IOCTL_HELPER_RELEASE_FUNCTION_CALL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, RW_ACCESS)

class CREATE_FUNCTION_CALL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [('StructSize',ctypes.c_uint32),('Version',ctypes.c_uint32),
        ('ProcessId',ctypes.c_uint32),('Flags',ctypes.c_uint32),
        ('ProcessStartKey',ctypes.c_uint64),('FunctionAddress',ctypes.c_uint64),
        ('Parameter',ctypes.c_uint64),('WaitMilliseconds',ctypes.c_uint32),
        ('ResultStatus',ctypes.c_int32),('CallId',ctypes.c_uint64),('ThreadId',ctypes.c_uint64),
        ('ThreadCreated',ctypes.c_uint32),('Completed',ctypes.c_uint32),
        ('WaitStatus',ctypes.c_int32),('ExitStatus',ctypes.c_int32),
        ('QueryStatus',ctypes.c_int32),('Reserved',ctypes.c_uint32)]

class QUERY_FUNCTION_CALL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [('StructSize',ctypes.c_uint32),('Version',ctypes.c_uint32),
        ('CallId',ctypes.c_uint64),('WaitMilliseconds',ctypes.c_uint32),('ResultStatus',ctypes.c_int32),
        ('ProcessId',ctypes.c_uint64),('ProcessStartKey',ctypes.c_uint64),('ThreadId',ctypes.c_uint64),
        ('FunctionAddress',ctypes.c_uint64),('Parameter',ctypes.c_uint64),('CreatedAtTime',ctypes.c_uint64),
        ('ThreadCreated',ctypes.c_uint32),('Completed',ctypes.c_uint32),('WaitStatus',ctypes.c_int32),
        ('ExitStatus',ctypes.c_int32),('QueryStatus',ctypes.c_int32),('Reserved',ctypes.c_uint32)]

class RELEASE_FUNCTION_CALL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [('StructSize',ctypes.c_uint32),('Version',ctypes.c_uint32),
        ('CallId',ctypes.c_uint64),('ResultStatus',ctypes.c_int32),('Reserved',ctypes.c_uint32)]

assert ctypes.sizeof(CREATE_FUNCTION_CALL_REQUEST)==88
assert ctypes.sizeof(QUERY_FUNCTION_CALL_REQUEST)==96
assert ctypes.sizeof(RELEASE_FUNCTION_CALL_REQUEST)==24

# -------------------------------------------------------------
# CTypes Structure Definitions (Strict 8-byte Alignment)
# -------------------------------------------------------------

class PROCESS_INFORMATION_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("ProcessIdResult", ctypes.c_ulonglong),
        ("ParentProcessId", ctypes.c_ulonglong),
        ("PebBaseAddress", ctypes.c_ulonglong),
        ("ExitStatus", ctypes.c_long),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", ctypes.c_long),
        ("ProcessStartKey", ctypes.c_ulonglong),
        ("IsProtectedProcess", ctypes.c_ubyte),
        ("ImagePath", ctypes.c_wchar * 512),
    ]

class ALLOC_VIRTUAL_MEMORY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("Size", ctypes.c_ulonglong),
        ("Protect", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("AllocatedAddress", ctypes.c_ulonglong),
    ]

class FREE_VIRTUAL_MEMORY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("Address", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
    ]

class COPY_PROCESS_MEMORY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("SourceProcessId", ctypes.c_ulong),
        ("SourceAddress", ctypes.c_ulonglong),
        ("DestinationProcessId", ctypes.c_ulong),
        ("DestinationAddress", ctypes.c_ulonglong),
        ("Size", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("CopiedSize", ctypes.c_ulonglong),
    ]

class SCAN_VALUE_PROCESS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("TargetProcessId", ctypes.c_ulong),
        ("SourceValueAddress", ctypes.c_ulonglong),
        ("SourceValueSize", ctypes.c_ulonglong),
        ("PageProtect", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("ResultListAddress", ctypes.c_ulonglong),
    ]

class READ_PROCESS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("TargetProcessId", ctypes.c_ulong),
        ("ReadAddress", ctypes.c_ulonglong),
        ("Size", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("DumpedAddress", ctypes.c_ulonglong),
    ]

class READ_STRING_PROCESS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("TargetProcessId", ctypes.c_ulong),
        ("MinimumCharacterCount", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("ResultListAddress", ctypes.c_ulonglong),
    ]

class READ_PROCESS_INFORMATION_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("TargetProcessId", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("ResultListAddress", ctypes.c_ulonglong),
    ]

class FREE_LINKED_LIST_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("FirstNodeAddress", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
    ]

class FREE_STRING_LIST_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("FirstNodeAddress", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
    ]

class IOCTL_HWBP_SET_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
        ("Address", ctypes.c_ulonglong),
        ("Type", ctypes.c_ulong),
        ("Length", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("Reserved2", ctypes.c_ulong),
        ("FirstResultNode", ctypes.c_ulonglong),
        ("AppliedThreadCount", ctypes.c_ulong),
        ("FailedThreadCount", ctypes.c_ulong),
    ]

class IOCTL_HWBP_QUERY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("Reserved2", ctypes.c_ulong),
        ("FirstResultNode", ctypes.c_ulonglong),
        ("ThreadCount", ctypes.c_ulong),
        ("BreakpointCount", ctypes.c_ulong),
    ]

class IOCTL_HWBP_REMOVE_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
        ("FirstResultNode", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("RemovedThreadCount", ctypes.c_ulong),
        ("FailedThreadCount", ctypes.c_ulong),
        ("Reserved2", ctypes.c_ulong),
    ]

class IOCTL_HWBP_FREE_RESULT_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("FirstResultNode", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("Reserved", ctypes.c_ulong),
    ]

class REGISTER_DLL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("DllPath", ctypes.c_char * 520),
        ("ResultStatus", ctypes.c_long),
        ("TargetIsWow64", ctypes.c_ubyte),
        ("Kernel32Found", ctypes.c_ubyte),
        ("LoadLibraryFound", ctypes.c_ubyte),
        ("Kernel32Base", ctypes.c_ulonglong),
        ("Kernel32Size", ctypes.c_ulonglong),
        ("LoadLibraryAddress", ctypes.c_ulonglong),
    ]

class WRITE_PROCESS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("TargetAddress", ctypes.c_ulonglong),
        ("Size", ctypes.c_ulonglong),
        ("Buffer", ctypes.c_ubyte * 4096),
        ("UserBufferAddress", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("BytesWritten", ctypes.c_ulonglong),
    ]

class PROTECT_VIRTUAL_MEMORY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("BaseAddress", ctypes.c_ulonglong),
        ("RegionSize", ctypes.c_ulonglong),
        ("NewProtect", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("OldProtect", ctypes.c_ulong),
        ("ResultBaseAddress", ctypes.c_ulonglong),
        ("ResultRegionSize", ctypes.c_ulonglong),
    ]

class PATTERN_SCAN_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("StartAddress", ctypes.c_ulonglong),
        ("ScanLength", ctypes.c_ulonglong),
        ("PatternLength", ctypes.c_ulong),
        ("Pattern", ctypes.c_ubyte * 256),
        ("Mask", ctypes.c_char * 256),
        ("PageProtect", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("FoundAddress", ctypes.c_ulonglong),
        ("MatchesCount", ctypes.c_ulong),
    ]

class THREAD_SNAPSHOT_INFO(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulonglong),
        ("StartAddress", ctypes.c_ulonglong),
        ("Priority", ctypes.c_ulong),
        ("BasePriority", ctypes.c_long),
        ("State", ctypes.c_ulong),
        ("WaitReason", ctypes.c_ulong),
        ("ContextSwitches", ctypes.c_ulong),
    ]

class ENUMERATE_THREADS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulong),
        ("MaxThreads", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("ThreadCount", ctypes.c_ulong),
        ("Threads", THREAD_SNAPSHOT_INFO * 64),
    ]

class THREAD_CONTROL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("PreviousSuspendCount", ctypes.c_ulong),
    ]

class THREAD_REGISTERS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("Rip", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("EFlags", ctypes.c_ulong),
    ]

class EVENT_MONITOR_CONTROL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("EnableProcessMonitor", ctypes.c_ubyte),
        ("EnableImageLoadMonitor", ctypes.c_ubyte),
        ("ResultStatus", ctypes.c_long),
        ("ProcessMonitorActive", ctypes.c_ubyte),
        ("ImageMonitorActive", ctypes.c_ubyte),
    ]

class KERNEL_MONITOR_EVENT(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("EventType", ctypes.c_ulong),
        ("Timestamp", ctypes.c_int64),
        ("ProcessId", ctypes.c_ulong),
        ("ParentProcessId", ctypes.c_ulong),
        ("CreatingThreadId", ctypes.c_ulong),
        ("ImageBase", ctypes.c_ulonglong),
        ("ImageSize", ctypes.c_ulonglong),
        ("ImageName", ctypes.c_wchar * 260),
        ("CommandLine", ctypes.c_wchar * 260),
    ]

class POLL_EVENTS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("MaxEventsToRead", ctypes.c_ulong),
        ("ResultStatus", ctypes.c_long),
        ("EventsReturned", ctypes.c_ulong),
        ("EventsRemaining", ctypes.c_ulong),
        ("Events", KERNEL_MONITOR_EVENT * 16),
    ]

class DRIVER_STATUS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ResultStatus", ctypes.c_long),
        ("MajorVersion", ctypes.c_ulong),
        ("MinorVersion", ctypes.c_ulong),
        ("BuildNumber", ctypes.c_ulong),
        ("DriverStartTime", ctypes.c_int64),
        ("TotalIoctlRequests", ctypes.c_ulonglong),
        ("EventMonitorActive", ctypes.c_ubyte),
        ("QueuedEventCount", ctypes.c_ulong),
    ]

class PROCESS_EXTENDED_INFO(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulonglong),
        ("ParentProcessId", ctypes.c_ulonglong),
        ("PebBaseAddress", ctypes.c_ulonglong),
        ("AffinityMask", ctypes.c_ulonglong),
        ("BasePriority", ctypes.c_long),
        ("ExitStatus", ctypes.c_long),
        ("SessionId", ctypes.c_ulong),
        ("HandleCount", ctypes.c_ulong),
        ("ThreadCount", ctypes.c_ulong),
        ("IsWow64", ctypes.c_ulong),
        ("IsProtectedProcess", ctypes.c_ulong),
        ("CreateTime", ctypes.c_int64),
        ("ExitTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
        ("PeakVirtualSize", ctypes.c_ulonglong),
        ("VirtualSize", ctypes.c_ulonglong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_ulonglong),
        ("WorkingSetSize", ctypes.c_ulonglong),
        ("QuotaPagedPoolUsage", ctypes.c_ulonglong),
        ("QuotaNonPagedPoolUsage", ctypes.c_ulonglong),
        ("PagefileUsage", ctypes.c_ulonglong),
        ("PeakPagefileUsage", ctypes.c_ulonglong),
        ("PrivateUsage", ctypes.c_ulonglong),
        ("ImageFileName", ctypes.c_wchar * 260),
        ("CommandLine", ctypes.c_wchar * 512),
    ]

class PROCESS_EXTENDED_INFO_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("Info", PROCESS_EXTENDED_INFO),
    ]

class PROCESS_HANDLE_ENTRY(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("HandleValue", ctypes.c_ulonglong),
        ("ObjectTypeIndex", ctypes.c_ulong),
        ("GrantedAccess", ctypes.c_ulong),
        ("ObjectPointer", ctypes.c_ulonglong),
    ]

class PROCESS_HANDLES_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("MaxHandles", ctypes.c_ulong),
        ("ReturnedHandleCount", ctypes.c_ulong),
        ("Handles", PROCESS_HANDLE_ENTRY * 128),
    ]

class PROCESS_TOKEN_INFO(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulonglong),
        ("TokenType", ctypes.c_ulong),
        ("ElevationType", ctypes.c_ulong),
        ("IsElevated", ctypes.c_ulong),
        ("IntegrityLevel", ctypes.c_ulong),
        ("SessionId", ctypes.c_ulong),
        ("PrivilegeCount", ctypes.c_ulong),
        ("EnabledPrivilegesMask", ctypes.c_ulonglong),
    ]

class PROCESS_TOKEN_INFO_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("TokenInfo", PROCESS_TOKEN_INFO),
    ]

class THREAD_EXTENDED_INFO(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ProcessId", ctypes.c_ulonglong),
        ("ThreadId", ctypes.c_ulonglong),
        ("ExitStatus", ctypes.c_long),
        ("TebBaseAddress", ctypes.c_ulonglong),
        ("StartAddress", ctypes.c_ulonglong),
        ("Win32StartAddress", ctypes.c_ulonglong),
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
        ("AffinityMask", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("WaitReason", ctypes.c_ulong),
        ("SuspendCount", ctypes.c_ulong),
        ("ContextSwitches", ctypes.c_ulong),
        ("CreateTime", ctypes.c_int64),
        ("ExitTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
    ]

class THREAD_INFO_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
        ("ThreadInfo", THREAD_EXTENDED_INFO),
    ]

class THREAD_PRIORITY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulonglong),
        ("Priority", ctypes.c_long),
        ("ResultStatus", ctypes.c_long),
    ]

class THREAD_AFFINITY_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulonglong),
        ("AffinityMask", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
    ]

class THREAD_TERMINATE_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulonglong),
        ("ExitStatus", ctypes.c_long),
        ("ResultStatus", ctypes.c_long),
    ]

class THREAD_HIDE_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("ThreadId", ctypes.c_ulonglong),
        ("ResultStatus", ctypes.c_long),
    ]


# -------------------------------------------------------------
# Kernel Driver Bridge Class
# -------------------------------------------------------------

class KernelDriverBridge:
    DEVICE_PATH = r"\\.\MyDriver"

    def __init__(self, device_path: str = DEVICE_PATH):
        self.device_path = device_path
        self.handle = None
        self._lock = threading.RLock()
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # ctypes defaults to 32-bit int without prototypes, truncating x64
        # HANDLEs and pointers. Keep signatures local to this DLL instance.
        self._kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self._kernel32.CreateFileW.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        self._kernel32.DeviceIoControl.restype = wintypes.BOOL
        self._kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
        self._kernel32.VirtualFree.restype = wintypes.BOOL

    def open(self) -> bool:
        with self._lock:
            if self.handle and self.handle != INVALID_HANDLE_VALUE:
                return True

            self.handle = self._kernel32.CreateFileW(
                self.device_path,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )

            if not self.handle or self.handle == ctypes.c_void_p(INVALID_HANDLE_VALUE).value:
                self.handle = None
                return False
            return True

    def close(self):
        with self._lock:
            if self.handle and self.handle != INVALID_HANDLE_VALUE:
                self._kernel32.CloseHandle(self.handle)
                self.handle = None

    def is_connected(self) -> bool:
        with self._lock:
            return self.handle is not None and self.handle != INVALID_HANDLE_VALUE

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def send_ioctl(self, ioctl_code: int, request_struct: ctypes.Structure) -> Tuple[bool, int, int]:
        """Send METHOD_BUFFERED I/O; return (success, error, bytes_returned)."""
        with self._lock:
            if not self.open():
                return False, 2, 0 # ERROR_FILE_NOT_FOUND

            struct_size = ctypes.sizeof(request_struct)
            bytes_returned = wintypes.DWORD(0)

            ok = self._kernel32.DeviceIoControl(
                self.handle,
                ioctl_code,
                ctypes.byref(request_struct),
                struct_size,
                ctypes.byref(request_struct),
                struct_size,
                ctypes.byref(bytes_returned),
                None
            )

            last_error = 0 if ok else ctypes.get_last_error()
            return bool(ok), last_error, bytes_returned.value

    # High-level IOCTL wrappers (packet layouts and result fields unchanged).

    def get_driver_status(self) -> Dict[str, Any]:
        req = DRIVER_STATUS_REQUEST()
        ok, err, bytes_ret = self.send_ioctl(IOCTL_HELPER_GET_DRIVER_STATUS, req)
        return {
            "success": ok,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "major_version": req.MajorVersion,
            "minor_version": req.MinorVersion,
            "build_number": req.BuildNumber,
            "driver_start_time": req.DriverStartTime,
            "total_ioctl_requests": req.TotalIoctlRequests,
            "event_monitor_active": bool(req.EventMonitorActive),
            "queued_event_count": req.QueuedEventCount
        }

    # 2. 0x800: Process Information
    def query_process_info(self, pid: int) -> Dict[str, Any]:
        req = PROCESS_INFORMATION_REQUEST()
        req.ProcessId = pid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_PROCESS_INFORMATION, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "process_id": req.ProcessIdResult,
            "parent_process_id": req.ParentProcessId,
            "peb_base_address": f"0x{req.PebBaseAddress:X}",
            "exit_status": req.ExitStatus,
            "affinity_mask": f"0x{req.AffinityMask:X}",
            "base_priority": req.BasePriority,
            "process_start_key": req.ProcessStartKey,
            "is_protected_process": bool(req.IsProtectedProcess),
            "image_path": req.ImagePath
        }

    # 3. 0x81A: Process Extended Info
    def query_process_extended(self, pid: int) -> Dict[str, Any]:
        req = PROCESS_EXTENDED_INFO_REQUEST()
        req.ProcessId = pid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_QUERY_PROCESS_EXTENDED, req)
        info = req.Info
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "process_id": info.ProcessId,
            "parent_process_id": info.ParentProcessId,
            "peb_base_address": f"0x{info.PebBaseAddress:X}",
            "affinity_mask": f"0x{info.AffinityMask:X}",
            "base_priority": info.BasePriority,
            "exit_status": info.ExitStatus,
            "session_id": info.SessionId,
            "handle_count": info.HandleCount,
            "thread_count": info.ThreadCount,
            "is_wow64": bool(info.IsWow64),
            "is_protected": bool(info.IsProtectedProcess),
            "create_time": info.CreateTime,
            "exit_time": info.ExitTime,
            "kernel_time": info.KernelTime,
            "user_time": info.UserTime,
            "virtual_size_kb": info.VirtualSize // 1024,
            "peak_virtual_size_kb": info.PeakVirtualSize // 1024,
            "working_set_kb": info.WorkingSetSize // 1024,
            "peak_working_set_kb": info.PeakWorkingSetSize // 1024,
            "private_usage_kb": info.PrivateUsage // 1024,
            "page_fault_count": info.PageFaultCount,
            "image_file_name": info.ImageFileName,
            "command_line": info.CommandLine
        }

    # 4. 0x81B: Process Handles
    def query_process_handles(self, pid: int, max_handles: int = 128) -> Dict[str, Any]:
        req = PROCESS_HANDLES_REQUEST()
        req.ProcessId = pid
        req.MaxHandles = min(max(max_handles, 1), 128)
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_QUERY_PROCESS_HANDLES, req)
        count = min(req.ReturnedHandleCount, 128)
        handles = []
        for i in range(count):
            h = req.Handles[i]
            handles.append({
                "handle_value": f"0x{h.HandleValue:X}",
                "object_type_index": h.ObjectTypeIndex,
                "granted_access": f"0x{h.GrantedAccess:08X}",
                "object_pointer": f"0x{h.ObjectPointer:X}"
            })
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "returned_count": count,
            "handles": handles
        }

    # 5. 0x81C: Process Token
    def query_process_token(self, pid: int) -> Dict[str, Any]:
        req = PROCESS_TOKEN_INFO_REQUEST()
        req.ProcessId = pid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_QUERY_PROCESS_TOKEN, req)
        token = req.TokenInfo
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "process_id": token.ProcessId,
            "token_type": token.TokenType,
            "elevation_type": token.ElevationType,
            "is_elevated": bool(token.IsElevated),
            "integrity_level": f"0x{token.IntegrityLevel:X}",
            "session_id": token.SessionId,
            "privilege_count": token.PrivilegeCount,
            "enabled_privileges_mask": f"0x{token.EnabledPrivilegesMask:X}"
        }

    # 6. 0x812: Enumerate Threads
    def enumerate_threads(self, pid: int, max_threads: int = 64) -> Dict[str, Any]:
        req = ENUMERATE_THREADS_REQUEST()
        req.ProcessId = pid
        req.MaxThreads = min(max_threads, 64)
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_ENUMERATE_THREADS, req)
        count = min(req.ThreadCount, 64)
        threads = []
        for i in range(count):
            t = req.Threads[i]
            threads.append({
                "thread_id": t.ThreadId,
                "start_address": f"0x{t.StartAddress:X}",
                "priority": t.Priority,
                "base_priority": t.BasePriority,
                "state": t.State,
                "wait_reason": t.WaitReason,
                "context_switches": t.ContextSwitches
            })
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "thread_count": count,
            "threads": threads
        }

    # 7. 0x81D: Query Thread Info
    def query_thread_info(self, tid: int) -> Dict[str, Any]:
        req = THREAD_INFO_REQUEST()
        req.ThreadId = tid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_QUERY_THREAD_INFO, req)
        t = req.ThreadInfo
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "process_id": t.ProcessId,
            "thread_id": t.ThreadId,
            "exit_status": t.ExitStatus,
            "teb_base_address": f"0x{t.TebBaseAddress:X}",
            "start_address": f"0x{t.StartAddress:X}",
            "win32_start_address": f"0x{t.Win32StartAddress:X}",
            "priority": t.Priority,
            "base_priority": t.BasePriority,
            "affinity_mask": f"0x{t.AffinityMask:X}",
            "state": t.State,
            "wait_reason": t.WaitReason,
            "suspend_count": t.SuspendCount,
            "context_switches": t.ContextSwitches,
            "create_time": t.CreateTime,
            "exit_time": t.ExitTime,
            "kernel_time": t.KernelTime,
            "user_time": t.UserTime
        }

    # 8. 0x813: Suspend Thread
    def suspend_thread(self, tid: int) -> Dict[str, Any]:
        req = THREAD_CONTROL_REQUEST()
        req.ThreadId = tid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SUSPEND_THREAD, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "previous_suspend_count": req.PreviousSuspendCount
        }

    # 9. 0x814: Resume Thread
    def resume_thread(self, tid: int) -> Dict[str, Any]:
        req = THREAD_CONTROL_REQUEST()
        req.ThreadId = tid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_RESUME_THREAD, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "previous_suspend_count": req.PreviousSuspendCount
        }

    # 10. 0x815: Get Thread Context
    def get_thread_context(self, tid: int) -> Dict[str, Any]:
        req = THREAD_REGISTERS_REQUEST()
        req.ThreadId = tid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_GET_THREAD_CONTEXT, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "thread_id": req.ThreadId,
            "rip": f"0x{req.Rip:016X}",
            "rsp": f"0x{req.Rsp:016X}",
            "rbp": f"0x{req.Rbp:016X}",
            "rax": f"0x{req.Rax:016X}",
            "rbx": f"0x{req.Rbx:016X}",
            "rcx": f"0x{req.Rcx:016X}",
            "rdx": f"0x{req.Rdx:016X}",
            "rsi": f"0x{req.Rsi:016X}",
            "rdi": f"0x{req.Rdi:016X}",
            "r8": f"0x{req.R8:016X}",
            "r9": f"0x{req.R9:016X}",
            "r10": f"0x{req.R10:016X}",
            "r11": f"0x{req.R11:016X}",
            "r12": f"0x{req.R12:016X}",
            "r13": f"0x{req.R13:016X}",
            "r14": f"0x{req.R14:016X}",
            "r15": f"0x{req.R15:016X}",
            "eflags": f"0x{req.EFlags:08X}"
        }

    # 11. 0x816: Set Thread Context
    def set_thread_context(self, tid: int, regs: Dict[str, int]) -> Dict[str, Any]:
        req = THREAD_REGISTERS_REQUEST()
        req.ThreadId = tid
        fields = {name.lower(): name for name, _ in THREAD_REGISTERS_REQUEST._fields_
                  if name not in ("ThreadId", "ResultStatus")}
        for k, v in regs.items():
            attr = fields.get(k.lower())
            if attr is not None:
                setattr(req, attr, v)
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SET_THREAD_CONTEXT, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 12. 0x81E: Set Thread Priority
    def set_thread_priority(self, tid: int, priority: int) -> Dict[str, Any]:
        req = THREAD_PRIORITY_REQUEST()
        req.ThreadId = tid
        req.Priority = priority
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SET_THREAD_PRIORITY, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 13. 0x81F: Set Thread Affinity
    def set_thread_affinity(self, tid: int, affinity_mask: int) -> Dict[str, Any]:
        req = THREAD_AFFINITY_REQUEST()
        req.ThreadId = tid
        req.AffinityMask = affinity_mask
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SET_THREAD_AFFINITY, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 14. 0x820: Terminate Thread
    def terminate_thread(self, tid: int, exit_status: int = 0) -> Dict[str, Any]:
        req = THREAD_TERMINATE_REQUEST()
        req.ThreadId = tid
        req.ExitStatus = exit_status
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_TERMINATE_THREAD, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 15. 0x821: Set Thread Hide From Debugger
    def set_thread_hide_from_debugger(self, tid: int) -> Dict[str, Any]:
        req = THREAD_HIDE_REQUEST()
        req.ThreadId = tid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SET_THREAD_HIDE_FROM_DEBUGGER, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 16. 0x801: Alloc Virtual Memory
    def alloc_virtual_memory(self, pid: int, size: int, protect: int = PAGE_EXECUTE_READWRITE) -> Dict[str, Any]:
        req = ALLOC_VIRTUAL_MEMORY_REQUEST()
        req.ProcessId = pid
        req.Size = size
        req.Protect = protect
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_ALLOC_VIRTUAL_MEMORY, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "allocated_address": f"0x{req.AllocatedAddress:X}",
            "allocated_address_int": req.AllocatedAddress
        }

    # 17. 0x802: Free Virtual Memory
    def free_virtual_memory(self, pid: int, address: int) -> Dict[str, Any]:
        req = FREE_VIRTUAL_MEMORY_REQUEST()
        req.ProcessId = pid
        req.Address = address
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_FREE_VIRTUAL_MEMORY, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 18. 0x810: Protect Virtual Memory
    def protect_virtual_memory(self, pid: int, base_addr: int, region_size: int, new_protect: int) -> Dict[str, Any]:
        req = PROTECT_VIRTUAL_MEMORY_REQUEST()
        req.ProcessId = pid
        req.BaseAddress = base_addr
        req.RegionSize = region_size
        req.NewProtect = new_protect
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_PROTECT_VIRTUAL_MEMORY, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "old_protect": f"0x{req.OldProtect:X}",
            "result_base_address": f"0x{req.ResultBaseAddress:X}",
            "result_region_size": req.ResultRegionSize
        }

    # 19. 0x803: Copy Process Memory
    def copy_process_memory(self, src_pid: int, src_addr: int, dst_pid: int, dst_addr: int, size: int) -> Dict[str, Any]:
        req = COPY_PROCESS_MEMORY_REQUEST()
        req.SourceProcessId = src_pid
        req.SourceAddress = src_addr
        req.DestinationProcessId = dst_pid
        req.DestinationAddress = dst_addr
        req.Size = size
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_COPY_PROCESS_MEMORY, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "copied_size": req.CopiedSize
        }

    # 20. 0x80F: Write Process Memory
    def write_process_memory(self, pid: int, target_addr: int, data: bytes) -> Dict[str, Any]:
        req = WRITE_PROCESS_REQUEST()
        req.ProcessId = pid
        req.TargetAddress = target_addr
        req.Size = len(data)
        if len(data) <= 4096:
            for i, b in enumerate(data):
                req.Buffer[i] = b
            req.UserBufferAddress = 0
        else:
            # Pass user pointer for large buffers
            user_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            req.UserBufferAddress = ctypes.addressof(user_buf)

        ok, err, _ = self.send_ioctl(IOCTL_HELPER_WRITE_PROCESS, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "bytes_written": req.BytesWritten
        }

    # 21. 0x805: Read Process Memory
    def read_process_memory(self, pid: int, read_addr: int, size: int) -> Dict[str, Any]:
        req = READ_PROCESS_REQUEST()
        req.TargetProcessId = pid
        req.ReadAddress = read_addr
        req.Size = size
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_READ_PROCESS, req)
        dumped_ptr = req.DumpedAddress
        data_hex = ""
        if ok and req.ResultStatus >= 0 and dumped_ptr != 0:
            try:
                raw_bytes = ctypes.string_at(dumped_ptr, min(size, 4096))
                data_hex = raw_bytes.hex()
            except Exception as e:
                data_hex = f"read_error: {e}"
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "dumped_address": f"0x{dumped_ptr:X}",
            "size": size,
            "data_hex": data_hex
        }

    def read_process_memory_snapshot(self, pid: int, read_addr: int, size: int) -> Dict[str, Any]:
        """Copy a read result and release its caller-owned allocation.

        Keep read_process_memory's raw-pointer ownership contract unchanged.
        Snapshot consumers use data_hex; dumped_address is diagnostic only.
        The response fields and preview length remain the same.
        """
        with self._lock:
            result = self.read_process_memory(pid, read_addr, size)
            if result["success"]:
                address = int(result["dumped_address"], 16)
                if address and not self._kernel32.VirtualFree(address, 0, MEM_RELEASE):
                    raise ctypes.WinError(ctypes.get_last_error())
            return result

    # 22. 0x804: Scan Value Process
    def scan_value_process(self, pid: int, value_bytes: bytes, protect: int = PAGE_READWRITE) -> Dict[str, Any]:
        val_buf = (ctypes.c_ubyte * len(value_bytes)).from_buffer_copy(value_bytes)
        req = SCAN_VALUE_PROCESS_REQUEST()
        req.TargetProcessId = pid
        req.SourceValueAddress = ctypes.addressof(val_buf)
        req.SourceValueSize = len(value_bytes)
        req.PageProtect = protect
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SCAN_VALUE_PROCESS, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "result_list_address": f"0x{req.ResultListAddress:X}",
            "result_list_address_int": req.ResultListAddress
        }

    # 23. 0x811: Pattern Scan (AOB)
    def pattern_scan(self, pid: int, start_addr: int, scan_len: int, pattern: bytes, mask: str, protect: int = 0) -> Dict[str, Any]:
        req = PATTERN_SCAN_REQUEST()
        req.ProcessId = pid
        req.StartAddress = start_addr
        req.ScanLength = scan_len
        req.PatternLength = min(len(pattern), 256)
        req.PageProtect = protect
        for i in range(req.PatternLength):
            req.Pattern[i] = pattern[i]
        mask_bytes = mask.encode("ascii")[:256]
        req.Mask = mask_bytes

        ok, err, _ = self.send_ioctl(IOCTL_HELPER_PATTERN_SCAN, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "found_address": f"0x{req.FoundAddress:X}",
            "found_address_int": req.FoundAddress,
            "matches_count": req.MatchesCount
        }

    # 24. 0x806: Read String Process
    def read_string_process(self, pid: int, min_chars: int = 4) -> Dict[str, Any]:
        req = READ_STRING_PROCESS_REQUEST()
        req.TargetProcessId = pid
        req.MinimumCharacterCount = min_chars
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_READ_STRING_PROCESS, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "result_list_address": f"0x{req.ResultListAddress:X}",
            "result_list_address_int": req.ResultListAddress
        }

    # 25. 0x807: Read Process Information (VAD)
    def read_process_information_vad(self, pid: int) -> Dict[str, Any]:
        req = READ_PROCESS_INFORMATION_REQUEST()
        req.TargetProcessId = pid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_READ_PROCESS_INFORMATION, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "result_list_address": f"0x{req.ResultListAddress:X}",
            "result_list_address_int": req.ResultListAddress
        }

    # 26. 0x808: Free Usermode Linked List
    def free_linked_list(self, first_node: int) -> Dict[str, Any]:
        req = FREE_LINKED_LIST_REQUEST()
        req.FirstNodeAddress = first_node
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_FREE_LINKED_LIST, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 27. 0x809: Free String List
    def free_string_list(self, first_node: int) -> Dict[str, Any]:
        req = FREE_STRING_LIST_REQUEST()
        req.FirstNodeAddress = first_node
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_FREE_STRING_LIST, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    # 28. 0x80A: Set Hardware Breakpoint
    def set_hardware_breakpoint(self, pid: int, address: int, bp_type: int = 0, bp_len: int = 0) -> Dict[str, Any]:
        req = IOCTL_HWBP_SET_REQUEST()
        req.ProcessId = pid
        req.Address = address
        req.Type = bp_type   # 0: Exec, 1: Write, 3: RW
        # The panel accepts DR7 length encodings; the kernel enum uses bytes.
        req.Length = {0: 1, 1: 2, 3: 4, 2: 8}.get(bp_len, 0)
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_SET_HARDWARE_BREAKPOINT, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "first_result_node": f"0x{req.FirstResultNode:X}",
            "first_result_node_int": req.FirstResultNode,
            "applied_thread_count": req.AppliedThreadCount,
            "failed_thread_count": req.FailedThreadCount
        }

    # 29. 0x80B: Query Hardware Breakpoint
    def query_hardware_breakpoint(self, pid: int) -> Dict[str, Any]:
        req = IOCTL_HWBP_QUERY_REQUEST()
        req.ProcessId = pid
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_QUERY_HARDWARE_BREAKPOINT, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "first_result_node": f"0x{req.FirstResultNode:X}",
            "first_result_node_int": req.FirstResultNode,
            "thread_count": req.ThreadCount,
            "breakpoint_count": req.BreakpointCount
        }

    # 30. 0x80C: Remove Hardware Breakpoint
    def remove_hardware_breakpoint(self, pid: int, first_result_node: int) -> Dict[str, Any]:
        req = IOCTL_HWBP_REMOVE_REQUEST()
        req.ProcessId = pid
        req.FirstResultNode = first_result_node
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_REMOVE_HARDWARE_BREAKPOINT, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "removed_thread_count": req.RemovedThreadCount,
            "failed_thread_count": req.FailedThreadCount
        }

    # 31. 0x80D: Free Hardware Breakpoint Result
    def free_hardware_breakpoint_result(self, first_result_node: int) -> Dict[str, Any]:
        req = IOCTL_HWBP_FREE_RESULT_REQUEST()
        req.FirstResultNode = first_result_node
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_FREE_HARDWARE_BREAKPOINT_RESULT, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}"
        }

    def _function_call_response(self, code, req):
        ok, error, returned = self.send_ioctl(code, req)
        valid = ok and returned == ctypes.sizeof(req)
        result = {'success':valid and req.ResultStatus >= 0, 'transport_ok':ok,
            'packet_valid':valid, 'error_code':error,
            'result_status':f'0x{req.ResultStatus & 0xffffffff:08X}',
            'call_id':str(req.CallId), 'execution_unknown':not valid}
        if hasattr(req,'ThreadCreated'):
            result.update(thread_created=bool(req.ThreadCreated),completed=bool(req.Completed),
                thread_id=int(req.ThreadId),wait_status=f'0x{req.WaitStatus & 0xffffffff:08X}',
                query_status=f'0x{req.QueryStatus & 0xffffffff:08X}',
                exit_status=f'0x{req.ExitStatus & 0xffffffff:08X}',
                exit_value=(req.ExitStatus & 0xffffffff) if valid and req.Completed and req.QueryStatus==0 else None)
        if hasattr(req,'CreatedAtTime'):
            result.update(pid=int(req.ProcessId),process_start_key=str(req.ProcessStartKey),
                function_address=f'0x{req.FunctionAddress:X}',parameter=f'0x{req.Parameter:X}',
                created_at_time=str(req.CreatedAtTime))
        return result

    def create_function_call(self,pid,start_key,function_address,parameter=0,wait_ms=0):
        if not 0<pid<=0xffffffff or not 0<start_key<=0xffffffffffffffff:
            raise ValueError('PID 또는 프로세스 시작 키 오류')
        if not 0<function_address<0x800000000000 or not 0<=parameter<=0xffffffffffffffff or not 0<=wait_ms<=1000:
            raise ValueError('함수 주소, 64비트 인자 또는 대기 시간 오류')
        req=CREATE_FUNCTION_CALL_REQUEST();req.StructSize=ctypes.sizeof(req);req.Version=1
        req.ProcessId=pid;req.ProcessStartKey=start_key;req.FunctionAddress=function_address
        req.Parameter=parameter;req.WaitMilliseconds=wait_ms
        return self._function_call_response(IOCTL_HELPER_CREATE_FUNCTION_CALL,req)

    def query_function_call(self,call_id,wait_ms=0):
        if not 0<call_id<=0xffffffffffffffff or not 0<=wait_ms<=1000:raise ValueError('호출 ID 또는 대기 시간 오류')
        req=QUERY_FUNCTION_CALL_REQUEST();req.StructSize=ctypes.sizeof(req);req.Version=1
        req.CallId=call_id;req.WaitMilliseconds=wait_ms
        return self._function_call_response(IOCTL_HELPER_QUERY_FUNCTION_CALL,req)

    def release_function_call(self,call_id):
        if not 0<call_id<=0xffffffffffffffff:raise ValueError('호출 ID 오류')
        req=RELEASE_FUNCTION_CALL_REQUEST();req.StructSize=ctypes.sizeof(req);req.Version=1;req.CallId=call_id
        return self._function_call_response(IOCTL_HELPER_RELEASE_FUNCTION_CALL,req)

    # 32. 0x80E: Register DLL (Injection / LDR Inspection)
    def register_dll(self, pid: int, dll_path_ansi: str) -> Dict[str, Any]:
        req = REGISTER_DLL_REQUEST()
        req.ProcessId = pid
        encoded=dll_path_ansi.encode('mbcs',errors='strict')
        if not encoded or len(encoded)>518 or b'\0' in encoded:raise ValueError('DLL 경로 형식 또는 길이 오류')
        req.DllPath = encoded + b"\x00"
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_REGISTER_DLL, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "target_is_wow64": bool(req.TargetIsWow64),
            "kernel32_found": bool(req.Kernel32Found),
            "load_library_found": bool(req.LoadLibraryFound),
            "kernel32_base": f"0x{req.Kernel32Base:X}",
            "kernel32_size": req.Kernel32Size,
            "load_library_address": f"0x{req.LoadLibraryAddress:X}"
        }

    # 33. 0x817: Event Monitor Control
    def event_monitor_control(self, enable_process: bool, enable_image: bool) -> Dict[str, Any]:
        # Notification callbacks were removed. Block enable requests here even
        # when an older binary is still loaded; disabling remains available.
        if enable_process or enable_image:
            return {"success": False, "error_code": 50, "result_status": "0xC00000BB",
                "process_monitor_active": False, "image_monitor_active": False,
                "message": "프로세스·이미지 알림 콜백은 제거되었습니다."}
        req = EVENT_MONITOR_CONTROL_REQUEST()
        req.EnableProcessMonitor = 1 if enable_process else 0
        req.EnableImageLoadMonitor = 1 if enable_image else 0
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_EVENT_MONITOR_CONTROL, req)
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "process_monitor_active": bool(req.ProcessMonitorActive),
            "image_monitor_active": bool(req.ImageMonitorActive)
        }

    # 34. 0x818: Poll Kernel Events
    def poll_events(self, max_events: int = 16) -> Dict[str, Any]:
        req = POLL_EVENTS_REQUEST()
        req.MaxEventsToRead = min(max_events, 16)
        ok, err, _ = self.send_ioctl(IOCTL_HELPER_POLL_EVENTS, req)
        count = min(req.EventsReturned, 16)
        events = []
        for i in range(count):
            ev = req.Events[i]
            event_type_str = "UNKNOWN"
            if ev.EventType == 1:
                event_type_str = "PROCESS_CREATE"
            elif ev.EventType == 2:
                event_type_str = "PROCESS_TERMINATE"
            elif ev.EventType == 3:
                event_type_str = "IMAGE_LOAD"

            events.append({
                "event_type": event_type_str,
                "raw_event_type": ev.EventType,
                "timestamp": ev.Timestamp,
                "process_id": ev.ProcessId,
                "parent_process_id": ev.ParentProcessId,
                "creating_thread_id": ev.CreatingThreadId,
                "image_base": f"0x{ev.ImageBase:X}",
                "image_size": ev.ImageSize,
                "image_name": ev.ImageName,
                "command_line": ev.CommandLine
            })
        return {
            "success": ok and req.ResultStatus >= 0,
            "error_code": err,
            "result_status": f"0x{req.ResultStatus & 0xFFFFFFFF:08X}",
            "events_returned": count,
            "events_remaining": req.EventsRemaining,
            "events": events
        }
