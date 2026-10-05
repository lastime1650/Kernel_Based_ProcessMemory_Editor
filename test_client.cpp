#include "driver_client.hpp"
#include <iostream>
#include <iomanip>

int main()
{
    std::wcout << L"=== SampleKernel1 Driver Test Client ===" << std::endl;
    KernelClient::DriverConnection driver;
    if (!driver.Open())
    {
        std::wcout << L"[!] Driver not loaded or cannot open \\\\.\\MyDriver (Expected if driver not running)" << std::endl;
        return 0;
    }

    std::wcout << L"[+] Successfully opened connection to driver!" << std::endl;

    KernelClient::DRIVER_STATUS_REQUEST status = {};
    if (driver.GetStatus(status))
    {
        std::wcout << L"[+] Driver Status: v" << status.MajorVersion << L"." << status.MinorVersion << L" Build " << status.BuildNumber << std::endl;
        std::wcout << L"[+] Total IOCTL Requests: " << status.TotalIoctlRequests << std::endl;
    }

    DWORD currentPid = GetCurrentProcessId();
    KernelClient::PROCESS_EXTENDED_INFO procInfo = {};
    if (driver.QueryProcessExtended(currentPid, procInfo))
    {
        std::wcout << L"[+] Process ID: " << procInfo.ProcessId << std::endl;
        std::wcout << L"[+] Parent PID: " << procInfo.ParentProcessId << std::endl;
        std::wcout << L"[+] PEB Address: 0x" << std::hex << procInfo.PebBaseAddress << std::dec << std::endl;
        std::wcout << L"[+] Image Name: " << procInfo.ImageFileName << std::endl;
        std::wcout << L"[+] Command Line: " << procInfo.CommandLine << std::endl;
        std::wcout << L"[+] Working Set Size: " << (procInfo.WorkingSetSize / 1024) << L" KB" << std::endl;
        std::wcout << L"[+] Handle Count: " << procInfo.HandleCount << std::endl;
        std::wcout << L"[+] Thread Count: " << procInfo.ThreadCount << std::endl;
    }

    std::vector<KernelClient::PROCESS_HANDLE_ENTRY> handles;
    if (driver.QueryProcessHandles(currentPid, handles, 64))
    {
        std::wcout << L"[+] Retrieved " << handles.size() << L" handles for process" << std::endl;
    }

    KernelClient::PROCESS_TOKEN_INFO tokenInfo = {};
    if (driver.QueryProcessToken(currentPid, tokenInfo))
    {
        std::wcout << L"[+] Token Elevation: " << (tokenInfo.IsElevated ? L"Elevated" : L"Non-Elevated") << std::endl;
        std::wcout << L"[+] Integrity Level: 0x" << std::hex << tokenInfo.IntegrityLevel << std::dec << std::endl;
    }

    DWORD currentTid = GetCurrentThreadId();
    KernelClient::THREAD_EXTENDED_INFO threadInfo = {};
    if (driver.QueryThreadInfo(currentTid, threadInfo))
    {
        std::wcout << L"[+] Thread ID: " << threadInfo.ThreadId << std::endl;
        std::wcout << L"[+] TEB Address: 0x" << std::hex << threadInfo.TebBaseAddress << std::dec << std::endl;
        std::wcout << L"[+] Win32 Start Address: 0x" << std::hex << threadInfo.Win32StartAddress << std::dec << std::endl;
        std::wcout << L"[+] Priority: " << threadInfo.Priority << L" (Base: " << threadInfo.BasePriority << L")" << std::endl;
    }

    return 0;
}
