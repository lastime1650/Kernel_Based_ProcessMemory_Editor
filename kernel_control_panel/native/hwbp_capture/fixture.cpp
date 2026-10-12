#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "capture_abi.hpp"
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

constexpr unsigned WorkerCount = 6;
alignas(64) volatile unsigned long long g_write_value = 100;
alignas(64) volatile unsigned long long g_readwrite_value = 200;
std::atomic<unsigned long long> g_execute_count{0}, g_write_count{0}, g_read_count{0};
std::atomic<unsigned> g_ready_count{0};
std::mutex g_mutex;
std::condition_variable g_wake, g_done;
unsigned g_generation = 0, g_completed = 0, g_mode = 0, g_iterations = 1;
bool g_exit = false;
DWORD g_thread_ids[WorkerCount]{};

extern "C" __declspec(noinline) unsigned long long ExecuteProbe(unsigned long long value) {
    g_execute_count.fetch_add(1, std::memory_order_relaxed);
    return value * 17 + 3;
}
extern "C" __declspec(noinline) void WriteProbe() {
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&g_write_value));
    g_write_count.fetch_add(1, std::memory_order_relaxed);
}
extern "C" __declspec(noinline) unsigned long long ReadWriteProbe() {
    const auto value = g_readwrite_value;
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&g_readwrite_value));
    g_read_count.fetch_add(1, std::memory_order_relaxed);
    return value;
}
void Worker(unsigned index) {
    g_thread_ids[index] = GetCurrentThreadId();
    g_ready_count.fetch_add(1);
    unsigned last_generation = 0;
    for (;;) {
        std::unique_lock<std::mutex> lock(g_mutex);
        g_wake.wait(lock, [&] { return g_exit || g_generation != last_generation; });
        if (g_exit) break;
        last_generation = g_generation;
        const unsigned mode = g_mode, iterations = g_iterations;
        lock.unlock();
        for (unsigned i = 0; i < iterations; ++i) {
            if (mode == 1 || mode == 4) ExecuteProbe(i + index);
            if (mode == 2 || mode == 4) WriteProbe();
            if (mode == 3 || mode == 4) ReadWriteProbe();
        }
        lock.lock();
        ++g_completed;
        g_done.notify_one();
    }
}
std::string Status() {
    std::ostringstream out;
    out << "{\"pid\":" << GetCurrentProcessId() << ",\"main_tid\":" << GetCurrentThreadId()
        << ",\"execute_address\":\"0x" << std::hex << reinterpret_cast<uintptr_t>(&ExecuteProbe)
        << "\",\"write_address\":\"0x" << reinterpret_cast<uintptr_t>(&g_write_value)
        << "\",\"readwrite_address\":\"0x" << reinterpret_cast<uintptr_t>(&g_readwrite_value)
        << "\",\"write_value\":" << std::dec << g_write_value
        << ",\"readwrite_value\":" << g_readwrite_value
        << ",\"execute_count\":" << g_execute_count.load()
        << ",\"write_count\":" << g_write_count.load()
        << ",\"readwrite_count\":" << g_read_count.load() << ",\"worker_tids\":[";
    for (unsigned i = 0; i < WorkerCount; ++i) { if (i) out << ','; out << g_thread_ids[i]; }
    out << "]}";
    return out.str();
}
int main(int argc, char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc > 1 && (std::string(argv[1]) == "--capture-unrelated-single-step" ||
        std::string(argv[1]) == "--capture-unrelated-access-violation")) {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        std::wstring dll_path(path);
        dll_path.erase(dll_path.find_last_of(L"\\/") + 1);
        dll_path += L"KernelStudioCapture.dll";
        const HMODULE dll = LoadLibraryW(dll_path.c_str());
        if (!dll) return 91;
        const auto start = reinterpret_cast<DWORD(WINAPI*)(void*)>(GetProcAddress(dll, "StartCapture"));
        if (!start) return 92;
        kshwbp::StartConfig config{};
        config.magic = kshwbp::ConfigMagic; config.abi_version = 1; config.struct_size = sizeof(config);
        if (start(&config)) return 93;
        const DWORD code = std::string(argv[1]) == "--capture-unrelated-single-step" ?
            EXCEPTION_SINGLE_STEP : EXCEPTION_ACCESS_VIOLATION;
        RaiseException(code, 0, 0, nullptr);
        return 99;
    }
    if (argc > 1 && std::string(argv[1]) == "--unhandled-single-step") {
        // No fixture VEH: this reproduces the termination of an unhandled #DB.
        RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, nullptr);
        return 99;
    }
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < WorkerCount; ++i) workers.emplace_back(Worker, i);
    while (g_ready_count.load() != WorkerCount) Sleep(1);
    if (argc > 1) { std::ofstream ready(argv[1]); ready << Status(); }
    std::cout << Status() << std::endl;
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        std::string command; unsigned iterations = 1;
        input >> command >> iterations;
        if (command == "exit") break;
        unsigned mode = command == "execute" ? 1 : command == "write" ? 2 :
            command == "readwrite" ? 3 : command == "burst" ? 4 : 0;
        if (mode) {
            if (iterations < 1) iterations = 1;
            if (iterations > 100000) iterations = 100000;
            std::unique_lock<std::mutex> lock(g_mutex);
            g_mode = mode; g_iterations = iterations; g_completed = 0; ++g_generation;
            g_wake.notify_all();
            g_done.wait(lock, [] { return g_completed == WorkerCount; });
        }
        std::cout << Status() << std::endl;
    }
    { std::lock_guard<std::mutex> lock(g_mutex); g_exit = true; }
    g_wake.notify_all();
    for (auto& thread : workers) thread.join();
    return 0;
}
