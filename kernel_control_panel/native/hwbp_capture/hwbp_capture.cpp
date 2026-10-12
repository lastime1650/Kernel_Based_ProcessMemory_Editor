#define WIN32_LEAN_AND_MEAN
#include "capture_abi.hpp"
#include <cstring>

namespace {
using namespace kshwbp;
alignas(64) Ring g_ring{};
// Published records never change. Retaining old ownership avoids a queued #DB
// becoming unhandled while a control call changes the capture configuration.
constexpr LONG MaxHistoricalOwners = 1024;
Owner g_owner_history[MaxHistoricalOwners]{};
volatile LONG g_history_count = 0;
SRWLOCK g_control_lock = SRWLOCK_INIT;
PVOID g_handler = nullptr;
bool g_initialized = false;

LONG ReadState() { return InterlockedCompareExchange(&g_ring.header.state, 0, 0); }
bool SameOwner(const Owner& a, const Owner& b) {
    return a.address == b.address && a.type == b.type && a.size == b.size;
}
bool ValidOwner(const Owner& o) {
    if (!o.enabled || o.reserved || !o.address || o.address > 0x00007FFFFFFFFFFFULL)
        return false;
    if (o.type == 0) return o.size == 1;
    if (o.type != 1 && o.type != 3) return false;
    if (o.size != 1 && o.size != 2 && o.size != 4 && o.size != 8) return false;
    return (o.address & (o.size - 1)) == 0;
}
uint32_t DrLength(uint64_t dr7, unsigned slot) {
    constexpr uint32_t lengths[4] = { 1, 2, 8, 4 };
    return lengths[(dr7 >> (18 + slot * 4)) & 3];
}
void Publish(PEXCEPTION_POINTERS ep, uint32_t hit, uint32_t execute) {
    const LONG64 ticket = InterlockedIncrement64(&g_ring.header.next_ticket);
    Slot& slot = g_ring.slots[(static_cast<uint64_t>(ticket) - 1) % Capacity];
    if (InterlockedCompareExchange(&slot.writer_lock, 1, 0) != 0) {
        InterlockedIncrement64(&g_ring.header.contention_dropped);
        return; // Never spin, wait, allocate, signal or perform I/O in VEH.
    }
    // A later ticket can reach this slot before an earlier preempted writer.
    if (slot.ticket >= static_cast<uint64_t>(ticket)) {
        InterlockedIncrement64(&g_ring.header.contention_dropped);
        InterlockedExchange(&slot.writer_lock, 0);
        return;
    }
    const bool replaces = slot.ticket != 0;
    const LONG64 even = ticket * 2;
    InterlockedExchange64(&slot.guard_end, even + 1);
    InterlockedExchange64(&slot.guard_begin, even + 1);
    slot.ticket = static_cast<uint64_t>(ticket);
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);
    slot.qpc = qpc.QuadPart;
    slot.process_id = g_ring.header.process_id;
    slot.thread_id = GetCurrentThreadId();
    slot.hit_mask = hit;
    slot.execute_mask = execute;
    slot.exception_address = reinterpret_cast<uint64_t>(ep->ExceptionRecord->ExceptionAddress);
    slot.exception_code = ep->ExceptionRecord->ExceptionCode;
    slot.context_flags = ep->ContextRecord->ContextFlags;
    slot.context_size = sizeof(CONTEXT);
    std::memcpy(slot.raw_context, ep->ContextRecord, sizeof(CONTEXT));
    InterlockedExchange64(&slot.guard_end, even);
    InterlockedExchange64(&slot.guard_begin, even);
    InterlockedExchange(&slot.writer_lock, 0);
    if (replaces) InterlockedIncrement64(&g_ring.header.overwritten_records);
    InterlockedIncrement64(&g_ring.header.published_count);
}
LONG CALLBACK CaptureHandler(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord ||
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&g_ring.header.handlers_inflight);
    CONTEXT& c = *ep->ContextRecord;
    const uint32_t hit = static_cast<uint32_t>(c.Dr6 & 0xF);
    // BD/BS/BT, trap-flag stepping, and another handler's slot stay untouched.
    if (!hit || (c.Dr6 & 0xE000) || (c.EFlags & 0x100)) {
        InterlockedDecrement(&g_ring.header.handlers_inflight);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const uint64_t addresses[4] = { c.Dr0, c.Dr1, c.Dr2, c.Dr3 };
    const LONG count = InterlockedCompareExchange(&g_history_count, 0, 0);
    uint32_t owned = 0, execute = 0;
    for (unsigned slot = 0; slot < 4; ++slot) {
        const uint32_t bit = 1u << slot;
        if (!(hit & bit) || !(c.Dr7 & (3ULL << (slot * 2)))) continue;
        const uint32_t type = static_cast<uint32_t>((c.Dr7 >> (16 + slot * 4)) & 3);
        const uint32_t length = DrLength(c.Dr7, slot);
        for (LONG i = 0; i < count; ++i) {
            const Owner& owner = g_owner_history[i];
            if (owner.address == addresses[slot] && owner.type == type && owner.size == length) {
                owned |= bit;
                if (type == 0) execute |= bit;
                break;
            }
        }
    }
    if (owned != hit) {
        InterlockedDecrement(&g_ring.header.handlers_inflight);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Preserve the exact Windows CONTEXT before RF/DR6 resumption changes.
    if (ReadState() == 1) Publish(ep, owned, execute);
    if (execute) c.EFlags |= 0x10000;
    c.Dr6 &= ~static_cast<uint64_t>(owned);
    InterlockedDecrement(&g_ring.header.handlers_inflight);
    return EXCEPTION_CONTINUE_EXECUTION;
}
DWORD ReadConfig(void* parameter, StartConfig& config) {
    if (!parameter) return ERROR_INVALID_PARAMETER;
    __try { std::memcpy(&config, parameter, sizeof(config)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return ERROR_NOACCESS; }
    if (config.magic != ConfigMagic || config.abi_version != AbiVersion ||
        config.struct_size != sizeof(config) || config.owner_count > 4 ||
        config.reserved || (config.flags & ~FlagBreakpointsCleared))
        return ERROR_INVALID_PARAMETER;
    for (uint32_t i = 0; i < config.owner_count; ++i)
        if (!ValidOwner(config.owners[i])) return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}
}

extern "C" __declspec(dllexport) DWORD WINAPI GetCaptureAbiVersion(void*) { return kshwbp::AbiVersion; }
extern "C" __declspec(dllexport) DWORD WINAPI GetCaptureBuffer(void* output_address) {
    if (!output_address) return ERROR_INVALID_PARAMETER;
    __try { *static_cast<uint64_t*>(output_address) = reinterpret_cast<uint64_t>(&g_ring); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return ERROR_NOACCESS; }
    return ERROR_SUCCESS;
}
extern "C" __declspec(dllexport) DWORD WINAPI StartCapture(void* parameter) {
    StartConfig config{};
    DWORD error = ReadConfig(parameter, config);
    if (error || config.flags) return error ? error : ERROR_INVALID_PARAMETER;
    AcquireSRWLockExclusive(&g_control_lock);
    LONG history_count = InterlockedCompareExchange(&g_history_count, 0, 0);
    Owner additions[4]{};
    LONG add_count = 0;
    for (uint32_t i = 0; i < config.owner_count; ++i) {
        bool found = false;
        for (LONG j = 0; j < history_count; ++j) found |= SameOwner(config.owners[i], g_owner_history[j]);
        for (LONG j = 0; j < add_count; ++j) found |= SameOwner(config.owners[i], additions[j]);
        if (!found) additions[add_count++] = config.owners[i];
    }
    if (history_count + add_count > MaxHistoricalOwners) error = ERROR_TOO_MANY_CMDS;
    if (!error && !g_initialized) {
        LARGE_INTEGER frequency{};
        if (!QueryPerformanceFrequency(&frequency)) error = ERROR_NOT_SUPPORTED;
        else {
            g_ring.header.magic = RingMagic;
            g_ring.header.abi_version = AbiVersion;
            g_ring.header.header_size = sizeof(Header);
            g_ring.header.slot_size = sizeof(Slot);
            g_ring.header.capacity = Capacity;
            g_ring.header.context_size = sizeof(CONTEXT);
            g_ring.header.process_id = GetCurrentProcessId();
            g_ring.header.qpc_frequency = frequency.QuadPart;
            g_initialized = true;
        }
    }
    if (!error && !g_handler) {
        // Register and pin outside DllMain: no loader-lock work or unsafe DLL unload.
        HMODULE pinned{};
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&StartCapture), &pinned)) error = GetLastError();
        else {
            g_handler = AddVectoredExceptionHandler(1, CaptureHandler);
            if (!g_handler) error = ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    if (!error) {
        for (LONG i = 0; i < add_count; ++i) g_owner_history[history_count + i] = additions[i];
        InterlockedExchange(&g_history_count, history_count + add_count);
        g_ring.header.owner_count = config.owner_count;
        std::memcpy(g_ring.header.owners, config.owners, sizeof(config.owners));
        InterlockedExchange(&g_ring.header.state, 1);
    }
    ReleaseSRWLockExclusive(&g_control_lock);
    return error;
}
extern "C" __declspec(dllexport) DWORD WINAPI StopCapture(void*) {
    AcquireSRWLockExclusive(&g_control_lock);
    DWORD error = g_handler ? ERROR_SUCCESS : ERROR_NOT_READY;
    if (!error) InterlockedExchange(&g_ring.header.state, 3);
    ReleaseSRWLockExclusive(&g_control_lock);
    return error;
}
extern "C" __declspec(dllexport) DWORD WINAPI ShutdownCapture(void* parameter) {
    StartConfig config{};
    DWORD error = ReadConfig(parameter, config);
    if (error || config.flags != FlagBreakpointsCleared || config.owner_count)
        return error ? error : ERROR_INVALID_PARAMETER;
    AcquireSRWLockExclusive(&g_control_lock);
    if (g_handler) {
        InterlockedExchange(&g_ring.header.state, 3);
        if (!RemoveVectoredExceptionHandler(g_handler)) error = ERROR_GEN_FAILURE;
        else { g_handler = nullptr; InterlockedExchange(&g_ring.header.state, 0); }
    }
    ReleaseSRWLockExclusive(&g_control_lock);
    // Static ring, pinned code, immutable historical whitelist remain valid
    // even if a callback was already dispatched when removal occurred.
    return error;
}
#ifndef KSHWBP_TEST
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    // /MT CRT still needs normal thread notifications. Keep loader entry empty.
    return TRUE;
}
#endif
