#define KSHWBP_TEST
#include "hwbp_capture.cpp"
#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } ++checks; } while (0)

int main() {
    unsigned checks = 0;
    StartConfig config{};
    config.magic = ConfigMagic; config.abi_version = 1; config.struct_size = sizeof(config);
    CHECK(StartCapture(&config) == ERROR_SUCCESS);
    CHECK(g_ring.header.state == 1);
    uint64_t out = 0;
    CHECK(GetCaptureBuffer(&out) == 0 && out == reinterpret_cast<uint64_t>(&g_ring));
    CHECK(GetCaptureBuffer(nullptr) == ERROR_INVALID_PARAMETER);
    CHECK(StartCapture(nullptr) == ERROR_INVALID_PARAMETER);
    config.owner_count = 3;
    config.owners[0] = { 0x100000, 0, 1, 1, 0 };
    config.owners[1] = { 0x200000, 1, 8, 1, 0 };
    config.owners[2] = { 0x300000, 3, 4, 1, 0 };
    CHECK(StartCapture(&config) == 0);
    CONTEXT context{};
    context.ContextFlags = CONTEXT_ALL;
    context.Rax = 0x1122334455667788;
    context.R12 = 0xAABBCCDDEEFF0011;
    context.Rip = 0x100000;
    context.Dr0 = 0x100000; context.Dr1 = 0x200000; context.Dr2 = 0x300000;
    context.Dr6 = 1; context.Dr7 = 1 | 4 | 16 | (9ULL << 20) | (15ULL << 24);
    context.EFlags = 0x202;
    EXCEPTION_RECORD record{};
    record.ExceptionCode = EXCEPTION_SINGLE_STEP;
    record.ExceptionAddress = reinterpret_cast<void*>(context.Rip);
    EXCEPTION_POINTERS ep{ &record, &context };
    const CONTEXT original = context;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_EXECUTION);
    CHECK(context.EFlags == (original.EFlags | 0x10000));
    CHECK(context.Dr6 == 0);
    CHECK(std::memcmp(g_ring.slots[0].raw_context, &original, sizeof(original)) == 0);
    CHECK(g_ring.slots[0].guard_begin == 2 && g_ring.slots[0].guard_end == 2);
    CHECK(g_ring.slots[0].hit_mask == 1 && g_ring.slots[0].execute_mask == 1);
    context = original; context.Dr6 = 2;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_EXECUTION);
    CHECK(context.EFlags == original.EFlags && context.Dr6 == 0);
    context = original; context.Dr6 = 4;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_EXECUTION);
    context = original; context.Dr6 = 8;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_SEARCH && context.Dr6 == 8);
    context = original; context.Dr0 = 0x400000;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_SEARCH);
    context = original; context.Dr7 = 0;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_SEARCH);
    context = original; context.EFlags |= 0x100;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_SEARCH);
    context = original; context.Dr6 |= 0x4000;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_SEARCH);
    record.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_SEARCH);
    record.ExceptionCode = EXCEPTION_SINGLE_STEP;
    CHECK(CaptureHandler(nullptr) == EXCEPTION_CONTINUE_SEARCH);
    CHECK(StopCapture(nullptr) == 0 && g_ring.header.state == 3);
    const LONG64 before = g_ring.header.published_count;
    context = original;
    CHECK(CaptureHandler(&ep) == EXCEPTION_CONTINUE_EXECUTION);
    CHECK(g_ring.header.published_count == before);
    CHECK(StartCapture(&config) == 0);
    std::atomic<bool> stable{true};
    std::vector<std::thread> writers;
    for (unsigned n = 0; n < 8; ++n) writers.emplace_back([&, n] {
        for (unsigned i = 0; i < 20000; ++i) {
            CONTEXT c = original; c.Rax = (static_cast<uint64_t>(n) << 32) | i;
            EXCEPTION_POINTERS e{ &record, &c };
            if (CaptureHandler(&e) != EXCEPTION_CONTINUE_EXECUTION) stable = false;
        }
    });
    for (auto& thread : writers) thread.join();
    CHECK(stable.load());
    CHECK(g_ring.header.next_ticket == 160003);
    CHECK(g_ring.header.published_count + g_ring.header.contention_dropped == g_ring.header.next_ticket);
    CHECK(g_ring.header.handlers_inflight == 0);
    for (const auto& slot : g_ring.slots) {
        CHECK(slot.guard_begin == slot.guard_end && !(slot.guard_begin & 1));
        CHECK(slot.guard_begin == static_cast<LONG64>(slot.ticket * 2));
        CHECK(slot.writer_lock == 0 && slot.context_size == sizeof(CONTEXT));
    }
    config.owner_count = 0; config.flags = FlagBreakpointsCleared;
    CHECK(ShutdownCapture(&config) == 0 && g_ring.header.state == 0);
    CHECK(StopCapture(nullptr) == ERROR_NOT_READY);
    std::printf("PASS %u checks; published=%lld contention=%lld overwritten=%lld\n", checks,
        g_ring.header.published_count, g_ring.header.contention_dropped, g_ring.header.overwritten_records);
    return 0;
}
