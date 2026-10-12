#pragma once
#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace kshwbp {
constexpr uint64_t RingMagic = 0x313050425748534BULL; // KSHWBP01
constexpr uint64_t ConfigMagic = 0x313030474643534BULL; // KSCFG001
constexpr uint32_t AbiVersion = 1;
constexpr uint32_t Capacity = 256;
constexpr uint32_t RawContextSize = 1232;
constexpr uint32_t FlagBreakpointsCleared = 1;

#pragma pack(push, 8)
struct Owner {
    uint64_t address;
    uint32_t type; // DR7 RW: 0 execute, 1 write, 3 read/write
    uint32_t size; // 1, 2, 4 or 8; execute must be 1
    uint32_t enabled;
    uint32_t reserved;
};
struct StartConfig {
    uint64_t magic;
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t owner_count;
    uint32_t flags;
    uint64_t reserved;
    Owner owners[4];
};
struct alignas(64) Header {
    uint64_t magic;
    uint32_t abi_version;
    uint32_t header_size;
    uint32_t slot_size;
    uint32_t capacity;
    uint32_t context_size;
    volatile LONG state; // 0 unregistered, 1 capturing, 3 guard only
    uint32_t process_id;
    uint32_t reserved0;
    uint64_t qpc_frequency;
    volatile LONG64 next_ticket;
    volatile LONG64 published_count;
    volatile LONG64 contention_dropped;
    volatile LONG64 overwritten_records;
    volatile LONG handlers_inflight;
    uint32_t owner_count;
    uint64_t reserved1;
    Owner owners[4];
    unsigned char reserved2[64];
};
struct alignas(64) Slot {
    volatile LONG64 guard_begin;
    uint64_t ticket;
    int64_t qpc;
    uint32_t process_id;
    uint32_t thread_id;
    uint32_t hit_mask;
    uint32_t execute_mask;
    uint64_t exception_address;
    uint32_t exception_code;
    uint32_t context_flags;
    uint32_t context_size;
    uint32_t reserved0;
    unsigned char raw_context[RawContextSize];
    volatile LONG64 guard_end;
    volatile LONG writer_lock;
    uint32_t reserved1;
    unsigned char padding[32];
};
struct alignas(64) Ring { Header header; Slot slots[Capacity]; };
#pragma pack(pop)
static_assert(sizeof(Owner) == 24);
static_assert(sizeof(StartConfig) == 128);
static_assert(sizeof(Header) == 256);
static_assert(sizeof(Slot) == 1344);
static_assert(sizeof(Ring) == 344320);
static_assert(offsetof(Header, next_ticket) == 48);
static_assert(offsetof(Header, owners) == 96);
static_assert(offsetof(Slot, raw_context) == 64);
static_assert(offsetof(Slot, guard_end) == 1296);
static_assert(sizeof(CONTEXT) == RawContextSize);
static_assert(offsetof(CONTEXT, ContextFlags) == 48);
static_assert(offsetof(CONTEXT, EFlags) == 68);
static_assert(offsetof(CONTEXT, Dr0) == 72);
static_assert(offsetof(CONTEXT, Rax) == 120);
static_assert(offsetof(CONTEXT, Rip) == 248);
}
