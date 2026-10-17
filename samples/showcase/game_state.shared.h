#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>

// This is an owned, synthetic training process. Stable addresses last for one
// process lifetime. Re-read the manifest after launch and identify the instance
// with its PID plus creation/start key; ASLR may reuse addresses across instances.
namespace showcase {
constexpr uint32_t StateVersion = 1;
constexpr uint64_t ProbeSeed = 0x53484F5743415345ULL; // "SHOWCASE"
constexpr uint64_t PluginResult = 0x41535452ULL;      // "ASTR"

struct InventorySlot {
    uint32_t item_id;
    int32_t quantity;
    uint32_t rarity;
    float weight;
    char label[24];
};

struct PointerNode {
    uintptr_t next;
    uint64_t tag;
};

struct alignas(64) GameState {
    char marker[16]; // 41 53 54 45 52 46 41 4C 4C 2D 52 50 47 2D 30 31
    uint32_t schema_version;
    uint32_t struct_size;
    volatile LONG hp;
    volatile LONG mp;
    volatile LONG gold;
    volatile LONG xp;
    volatile LONG level;
    volatile LONG ammo;
    volatile LONG armor;
    float position_x;
    float position_y;
    char player_name[32];
    InventorySlot inventory[6];
    volatile LONG damage_events;
    volatile LONG loot_events;
    volatile LONG probe_events;
    volatile LONG plugin_pings;
    volatile LONG64 watch_value;
    uintptr_t pointer_chain_root;
    volatile LONG64 gold64;
    float mana_float;
    wchar_t player_name_utf16[32];
};

static_assert(sizeof(void*) == 8, "Build the showcase as x64.");
static_assert(sizeof(LONG) == 4);
static_assert(sizeof(InventorySlot) == 40);
static_assert(offsetof(GameState, hp) == 24);
static_assert(offsetof(GameState, gold) == 32);
static_assert(offsetof(GameState, position_x) == 52);
static_assert(offsetof(GameState, player_name) == 60);
static_assert(offsetof(GameState, inventory) == 92);
static_assert(offsetof(GameState, watch_value) == 352);
static_assert(offsetof(GameState, pointer_chain_root) == 360);
static_assert(offsetof(GameState, gold64) == 368);
static_assert(offsetof(GameState, mana_float) == 376);
static_assert(offsetof(GameState, player_name_utf16) == 380);
static_assert(sizeof(GameState) == 448);
} // namespace showcase

extern "C" __declspec(dllexport) showcase::GameState* WINAPI GameGetState();
// One integer argument, x64 Windows calling convention, DWORD result. An amount
// of 500 adds 500 synthetic gold. Values above 1,000,000 are rejected.
extern "C" __declspec(dllexport) DWORD WINAPI GameAddGold64(uint64_t amount);
extern "C" __declspec(dllexport) uint64_t WINAPI GameProbeRead(uint64_t salt);
extern "C" __declspec(dllexport) DWORD WINAPI GameProbeWrite(uint64_t amount);
extern "C" __declspec(dllexport) DWORD WINAPI GamePatchProbe(uint64_t value);
