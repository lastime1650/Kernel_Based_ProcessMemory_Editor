#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include "game_state.shared.h"

namespace {
constexpr int ClientWidth = 1180;
constexpr int ClientHeight = 780;
constexpr COLORREF Background = RGB(9, 15, 24);
constexpr COLORREF Surface = RGB(16, 27, 39);
constexpr COLORREF Border = RGB(39, 62, 77);
constexpr COLORREF Text = RGB(223, 235, 239);
constexpr COLORREF Muted = RGB(128, 157, 170);
constexpr COLORREF Teal = RGB(62, 218, 187);
constexpr COLORREF Gold = RGB(241, 196, 98);
constexpr COLORREF Red = RGB(242, 112, 123);
constexpr COLORREF Blue = RGB(103, 170, 241);
constexpr UINT_PTR TimerId = 1;
constexpr int ButtonDamage = 100;
constexpr int ButtonLoot = 101;
constexpr int ButtonHeal = 102;
constexpr int ButtonProbe = 103;
constexpr int ButtonPause = 104;
constexpr int ButtonReset = 105;
constexpr int ButtonPlugin = 106;

alignas(64) showcase::GameState g_state{};
showcase::PointerNode g_pointer_node1{};
showcase::PointerNode g_pointer_node2{};
HWND g_window = nullptr;
HANDLE g_stop_event = nullptr;
std::array<HANDLE, 3> g_workers{};
std::array<DWORD, 3> g_worker_ids{};
DWORD g_main_tid = 0;
bool g_paused = false;
unsigned g_frame = 0;
uint64_t g_last_probe = 0;
DWORD g_patch_result = 0;
HMODULE g_plugin = nullptr;
DWORD g_plugin_result = 0;
std::wstring g_executable_path;
std::wstring g_manifest_path;
std::wstring g_event_text = L"Welcome to the training shard. Your process, your adventure.";
HFONT g_font_title = nullptr;
HFONT g_font_heading = nullptr;
HFONT g_font_body = nullptr;
HFONT g_font_small = nullptr;
HFONT g_font_mono = nullptr;
HFONT g_font_value = nullptr;

std::wstring Hex(uintptr_t value) {
    wchar_t result[32]{};
    swprintf_s(result, L"0x%016llX", static_cast<unsigned long long>(value));
    return result;
}

std::wstring Number(LONG value) {
    wchar_t result[32]{};
    swprintf_s(result, L"%ld", value);
    return result;
}

std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        result.data(), size, nullptr, nullptr);
    return result;
}

std::string JsonQuoted(const std::wstring& value) {
    std::string result = "\"";
    for (const char ch : Utf8(value)) {
        if (ch == '\\' || ch == '"') result += '\\';
        result += ch;
    }
    return result + '"';
}

std::wstring SiblingPath(const wchar_t* name) {
    return g_executable_path.substr(0, g_executable_path.find_last_of(L"\\/") + 1) + name;
}

void WriteManifest() {
    if (g_manifest_path.empty()) return;
    FILETIME created{}, exited{}, kernel{}, user{};
    GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user);
    const uint64_t creation = (static_cast<uint64_t>(created.dwHighDateTime) << 32)
        | created.dwLowDateTime;
    std::ostringstream output;
    const auto address = [](const void* value) {
        std::ostringstream text;
        text << "\"0x" << std::uppercase << std::hex << reinterpret_cast<uintptr_t>(value) << '"';
        return text.str();
    };
    const auto field = [&](const char* name, const volatile void* value, bool comma = true) {
        output << "      \"" << name << "\": "
            << address(const_cast<const void*>(value)) << (comma ? ",\n" : "\n");
    };
    output << "{\n  \"fixture\": \"Asterfall owned synthetic RPG\",\n"
        << "  \"schema_version\": 1,\n  \"pid\": " << GetCurrentProcessId()
        << ",\n  \"main_tid\": " << g_main_tid
        << ",\n  \"dedicated_worker_tid\": " << g_worker_ids[0]
        << ",\n  \"worker_tids\": [" << g_worker_ids[0] << ',' << g_worker_ids[1] << ',' << g_worker_ids[2]
        << "],\n  \"process_creation_filetime\": \"" << creation << "\",\n"
        << "  \"executable_path\": " << JsonQuoted(g_executable_path) << ",\n"
        << "  \"module_base\": " << address(GetModuleHandleW(nullptr)) << ",\n"
        << "  \"fixture_dll_path\": " << JsonQuoted(SiblingPath(L"ShowcasePlugin.dll")) << ",\n"
        << "  \"fixture_pdb_path\": " << JsonQuoted(SiblingPath(L"Asterfall.pdb")) << ",\n"
        << "  \"plugin_pdb_path\": " << JsonQuoted(SiblingPath(L"ShowcasePlugin.pdb")) << ",\n"
        << "  \"state\": {\n    \"address\": " << address(&g_state)
        << ",\n    \"size\": " << sizeof(g_state)
        << ",\n    \"marker_hex\": \"41 53 54 45 52 46 41 4C 4C 2D 52 50 47 2D 30 31\",\n"
        << "    \"fields\": {\n";
    field("hp", &g_state.hp); field("health", &g_state.hp); field("mp", &g_state.mp); field("gold", &g_state.gold);
    field("xp", &g_state.xp); field("level", &g_state.level); field("ammo", &g_state.ammo);
    field("armor", &g_state.armor); field("position_x", &g_state.position_x);
    field("position_y", &g_state.position_y); field("player_name", &g_state.player_name);
    field("inventory", &g_state.inventory); field("watch_value", &g_state.watch_value);
    field("gold64", &g_state.gold64); field("mana_float", &g_state.mana_float);
    field("player_name_utf16", &g_state.player_name_utf16);
    field("pointer_chain_root", &g_state.pointer_chain_root, false);
    output << "    }\n  },\n  \"pointer_chain\": {\"root_slot\": "
        << address(&g_state.pointer_chain_root) << ", \"node1\": " << address(&g_pointer_node1)
        << ", \"node2\": " << address(&g_pointer_node2) << ", \"target\": "
        << address(const_cast<const LONG*>(&g_state.gold)) << ", \"offsets\": [0,0,0]},\n"
        << "  \"writable_spans\": [{\"address\": " << address(&g_state)
        << ", \"size\": " << sizeof(g_state) << "}],\n"
        << "  \"readable_spans\": [{\"address\": " << address(&g_state)
        << ", \"size\": " << sizeof(g_state) << "}, {\"address\": " << address(&g_pointer_node1)
        << ", \"size\": " << sizeof(g_pointer_node1) << "}, {\"address\": "
        << address(&g_pointer_node2) << ", \"size\": " << sizeof(g_pointer_node2) << "}],\n"
        << "  \"exports\": {\n";
    field("GameGetState", reinterpret_cast<const void*>(&GameGetState));
    field("GameAddGold64", reinterpret_cast<const void*>(&GameAddGold64));
    field("GameProbeRead", reinterpret_cast<const void*>(&GameProbeRead));
    field("GameProbeWrite", reinterpret_cast<const void*>(&GameProbeWrite));
    field("GamePatchProbe", reinterpret_cast<const void*>(&GamePatchProbe), false);
    output << "  },\n  \"probe_write_size\": 8,\n"
        << "  \"code_patch_target\": " << address(reinterpret_cast<const void*>(&GamePatchProbe)) << "\n}\n";
    HANDLE file = CreateFileW(g_manifest_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    const std::string bytes = output.str();
    DWORD written = 0;
    WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    CloseHandle(file);
}

void ResetState() {
    constexpr char marker[16] = {'A','S','T','E','R','F','A','L','L','-','R','P','G','-','0','1'};
    memcpy(g_state.marker, marker, sizeof(marker));
    g_state.schema_version = showcase::StateVersion;
    g_state.struct_size = sizeof(g_state);
    g_state.hp = 100; g_state.mp = 80; g_state.gold = 1337; g_state.xp = 420;
    g_state.level = 7; g_state.ammo = 30; g_state.armor = 25;
    g_state.position_x = 4.25f; g_state.position_y = 2.50f;
    strcpy_s(g_state.player_name, "Nyx Copperfield");
    const showcase::InventorySlot items[6] = {
        {1001, 3, 1, 0.50f, "Health potion"}, {1002, 2, 2, 0.25f, "Mana crystal"},
        {2001, 1, 3, 2.75f, "Glasskeep key"}, {2002, 12, 1, 0.10f, "Silver arrows"},
        {3001, 1, 4, 3.25f, "Moonsteel sword"}, {3002, 5, 2, 0.05f, "Ancient coins"}
    };
    memcpy(g_state.inventory, items, sizeof(items));
    g_state.damage_events = 0; g_state.loot_events = 0; g_state.probe_events = 0;
    g_state.plugin_pings = 0; g_state.watch_value = static_cast<LONG64>(showcase::ProbeSeed);
    g_pointer_node2.next = reinterpret_cast<uintptr_t>(&g_state.gold);
    g_pointer_node2.tag = 0x4C494E4B3032ULL;
    g_pointer_node1.next = reinterpret_cast<uintptr_t>(&g_pointer_node2);
    g_pointer_node1.tag = 0x4C494E4B3031ULL;
    g_state.pointer_chain_root = reinterpret_cast<uintptr_t>(&g_pointer_node1);
    g_state.gold64 = 1337;
    g_state.mana_float = 80.0f;
    wcscpy_s(g_state.player_name_utf16, L"Nyx Copperfield");
    g_last_probe = 0;
    g_patch_result = 0;
}

DWORD WINAPI IdleWorker(void*) {
    WaitForSingleObject(g_stop_event, INFINITE);
    return 0;
}

HFONT Font(int height, int weight, const wchar_t* family) {
    return CreateFontW(-height, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, family);
}

void Fill(HDC dc, const RECT& rect, COLORREF color) {
    const HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, &rect, brush);
    DeleteObject(brush);
}

void RoundBox(HDC dc, int x, int y, int width, int height, COLORREF color,
    COLORREF stroke = Border, int radius = 12) {
    const HBRUSH brush = CreateSolidBrush(color);
    const HPEN pen = CreatePen(PS_SOLID, 1, stroke);
    const HGDIOBJ old_brush = SelectObject(dc, brush);
    const HGDIOBJ old_pen = SelectObject(dc, pen);
    RoundRect(dc, x, y, x + width, y + height, radius, radius);
    SelectObject(dc, old_pen); SelectObject(dc, old_brush);
    DeleteObject(pen); DeleteObject(brush);
}

void DrawLabel(HDC dc, int x, int y, const std::wstring& text, HFONT font,
    COLORREF color = Text) {
    const HGDIOBJ old = SelectObject(dc, font);
    SetTextColor(dc, color);
    SetBkMode(dc, TRANSPARENT);
    TextOutW(dc, x, y, text.c_str(), static_cast<int>(text.size()));
    SelectObject(dc, old);
}

void Line(HDC dc, int x1, int y1, int x2, int y2, COLORREF color, int width = 1) {
    const HPEN pen = CreatePen(PS_SOLID, width, color);
    const HGDIOBJ old = SelectObject(dc, pen);
    MoveToEx(dc, x1, y1, nullptr); LineTo(dc, x2, y2);
    SelectObject(dc, old); DeleteObject(pen);
}

void Circle(HDC dc, int x, int y, int radius, COLORREF fill, COLORREF stroke) {
    const HBRUSH brush = CreateSolidBrush(fill);
    const HPEN pen = CreatePen(PS_SOLID, 2, stroke);
    const HGDIOBJ old_brush = SelectObject(dc, brush);
    const HGDIOBJ old_pen = SelectObject(dc, pen);
    Ellipse(dc, x-radius, y-radius, x+radius, y+radius);
    SelectObject(dc, old_pen); SelectObject(dc, old_brush);
    DeleteObject(pen); DeleteObject(brush);
}

void StatCard(HDC dc, int x, const wchar_t* title, LONG value,
    const wchar_t* suffix, COLORREF accent, LONG maximum = 0) {
    RoundBox(dc, x, 105, 173, 84, Surface);
    DrawLabel(dc, x+15, 118, title, g_font_small, Muted);
    DrawLabel(dc, x+15, 139, Number(value), g_font_value, accent);
    DrawLabel(dc, x+106, 153, suffix, g_font_small, Muted);
    if (maximum > 0) {
        const int bar = static_cast<int>(std::clamp(value, 0L, maximum) * 141 / maximum);
        Fill(dc, RECT{x+15, 180, x+156, 183}, Border);
        Fill(dc, RECT{x+15, 180, x+15+bar, 183}, accent);
    }
}

void DrawDungeon(HDC dc) {
    RoundBox(dc, 28, 205, 734, 390, Surface);
    DrawLabel(dc, 48, 219, L"THE GLASSKEEP", g_font_heading);
    DrawLabel(dc, 561, 226, L"FLOOR 07  /  TRAINING", g_font_small, Gold);
    constexpr int origin_x = 44, origin_y = 256, tile_w = 63, tile_h = 57;
    for (int row = 0; row < 5; ++row) {
        for (int col = 0; col < 11; ++col) {
            const bool wall = (row == 0 && col < 3) || (col == 10 && row > 1)
                || (row == 3 && (col == 2 || col == 7));
            const int x = origin_x + col * tile_w;
            const int y = origin_y + row * tile_h;
            const COLORREF tile_color = wall ? RGB(33, 48, 63) :
                ((row+col)%2 ? RGB(22, 35, 46) : RGB(20, 32, 43));
            RoundBox(dc, x+2, y+2, tile_w-5, tile_h-5, tile_color,
                wall ? RGB(52, 74, 88) : RGB(29, 47, 58), 5);
            if (wall) {
                Line(dc, x+11, y+23, x+50, y+23, RGB(56, 74, 87));
                Line(dc, x+31, y+8, x+31, y+23, RGB(56, 74, 87));
                Line(dc, x+20, y+24, x+20, y+45, RGB(56, 74, 87));
            } else if ((row*11+col)%13 == 0) {
                DrawLabel(dc, x+24, y+19, L"+", g_font_body, RGB(61, 83, 87));
            }
        }
    }
    // Synthetic NPCs and loot are drawn with GDI; no downloaded art is used.
    const int bob = g_paused ? 0 : static_cast<int>((g_frame/6)%3)-1;
    const int player_col = static_cast<int>(std::clamp(g_state.position_x, 0.0f, 9.0f));
    const int player_row = static_cast<int>(std::clamp(g_state.position_y, 0.0f, 4.0f));
    const int px = origin_x + player_col*tile_w + 31;
    const int py = origin_y + player_row*tile_h + 27;
    Circle(dc, px, py+2, 21, RGB(29, 75, 72), RGB(62, 118, 107));
    Circle(dc, px, py-5+bob, 8, RGB(241, 211, 173), Gold);
    RoundBox(dc, px-11, py+3+bob, 22, 20, RGB(39, 155, 139), Teal, 5);
    Line(dc, px+16, py-6+bob, px+16, py+22+bob, Gold, 3);
    DrawLabel(dc, px-28, py+28, L"YOU", g_font_small, Teal);
    for (const POINT location : {POINT{7,1}, POINT{1,4}, POINT{8,3}}) {
        const int mx = origin_x + location.x*tile_w + 31;
        const int my = origin_y + location.y*tile_h + 26;
        Circle(dc, mx, my+bob, 14, RGB(84, 37, 52), Red);
        Line(dc, mx-8, my-15+bob, mx-13, my-23+bob, Red, 2);
        Line(dc, mx+8, my-15+bob, mx+13, my-23+bob, Red, 2);
        Circle(dc, mx-5, my-2+bob, 2, Gold, Gold);
        Circle(dc, mx+5, my-2+bob, 2, Gold, Gold);
    }
    for (const POINT location : {POINT{8,0}, POINT{3,4}}) {
        const int tx = origin_x + location.x*tile_w + 17;
        const int ty = origin_y + location.y*tile_h + 17;
        RoundBox(dc, tx, ty, 30, 24, RGB(85, 65, 33), Gold, 5);
        Line(dc, tx, ty+9, tx+30, ty+9, Gold, 2);
        Fill(dc, RECT{tx+13,ty+8,tx+17,ty+15}, Gold);
    }
    DrawLabel(dc, 49, 558, L"WASD / arrows: move     |     Monsters have a union. Please be polite.",
        g_font_small, Muted);
}

void DrawInspector(HDC dc) {
    RoundBox(dc, 782, 105, 370, 630, Surface, RGB(46, 107, 104));
    DrawLabel(dc, 802, 120, L"MEMORY INSPECTOR", g_font_heading, Teal);
    DrawLabel(dc, 802, 149, L"OWNED TEST FIXTURE  /  LIVE ADDRESSES", g_font_small, Muted);
    Line(dc, 803, 175, 1131, 175, Border);
    int y = 188;
    const auto address_row = [&](const wchar_t* name, const volatile void* value) {
        DrawLabel(dc, 802, y, name, g_font_mono, Muted);
        DrawLabel(dc, 924, y, Hex(reinterpret_cast<uintptr_t>(value)), g_font_mono);
        y += 20;
    };
    DrawLabel(dc, 802, y, L"PID / TID", g_font_mono, Muted);
    DrawLabel(dc, 924, y, Number(static_cast<LONG>(GetCurrentProcessId())) + L" / "
        + Number(static_cast<LONG>(g_main_tid)), g_font_mono, Gold);
    y += 28;
    address_row(L"State / AoB", &g_state);
    address_row(L"HP : i32", &g_state.hp);
    address_row(L"MP : i32", &g_state.mp);
    address_row(L"Mana : float", &g_state.mana_float);
    address_row(L"Gold : i32", &g_state.gold);
    address_row(L"Wallet : i64", &g_state.gold64);
    address_row(L"XP : i32", &g_state.xp);
    address_row(L"Ammo : i32", &g_state.ammo);
    address_row(L"X : float", &g_state.position_x);
    address_row(L"Y : float", &g_state.position_y);
    address_row(L"Name : ASCII", &g_state.player_name);
    address_row(L"Name : UTF16", &g_state.player_name_utf16);
    address_row(L"Inventory[6]", &g_state.inventory);
    address_row(L"Root slot", &g_state.pointer_chain_root);
    address_row(L"Watch : u64", &g_state.watch_value);
    address_row(L"Read probe", reinterpret_cast<const void*>(&GameProbeRead));
    address_row(L"Write probe", reinterpret_cast<const void*>(&GameProbeWrite));
    address_row(L"AddGold64", reinterpret_cast<const void*>(&GameAddGold64));
    address_row(L"Patch probe", reinterpret_cast<const void*>(&GamePatchProbe));
    Line(dc, 803, y+5, 1131, y+5, Border);
    y += 18;
    DrawLabel(dc, 802, y, L"PTR  root -> node -> node -> Gold", g_font_mono, Teal);
    DrawLabel(dc, 802, y+22, L"AoB  ASCII: ASTERFALL-RPG-01", g_font_mono, Muted);
    DrawLabel(dc, 802, y+44, L"Exports + PDB included. No real game data.", g_font_small, Muted);
}

void DrawFrame(HDC dc) {
    Fill(dc, RECT{0,0,ClientWidth,ClientHeight}, Background);
    DrawLabel(dc, 28, 19, L"ASTERFALL", g_font_title, Text);
    DrawLabel(dc, 30, 65, L"THE MEMORY FORGE  /  A PLAYABLE KERNEL STUDIO SHOWCASE", g_font_small, Muted);
    RoundBox(dc, 902, 25, 250, 49, RGB(16,43,43), RGB(39,103,95));
    DrawLabel(dc, 918, 34, L"LOCAL SANDBOX", g_font_body, Teal);
    DrawLabel(dc, 918, 55, L"SYNTHETIC DATA  ·  x64", g_font_small, Muted);
    StatCard(dc, 28, L"HEALTH", g_state.hp, L"/ 100", Red, 100);
    StatCard(dc, 215, L"MANA", g_state.mp, L"/ 80", Blue, 80);
    StatCard(dc, 402, L"GOLD", g_state.gold, L"coins", Gold);
    StatCard(dc, 589, L"EXPERIENCE", g_state.xp, L"LV " , Teal);
    DrawLabel(dc, 711, 152, Number(g_state.level), g_font_small, Teal);
    DrawDungeon(dc);
    DrawInspector(dc);
    RoundBox(dc, 28, 609, 734, 68, Surface);
    wchar_t inventory_line[128]{};
    swprintf_s(inventory_line, L"Wallet64 %lld  /  Mana(float) %.1f  /  Ammo %ld  /  Armor %ld  /  Position %.2f, %.2f",
        static_cast<long long>(g_state.gold64), static_cast<double>(g_state.mana_float),
        g_state.ammo, g_state.armor, static_cast<double>(g_state.position_x),
        static_cast<double>(g_state.position_y));
    wchar_t name[40]{};
    const size_t name_length = strnlen_s(g_state.player_name, sizeof(g_state.player_name));
    MultiByteToWideChar(CP_ACP, 0, g_state.player_name, static_cast<int>(name_length), name, 39);
    const size_t wide_name_length = wcsnlen_s(g_state.player_name_utf16,
        std::size(g_state.player_name_utf16));
    const std::wstring wide_name(g_state.player_name_utf16, wide_name_length);
    DrawLabel(dc, 43, 620, L"ASCII: " + std::wstring(name) + L"  /  UTF-16: "
        + wide_name + L"  ·  LEVEL " + Number(g_state.level), g_font_body, Text);
    DrawLabel(dc, 43, 648, inventory_line, g_font_small, Muted);
    const std::wstring last = L"EVENT  " + g_event_text;
    DrawLabel(dc, 30, 748, last.substr(0, 130), g_font_small, Muted);
}

void CreateAction(HWND window, int id, const wchar_t* text, int x, int y, int width) {
    CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        x, y, width, 40, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr), nullptr);
}

void LoadPlugin() {
    if (!g_plugin) g_plugin = LoadLibraryW(SiblingPath(L"ShowcasePlugin.dll").c_str());
    if (!g_plugin) {
        g_event_text = L"Plugin load failed. Build the sibling ShowcasePlugin.dll first.";
        return;
    }
    using Ping = DWORD(WINAPI*)(uint64_t);
    const auto ping = reinterpret_cast<Ping>(GetProcAddress(g_plugin, "ShowcasePluginPing"));
    if (!ping) { g_event_text = L"Plugin export is missing."; return; }
    g_plugin_result = ping(2026);
    InterlockedIncrement(&g_state.plugin_pings);
    g_event_text = L"ShowcasePlugin.dll loaded normally; Ping(2026) = "
        + Hex(g_plugin_result) + L". Loader baseline ready.";
}

void Action(int id) {
    switch (id) {
    case ButtonDamage:
        InterlockedExchange(&g_state.hp, std::max(0L, g_state.hp-17));
        InterlockedIncrement(&g_state.damage_events);
        g_event_text = L"A glass goblin dealt 17 damage. Your HP is now " + Number(g_state.hp) + L".";
        break;
    case ButtonLoot:
        GameAddGold64(125); InterlockedExchangeAdd(&g_state.xp, 25);
        InterlockedIncrement(&g_state.loot_events);
        ++g_state.inventory[5].quantity;
        g_event_text = L"Chest opened: +125 gold, +25 XP, +1 ancient coin. Inflation has entered the dungeon.";
        break;
    case ButtonHeal:
        InterlockedExchange(&g_state.hp, 100);
        InterlockedExchange(&g_state.mp, 80);
        g_state.mana_float = 80.0f;
        g_event_text = L"Health and mana restored. The potion manufacturer approves this message.";
        break;
    case ButtonProbe:
        g_last_probe = GameProbeRead(7);
        GameProbeWrite(1);
        g_patch_result = GamePatchProbe(100);
        g_event_text = L"Probe read = " + Hex(static_cast<uintptr_t>(g_last_probe))
            + L"; watch incremented; PatchProbe(100) = " + Number(static_cast<LONG>(g_patch_result)) + L".";
        break;
    case ButtonPause:
        g_paused = !g_paused;
        SetWindowTextW(GetDlgItem(g_window, ButtonPause), g_paused ? L"Resume tick" : L"Pause tick");
        g_event_text = g_paused ? L"Animation paused. Gameplay values never change on a timer."
            : L"Animation resumed. Gameplay values change only through actions or your editor.";
        break;
    case ButtonReset:
        ResetState();
        g_event_text = L"Training shard reset: HP 100, MP 80, Gold 1337. The goblins forgot everything.";
        break;
    case ButtonPlugin:
        LoadPlugin();
        break;
    default:
        return;
    }
    InvalidateRect(g_window, nullptr, FALSE);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case WM_CREATE:
        g_window = window;
        CreateAction(window, ButtonDamage, L"Take damage", 28, 694, 112);
        CreateAction(window, ButtonLoot, L"Loot chest", 152, 694, 112);
        CreateAction(window, ButtonHeal, L"Heal", 276, 694, 112);
        CreateAction(window, ButtonProbe, L"Run probes", 400, 694, 112);
        CreateAction(window, ButtonPause, L"Pause tick", 524, 694, 112);
        CreateAction(window, ButtonReset, L"Reset", 648, 694, 112);
        CreateAction(window, ButtonPlugin, L"Load plugin · normal loader baseline", 803, 684, 328);
        SetTimer(window, TimerId, 120, nullptr);
        return 0;
    case WM_DRAWITEM: {
        const auto* item = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
        const bool pressed = (item->itemState & ODS_SELECTED) != 0;
        const int width = item->rcItem.right-item->rcItem.left;
        const int height = item->rcItem.bottom-item->rcItem.top;
        RoundBox(item->hDC, 0, 0, width, height,
            pressed ? RGB(34,79,73) : RGB(23,48,51), RGB(49,110,105), 9);
        wchar_t text[96]{};
        GetWindowTextW(item->hwndItem, text, 96);
        const HGDIOBJ old = SelectObject(item->hDC, g_font_body);
        SetBkMode(item->hDC, TRANSPARENT); SetTextColor(item->hDC, Text);
        RECT rect = item->rcItem;
        DrawTextW(item->hDC, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(item->hDC, old);
        return TRUE;
    }
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED) {
            Action(LOWORD(wp));
            SetFocus(window);
        }
        return 0;
    case WM_KEYDOWN:
        if (wp == 'W' || wp == VK_UP) g_state.position_y = std::max(0.0f, g_state.position_y-1.0f);
        if (wp == 'S' || wp == VK_DOWN) g_state.position_y = std::min(4.0f, g_state.position_y+1.0f);
        if (wp == 'A' || wp == VK_LEFT) g_state.position_x = std::max(0.0f, g_state.position_x-1.0f);
        if (wp == 'D' || wp == VK_RIGHT) g_state.position_x = std::min(9.0f, g_state.position_x+1.0f);
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    case WM_TIMER:
        if (!g_paused) ++g_frame;
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    case WM_ERASEBKGND:
        return TRUE;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        const HDC dc = BeginPaint(window, &paint);
        const HDC back = CreateCompatibleDC(dc);
        const HBITMAP bitmap = CreateCompatibleBitmap(dc, ClientWidth, ClientHeight);
        const HGDIOBJ old = SelectObject(back, bitmap);
        DrawFrame(back);
        BitBlt(dc, 0, 0, ClientWidth, ClientHeight, back, 0, 0, SRCCOPY);
        SelectObject(back, old); DeleteObject(bitmap); DeleteDC(back);
        EndPaint(window, &paint);
        return 0;
    }
    case WM_DESTROY:
        KillTimer(window, TimerId);
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, wp, lp);
    }
}
} // namespace

extern "C" __declspec(dllexport) showcase::GameState* WINAPI GameGetState() {
    return &g_state;
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI GameAddGold64(uint64_t amount) {
    if (amount > 1000000) return ERROR_INVALID_PARAMETER;
    const LONG previous = InterlockedExchangeAdd(&g_state.gold, static_cast<LONG>(amount));
    InterlockedAdd64(&g_state.gold64, static_cast<LONG64>(amount));
    return static_cast<DWORD>(previous + static_cast<LONG>(amount));
}

extern "C" __declspec(dllexport) __declspec(noinline) uint64_t WINAPI GameProbeRead(uint64_t salt) {
    const uint64_t observed = static_cast<uint64_t>(g_state.watch_value);
    InterlockedIncrement(&g_state.probe_events);
    return observed ^ salt;
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI GameProbeWrite(uint64_t amount) {
    const LONG64 next = InterlockedAdd64(&g_state.watch_value, static_cast<LONG64>(amount));
    return static_cast<DWORD>(next);
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI GamePatchProbe(uint64_t value) {
    return static_cast<DWORD>(value) + 7;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetProcessDPIAware();
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)));
    g_executable_path = executable;
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int index = 1; argv && index+1 < argc; ++index) {
        if (wcscmp(argv[index], L"--manifest") == 0) {
            g_manifest_path = argv[++index];
        }
    }
    if (argv) LocalFree(argv);
    g_main_tid = GetCurrentThreadId();
    ResetState();
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) return 2;
    for (size_t index = 0; index < g_workers.size(); ++index) {
        g_workers[index] = CreateThread(nullptr, 0, IdleWorker, nullptr, 0, &g_worker_ids[index]);
        if (!g_workers[index]) { SetEvent(g_stop_event); return 3; }
    }
    WriteManifest();
    g_font_title = Font(38, FW_BOLD, L"Segoe UI");
    g_font_heading = Font(18, FW_SEMIBOLD, L"Segoe UI");
    g_font_body = Font(14, FW_SEMIBOLD, L"Segoe UI");
    g_font_small = Font(12, FW_NORMAL, L"Segoe UI");
    g_font_mono = Font(18, FW_NORMAL, L"Consolas");
    g_font_value = Font(32, FW_BOLD, L"Segoe UI");
    WNDCLASSEXW cls{};
    cls.cbSize = sizeof(cls); cls.hInstance = instance; cls.lpfnWndProc = WindowProc;
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW); cls.lpszClassName = L"AsterfallShowcaseWindow";
    if (!RegisterClassExW(&cls)) return 4;
    constexpr DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT rect{0,0,ClientWidth,ClientHeight};
    AdjustWindowRectEx(&rect, style, FALSE, 0);
    const HWND window = CreateWindowExW(0, cls.lpszClassName,
        L"Asterfall - The Memory Forge | Owned Kernel Studio Showcase", style,
        CW_USEDEFAULT, CW_USEDEFAULT, rect.right-rect.left, rect.bottom-rect.top,
        nullptr, nullptr, instance, nullptr);
    if (!window) return 5;
    ShowWindow(window, show); UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message); DispatchMessageW(&message);
    }
    SetEvent(g_stop_event);
    WaitForMultipleObjects(static_cast<DWORD>(g_workers.size()), g_workers.data(), TRUE, INFINITE);
    for (HANDLE worker : g_workers) CloseHandle(worker);
    CloseHandle(g_stop_event);
    for (HFONT font : {g_font_title,g_font_heading,g_font_body,g_font_small,g_font_mono,g_font_value}) {
        if (font) DeleteObject(font);
    }
    return static_cast<int>(message.wParam);
}
