# Asterfall — The Memory Forge

Asterfall is a small, original Win32 RPG-style **owned test process** for Kernel
Studio screenshots and reproducible demonstrations. Its dungeon, goblins, treasure,
and UI are drawn with GDI. Its character data is synthetic. It has no network
connection, anti-cheat, external game assets, or connection to a commercial game.

> [!NOTE]
> This fixture makes memory changes visible. The screenshots are demonstrations of
> Kernel Studio controlling our own program; they are not claims about support for
> another game's protection system.

## Build and launch

From a PowerShell prompt with Visual Studio C++ x64 tools installed:

```powershell
./samples/showcase/build_showcase.ps1
./samples/showcase/build/Asterfall.exe --manifest ./samples/showcase/build/manifest.json
```

The build uses MSVC, C++17, x64, `/Od /Zi /MD /W4 /WX`, and creates:

| File | Purpose |
| --- | --- |
| `build/Asterfall.exe` | Interactive 1180 × 780 RPG-style GUI |
| `build/Asterfall.pdb` | Private symbols for the owned fixture |
| `build/ShowcasePlugin.dll` | Small DLL for owned-process loader/mapping exercises |
| `build/ShowcasePlugin.pdb` | Symbols for DLL exports and state |

Build products and runtime manifests are ignored by Git. The manifest contains
runtime addresses, process ID, creation FILETIME, main/worker thread IDs, executable
identity, exports, and explicitly described state ranges. Addresses are valid only
for that particular process lifetime. ASLR may reuse addresses across instances;
identify the target by its PID and creation/start key, and read its manifest again
after every launch.

## Play and inspect

| Action | Observable result |
| --- | --- |
| **Take damage** | HP decreases by 17, with a floor of 0 |
| **Loot chest** | +125 gold in both integer wallets, +25 XP, +1 ancient coin |
| **Heal** | HP becomes 100; integer and floating-point mana become 80 |
| **Run probes** | Reads and increments the dedicated watch value; runs `GamePatchProbe(100)` |
| **Pause tick** | Stops the cosmetic animation; stats never change on a timer |
| **Reset** | Restores all synthetic state values and stable pointer links |
| **Load plugin** | Normal `LoadLibraryW` baseline; `ShowcasePluginPing(2026)` returns `0x41535452` |
| **WASD / arrow keys** | Moves the character and changes its floating-point X/Y position |

The HUD shows HP, MP, 32-bit gold, XP and level. The pack strip also shows the
64-bit wallet, floating-point mana, ammo, armor and position. The live **Memory
Inspector** shows addresses and types, including the UTF-16 name, inventory,
pointer-chain root, watch value and callable probes. Cosmetic animation refreshes
the display, so an external edit is visible without a private control channel.

> [!TIP]
> The goblins are unionized. The gold is not. If a value looks suspiciously like
> `1337`, that is because this entire dungeon was built for debugging.

## Address and type contract

`game_state.shared.h` defines an aligned, 448-byte state object. Its field layout
is checked with `static_assert`, and the running instance writes actual addresses
to the optional JSON manifest.

| Field | Offset | Type / initial value |
| --- | ---: | --- |
| Marker | 0 | 16 bytes: `ASTERFALL-RPG-01` |
| Schema version / structure size | 16 / 20 | `uint32_t` / `uint32_t` |
| HP / MP / Gold / XP | 24 / 28 / 32 / 36 | `int32_t`: 100 / 80 / 1337 / 420 |
| Level / Ammo / Armor | 40 / 44 / 48 | `int32_t`: 7 / 30 / 25 |
| Position X / Y | 52 / 56 | `float`: 4.25 / 2.50 |
| Player name | 60 | 32-byte, NUL-terminated ASCII/UTF-8 text |
| Inventory | 92 | Six 40-byte `InventorySlot` records |
| Damage / Loot / Probe / Plugin counters | 332 / 336 / 340 / 344 | `int32_t` |
| Dedicated watch value | 352 | 8-byte aligned `int64_t`: `0x53484F5743415345` |
| Pointer-chain root slot | 360 | 64-bit pointer |
| 64-bit wallet | 368 | `int64_t`: 1337 |
| Floating-point mana | 376 | `float`: 80.0 |
| UTF-16 player name | 380 | 32 `wchar_t` units, initially `Nyx Copperfield` |

Each inventory record contains `item_id:u32`, `quantity:i32`, `rarity:u32`,
`weight:float`, then a 24-byte ASCII label. The pointer chain uses three reads:

```text
root slot + 0 → node1 + 0 → node2 + 0 → Gold (int32)
```

The exact pattern bytes are:

```text
41 53 54 45 52 46 41 4C 4C 2D 52 50 47 2D 30 31
```

The process owns a main GUI thread and three idle worker threads. Workers wait on
a shutdown event and do not modify game state. Thread controls can therefore be
demonstrated on a worker without suspending the GUI thread.

## Exported functions

| Export | Signature and behavior |
| --- | --- |
| `GameGetState` | No arguments; returns the state address |
| `GameAddGold64` | One `uint64_t` argument; adds up to 1,000,000 to both gold fields; returns resulting 32-bit gold as `DWORD` |
| `GameProbeRead` | One `uint64_t` salt; reads the dedicated watch value, increments probe count, returns value XOR salt |
| `GameProbeWrite` | One `uint64_t` increment; changes only the dedicated watch value; returns its low 32 bits |
| `GamePatchProbe` | One `uint64_t` argument; pure leaf fixture function returning its low 32 bits plus 7 |

The UI's **Run probes** button calls the read, write and patch probes. It reports
the result in the event line; the original `GamePatchProbe(100)` result is 107.
For code-patch exercises, first inspect this dedicated function's actual compiled
instructions and restore its bytes afterward. Do not assume a fixed instruction
encoding across compiler versions.

> [!IMPORTANT]
> The game deliberately installs no permanent exception handler that swallows
> debug traps. Hardware-breakpoint recording must use Kernel Studio's capture
> setup/ownership protocol before a probe is triggered. A bare, unhandled hardware
> breakpoint can terminate this owned fixture, just as it can any ordinary process.

`ShowcasePlugin.dll` has a fast `DllMain`: it only increments an attach counter.
It creates no thread and performs no loader-lock work. `ShowcasePluginPing` records
its argument, increments a call counter and returns `0x41535452` (`ASTR`). The
exported counters allow normal loading and manual mapping to be compared on this
owned target. No mitigation, protection or signing-policy bypass is implemented.
