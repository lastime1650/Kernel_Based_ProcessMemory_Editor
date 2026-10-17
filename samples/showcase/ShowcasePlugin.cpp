#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>

// A small owned DLL fixture. DllMain only records its attach count; it creates
// no threads, opens no handles, and performs no work under the loader lock.
extern "C" __declspec(dllexport) volatile LONG g_ShowcasePluginAttachCount = 0;
extern "C" __declspec(dllexport) volatile LONG g_ShowcasePluginCallCount = 0;
extern "C" __declspec(dllexport) uint64_t g_ShowcasePluginLastArgument = 0;

extern "C" __declspec(dllexport) DWORD WINAPI ShowcasePluginPing(uint64_t value) {
    g_ShowcasePluginLastArgument = value;
    InterlockedIncrement(&g_ShowcasePluginCallCount);
    return 0x41535452UL; // "ASTR". Visible, deterministic remote-call result.
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        InterlockedIncrement(&g_ShowcasePluginAttachCount);
    }
    return TRUE;
}
