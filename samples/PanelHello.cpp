#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

struct HelloResult {
    char text[64];
    DWORD calls;
    DWORD threadId;
    uint64_t parameter;
    int printedBytes;
    int flushResult;
};
extern "C" __declspec(dllexport) HelloResult g_HelloResult={};

__declspec(noinline) static void InternalFormat(char* destination,size_t capacity,uint64_t value){
    sprintf_s(destination,capacity,"Hello World | value=%llu",static_cast<unsigned long long>(value));
}

extern "C" __declspec(dllexport) DWORD WINAPI HelloWorld(void* parameter){
    const auto value=reinterpret_cast<uintptr_t>(parameter);
    InternalFormat(g_HelloResult.text,sizeof(g_HelloResult.text),value);
    ++g_HelloResult.calls;g_HelloResult.threadId=GetCurrentThreadId();g_HelloResult.parameter=value;
    // Executes inside the target process. The controller never calls this directly.
    g_HelloResult.printedBytes=printf("\n[PanelHello.dll] %s (TID=%lu)\n",g_HelloResult.text,g_HelloResult.threadId);
    g_HelloResult.flushResult=fflush(stdout);OutputDebugStringA(g_HelloResult.text);
    return 0x48454C4FUL;
}

extern "C" __declspec(dllexport) DWORD WINAPI EchoValue(void* parameter){
    return static_cast<DWORD>(reinterpret_cast<uintptr_t>(parameter));
}
extern "C" __declspec(dllexport) DWORD WINAPI SlowHello(void* parameter){
    Sleep(1600);return HelloWorld(parameter);
}
extern "C" __declspec(dllexport) double FloatFunction(double value){return value+0.5;}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}
