"""Offline Win64 declarations from Windows SDK/UCRT 10.0.26100 headers.

Module names are part of the match. Unsupported/variadic exports stay unknown.
This catalog carries declarations, not debug symbols or target-specific names.
"""
import copy

TYPES = {
    'p': ('void*','pointer',8), 'cp': ('const void*','pointer',8),
    's': ('const char*','pointer',8), 'w': ('const wchar_t*','pointer',8),
    'd': ('uint32_t*','pointer',8), 'i': ('int32_t','integer',4),
    'u': ('uint32_t','integer',4), 'z': ('uint64_t','integer',8),
    'f': ('float','float',4), 'r': ('double','float',8), 'v': ('void','void',0),
}
# result, parameters, source header. Pointer aliases have the same Win64 ABI.
CRT = {
    'memcpy': ('p','pcpz','corecrt_memory.h'), 'memmove': ('p','pcpz','corecrt_memory.h'),
    'memset': ('p','piz','corecrt_memory.h'), 'memcmp': ('i','cpcpz','corecrt_memory.h'),
    'malloc': ('p','z','corecrt_malloc.h'), 'calloc': ('p','zz','corecrt_malloc.h'),
    'realloc': ('p','pz','corecrt_malloc.h'), 'free': ('v','p','corecrt_malloc.h'),
    'strlen': ('z','s','string.h'), 'strcmp': ('i','ss','string.h'),
    'strncmp': ('i','ssz','string.h'), 'strcpy': ('p','ps','string.h'),
    'strncpy': ('p','psz','string.h'), 'strchr': ('p','si','string.h'),
    'puts': ('i','s','stdio.h'), 'putchar': ('i','i','stdio.h'),
    'fopen': ('p','ss','stdio.h'), 'fclose': ('i','p','stdio.h'),
    'fread': ('z','pzzp','stdio.h'), 'fwrite': ('z','cpzzp','stdio.h'),
    'system': ('i','s','stdlib.h'), 'abs': ('i','i','stdlib.h'),
    'sqrt': ('r','r','corecrt_math.h'), 'sqrtf': ('f','f','corecrt_math.h'),
    'fabs': ('r','r','corecrt_math.h'), 'fabsf': ('f','f','corecrt_math.h'),
    'pow': ('r','rr','corecrt_math.h'), 'powf': ('f','ff','corecrt_math.h'),
}
WIN = {
    'GetCurrentProcessId': ('u','','processthreadsapi.h'),
    'GetCurrentThreadId': ('u','','processthreadsapi.h'),
    'GetCurrentProcess': ('p','','processthreadsapi.h'),
    'GetCurrentThread': ('p','','processthreadsapi.h'),
    'GetLastError': ('u','','errhandlingapi.h'), 'SetLastError': ('v','u','errhandlingapi.h'),
    'GetTickCount': ('u','','sysinfoapi.h'), 'GetTickCount64': ('z','','sysinfoapi.h'),
    'Sleep': ('v','u','synchapi.h'), 'CloseHandle': ('i','p','handleapi.h'),
    'VirtualAlloc': ('p','pzuu','memoryapi.h'), 'VirtualFree': ('i','pzu','memoryapi.h'),
    'VirtualProtect': ('i','pzud','memoryapi.h'),
    'ReadFile': ('i','ppudp','fileapi.h'), 'WriteFile': ('i','pcpudp','fileapi.h'),
    'CreateFileA': ('p','suup uup','fileapi.h'), 'CreateFileW': ('p','wuup uup','fileapi.h'),
    'GetModuleHandleA': ('p','s','libloaderapi.h'), 'GetModuleHandleW': ('p','w','libloaderapi.h'),
    'LoadLibraryA': ('p','s','libloaderapi.h'), 'LoadLibraryW': ('p','w','libloaderapi.h'),
    'GetProcAddress': ('p','ps','libloaderapi.h'),
    'QueryPerformanceCounter': ('i','p','profileapi.h'), 'QueryPerformanceFrequency': ('i','p','profileapi.h'),
}


def split_types(text):
    text = text.replace(' ','')
    result = []
    while text:
        code = 'cp' if text.startswith('cp') else text[0]
        result.append(code);text = text[len(code):]
    return result


def type_info(code):
    spelling, kind, size = TYPES[code]
    value = {'type':spelling,'kind':kind,'size':size}
    if code == 'w':value['encoding'] = 'utf-16le'
    return value


def lookup(name, module, bits):
    if bits != 64:
        return None
    module = module.lower()
    crt = module in ('ucrtbase.dll','msvcrt.dll') or module.startswith('api-ms-win-crt-')
    windows = module in ('kernel32.dll','kernelbase.dll') or module.startswith(('api-ms-win-core-','ext-ms-win-kernel32-'))
    entry = CRT.get(name) if crt else WIN.get(name) if windows else None
    if not entry:
        return None
    result, parameters, header = entry
    return copy.deepcopy({'name':name,'return':type_info(result),
        'parameters':[dict(type_info(code),name='arg'+str(i+1)) for i,code in enumerate(split_types(parameters))],
        'valid':True,'calling_convention':'win64','source':'windows_sdk_declaration',
        'declaration':{'sdk':'10.0.26100.0','header':header}})
