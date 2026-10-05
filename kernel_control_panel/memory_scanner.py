"""
High-Performance Memory Scanning & Structure Dissection Engine
Supports Cheat Engine style data types, comparison conditions, and multi-pass filtering.
"""

import struct
import math
import ctypes
import threading
from functools import wraps
from contextlib import contextmanager
from ctypes import wintypes
from typing import List, Dict, Any, Optional, Tuple

FORMATS = {
    "int8": ("<b", 1),
    "uint8": ("<B", 1),
    "int16": ("<h", 2),
    "uint16": ("<H", 2),
    "int32": ("<i", 4),
    "uint32": ("<I", 4),
    "int64": ("<q", 8),
    "uint64": ("<Q", 8),
    "float32": ("<f", 4),
    "float64": ("<d", 8),
}

# Windows API for Memory Querying
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("Alignment1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("Alignment2", ctypes.c_ulong),
    ]

def _memory_api():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    api.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION64), ctypes.c_size_t]
    api.VirtualQueryEx.restype = ctypes.c_size_t
    api.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    api.ReadProcessMemory.restype = wintypes.BOOL
    return api

@contextmanager
def _process_handle(api, access, pid):
    handle = api.OpenProcess(access, False, pid)
    try:
        yield handle
    finally:
        if handle:
            api.CloseHandle(handle)

def _serialized_scan(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        with self._lock:
            try:
                return method(self, *args, **kwargs)
            finally:
                self.is_scanning = False
    return invoke

def get_memory_regions(pid: int, writable_only: bool = False, executable_only: bool = False) -> List[Dict[str, Any]]:
    """Enumerate valid readable memory regions of target process using VirtualQueryEx."""
    kernel32 = _memory_api()
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    with _process_handle(kernel32, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid) as h_proc:
        if not h_proc:
            return []

        regions = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION64()
        mbi_size = ctypes.sizeof(mbi)

        max_user_addr = 0x7FFFFFFF0000

        while addr < max_user_addr:
            ret = kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
            if ret == 0:
                break

            base = mbi.BaseAddress
            size = mbi.RegionSize
            if size == 0:
                break
            state = mbi.State
            protect = mbi.Protect
            type_flag = mbi.Type

            is_commit = (state == MEM_COMMIT)
            is_readable = is_commit and not (protect & PAGE_GUARD) and not (protect & PAGE_NOACCESS)
            is_writable = is_readable and bool(protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            is_executable = is_readable and bool(protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))

            keep = is_readable
            if writable_only and not is_writable:
                keep = False
            if executable_only and not is_executable:
                keep = False

            protect_str = []
            if protect & PAGE_READONLY: protect_str.append("PAGE_READONLY")
            elif protect & PAGE_READWRITE: protect_str.append("PAGE_READWRITE")
            elif protect & PAGE_WRITECOPY: protect_str.append("PAGE_WRITECOPY")
            elif protect & PAGE_EXECUTE: protect_str.append("PAGE_EXECUTE")
            elif protect & PAGE_EXECUTE_READ: protect_str.append("PAGE_EXECUTE_READ")
            elif protect & PAGE_EXECUTE_READWRITE: protect_str.append("PAGE_EXECUTE_READWRITE")
            elif protect & PAGE_EXECUTE_WRITECOPY: protect_str.append("PAGE_EXECUTE_WRITECOPY")
            else: protect_str.append("PAGE_NOACCESS")

            type_str = "MEM_PRIVATE" if type_flag == 0x20000 else "MEM_IMAGE" if type_flag == 0x1000000 else "MEM_MAPPED" if type_flag == 0x40000 else "OTHER"

            if is_commit:
                regions.append({
                    "base_address": f"0x{base:X}",
                    "base_address_int": base,
                    "region_size": size,
                    "region_size_kb": size // 1024,
                    "state": "MEM_COMMIT",
                    "protect": "|".join(protect_str),
                    "type": type_str,
                    "is_writable": is_writable,
                    "is_executable": is_executable,
                    "keep_for_scan": keep
                })

            addr = base + size


    return regions

class ScanCandidate:
    __slots__ = ("address", "current_value", "previous_value")
    def __init__(self, address: int, current_value: Any, previous_value: Any = None):
        self.address = address
        self.current_value = current_value
        self.previous_value = previous_value

class MemoryScannerSession:
    def __init__(self, bridge):
        self._lock = threading.RLock()
        self.bridge = bridge
        self.pid: Optional[int] = None
        self.data_type: str = "int32"
        self.candidates: List[ScanCandidate] = []
        self.scan_count: int = 0
        self.is_scanning: bool = False

    @_serialized_scan
    def reset(self):
        self.candidates.clear()
        self.scan_count = 0
        self.is_scanning = False

    @_serialized_scan
    def first_scan(
        self,
        pid: int,
        data_type: str,
        scan_type: str, # "exact", "bigger", "smaller", "between", "unknown"
        val1: Any,
        val2: Optional[Any] = None,
        writable_only: bool = True,
        max_results: int = 50000
    ) -> Dict[str, Any]:
        self.reset()
        self.pid = pid
        self.data_type = data_type
        self.is_scanning = True

        regions = get_memory_regions(pid, writable_only=writable_only)
        scan_regions = [r for r in regions if r["keep_for_scan"]]

        fmt, size = FORMATS.get(data_type, ("<i", 4))
        step = size

        candidates = []
        val1_parsed = self._parse_val(val1, data_type) if scan_type != "unknown" else None
        val2_parsed = self._parse_val(val2, data_type) if val2 is not None else None

        kernel32 = _memory_api()
        with _process_handle(kernel32, 0x0010 | 0x0400, pid) as h_proc:
            if not h_proc:
                return {"success": False, "error": "Cannot open target process", "count": 0}

            buf = (ctypes.c_ubyte * 65536)()
            buf_ptr = ctypes.addressof(buf)
            bytes_read = ctypes.c_size_t(0)

            for reg in scan_regions:
                base = reg["base_address_int"]
                reg_sz = reg["region_size"]
                offset = 0

                while offset < reg_sz:
                    chunk = min(65536, reg_sz - offset)
                    if kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(base + offset), buf_ptr, chunk, ctypes.byref(bytes_read)):
                        n = bytes_read.value
                        raw_bytes = bytes(buf[:n])
                        max_idx = n - size

                        for idx in range(0, max_idx + 1, step):
                            try:
                                val = struct.unpack_from(fmt, raw_bytes, idx)[0]
                            except Exception:
                                continue

                            match = False
                            is_flt = "float" in data_type
                            if is_flt and math.isnan(val):
                                match = False
                            elif scan_type == "unknown":
                                match = True
                            elif scan_type == "exact":
                                match = math.isclose(val, val1_parsed, rel_tol=1e-5, abs_tol=1e-6) if is_flt else (val == val1_parsed)
                            elif scan_type == "bigger":
                                match = (val >= val1_parsed)
                            elif scan_type == "smaller":
                                match = (val <= val1_parsed)
                            elif scan_type == "between":
                                match = (val1_parsed <= val <= val2_parsed)

                            if match:
                                candidates.append(ScanCandidate(base + offset + idx, val, val))
                                if len(candidates) >= max_results:
                                    break

                    if len(candidates) >= max_results:
                        break
                    offset += chunk
                if len(candidates) >= max_results:
                    break


        self.candidates = candidates
        self.scan_count = 1
        self.is_scanning = False

        return {
            "success": True,
            "count": len(candidates),
            "scan_count": self.scan_count,
            "max_hit": len(candidates) >= max_results
        }

    @_serialized_scan
    def next_scan(
        self,
        scan_type: str, # "exact", "increased", "decreased", "changed", "unchanged", "bigger", "smaller"
        val1: Optional[Any] = None,
        val2: Optional[Any] = None
    ) -> Dict[str, Any]:
        if not self.candidates or not self.pid:
            return {"success": False, "error": "No previous scan candidates", "count": 0}

        fmt, size = FORMATS.get(self.data_type, ("<i", 4))
        val1_parsed = self._parse_val(val1, self.data_type) if val1 is not None and val1 != "" else None

        kernel32 = _memory_api()
        with _process_handle(kernel32, 0x0010, self.pid) as h_proc:
            if not h_proc:
                return {"success": False, "error": "Cannot open target process", "count": 0}

            val_buf = (ctypes.c_ubyte * size)()
            val_ptr = ctypes.addressof(val_buf)
            read_sz = ctypes.c_size_t(0)

            survivors = []
            for cand in self.candidates:
                if kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(cand.address), val_ptr, size, ctypes.byref(read_sz)) and read_sz.value == size:
                    now_val = struct.unpack(fmt, bytes(val_buf))[0]
                    prev_val = cand.current_value

                    match = False
                    is_flt = "float" in self.data_type
                    if is_flt and (math.isnan(now_val) or (prev_val is not None and math.isnan(prev_val))):
                        match = False
                    elif scan_type == "exact":
                        match = math.isclose(now_val, val1_parsed, rel_tol=1e-5, abs_tol=1e-6) if is_flt else (now_val == val1_parsed)
                    elif scan_type == "increased":
                        match = (now_val > prev_val)
                    elif scan_type == "decreased":
                        match = (now_val < prev_val)
                    elif scan_type == "changed":
                        match = not math.isclose(now_val, prev_val, rel_tol=1e-5, abs_tol=1e-6) if is_flt else (now_val != prev_val)
                    elif scan_type == "unchanged":
                        match = math.isclose(now_val, prev_val, rel_tol=1e-5, abs_tol=1e-6) if is_flt else (now_val == prev_val)
                    elif scan_type == "bigger":
                        match = (now_val >= val1_parsed)
                    elif scan_type == "smaller":
                        match = (now_val <= val1_parsed)

                    if match:
                        survivors.append(ScanCandidate(cand.address, now_val, prev_val))


        self.candidates = survivors
        self.scan_count += 1

        return {
            "success": True,
            "count": len(survivors),
            "scan_count": self.scan_count
        }

    @_serialized_scan
    def get_results(self, page: int = 1, page_size: int = 100) -> Dict[str, Any]:
        total = len(self.candidates)
        start = (page - 1) * page_size
        end = start + page_size
        chunk = self.candidates[start:end]

        results = []
        for c in chunk:
            results.append({
                "address": f"0x{c.address:X}",
                "address_int": c.address,
                "current_value": self._format_val(c.current_value),
                "previous_value": self._format_val(c.previous_value),
                "data_type": self.data_type
            })

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "results": results
        }

    def _parse_val(self, val: Any, data_type: str) -> Any:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return val
        s = str(val).strip()
        if not s:
            return None
        if "float" in data_type:
            return float(s)
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)

    def _format_val(self, val: Any) -> str:
        if val is None:
            return "-"
        if isinstance(val, float):
            return f"{val:.6g}"
        return str(val)

# -------------------------------------------------------------
# Structure Dissection Helper
# -------------------------------------------------------------
def dissect_structure(bridge, pid: int, base_address: int, total_size: int = 256) -> List[Dict[str, Any]]:
    """Dissects memory starting at base_address into fields and infers types."""
    read_res = bridge.read_process_memory_snapshot(pid, base_address, min(total_size, 4096))
    if not read_res.get("data_hex"):
        return []

    raw = bytes.fromhex(read_res["data_hex"])
    length = len(raw)
    fields = []

    for offset in range(0, length, 8):
        slice8 = raw[offset:offset+8]
        if len(slice8) < 8:
            break

        i8 = struct.unpack("<b", slice8[:1])[0]
        u8 = struct.unpack("<B", slice8[:1])[0]
        i16 = struct.unpack("<h", slice8[:2])[0]
        u16 = struct.unpack("<H", slice8[:2])[0]
        i32 = struct.unpack("<i", slice8[:4])[0]
        u32 = struct.unpack("<I", slice8[:4])[0]
        i64 = struct.unpack("<q", slice8)[0]
        u64 = struct.unpack("<Q", slice8)[0]
        f32 = struct.unpack("<f", slice8[:4])[0]
        f64 = struct.unpack("<d", slice8)[0]

        # ASCII hint
        ascii_hint = "".join(chr(b) if 32 <= b <= 126 else "." for b in slice8)

        # Type inference guess
        inferred = "int64 / uint64"
        if u64 == 0:
            inferred = "NULL / 0"
        elif 0x0000000000400000 <= u64 <= 0x7FFFFFFFFFFF:
            inferred = f"Pointer -> 0x{u64:X}"
        elif not math.isnan(f32) and not math.isinf(f32) and 0.0001 <= abs(f32) <= 1000000.0:
            inferred = f"Float ({f32:.4g})"
        elif -2147483648 <= i32 <= 2147483647 and abs(i64) > 2147483647:
            inferred = "int64"

        fields.append({
            "offset": f"+0x{offset:04X}",
            "address": f"0x{base_address + offset:X}",
            "hex": slice8.hex().upper(),
            "ascii": ascii_hint,
            "int32": i32,
            "uint32": u32,
            "int64": i64,
            "uint64": f"0x{u64:X}",
            "float32": f"{f32:.6g}" if not (math.isnan(f32) or math.isinf(f32)) else "NaN",
            "float64": f"{f64:.6g}" if not (math.isnan(f64) or math.isinf(f64)) else "NaN",
            "inferred": inferred
        })

    return fields
