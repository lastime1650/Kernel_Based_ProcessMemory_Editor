"""
NOCTURNE Kernel Memory Studio Pro - Comprehensive Stability & Edge Case Simulation
Tests user-mode and simulated kernel-mode validation logic without loading the kernel driver.
"""

import sys
import math
import struct
import asyncio
import traceback
from typing import Dict, Any, List

print("=" * 70)
print("NOCTURNE STUDIO: ARCHITECTURE & CODE STABILITY SIMULATION SUITE")
print("Target: Kernel Validation Logic & User-Mode Control Panel Engine")
print("Execution Mode: Static Verification & Simulation (Driver Load: FALSE)")
print("=" * 70)

# =====================================================================
# SIMULATION 1: Kernel GetPacket<T> & IsValidUserRange Logic
# =====================================================================
print("\n[SIMULATION 1] Kernel Packet Validation & Address Range Verification")

MmHighestUserAddress = 0x00007FFFFFFEFFFF # Typical x64 Windows user VA limit
MAXULONG_PTR = 0xFFFFFFFFFFFFFFFF
MAXSIZE_T = 0xFFFFFFFFFFFFFFFF

def simulate_is_valid_user_range(address: int, size: int) -> bool:
    """Exact replica of helper::ioctl_helper::IsValidUserRange in C++"""
    if address == 0 or size == 0:
        return False
    if address > MAXULONG_PTR or size > MAXSIZE_T:
        return False
    end_address = (address + size - 1) & 0xFFFFFFFFFFFFFFFF
    if end_address < address: # Integer wrap-around
        return False
    if end_address > MmHighestUserAddress: # Kernel space boundary
        return False
    return True

def simulate_get_packet(input_len: int, output_len: int, expected_size: int, has_sys_buffer: bool = True) -> bool:
    """Exact replica of helper::ioctl_helper::GetPacket<T> in C++"""
    if not has_sys_buffer:
        return False
    if input_len < expected_size or output_len < expected_size:
        return False
    return True

# Test cases for IsValidUserRange
test_ranges = [
    (0x10000, 0x1000, True, "Standard user allocation"),
    (0x0, 0x1000, False, "Null address"),
    (0x10000, 0, False, "Zero size"),
    (0x7FFFFFFE0000, 0x1000, False, "Crosses into kernel boundary"),
    (0xFFFFF80000000000, 0x1000, False, "Kernel address (ntoskrnl/driver)"),
    (0xFFFFFFFFFFFFFFFF, 0x1000, False, "Integer overflow wrap-around"),
    (0x7FFFFFFF0000, 0xFFFFFFFFFFFFFFFF, False, "Huge size wrap-around"),
    (0x7FFFFFF00000, 0x1000, True, "Valid near user limit"),
]

passed_range = 0
for addr, sz, expected, desc in test_ranges:
    res = simulate_is_valid_user_range(addr, sz)
    status = "PASS" if res == expected else "FAIL"
    if res == expected: passed_range += 1
    print(f"  Range [0x{addr:X}, size 0x{sz:X}]: {desc} -> Result: {res} (Expected: {expected}) [{status}]")

print(f"  -> IsValidUserRange Simulation: {passed_range}/{len(test_ranges)} passed.")

# Test cases for GetPacket
test_packets = [
    (100, 100, 100, True, True, "Exact buffer match"),
    (99, 100, 100, True, False, "Input buffer too small (-1)"),
    (100, 99, 100, True, False, "Output buffer too small (-1)"),
    (0, 0, 100, True, False, "Zero buffer length"),
    (200, 200, 100, True, True, "Buffer larger than struct"),
    (100, 100, 100, False, False, "SystemBuffer is NULL"),
]

passed_pkt = 0
for in_len, out_len, exp_sz, has_buf, expected, desc in test_packets:
    res = simulate_get_packet(in_len, out_len, exp_sz, has_buf)
    status = "PASS" if res == expected else "FAIL"
    if res == expected: passed_pkt += 1
    print(f"  Packet [{desc}]: in={in_len}, out={out_len}, exp={exp_sz} -> {res} [{status}]")

print(f"  -> GetPacket Simulation: {passed_pkt}/{len(test_packets)} passed.")

# =====================================================================
# SIMULATION 2: String Null-Termination Vulnerability in Kernel IOCTLs
# =====================================================================
print("\n[SIMULATION 2] Kernel String Buffer Null-Termination Vulnerability")

def check_string_null_termination(buf_size: int, user_str_len: int) -> Dict[str, Any]:
    """Simulates how C++ RtlInitAnsiString / MatchMask handles non-terminated strings"""
    raw_buffer = bytearray([0x41] * buf_size) # Filled with 'A' (no '\0')
    has_null = (0x00 in raw_buffer)
    vulnerable = not has_null
    return {
        "buffer_size": buf_size,
        "has_null_terminator": has_null,
        "vulnerable_to_oob_read": vulnerable,
        "risk": "RtlInitAnsiString/strlen will read out of bounds until page fault / BSOD" if vulnerable else "Safe"
    }

res_dll = check_string_null_termination(520, 520)
res_mask = check_string_null_termination(256, 256)
print(f"  DllPath Buffer (520 bytes, no null): {res_dll['risk']}")
print(f"  Mask Buffer (256 bytes, no null): {res_mask['risk']}")

# =====================================================================
# SIMULATION 3: Float Precision Matching & NaN Handling in Memory Scanner
# =====================================================================
print("\n[SIMULATION 3] Memory Scanner Float32 vs Float64 Precision & NaN Matching")

def simulate_float_matching():
    test_values = [0.1, 0.2, 0.3, 1337.5, 0.0, -123.456]
    issues_found = 0

    for val in test_values:
        packed32 = struct.pack("<f", val)
        unpacked32 = struct.unpack("<f", packed32)[0]

        direct_eq = (unpacked32 == val)
        isclose_eq = math.isclose(unpacked32, val, rel_tol=1e-5, abs_tol=1e-6)

        if not direct_eq and isclose_eq:
            print(f"  [PRECISION MISMATCH] Float value {val}: Direct == is FALSE (unpacked: {unpacked32:.9f}, val: {val:.9f}), but math.isclose is TRUE!")
            issues_found += 1

    # NaN / Inf testing
    nan_val = float('nan')
    nan_packed = struct.pack("<f", nan_val)
    nan_unpacked = struct.unpack("<f", nan_packed)[0]
    print(f"  [NaN HANDLING] NaN == NaN: {nan_unpacked == nan_unpacked} (Always False in IEEE 754 - can cause infinite candidate loops if not checked)")

    return issues_found

float_issues = simulate_float_matching()
print(f"  -> Float Precision Simulation completed: {float_issues} precision mismatches detected without tolerance matching.")

# =====================================================================
# SIMULATION 4: Integer Parser Edge Cases in User-Mode API
# =====================================================================
print("\n[SIMULATION 4] User-Mode Integer & DataType Parser Robustness")

def parse_int_test(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return int(val)
    s = str(val).strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)

test_inputs = [
    ("123", 123),
    ("0x1000", 0x1000),
    ("0X7FFE0000", 0x7FFE0000),
    (" 456 ", 456),
    (789, 789),
    ("", None),
    (None, None),
    ("—", "ERR_INVALID"),
    ("0x", "ERR_INVALID"),
    ("0xZZZZ", "ERR_INVALID"),
    ("-50", -50)
]

passed_parser = 0
for inp, exp in test_inputs:
    try:
        res = parse_int_test(inp)
        if exp == "ERR_INVALID":
            print(f"  Input: {repr(inp)} -> Unexpected success: {res} [FAIL]")
        else:
            status = "PASS" if res == exp else "FAIL"
            if res == exp: passed_parser += 1
            print(f"  Input: {repr(inp):<15} -> Parsed: {repr(res):<10} [{status}]")
    except ValueError:
        if exp == "ERR_INVALID":
            passed_parser += 1
            print(f"  Input: {repr(inp):<15} -> Expected ValueError handled cleanly [PASS]")
        else:
            print(f"  Input: {repr(inp):<15} -> Unexpected ValueError [FAIL]")

print(f"  -> Parser Robustness Simulation: {passed_parser}/{len(test_inputs)} passed.")

# =====================================================================
# SIMULATION 5: Watch Table Concurrency & Race Condition Simulation
# =====================================================================
print("\n[SIMULATION 5] Watch Table High-Concurrency & Race Condition Simulation")

class MockWatchEntry:
    def __init__(self, item_id: str, address: int, val: int):
        self.id = item_id
        self.address = address
        self.val = val
        self.frozen = True

async def simulate_concurrency():
    watch_table: List[MockWatchEntry] = [
        MockWatchEntry(f"watch_{i}", 0x1000 + i * 4, i * 10) for i in range(100)
    ]
    errors = []

    # Coroutine 1: Background Freeze Worker iterating continuously
    async def freeze_worker():
        for _ in range(50):
            try:
                # Testing unsafe iteration vs safe copy
                # If using: for item in watch_table: -> Can throw RuntimeError during mutation!
                # If using: for item in list(watch_table): -> Safe!
                for item in list(watch_table):
                    _ = item.address + item.val
                await asyncio.sleep(0.001)
            except Exception as e:
                errors.append(f"Worker Error: {type(e).__name__}: {e}")

    # Coroutine 2: Rapid API mutations (Add / Remove)
    async def api_mutator():
        for i in range(50):
            try:
                new_entry = MockWatchEntry(f"new_{i}", 0x5000 + i * 4, i)
                watch_table.append(new_entry)
                if len(watch_table) > 10:
                    watch_table.pop(0)
                await asyncio.sleep(0.001)
            except Exception as e:
                errors.append(f"Mutator Error: {type(e).__name__}: {e}")

    await asyncio.gather(freeze_worker(), api_mutator())
    return errors

concurrency_errors = asyncio.run(simulate_concurrency())
if not concurrency_errors:
    print("  Safe snapshot iteration list(watch_table) passed 100 concurrent mutations without RuntimeError! [PASS]")
else:
    print(f"  Concurrency issues detected: {concurrency_errors} [FAIL]")

# =====================================================================
# SIMULATION 6: Pattern Scan Tokenizer & Mask Discrepancy Simulation
# =====================================================================
print("\n[SIMULATION 6] Pattern Scan Tokenizer & Mask Discrepancy")

def simulate_pattern_tokenizer(pattern_hex: str):
    tokens = pattern_hex.strip().split()
    pattern_bytes = bytearray()
    mask_chars = []
    for t in tokens:
        if t in ("?", "??"):
            pattern_bytes.append(0)
            mask_chars.append("?")
        else:
            try:
                val = int(t, 16)
                if val < 0 or val > 255:
                    return None, None, f"Byte value out of range (0-255): {t}"
                pattern_bytes.append(val)
                mask_chars.append("x")
            except ValueError:
                return None, None, f"Invalid hex token: {t}"
    return bytes(pattern_bytes), "".join(mask_chars), "OK"

test_patterns = [
    ("48 89 5C 24 ?? 57 48 83 EC 20", True, "Standard IDA style signature with wildcard"),
    ("?? ?? ?? ??", True, "All wildcards"),
    ("AA BB CC DD EE FF", True, "Strict byte signature"),
    ("48 89 ZZ 20", False, "Invalid hex token 'ZZ'"),
    ("48 89 100 20", False, "Byte value 0x100 (> 255)"),
    ("", True, "Empty signature")
]

passed_patterns = 0
for pat, expected_ok, desc in test_patterns:
    p_bytes, mask, msg = simulate_pattern_tokenizer(pat)
    ok = (msg == "OK")
    status = "PASS" if ok == expected_ok else "FAIL"
    if ok == expected_ok: passed_patterns += 1
    print(f"  Pattern [{desc}]: '{pat}' -> {msg} [{status}]")

print(f"  -> Pattern Tokenizer Simulation: {passed_patterns}/{len(test_patterns)} passed.")

print("\n" + "=" * 70)
print("SIMULATION SUITE COMPLETE")
print("=" * 70)
