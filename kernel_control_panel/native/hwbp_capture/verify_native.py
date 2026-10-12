"""Native-only deterministic checks. External target inspection is not used."""
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
results = []

def record(name, passed, **details):
    results.append({"name": name, "passed": bool(passed), **details})
    if not passed:
        raise AssertionError(results[-1])

test = subprocess.run([str(ROOT / "CaptureSelftest.exe")], capture_output=True, text=True, timeout=20)
record("synthetic_context_and_8_producer_ring_160000_hits", test.returncode == 0,
       exit_code=test.returncode, output=test.stdout.strip())
for option, expected in [
    ("--unhandled-single-step", 0x80000004),
    ("--capture-unrelated-single-step", 0x80000004),
    ("--capture-unrelated-access-violation", 0xC0000005),
]:
    child = subprocess.run([str(ROOT / "HwbpFixture.exe"), option],
                           capture_output=True, text=True, timeout=15)
    code = child.returncode & 0xFFFFFFFF
    record(option, code == expected, exit_hex=f"0x{code:08X}")

child = subprocess.Popen([str(ROOT / "HwbpFixture.exe")], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    ready = json.loads(child.stdout.readline())
    record("six_worker_fixture_start", len(ready["worker_tids"]) == 6, ready=ready)
    for command, counts in [
        ("execute 2", (12, 0, 0)),
        ("write 3", (12, 18, 0)),
        ("readwrite 4", (12, 18, 24)),
        ("burst 100", (612, 618, 624)),
    ]:
        child.stdin.write(command + "\n"); child.stdin.flush()
        status = json.loads(child.stdout.readline())
        observed = tuple(status[key] for key in ("execute_count", "write_count", "readwrite_count"))
        record(command, observed == counts, observed=observed, expected=counts)
    child.stdin.write("exit\n"); child.stdin.flush()
    child.wait(timeout=10)
    record("fixture_graceful_exit", child.returncode == 0)
finally:
    if child.poll() is None:
        child.kill(); child.wait(timeout=5)

report = {"timestamp": time.time(), "passed": all(r["passed"] for r in results), "tests": results}
(ROOT / "native-test-results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
