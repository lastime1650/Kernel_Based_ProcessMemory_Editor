"""Read-only driver diagnostics. Full live IOCTL coverage is in the validation package.

Never reports unexecuted operations as passing, changes registers, or registers callbacks.
"""
import argparse
import json
import os
from pathlib import Path
import threading
from driver_bridge import KernelDriverBridge


def run_tests(output=None):
    pid, tid = os.getpid(), threading.get_native_id()
    results = []
    with KernelDriverBridge() as driver:
        if not driver.is_connected():
            print('FAIL: driver connection unavailable', flush=True)
            return False
        cases = [
            ('driver_status', lambda: driver.get_driver_status(), lambda r: not r['event_monitor_active'] and r['queued_event_count'] == 0),
            ('process_info', lambda: driver.query_process_info(pid), lambda r: r['process_id'] == pid and r['exit_status'] == 259),
            ('process_extended', lambda: driver.query_process_extended(pid), lambda r: r['process_id'] == pid),
            ('process_handles', lambda: driver.query_process_handles(pid, 128), lambda r: r['returned_count'] > 0),
            ('process_token', lambda: driver.query_process_token(pid), lambda r: r['process_id'] == pid),
            ('process_threads', lambda: driver.enumerate_threads(pid, 64), lambda r: tid in [t['thread_id'] for t in r['threads']]),
            ('thread_info', lambda: driver.query_thread_info(tid), lambda r: r['process_id'] == pid and r['thread_id'] == tid),
        ]
        for name, call, validate in cases:
            try:
                response = call()
                passed = bool(response.get('success') and validate(response))
                record = {'name': name, 'outcome': 'PASS' if passed else 'FAIL', 'response': response}
            except Exception as exc:
                record = {'name': name, 'outcome': 'FAIL', 'error': str(exc)}
            results.append(record)
            print(record['outcome'] + ': ' + name, flush=True)
    report = {'scope': '7 read-only diagnostics; full live tests are separate', 'pid': pid, 'cases': results}
    if output: Path(output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return all(r['outcome'] == 'PASS' for r in results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    options = parser.parse_args()
    raise SystemExit(0 if run_tests(options.output) else 1)
