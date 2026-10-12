"""VEH ABI, committed telemetry and fail-closed control lifetime regressions.

All target IO is modeled here. Real DLL/IOCTL qualification is a separate suite.
"""
import base64
from collections import deque
import struct
import threading
import unittest
from unittest.mock import patch

import hwbp_capture as H

PID = 42
IDENTITY = '987654321'
RING = 0x7FFE10000000


def raw_context():
    raw = bytearray(H.CONTEXT_SIZE)
    struct.pack_into('<II', raw, 48, 0x10001F, 0x1F80)
    for i in range(6):
        struct.pack_into('<H', raw, 56 + 2*i, 0x30 + i)
        struct.pack_into('<Q', raw, 72 + 8*i, 0x1234567890ABC000 + i)
    struct.pack_into('<I', raw, 68, 0x202)
    for i in range(17):
        struct.pack_into('<Q', raw, 120 + 8*i, 0xFEDCBA9876540000 + i)
    for i in range(16):
        raw[416 + 16*i:432 + 16*i] = bytes([i])*16
    return bytes(raw)


class Driver:
    def __init__(self, studio):
        self.studio = studio
        self._lock = threading.RLock()
        self.io = []
        self.allocations = {}
        self.create_responses = deque()
        self.query_responses = deque()
        self.free_responses = deque()
        self.release_responses = deque()
        self.query_response = {'success': True, 'exit_status': 259, 'process_start_key': IDENTITY}
        self.hwbp_response = {'success': True, 'results': [], 'truncated': False}
        self.remove_response = {'success': True}
        self.free_hwbp_response = {'success': True}
        self.write_response = None

    def query_process_info(self, pid):
        self.io.append(('identity', pid))
        return dict(self.query_response)

    def alloc_virtual_memory(self, pid, size, protect):
        at = 0x200000 + 0x1000*len(self.allocations)
        self.allocations[at] = bytearray(size)
        self.io.append(('allocate', pid, at, size))
        return {'success': True, 'allocated_address': hex(at)}

    def write_process_memory(self, pid, at, data):
        self.io.append(('write', pid, at))
        self.allocations[at][:] = data
        return self.write_response or {'success': True, 'bytes_written': len(data)}

    def free_virtual_memory(self, pid, at):
        self.io.append(('free', pid, at))
        result = self.free_responses.popleft() if self.free_responses else {'success': True}
        if result.get('success'):
            self.allocations.pop(at, None)
        return result

    def create_function_call(self, pid, key, address, parameter, wait):
        name = next(k for k, v in self.studio.record['exports'].items() if v == address)
        self.io.append(('create', name, parameter))
        response = self.create_responses.popleft() if self.create_responses else {
            'success': True, 'packet_valid': True, 'thread_created': True,
            'call_id': '11', 'completed': True, 'exit_value': 0,
            'execution_unknown': False}
        if isinstance(response, Exception):
            raise response
        if response.get('success') and response.get('completed') and response.get('exit_value') == 0:
            if name == 'GetCaptureBuffer':
                self.allocations[parameter][:] = struct.pack('<Q', RING)
            elif name == 'StartCapture':
                struct.pack_into('<I', self.studio.ring, 28, 1)
            elif name == 'StopCapture':
                struct.pack_into('<I', self.studio.ring, 28, 3)
            elif name == 'ShutdownCapture':
                struct.pack_into('<I', self.studio.ring, 28, 0)
        return dict(response)

    def query_function_call(self, call_id, wait):
        self.io.append(('query_call', call_id))
        response = self.query_responses.popleft() if self.query_responses else {
            'success': True, 'pid': PID, 'process_start_key': IDENTITY,
            'call_id': str(call_id), 'completed': True, 'exit_value': 0}
        return dict(response)

    def release_function_call(self, call_id):
        self.io.append(('release', call_id))
        return self.release_responses.popleft() if self.release_responses else {'success': True}

    def remove_hardware_breakpoint(self, pid, node):
        self.io.append(('remove_bp', pid, node))
        return dict(self.remove_response)

    def free_hardware_breakpoint_result(self, node):
        self.io.append(('free_bp', node))
        return dict(self.free_hwbp_response)

    def query_hardware_breakpoint(self, pid):
        self.io.append(('query_bp', pid))
        return dict(self.hwbp_response)


class Studio:
    def __init__(self):
        self.lock = threading.RLock()
        self.key = IDENTITY
        self.breakpoints = {}
        self.ring = bytearray(H.HEADER + H.SLOT*H.CAPACITY)
        self.reads = []
        self.read_hook = None
        self.driver = Driver(self)
        self.record = {
            'pid': PID, 'identity': IDENTITY, 'state': 'ready', 'base': hex(RING-0x10000),
            'dll_path': 'model.dll', 'ring': RING,
            'exports': {name: 0x7FFE00001000 + i*16 for i, name in enumerate(
                ('StartCapture', 'StopCapture', 'ShutdownCapture', 'GetCaptureBuffer'))},
            'owners': [], 'guard_owners': [], 'events': deque(maxlen=H.HISTORY),
            'cursor': 0, 'last_ticket': 0, 'received': 0, 'ring_lost': 0,
            'history_evicted': 0, 'read_failures': 0, 'last_error': '', 'stats': {},
            'unknown_arm': False, 'control_uncertain': False, 'pending_buffers': {},
            'pending_calls': set(), 'poll_lock': threading.Lock()}
        self.header()

    def header(self, ticket=0, published=0, inflight=0, contention=0):
        struct.pack_into('<8sIIIII', self.ring, 0, H.MAGIC, 1, H.HEADER, H.SLOT,
                         H.CAPACITY, H.CONTEXT_SIZE)
        struct.pack_into('<II', self.ring, 28, 1, PID)
        struct.pack_into('<QQQQQ', self.ring, 40, 10_000_000, ticket, published,
                         contention, max(0, published-H.CAPACITY))
        struct.pack_into('<I', self.ring, 80, inflight)

    def event(self, ticket, *, pid=PID, tid=1001, code=0x80000004, committed=True):
        at = H.HEADER + ((ticket-1) % H.CAPACITY)*H.SLOT
        slot = bytearray(H.SLOT)
        guard = ticket*2 if committed else ticket*2+1
        struct.pack_into('<QQQIIIIQIIII', slot, 0, guard, ticket, 500000+ticket,
                         pid, tid, 1, 1, 0x7FFE00102030, code, 0x10001F,
                         H.CONTEXT_SIZE, 0)
        slot[64:64+H.CONTEXT_SIZE] = raw_context()
        struct.pack_into('<Q', slot, 1296, guard)
        self.ring[at:at+H.SLOT] = slot

    def identity(self, pid):
        return self.key

    def check_owner(self, record):
        if self.key != record['identity']:
            raise ValueError('프로세스가 교체되었습니다')

    def read_bytes(self, pid, at, size):
        self.reads.append((pid, at, size))
        if self.read_hook:
            self.read_hook(pid, at, size)
        if RING <= at and at+size <= RING+len(self.ring):
            return bytes(self.ring[at-RING:at-RING+size])
        for start, value in self.driver.allocations.items():
            if start <= at and at+size <= start+len(value):
                return bytes(value[at-start:at-start+size])
        raise ValueError('모델 주소가 매핑되지 않았습니다')

    def parsed_list(self, response, kind):
        if not response.get('success'):
            from studio_api import StudioError
            raise StudioError('모델 드라이버 요청 실패', response)
        return response


class CaptureRegressions(unittest.TestCase):
    def setUp(self):
        self.studio = Studio()
        self.capture = H.Capture(self.studio)
        self.record = self.studio.record
        self.capture.sessions[PID] = self.record

    def create_names(self):
        return [row[1] for row in self.studio.driver.io if row[0] == 'create']

    def add_breakpoint(self):
        self.studio.breakpoints['bp'] = {'pid': PID, 'identity': IDENTITY,
            'address': '0x10000', 'type': 1, 'length': 4, 'node': 0x30000}
        self.record['guard_owners'] = [{'address': '0x10000', 'type': 1, 'length': 4}]

    def test_context_offsets_preserve_64_bit_GPR_DR_segments_and_XMM(self):
        values = H.registers(raw_context())
        self.assertEqual(values['rax'], '0xfedcba9876540000')
        self.assertEqual(values['rip'], '0xfedcba9876540010')
        self.assertEqual(values['dr7'], '0x1234567890abc005')
        self.assertEqual(values['gs'], '0x34')
        self.assertEqual(values['eflags'], '0x202')
        self.assertEqual(values['xmm15'], '0x'+'0f'*16)

    def test_short_context_rejected(self):
        with self.assertRaises(ValueError):
            H.registers(bytes(H.CONTEXT_SIZE-1))

    def test_full_CONTEXT_home_flt_scalar_and_branch_field_offsets(self):
        raw = bytearray(raw_context())
        for i in range(6):
            struct.pack_into('<Q', raw, 8*i, 0xAABBCCDD00000000+i)
        scalars = [('control_word', 256, 'H', 0x1234), ('status_word', 258, 'H', 0x5678),
            ('tag_word', 260, 'B', 0x9A), ('reserved1', 261, 'B', 0xBC),
            ('error_opcode', 262, 'H', 0xDEF0), ('error_offset', 264, 'I', 0x10203040),
            ('error_selector', 268, 'H', 0x5060), ('reserved2', 270, 'H', 0x7080),
            ('data_offset', 272, 'I', 0x90A0B0C0), ('data_selector', 276, 'H', 0xD0E0),
            ('reserved3', 278, 'H', 0xF010), ('mxcsr', 280, 'I', 0x20304050),
            ('mxcsr_mask', 284, 'I', 0x60708090)]
        for name, at, fmt, value in scalars:
            struct.pack_into('<'+fmt, raw, at, value)
        branches = ('vector_control', 'debug_control', 'last_branch_to_rip',
                    'last_branch_from_rip', 'last_exception_to_rip', 'last_exception_from_rip')
        for i in range(6):
            struct.pack_into('<Q', raw, 1184+8*i, 0xFEDCBA9876000000+i)
        result = H.registers(bytes(raw))
        for i in range(6):
            self.assertEqual(result[f'p{i+1}_home'], hex(0xAABBCCDD00000000+i))
        for name, at, fmt, value in scalars:
            self.assertEqual(result['flt_save_'+name], hex(value))
        for i, name in enumerate(branches):
            self.assertEqual(result[name], hex(0xFEDCBA9876000000+i))

    def test_x87_XMM_and_26_vector_registers_keep_all_128_bits_in_little_endian_order(self):
        raw = bytearray(raw_context())
        for count, start in ((8, 288), (16, 416), (26, 768)):
            for i in range(count):
                raw[start+16*i:start+16*(i+1)] = bytes(range(i, i+16))
        result = H.registers(bytes(raw))
        for count, prefix in ((8, 'flt_save_float_register'), (16, 'xmm'), (26, 'vector_register')):
            for i in range(count):
                self.assertEqual(result[prefix+str(i)], '0x'+bytes(range(i, i+16))[::-1].hex())

    def test_flt_reserved_area_is_preserved_as_96_raw_bytes(self):
        raw = bytearray(raw_context())
        raw[672:768] = bytes(range(96))
        values = H.registers(bytes(raw))
        self.assertEqual(values['flt_save_reserved4'], '0x'+bytes(range(96)).hex())
        self.assertEqual(len(bytes.fromhex(values['flt_save_reserved4'][2:])), 96)

    def test_config_exact_native_offsets_and_release_flag(self):
        packed = H.config([{'address': '0xfedcba98', 'type': 3, 'length': 8}])
        self.assertEqual(len(packed), 128)
        self.assertEqual(struct.unpack_from('<8sIIIIQ', packed),
                         (H.CONFIG_MAGIC, 1, 128, 1, 0, 0))
        self.assertEqual(struct.unpack_from('<QIIII', packed, 32),
                         (0xFEDCBA98, 3, 8, 1, 0))
        self.assertEqual(struct.unpack_from('<I', H.config(release=True), 20)[0], 1)

    def test_config_more_than_four_owners_rejected(self):
        with self.assertRaises(ValueError):
            H.config([{'address': '0x1000', 'type': 0, 'length': 1}]*5)

    def test_zero_events_only_reads_header(self):
        self.capture.poll(self.record)
        self.assertEqual(self.record['received'], 0)
        self.assertEqual(self.studio.reads, [(PID, RING, H.HEADER)])

    def test_committed_event_exact_context_and_cursor(self):
        self.studio.event(1)
        self.studio.header(1, 1)
        self.capture.poll(self.record)
        result = self.capture.view(PID)
        event = result['events'][0]
        self.assertEqual(event['sequence'], '1')
        self.assertEqual((event['pid'], event['thread_id'], event['id']), (PID, 1001, 1))
        self.assertEqual(base64.b64decode(event['context_base64']), raw_context())
        self.assertEqual(result['next_cursor'], 1)
        self.assertEqual(self.record['last_ticket'], 1)

    def test_reserved_odd_guard_waits_while_handler_is_live(self):
        self.studio.event(1, committed=False)
        self.studio.header(1, 0, inflight=1)
        self.capture.poll(self.record)
        self.assertEqual((self.record['last_ticket'], self.record['received']), (0, 0))
        self.assertEqual(self.record['ring_lost'], 0)

    def test_settled_contention_hole_does_not_hide_later_events(self):
        self.studio.event(2)
        self.studio.event(3)
        self.studio.header(3, 2, contention=1)
        self.capture.poll(self.record)
        self.assertEqual([x['sequence'] for x in self.record['events']], ['2', '3'])
        self.assertEqual((self.record['last_ticket'], self.record['ring_lost']), (3, 1))

    def test_torn_event_guard_changed_during_post_copy_validation_is_not_published(self):
        self.studio.event(1)
        self.studio.header(1, 1)
        def mutate(pid, at, size):
            if at == RING+H.HEADER+1296 and size == 8:
                struct.pack_into('<Q', self.studio.ring, H.HEADER+1296, 3)
        self.studio.read_hook = mutate
        self.capture.poll(self.record)
        self.assertEqual((self.record['received'], self.record['last_ticket']), (0, 0))

    def test_overtaken_window_reports_exact_lost_count_and_keeps_latest_256(self):
        for ticket in range(45, 301):
            self.studio.event(ticket)
        self.studio.header(300, 300)
        self.capture.poll(self.record)
        self.assertEqual((self.record['received'], self.record['ring_lost']), (256, 44))
        self.assertEqual((self.record['events'][0]['sequence'], self.record['events'][-1]['sequence']), ('45', '300'))

    def test_repeated_poll_never_duplicates_committed_event(self):
        self.studio.event(1)
        self.studio.header(1, 1)
        self.capture.poll(self.record)
        self.capture.poll(self.record)
        self.assertEqual(self.record['received'], 1)

    def test_event_for_wrong_PID_is_rejected(self):
        self.studio.event(1, pid=PID+1)
        self.studio.header(1, 1)
        with self.assertRaisesRegex(ValueError, '형식'):
            self.capture.poll(self.record)
        self.assertEqual(self.record['received'], 0)

    def test_unrelated_exception_code_is_rejected(self):
        self.studio.event(1, code=0xC0000005)
        self.studio.header(1, 1)
        with self.assertRaises(ValueError):
            self.capture.poll(self.record)

    def test_PID_reuse_stops_before_reading_any_target_byte(self):
        self.studio.driver.query_response['process_start_key'] = 'different'
        self.capture.poll(self.record)
        self.assertEqual(self.record['state'], 'exited')
        self.assertEqual(self.studio.reads, [])

    def test_transient_identity_failure_is_not_treated_as_exit_or_empty_success(self):
        self.studio.driver.query_response = {'success': False, 'error_code': 5,
                                             'result_status': '0x00000000'}
        with self.assertRaises(Exception):
            self.capture.poll(self.record)
        self.assertEqual(self.record['state'], 'ready')
        self.assertEqual(self.studio.reads, [])

    def test_concurrent_poll_is_skipped_without_native_IO(self):
        self.record['poll_lock'].acquire()
        try:
            self.capture.poll(self.record)
        finally:
            self.record['poll_lock'].release()
        self.assertEqual(self.studio.driver.io, [])

    def test_header_layout_and_PID_mismatch_fail_closed(self):
        for offset, value in ((16, H.SLOT+1), (20, H.CAPACITY+1), (32, PID+1)):
            with self.subTest(offset=offset):
                self.studio.header()
                struct.pack_into('<I', self.studio.ring, offset, value)
                with self.assertRaises(ValueError):
                    self.capture._header(self.record)

    def test_cursor_pagination_and_client_history_gap(self):
        self.record['events'].extend({'id': i, 'sequence': str(i)} for i in range(10, 14))
        self.record['cursor'] = 13
        result = self.capture.view(PID, after=2, limit=2)
        self.assertEqual([x['id'] for x in result['events']], [10, 11])
        self.assertEqual((result['client_gap'], result['next_cursor'], result['has_more']), (7, 11, True))
        result = self.capture.view(PID, after=13)
        self.assertEqual((result['events'], result['next_cursor'], result['has_more']), ([], 13, False))

    def test_clear_preserves_monotonic_cursor_and_target_memory(self):
        self.record['events'].append({'id': 7})
        self.record['cursor'] = 7
        result = self.capture.action('clear', {'pid': PID})
        self.assertEqual(result['next_cursor'], 7)
        self.assertEqual(result['events'], [])
        self.assertEqual(self.studio.driver.io, [])

    def test_history_eviction_is_visible_without_resetting_monotonic_event_IDs(self):
        self.record['events'].extend({'id': i} for i in range(1, H.HISTORY+1))
        self.record['cursor'] = H.HISTORY
        self.studio.event(1)
        self.studio.header(1, 1)
        self.capture.poll(self.record)
        self.assertEqual(self.record['history_evicted'], 1)
        self.assertEqual(self.record['events'][0]['id'], 2)
        self.assertEqual(self.record['events'][-1]['id'], H.HISTORY+1)

    def test_partial_config_write_cannot_launch_function(self):
        self.studio.driver.write_response = {'success': True, 'bytes_written': 64}
        with self.assertRaisesRegex(ValueError, '쓰기 크기'):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.create_names(), [])
        self.assertEqual(self.record['pending_buffers'], {})

    def test_completed_argument_is_read_then_freed_and_call_released(self):
        output = self.capture._call(self.record, 'GetCaptureBuffer', bytes(8))
        self.assertEqual(struct.unpack('<Q', output)[0], RING)
        self.assertEqual(self.record['pending_buffers'], {})
        self.assertEqual(self.studio.driver.allocations, {})
        self.assertIn(('release', 11), self.studio.driver.io)

    def test_PID_reuse_during_completed_call_release_never_frees_new_process_address(self):
        original = self.studio.driver.release_function_call
        def release(call_id):
            response = original(call_id)
            self.studio.key = 'new process'
            return response
        self.studio.driver.release_function_call = release
        self.capture._call(self.record, 'GetCaptureBuffer', bytes(8))
        self.assertEqual(self.record['state'], 'exited')
        self.assertEqual(self.record['pending_buffers'], {})
        self.assertFalse(any(x[0] == 'free' for x in self.studio.driver.io))

    def test_confirmed_no_thread_failure_frees_unused_argument(self):
        self.studio.driver.create_responses.append({'success': False, 'packet_valid': True,
            'thread_created': False, 'call_id': '0', 'execution_unknown': False})
        with self.assertRaises(Exception):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.record['pending_buffers'], {})
        self.assertEqual(self.studio.driver.allocations, {})
        self.assertFalse(self.record['control_uncertain'])

    def test_known_failed_function_exit_releases_argument(self):
        self.studio.driver.create_responses.append({'success': True, 'call_id': '11',
            'completed': True, 'exit_value': 87})
        with self.assertRaisesRegex(ValueError, 'Win32 87'):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.record['pending_buffers'], {})

    def test_unknown_create_preserves_argument_and_blocks_later_control(self):
        self.studio.driver.create_responses.append({'success': False, 'packet_valid': False,
            'call_id': '0', 'execution_unknown': True})
        with self.assertRaises(Exception):
            self.capture._call(self.record, 'ShutdownCapture', H.config(release=True))
        self.assertTrue(self.record['control_uncertain'])
        self.assertEqual(len(self.record['pending_buffers']), 1)
        with self.assertRaisesRegex(ValueError, '불확실'):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.create_names(), ['ShutdownCapture'])
        self.assertFalse(any(x[0] == 'free' for x in self.studio.driver.io))

    def test_function_call_exception_is_also_execution_unknown(self):
        self.studio.driver.create_responses.append(OSError('native response unavailable'))
        with self.assertRaises(OSError):
            self.capture._call(self.record, 'ShutdownCapture', H.config(release=True))
        self.assertTrue(self.record['control_uncertain'])
        self.assertEqual(len(self.record['pending_buffers']), 1)
        with self.assertRaises(ValueError):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.create_names(), ['ShutdownCapture'])

    def test_pending_call_blocks_new_control_until_owner_checked_completion(self):
        self.studio.driver.create_responses.append({'success': False, 'call_id': '22',
            'execution_unknown': True})
        with self.assertRaises(Exception):
            self.capture._call(self.record, 'ShutdownCapture', H.config(release=True))
        self.assertEqual(self.record['pending_calls'], {22})
        self.studio.driver.query_responses.append({'success': True, 'pid': PID,
            'process_start_key': IDENTITY, 'completed': False, 'exit_value': None})
        with self.assertRaisesRegex(ValueError, '실행 중'):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.create_names(), ['ShutdownCapture'])
        self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.record['pending_calls'], set())
        self.assertEqual(self.record['pending_buffers'], {})

    def test_pending_call_echo_owner_mismatch_never_frees_live_parameter(self):
        self.record['pending_calls'].add(33)
        self.record['pending_buffers'][0x200000] = {'call_id': 33, 'name': 'ShutdownCapture'}
        self.studio.driver.query_responses.append({'success': True, 'pid': PID,
            'process_start_key': 'another', 'completed': True, 'exit_value': 0})
        with self.assertRaisesRegex(ValueError, '소유'):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.create_names(), [])
        self.assertFalse(any(x[0] == 'free' for x in self.studio.driver.io))

    def test_unsubmitted_argument_failed_free_is_retried_before_new_control(self):
        self.studio.driver.write_response = {'success': False, 'error_code': 5}
        self.studio.driver.free_responses.append({'success': False})
        with self.assertRaises(Exception):
            self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(self.create_names(), [])
        self.assertEqual(len(self.record['pending_buffers']), 1)
        self.studio.driver.write_response = None
        self.capture._call(self.record, 'StopCapture')
        self.assertEqual(self.record['pending_buffers'], {})

    def test_completed_free_failure_is_retained_and_retried(self):
        self.studio.driver.free_responses.append({'success': False})
        self.capture._call(self.record, 'StartCapture', H.config())
        self.assertEqual(len(self.record['pending_buffers']), 1)
        self.capture._call(self.record, 'StopCapture')
        self.assertEqual(self.record['pending_buffers'], {})

    def test_stop_rollback_failure_keeps_handler_and_recovery_node(self):
        self.add_breakpoint()
        self.studio.driver.remove_response = {'success': False, 'error_code': 31}
        with self.assertRaisesRegex(ValueError, '복원 실패'):
            self.capture.stop(self.record)
        self.assertEqual(self.record['state'], 'guard')
        self.assertIn('bp', self.studio.breakpoints)
        self.assertNotIn('ShutdownCapture', self.create_names())
        self.assertFalse(any(x[0] == 'free_bp' for x in self.studio.driver.io))

    def test_stop_recovery_buffer_free_failure_keeps_handler(self):
        self.add_breakpoint()
        self.studio.driver.free_hwbp_response = {'success': False}
        with self.assertRaises(ValueError):
            self.capture.stop(self.record)
        self.assertIn('bp', self.studio.breakpoints)
        self.assertNotIn('ShutdownCapture', self.create_names())

    def test_stop_query_failure_never_unregisters_handler(self):
        self.studio.driver.hwbp_response = {'success': False, 'error_code': 5}
        with self.assertRaises(Exception):
            self.capture.stop(self.record)
        self.assertNotIn('ShutdownCapture', self.create_names())

    def test_stop_truncated_thread_verification_never_unregisters_handler(self):
        self.studio.driver.hwbp_response['truncated'] = True
        with self.assertRaisesRegex(ValueError, '전체 스레드'):
            self.capture.stop(self.record)
        self.assertNotIn('ShutdownCapture', self.create_names())

    def test_stop_unknown_remaining_managed_slot_keeps_guard(self):
        self.record['unknown_arm'] = True
        self.record['guard_owners'] = [{'address': '0x10000', 'type': 1, 'length': 4}]
        self.studio.driver.hwbp_response['results'] = [{'dr0': '0x10000', 'dr7': '0x1'}]
        with self.assertRaisesRegex(ValueError, '중단점이 남아'):
            self.capture.stop(self.record)
        self.assertEqual(self.record['state'], 'guard')
        self.assertNotIn('ShutdownCapture', self.create_names())

    def test_unrelated_enabled_debug_slot_does_not_block_safe_shutdown(self):
        self.record['guard_owners'] = [{'address': '0x10000', 'type': 1, 'length': 4}]
        self.studio.driver.hwbp_response['results'] = [{'dr0': '0x20000', 'dr7': '0x1'}]
        self.capture.stop(self.record)
        self.assertEqual(self.record['state'], 'stopped')
        self.assertEqual(self.create_names(), ['StopCapture'])
        self.assertEqual(struct.unpack_from('<I', self.studio.ring, 28)[0], 3)
        self.assertTrue(self.capture.view(PID)['stats']['retained_guard'])
        self.assertNotIn('ShutdownCapture', self.create_names())

    def test_stop_pid_reuse_never_calls_remove_or_shutdown(self):
        self.add_breakpoint()
        self.studio.key = 'reused'
        with self.assertRaises(ValueError):
            self.capture.stop(self.record)
        self.assertEqual(self.studio.driver.io, [])

    def test_stop_unknown_control_never_removes_breakpoints_or_unregisters_handler(self):
        self.add_breakpoint()
        self.record['control_uncertain'] = True
        with self.assertRaisesRegex(ValueError, '불확실'):
            self.capture.stop(self.record)
        self.assertEqual(self.studio.driver.io, [])
        self.assertIn('bp', self.studio.breakpoints)

    def test_arm_duplicate_and_invalid_alignment_rejected_before_new_control(self):
        self.add_breakpoint()
        with patch.object(self.capture, 'prepare', return_value=self.record):
            with self.assertRaisesRegex(ValueError, '이미'):
                self.capture.arm(PID, 0x10000, 1, 4)
            with self.assertRaisesRegex(ValueError, '정렬'):
                self.capture.arm(PID, 0x10001, 1, 4)
            with self.assertRaises(ValueError):
                self.capture.arm(PID, 0x10000, 0, 4)
        self.assertEqual(self.create_names(), [])

    def test_arm_prepares_owned_handler_before_returning_ready_for_kernel_set(self):
        with patch.object(self.capture, 'prepare', return_value=self.record):
            result = self.capture.arm(PID, 0x10000, 1, 4)
        self.assertEqual(result['state'], 'capturing')
        self.assertEqual(self.create_names(), ['StartCapture'])
        self.assertEqual(self.record['guard_owners'], [{'address': '0x10000', 'type': 1, 'length': 4}])


if __name__ == '__main__':
    unittest.main()
