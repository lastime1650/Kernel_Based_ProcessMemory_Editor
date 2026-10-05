"""Memory-scan semantics and lifecycle regressions using fake kernel transport."""
import math
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
import csv
from scan_workspace import Session, Workspace, validate, aob, matches, FORMATS


class FakeStudio:
    def __init__(self, size=196608):
        self.base = 0x10000
        self.memory = bytearray(size)
        self.key = '12345678901234567890'
        self.driver = self
        self.reads = []; self.writes = []; self.fail_pages = set()
        self.truncated = False; self.alive = True; self.hook = None

    def identity(self, pid):
        if not self.alive: raise ValueError('대상 프로세스가 종료되었습니다')
        return self.key

    def operate(self, operation, args):
        assert operation == 'regions'
        return dict(success=True, truncated=self.truncated, results=[dict(address=hex(self.base), size=len(self.memory),
                    readable=True, writable=True, executable=False, guarded=False, state='0x1000')])

    def read_bytes(self, pid, addr, size):
        self.reads.append((addr, size))
        if self.hook: self.hook(addr, size)
        if addr < self.base or addr+size > self.base+len(self.memory): raise OSError('범위 밖')
        if any(addr < p+4096 and addr+size > p for p in self.fail_pages): raise OSError('읽기 실패')
        return bytes(self.memory[addr-self.base:addr-self.base+size])

    def write_process_memory(self, pid, addr, raw):
        self.writes.append((addr,raw)); self.memory[addr-self.base:addr-self.base+len(raw)] = raw
        return dict(success=True, bytes_written=len(raw))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.studio = FakeStudio()
        self.s = Session(self.studio, 42, Path(self.temp.name))
        self.event = threading.Event()

    def tearDown(self): self.temp.cleanup()

    def new(self, **args):
        return self.s.new(dict(data_type='uint32',condition='exact',value='100',**args) if not any(k in args for k in ('data_type','condition','value')) else
                          {'data_type':'uint32','condition':'exact','value':'100',**args}, self.event, {})

    def next(self, condition, **args):
        return self.s.next({'data_type':self.s.cfg['data_type'], 'condition':condition, **args}, self.event, {})

    def put(self, offset, value, fmt='<I'): struct.pack_into(fmt, self.studio.memory, offset, value)

    def test_new_results_show_addresses_and_exact_values(self):
        self.put(8,100); self.put(20,100)
        self.assertEqual(self.new()['count'],2)
        r=self.s.results(); self.assertEqual([x['address'] for x in r['results']],['0x0000000000010008','0x0000000000010014'])
        self.assertEqual(r['results'][0]['current_value'],'100'); self.assertEqual(r['transport'],'kernel_ioctl')

    def test_live_never_changes_next_baseline(self):
        self.put(8,100); self.new(); self.put(8,123)
        row=self.s.results()['results'][0]
        self.assertEqual((row['current_value'],row['scanned_value'],row['previous_value']),('123','100','100'))
        self.assertTrue(row['changed'])
        self.assertEqual(self.next('increased')['count'],1)
        row=self.s.results()['results'][0]; self.assertEqual((row['scanned_value'],row['previous_value']),('123','100'))
        self.put(8,111); self.assertEqual(self.next('decreased')['count'],1)

    def test_unknown_preserves_more_than_50000_and_all_pages(self):
        self.studio.memory=bytearray(1048576)
        r=self.new(condition='unknown',value='')
        self.assertEqual(r['count'],262144); self.assertFalse(r['partial'])
        rows=self.s.results(2622,100,False)['results']; self.assertEqual(len(rows),44)
        self.assertEqual(rows[-1]['address'],f'0x{self.studio.base+1048572:016X}')
        self.put(900000,777); self.assertEqual(self.next('increased')['count'],1)
        self.assertEqual(self.s.results()['results'][0]['address'],f'0x{self.studio.base+900000:016X}')

    def test_rescan_keeps_candidates_and_updates_baseline(self):
        self.put(0,100);self.put(4,100);self.new();self.put(0,101)
        self.assertEqual(self.next('rescan')['count'],2)
        self.assertEqual(self.next('unchanged')['count'],2)

    def test_all_numeric_conditions(self):
        for i,v in enumerate((10,20,30)): self.put(i*4,v)
        for cond, value,value2,expected in [('exact','20','',1),('not_equal','0','',3),('greater','20','',1),('less','20','',len(self.studio.memory)//4-2),
                                         ('greater_equal','20','',2),('less_equal','10','',len(self.studio.memory)//4-2),('between','10','20',2)]:
            with self.subTest(cond=cond): self.assertEqual(self.new(condition=cond,value=value,value2=value2)['count'],expected)
        self.new(condition='between',value='10',value2='30');self.assertEqual(self.next('between',value='15',value2='25')['count'],1)

    def test_uint64_is_a_string_without_precision_loss(self):
        self.put(0,18446744073709551615,'<Q');self.new(data_type='uint64',value='18446744073709551615')
        self.assertEqual(self.s.results()['results'][0]['current_value'],'18446744073709551615')

    def test_float32_exact_rounds_input_to_storage_precision(self):
        self.put(0,30.123,'<f');self.assertEqual(self.new(data_type='float32',value='30.123')['count'],1)

    def test_changed_compares_bits_including_nan_and_signed_zero(self):
        self.studio.memory=bytearray(4096);self.put(0,float('nan'),'<f');self.put(4,0.0,'<f')
        self.new(data_type='float32',condition='unknown',value='');self.put(4,-0.0,'<f')
        self.assertEqual(self.next('changed')['count'],1)
        self.assertEqual(self.s.results()['results'][0]['address'],'0x0000000000010004')

    def test_chunk_seam_unaligned_and_overlapping_aob(self):
        self.studio.memory[65533:65541]=b'\xde\xad\xaa\xef\xde\xad\xab\xef'
        self.assertEqual(self.new(data_type='aob',value='DE AD A? EF',alignment=1)['count'],2)
        self.assertEqual(self.next('unchanged')['count'],2)
        self.studio.memory[65535]=0xbc; self.assertEqual(self.next('changed')['count'],1)

    def test_pattern_overlap_no_duplicate(self):
        self.studio.memory[65534:65540]=b'AAAAAA'
        self.assertEqual(self.new(data_type='aob',value='41 41 41',alignment=1)['count'],4)

    def test_utf8_and_utf16_and_new_length_validation(self):
        for kind,text,offset in [('utf8','안녕 World',65530),('utf16','Hello 세계',120)]:
            raw=text.encode('utf-8' if kind=='utf8' else 'utf-16-le');self.studio.memory[offset:offset+len(raw)]=raw
            self.assertEqual(self.new(data_type=kind,value=text)['count'],1)
            self.assertEqual(self.s.results()['results'][0]['current_value'],text)
            with self.assertRaises(ValueError):self.next('exact',value='x')

    def test_structure_multi_field_and_unknown_relative(self):
        fields=[dict(name='hp',offset=0,type='uint32',value='123'),dict(name='coins',offset=8,type='uint64',condition='between',value='500',value2='600')]
        self.put(100,123);self.put(108,550,'<Q')
        self.assertEqual(self.new(data_type='structure',fields=fields,alignment=4)['count'],1)
        row=self.s.results()['results'][0];self.assertEqual(row['current_value'],'hp=123 · coins=550')
        self.put(100,124);self.put(108,551,'<Q');self.assertEqual(self.next('increased')['count'],1)
        self.next('rescan');self.assertEqual(self.next('unchanged')['count'],1)

    def test_structure_unknown_and_relative_need_no_input_values(self):
        self.studio.memory=bytearray(4096)
        fields=[dict(name='hp',offset=0,type='uint32',condition='exact'),dict(name='ignored',offset=4,type='uint32',condition='ignore')]
        self.assertEqual(self.new(data_type='structure',fields=fields,condition='unknown',alignment=8)['count'],512)
        self.put(0,100);self.assertEqual(self.next('increased')['count'],1)
        self.s.save({'address':hex(self.studio.base)})
        saved=self.s.results()['saved'][0];self.assertEqual(saved['current_value'],'hp=100 · ignored=0')

    def test_structure_saved_import_works_after_type_change(self):
        fields=[dict(name='hp',offset=0,type='uint32',value='100')]
        self.put(0,100);self.new(data_type='structure',fields=fields)
        self.s.save({'address':hex(self.studio.base)});saved=next(iter(self.s.saved.values()))
        self.new();self.s.saved.clear()
        self.s.save({k:saved[k] for k in ('address','data_type','width','fields')})
        self.assertEqual(self.s.results()['saved'][0]['current_value'],'hp=100')

    def test_new_cancellation_rolls_back_previous_search(self):
        self.put(0,100);self.new();before=self.s.results(live=False)
        self.studio.hook=lambda *_:self.event.set()
        with self.assertRaises(InterruptedError):self.new(condition='unknown')
        self.studio.hook=None;self.event.clear();after=self.s.results(live=False)
        self.assertEqual((before['count'],before['results'],before['scan_count']),(after['count'],after['results'],after['scan_count']))

    def test_next_cancellation_rolls_back_baseline(self):
        self.new(condition='unknown');self.put(0,222);self.studio.hook=lambda *_:self.event.set()
        with self.assertRaises(InterruptedError):self.next('changed')
        self.studio.hook=None;self.event.clear();self.assertEqual(self.next('changed')['count'],1)
        self.assertEqual(self.s.results()['results'][0]['previous_value'],'0')

    def test_bad_new_keeps_existing_candidates(self):
        self.put(0,100);self.new()
        for bad in [dict(value='4294967296'),dict(condition='between',value='10',value2='1'),dict(alignment=3),dict(start_address='0x20',end_address='0x10')]:
            with self.assertRaises((ValueError,struct.error)):self.new(**bad)
            self.assertEqual(self.s.count,1)

    def test_float32_overflow_is_an_input_error(self):
        with self.assertRaisesRegex(ValueError,'float32'):
            self.new(data_type='float32',value='1e300')

    def test_every_numeric_type_reads_and_refines_unaligned_value(self):
        for kind,(fmt,_) in FORMATS.items():
            with self.subTest(kind=kind):
                self.studio.memory=bytearray(8192)
                value=42.5 if kind.startswith('float') else 42 if kind.startswith('uint') else -42
                self.put(4093,value,fmt)
                self.assertEqual(self.new(data_type=kind,value=str(value),alignment=1)['count'],1)
                self.put(4093,value+1,fmt)
                self.assertEqual(self.next('increased')['count'],1)

    def test_snapshot_release_failure_is_fatal_without_retries(self):
        self.put(0,100);self.new();calls=[]
        def failure(*args):
            calls.append(args);raise RuntimeError('IOCTL snapshot release failed')
        self.studio.read_bytes=failure
        with self.assertRaises(RuntimeError):self.new(condition='unknown')
        self.assertEqual(len(calls),1);self.assertEqual(self.s.count,1)
        self.assertTrue(self.s.invalid)

    def test_close_waits_for_inflight_write(self):
        self.put(0,100);self.new();self.s.save({'address':hex(self.studio.base)})
        key=next(iter(self.s.saved));entered=threading.Event();release=threading.Event();done=threading.Event()
        original=self.studio.write_process_memory
        def delayed(*args):entered.set();release.wait(1);return original(*args)
        self.studio.write_process_memory=delayed;self.s.edit(key,{'frozen':True})
        writer=threading.Thread(target=self.s.freeze);writer.start();self.assertTrue(entered.wait(1))
        def close():
            self.s.closed=True
            with self.s.write_lock:done.set()
        closer=threading.Thread(target=close);closer.start();self.assertFalse(done.wait(.05));release.set()
        writer.join();closer.join();self.assertTrue(done.is_set())

    def test_budget_is_transparent_and_does_not_limit_hits(self):
        r=self.new(condition='unknown',max_bytes=65536);self.assertEqual(r['count'],16384)
        self.assertTrue(r['partial']);self.assertTrue(r['budget_exhausted']);self.assertEqual(r['bytes_scanned'],65536)
        self.assertTrue(self.next('unchanged')['partial'])

    def test_read_hole_never_fabricates_or_bridges_values(self):
        self.studio.fail_pages={self.studio.base+4096};self.studio.memory[4095]=0xab;self.studio.memory[8192]=0xcd
        r=self.new(data_type='aob',value='AB CD');self.assertEqual(r['count'],0);self.assertEqual(r['failed_bytes'],4096)
        self.assertTrue(r['partial'])

    def test_unaligned_range_failure_keeps_readable_page_prefix(self):
        self.studio.memory=bytearray(8192);self.studio.fail_pages={self.studio.base+4096}
        r=self.new(data_type='uint8',condition='unknown',alignment=1,start_address=hex(self.studio.base+7))
        self.assertEqual(r['count'],4089);self.assertEqual(r['bytes_scanned'],4089);self.assertEqual(r['failed_bytes'],4096)

    def test_next_read_failure_keeps_neighbors(self):
        self.studio.memory=bytearray(8192);self.new(condition='unknown');self.studio.fail_pages={self.studio.base+4096}
        r=self.next('unchanged');self.assertEqual(r['count'],1024);self.assertEqual(r['failed_candidates'],1024)

    def test_identity_change_stops_before_target_reads_and_writes(self):
        self.put(0,100);self.new();self.s.save({'address':hex(self.studio.base)})
        key=next(iter(self.s.saved));self.s.edit(key,{'frozen':True});self.studio.key='other';self.studio.reads.clear()
        with self.assertRaises(ValueError):self.next('unchanged')
        self.s.freeze();self.assertEqual(self.studio.reads,[]);self.assertEqual(self.studio.writes,[])
        self.assertFalse(self.s.saved[key]['frozen'])

    def test_truncated_map_cannot_claim_complete_scan(self):
        self.studio.truncated=True
        with self.assertRaises(ValueError):self.new()

    def test_save_dedup_edit_verify_and_conflict(self):
        self.put(0,100);self.new();r=self.s.save({'addresses':[hex(self.studio.base)]*2});self.assertEqual(r['added'],1)
        key=next(iter(self.s.saved));before=self.s.results()['saved'][0]['data_hex']
        self.s.edit(key,{'value':'123','expected_hex':before,'description':'HP'});self.assertEqual(struct.unpack_from('<I',self.studio.memory)[0],123)
        with self.assertRaises(ValueError):self.s.edit(key,{'value':'321','expected_hex':before})
        self.assertEqual(len(self.studio.writes),1)

    def test_string_edit_preserves_size_and_numeric_freeze(self):
        self.studio.memory[:5]=b'Hello';self.new(data_type='utf8',value='Hello');self.s.save({'address':hex(self.studio.base)})
        key=next(iter(self.s.saved));before=self.s.results()['saved'][0]['data_hex']
        with self.assertRaises(ValueError):self.s.edit(key,{'value':'Longer','expected_hex':before})
        with self.assertRaises(ValueError):self.s.edit(key,{'frozen':True})
        self.s.edit(key,{'value':'World','expected_hex':before});self.assertEqual(self.studio.memory[:5],b'World')

    def test_freeze_and_remove_are_bounded(self):
        self.put(0,100);self.new();self.s.save({'address':hex(self.studio.base)})
        key=next(iter(self.s.saved));self.s.edit(key,{'frozen':True});self.put(0,200);self.s.freeze();self.assertEqual(struct.unpack_from('<I',self.studio.memory)[0],100)
        self.s.edit(key,{'remove':True});self.s.freeze();self.assertEqual(len(self.studio.writes),1)

    def test_paging_and_live_failures(self):
        self.put(0,100);self.new();self.studio.fail_pages={self.studio.base}
        self.assertTrue(self.s.results()['results'][0]['error'])
        for page,size in [(0,10),(1,501)]:
            with self.assertRaises(ValueError):self.s.results(page,size)

    def test_scope_and_addresses(self):
        self.put(4,100);self.put(12,100)
        self.assertEqual(self.new(start_address=hex(self.studio.base+8),end_address=hex(self.studio.base+16))['count'],1)
        self.assertEqual(self.new(scope='executable')['count'],0)


class BrowseTests(unittest.TestCase):
    setUp = ScanTests.setUp
    tearDown = ScanTests.tearDown
    new = ScanTests.new
    next = ScanTests.next
    put = ScanTests.put

    def view(self, **args):
        return self.s.build_view(args, self.event, {})['view_id']

    def test_reverse_address_pages_cover_all_candidates_without_duplicates(self):
        self.new(condition='unknown');key=self.view(sort='address',descending=True)
        rows=self.s.results(1,500,False,key)['results']+self.s.results(2,500,False,key)['results']
        addresses=[int(r['address'],16) for r in rows]
        self.assertEqual(addresses,[self.studio.base+len(self.studio.memory)-4-i*4 for i in range(1000)])
        self.assertFalse(self.s.view['indexed'])

    def test_global_filter_finds_address_beyond_first_page(self):
        self.new(condition='unknown');address=self.studio.base+120000
        key=self.view(filter=hex(address));r=self.s.results(9,50,False,key)
        self.assertEqual(r['filtered_count'],1);self.assertEqual(r['count'],49152)
        self.assertEqual(r['page'],1);self.assertEqual(int(r['results'][0]['address'],16),address)

    def test_global_numeric_sort_preserves_all_ten_types(self):
        for kind,(fmt,width) in FORMATS.items():
            values=[9,2,7] if kind.startswith('uint') else [9,-2,7]
            if kind=='uint64':values=[18446744073709551615,9007199254740993,9007199254740992]
            if kind=='int64':values=[9223372036854775807,-9223372036854775808,-9007199254740993]
            for i,value in enumerate(values):self.put(i*width,value,fmt)
            self.new(data_type=kind,condition='unknown',end_address=hex(self.studio.base+len(values)*width))
            for column in ('current_value','scanned_value','previous_value'):
                key=self.view(sort=column)
                rows=self.s.results(1,50,False,key)['results']
                cast=float if kind.startswith('float') else int
                self.assertEqual([cast(r['scanned_value']) for r in rows],sorted(values),(kind,column))

    def test_float_sort_handles_infinities_nan_and_both_zero_signs(self):
        values=[float('nan'),float('inf'),-0.0,-9.,float('-inf'),0.0,9.]
        for i,value in enumerate(values):self.put(i*8,value,'<d')
        self.new(data_type='float64',condition='unknown',end_address=hex(self.studio.base+56))
        rows=self.s.results(live=False,view_id=self.view(sort='current_value'))['results']
        actual=[float(r['scanned_value']) for r in rows]
        self.assertEqual(actual[:-1],[float('-inf'),-9.,0.,0.,9.,float('inf')]);self.assertTrue(math.isnan(actual[-1]))

    def test_global_filter_and_sort_never_mutate_baseline_or_read_target(self):
        self.put(8,100);self.put(8000,100);self.new();before=self.s.results(live=False)['results'];self.studio.reads.clear()
        key=self.view(filter='100',sort='previous_value',descending=True)
        rows=self.s.results(live=False,view_id=key)['results']
        self.assertEqual(rows,list(reversed(before)));self.assertEqual(self.studio.reads,[])
        self.put(8,101);self.assertEqual(self.next('increased')['count'],1)

    def test_live_value_change_does_not_reorder_snapshot_view(self):
        for off,value in [(0,3),(4,1),(8,2)]:self.put(off,value)
        self.new(condition='unknown',end_address=hex(self.studio.base+12));key=self.view(sort='current_value')
        self.put(4,999);r=self.s.results(view_id=key)
        self.assertEqual([int(x['address'],16) for x in r['results']],[self.studio.base+4,self.studio.base+8,self.studio.base])
        self.assertEqual(r['results'][0]['current_value'],'999');self.assertEqual(r['results'][0]['scanned_value'],'1')

    def test_cancel_view_preserves_previous_view_and_results(self):
        self.new(condition='unknown');key=self.view(filter='0x10000');self.event.set()
        with self.assertRaises(InterruptedError):self.view(filter='0')
        self.event.clear();self.assertEqual(self.s.results(live=False,view_id=key)['filtered_count'],1)

    def test_cancel_during_view_transaction_rolls_back_index(self):
        self.new(condition='unknown');key=self.view(filter='0x10000');original=self.s.check;calls=[]
        def check(event):
            calls.append(1)
            if len(calls)==5:event.set()
            original(event)
        self.s.check=check
        with self.assertRaises(InterruptedError):self.view(sort='current_value')
        self.s.check=original;self.event.clear()
        self.assertEqual(self.s.results(live=False,view_id=key)['results'][0]['address'],'0x0000000000010000')

    def test_new_or_next_invalidates_old_view(self):
        self.put(0,100);self.new();key=self.view();self.next('unchanged')
        with self.assertRaises(ValueError):self.s.results(view_id=key)
        self.assertIsNone(self.s.view)

    def test_bad_view_preserves_previous_view(self):
        self.put(0,100);self.new();key=self.view()
        for args in ({'filter':'a'*257},{'sort':'arbitrary sql'},{'descending':'true'}):
            with self.assertRaises(ValueError):self.view(**args)
            self.assertEqual(self.s.view['id'],key)

    def test_filtered_zero_has_one_empty_page(self):
        self.new(condition='unknown');r=self.s.results(8,50,False,self.view(filter='not present'))
        self.assertEqual((r['filtered_count'],r['pages'],r['page'],r['results']),(0,1,1,[]))

    def test_string_global_filter_casefold_and_byte_order(self):
        self.studio.memory[:4]=b'AbCd';self.studio.memory[8000:8004]=b'ABCD'
        self.new(data_type='aob',value='41 ?? ?? ??');key=self.view(filter='abcd',sort='data_hex',descending=True)
        rows=self.s.results(live=False,view_id=key)['results'];self.assertEqual(len(rows),0)
        key=self.view(filter='41 42 43 44');self.assertEqual(self.s.results(live=False,view_id=key)['filtered_count'],1)

    def test_capacity_is_checked_before_memory_reads_and_saves_atomically(self):
        self.new(condition='unknown');self.s.save({'addresses':[hex(self.studio.base+i*4) for i in range(255)]})
        self.studio.reads.clear()
        with self.assertRaisesRegex(ValueError,'남은 공간 1개'):self.s.save({'addresses':[hex(self.studio.base+1100),hex(self.studio.base+1104)]})
        self.assertEqual(len(self.s.saved),255);self.assertEqual(self.studio.reads,[])
        self.s.save({'addresses':[hex(self.studio.base),hex(self.studio.base+1100)]})
        self.assertEqual(self.s.summary()['saved_remaining'],0)
        self.assertEqual(self.s.save({'address':hex(self.studio.base)})['added'],0)

    def test_reread_saved_returns_new_expected_bytes_without_mutating_baseline(self):
        self.put(0,100);self.new();self.s.save({'address':hex(self.studio.base)});key=next(iter(self.s.saved))
        self.put(0,101);r=self.s.read_saved(key)
        self.assertEqual(r['row']['current_value'],'101');self.assertEqual(self.s.saved[key]['baseline_hex'],'64000000')
        self.s.edit(key,{'value':'999','expected_hex':r['row']['data_hex']})
        self.assertEqual(struct.unpack_from('<I',self.studio.memory)[0],999)

    def test_reread_unreadable_address_then_recovery(self):
        self.put(0,100);self.new();self.s.save({'address':hex(self.studio.base)});key=next(iter(self.s.saved))
        self.studio.fail_pages.add(self.studio.base);self.assertTrue(self.s.read_saved(key)['row']['error'])
        self.studio.fail_pages.clear();self.assertFalse(self.s.read_saved(key)['row']['error'])

    def test_full_csv_export_covers_more_than_one_page_with_precise_values(self):
        for i in range(700):self.put(i*8,9007199254740993+i,'<Q')
        self.new(data_type='uint64',condition='unknown',end_address=hex(self.studio.base+5600))
        r=self.s.export_csv({},self.event,{})
        with self.s.exports[r['export_id']].open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
        self.assertEqual(len(rows),700);self.assertEqual(rows[-1]['current_value'],str(9007199254740993+699))
        self.assertTrue(all(x['value_basis']=='scan_snapshot' for x in rows))

    def test_csv_export_honors_global_filter_and_sort(self):
        self.put(0,100);self.put(8,100);self.new();key=self.view(sort='address',descending=True)
        r=self.s.export_csv({'view_id':key},self.event,{})
        with self.s.exports[r['export_id']].open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
        self.assertEqual([x['address'] for x in rows],['0x0000000000010008','0x0000000000010000'])

    def test_cancel_csv_removes_partial_file(self):
        self.new(condition='unknown');original=self.s.check;calls=[]
        def check(event):
            calls.append(1)
            if len(calls)==4:event.set()
            original(event)
        self.s.check=check
        with self.assertRaises(InterruptedError):self.s.export_csv({},self.event,{})
        self.assertEqual(self.s.exports,{});self.assertFalse(list(Path(self.temp.name).glob('*.csv')))


class ManagerTests(unittest.TestCase):
    def setUp(self):self.studio=FakeStudio();self.ws=Workspace(self.studio)
    def tearDown(self):self.ws.shutdown()
    def wait(self,key):
        for _ in range(100):
            r=self.ws.status(key)
            if r['state'] not in ('queued','running'):return r
            time.sleep(.01)
        self.fail('worker timeout')

    def test_async_job_lifecycle_and_reset_preserves_saved(self):
        s=self.ws.create(42)['session_id'];self.studio.memory[:4]=struct.pack('<I',100)
        job=self.ws.submit(s,'new',{'data_type':'uint32','condition':'exact','value':'100'})
        self.assertEqual(self.wait(job['job_id'])['state'],'completed')
        self.assertIsNone(self.ws.get(s).job)
        self.ws.invoke(s,'save',{'address':hex(self.studio.base)})
        self.ws.invoke(s,'reset',{});r=self.ws.invoke(s,'results',{});self.assertEqual(r['count'],0);self.assertEqual(len(r['saved']),1)
        self.ws.remove(s);self.assertFalse(any(self.ws.root.glob('*.sqlite')))

    def test_session_and_job_limits_cleanup(self):
        ids=[self.ws.create(i+1)['session_id'] for i in range(4)]
        with self.assertRaises(ValueError):self.ws.create(5)
        self.ws.remove(ids[0]);self.assertTrue(self.ws.create(5)['success'])

    def test_cancel_queued_or_running_and_preserve_state(self):
        s=self.ws.create(42)['session_id'];self.studio.hook=lambda *_:time.sleep(.01)
        job=self.ws.submit(s,'new',{'data_type':'uint32','condition':'unknown'})
        self.ws.cancel(job['job_id']);self.assertEqual(self.wait(job['job_id'])['state'],'cancelled')
        self.assertEqual(self.ws.get(s).count,0)

    def test_validation_before_enqueue(self):
        s=self.ws.create(42)['session_id']
        with self.assertRaises(ValueError):self.ws.submit(s,'new',{'data_type':'aob','condition':'exact','value':'??'})
        self.assertEqual(len(self.ws.jobs),0)

    def test_cancel_completed_job_reports_already_completed_without_mutating_job(self):
        sid=self.ws.create(42)['session_id'];job=self.ws.submit(sid,'new',{'condition':'unknown'})
        self.assertEqual(self.wait(job['job_id'])['state'],'completed')
        r=self.ws.cancel(job['job_id']);self.assertFalse(r['accepted']);self.assertEqual(r['disposition'],'already_completed')
        self.assertFalse(self.ws.status(job['job_id'])['cancel_requested'])

    def test_view_export_jobs_do_not_change_scan_round_and_cleanup_csv(self):
        sid=self.ws.create(42)['session_id'];job=self.ws.submit(sid,'new',{'condition':'unknown'})
        self.wait(job['job_id']);key=self.ws.submit(sid,'view',{'filter':'0x10000'})['job_id'];self.assertEqual(self.wait(key)['state'],'completed')
        key=self.ws.submit(sid,'export',{'view_id':self.ws.get(sid).view['id']})['job_id'];self.assertEqual(self.wait(key)['state'],'completed')
        self.assertEqual(self.ws.get(sid).round,1);self.assertTrue(list(self.ws.root.glob('*.csv')))
        self.ws.remove(sid);self.assertFalse(list(self.ws.root.iterdir()))

    def test_progress_poll_and_completion_keep_long_scan_session_alive(self):
        sid=self.ws.create(42)['session_id'];s=self.ws.get(sid)
        self.studio.hook=lambda *_:time.sleep(.02)
        job=self.ws.submit(sid,'new',{'data_type':'uint32','condition':'unknown'})
        s.touched=0;self.ws.status(job['job_id']);self.assertGreater(s.touched,0)
        self.assertEqual(self.wait(job['job_id'])['state'],'completed');self.assertGreater(s.touched,0)


if __name__=='__main__':unittest.main()
