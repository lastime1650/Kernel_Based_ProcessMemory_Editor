"""Evidence and bounded reads for typed views; no target process is accessed."""
import struct
import unittest
from unittest.mock import patch

import decompiler_metadata as DM
from image_workbench import CachedImageReader


class MetadataTests(unittest.TestCase):
    def test_utf16_literal_requires_known_wide_parameter(self):
        base=0x140000000;start=base+0x1000;target=base+0x3000;iat=base+0x4000
        raw=b'\x48\x8d\x0d'+struct.pack('<i',target-(start+7))+b'\xff\x25'+struct.pack('<i',iat-(start+13))
        record={'pid':7,'base':base,'size':0x5000,'sections':[
            {'start':0x3000,'end':0x3100,'readable':True,'writable':False,'executable':False}]}
        class Reader:
            def read_bytes(self,pid,address,size):return 'kernel32.dll\0'.encode('utf-16le')+bytes(size-26)
        self.assertFalse(DM.collect(raw,start,64,record,Reader())['strings'])
        record['import_symbols']={iat:DM.import_symbol({'name':'GetModuleHandleW','module':'kernel32.dll'},64)}
        item=DM.collect(raw,start,64,record,Reader())['strings'][target]
        self.assertEqual((item['encoding'],item['value']),('utf-16le','kernel32.dll'))

    def test_callee_inference_reads_only_executable_image_and_exact_row_extent(self):
        start=0x1000;leaf=0x1100;raw=b'\xe8'+struct.pack('<i',leaf-(start+5))+b'\xc3'
        class Reader:
            def __init__(self):self.reads=[]
            def read_bytes(self,pid,address,size):self.reads.append((address,size));return bytes.fromhex('8D0411C3')[:size]
        record={'pid':7,'base':0x1000,'size':0x1000,'sections':[{'executable':True,'start':0,'end':0x1000}],
                'rows':[{'address':hex(leaf),'size':4,'name':'leaf'}]}
        metadata={'functions':{},'imports':{},'notes':[]};reader=Reader()
        DM.infer_callees(raw,start,64,record,reader,metadata)
        self.assertEqual(reader.reads,[(leaf,4)]);self.assertTrue(metadata['functions'][leaf]['valid'])
        self.assertTrue(metadata['function']['valid']);self.assertEqual(len(metadata['function']['parameters']),2)
        record['sections'][0]['executable']=False;reader=Reader();metadata={'functions':{},'imports':{},'notes':[]}
        DM.infer_callees(raw,start,64,record,reader,metadata);self.assertFalse(reader.reads)

    def test_verified_pdb_scalar_types_and_unsupported_abis(self):
        symbol={'name':'typed','types_available':True,'calling_convention':0,
                'parameters':[DM.type_record('float','float',4)],
                'return':DM.type_record('int32_t','integer',4)}
        self.assertTrue(DM.pdb_prototype(symbol,64)['valid'])
        self.assertEqual(DM.pdb_prototype(symbol,64)['calling_convention'],'win64')
        self.assertEqual(DM.pdb_prototype(symbol,64)['pdb_calling_convention'],0)
        self.assertFalse(DM.pdb_prototype(symbol,32)['valid'])
        for extra in ({'requires_object':True},{'variadic':True},{'calling_convention':12},
                      {'return':DM.type_record('S','aggregate',16)},
                      {'parameters':[DM.type_record('S','aggregate',16)]}):
            self.assertFalse(DM.pdb_prototype(dict(symbol,**extra),64)['valid'])

    def test_imported_float_member_uses_position_two_after_implicit_object(self):
        raw='??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@M@Z'
        full=('public: class std::basic_ostream<char,struct std::char_traits<char> > & __ptr64 __cdecl '
              'std::basic_ostream<char,struct std::char_traits<char> >::operator<<(float) __ptr64')
        with patch.object(DM,'undecorate',return_value=full):
            result=DM.import_symbol({'name':raw,'module':'MSVCP140.dll'},64)
        self.assertTrue(result['valid']);self.assertEqual(result['name'],'std::ostream::operator<<')
        self.assertEqual([p['kind'] for p in result['parameters']],['pointer','float'])
        self.assertEqual(result['parameters'][0]['name'],'this')
        with patch.object(DM,'undecorate',return_value=full.replace('(float)','(double)')):
            self.assertFalse(DM.import_symbol({'name':raw},64)['valid'])
        with patch.object(DM,'undecorate',return_value=raw):
            self.assertFalse(DM.import_symbol({'name':raw},64)['valid'])

    def test_ordinary_system_name_requires_known_crt_module_and_win64(self):
        self.assertTrue(DM.import_symbol({'name':'system','module':'api-ms-win-crt-process-l1-1-0.dll'},64)['valid'])
        self.assertFalse(DM.import_symbol({'name':'system','module':'arbitrary.dll'},64)['valid'])
        self.assertFalse(DM.import_symbol({'name':'system','module':'ucrtbase.dll'},32)['valid'])
        self.assertTrue(DM.import_symbol({'name':'memcpy','module':'ucrtbase.dll'},64)['valid'])
        self.assertFalse(DM.import_symbol({'name':'memcpy','module':'arbitrary.dll'},64)['valid'])

    def test_literals_only_from_address_references_in_immutable_readable_sections(self):
        base=0x140000000;start=base+0x1000;target=base+0x3000
        raw=b'\x48\x8D\x15'+struct.pack('<i',target-(start+7))+b'\xC3'
        record={'pid':7,'base':base,'size':0x5000,'sections':[
            {'start':0x3000,'end':0x3100,'readable':True,'writable':False,'executable':False}]}
        class Reader:
            def __init__(self):self.reads=[]
            def read_bytes(self,pid,address,size):
                self.reads.append((pid,address,size));return b'hello\n\0'+bytes(size-7)
        reader=Reader();result=DM.collect(raw,start,64,record,reader)
        self.assertEqual(result['strings'][target]['value'],'hello\n')
        self.assertEqual(reader.reads,[(7,target,256)])
        record['sections'][0]['writable']=True
        reader=Reader();self.assertFalse(DM.collect(raw,start,64,record,reader)['strings']);self.assertFalse(reader.reads)
        record['sections'][0]['writable']=False
        record['import_symbols']={target:{'name':'iat'}}
        reader=Reader();self.assertFalse(DM.collect(raw,start,64,record,reader)['strings']);self.assertFalse(reader.reads)
        # Numeric RIP loads can coincidentally contain ASCII; never call them strings.
        load=b'\x48\x8B\x15'+struct.pack('<i',target-(start+7))+b'\xC3'
        record['import_symbols']={};reader=Reader()
        self.assertFalse(DM.collect(load,start,64,record,reader)['strings']);self.assertFalse(reader.reads)

    def test_missing_terminator_invalid_bytes_and_read_failures_keep_address(self):
        base=0x140000000;start=base+0x1000;target=base+0x3000
        raw=b'\x48\x8D\x15'+struct.pack('<i',target-(start+7))+b'\xC3'
        record={'pid':7,'base':base,'size':0x5000,'sections':[
            {'start':0x3000,'end':0x3100,'readable':True,'writable':False,'executable':False}]}
        for data in (b'A'*256,b'\xff\0',b'\x01\0',b'\0'):
            class Reader:
                def read_bytes(self,*args):return data
            self.assertFalse(DM.collect(raw,start,64,record,Reader())['strings'])
        class FailedReader:
            def read_bytes(self,*args):raise ValueError('unmapped')
        self.assertTrue(DM.collect(raw,start,64,record,FailedReader())['notes'])

    def test_metadata_reader_page_budget_and_image_bounds(self):
        class Studio:
            def __init__(self):self.reads=[]
            def read_bytes(self,pid,address,size):self.reads.append((address,size));return bytes(size)
        studio=Studio();reader=CachedImageReader(studio,7,0x100000,max_pages=2);reader.size=0x5000
        self.assertEqual(len(reader.read_bytes(7,0x100FFF,2)),2)
        self.assertEqual(len(studio.reads),2)
        with self.assertRaisesRegex(ValueError,'상한'):reader.read_bytes(7,0x102000,1)
        for args in ((8,0x100000,1),(7,0xFFFFF,1),(7,0x104FFF,2)):
            with self.assertRaises(ValueError):reader.read_bytes(*args)
        self.assertEqual(len(studio.reads),2)

    def test_workbench_passes_verified_selected_function_return_type(self):
        from test_image_workbench import Studio,EmptySymbols
        from image_workbench import Workbench,number
        studio=Studio();symbols=EmptySymbols();workbench=Workbench(studio,symbols)
        original=workbench.analyze(88,studio.base)
        row=next(r for r in original['results'] if r['name']=='HelloWorld')
        symbols.record={**original['codeview'],'functions':[{'rva':number(row['rva']),
            'size':row['size'],'name':'TypedHello','source':'pdb_function','types_available':True,
            'calling_convention':0,'parameters':[],'return':DM.type_record('int32_t','integer',4)}]}
        analysis=workbench.analyze(88,studio.base,'pdb')
        selected=next(r for r in analysis['results'] if r['name']=='TypedHello')
        detail=workbench.detail(analysis['analysis_id'],number(selected['address']),88)
        self.assertIn('int32_t TypedHello(void)',detail['pseudocode']['code'])
        self.assertEqual(detail['function']['return']['type'],'int32_t')
        self.assertFalse(studio.driver.calls)


if __name__=='__main__':unittest.main()
