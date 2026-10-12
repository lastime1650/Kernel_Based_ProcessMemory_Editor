"""Public symbols are optional and must match the current image identity."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import public_symbols as P
from image_workbench import Symbols,Workbench
from test_image_workbench import FIXTURE,Studio

ID={'pdb_path':r'C:\build\module.pdb','guid':'01234567-89ab-cdef-0123-456789abcdef','age':10}


class Response(io.BytesIO):
    def __init__(self,data,headers=None):
        super().__init__(data);self.headers=headers or {}


class PublicSymbolsTests(unittest.TestCase):
    def test_symbol_server_key_uses_guid_and_hex_age_with_basename(self):
        name,key,url=P.identity(ID)
        self.assertEqual(name,'module.pdb');self.assertEqual(key,'0123456789ABCDEF0123456789ABCDEFA')
        self.assertEqual(url,P.SERVER+'/module.pdb/'+key+'/module.pdb')
        for invalid in ({'pdb_path':'bad?.pdb'},{'guid':'invalid'},{'age':-1},{'age':True},{'age':0x100000000}):
            with self.assertRaises(ValueError):P.identity(dict(ID,**invalid))

    def test_download_and_cached_reuse_each_validate_identity(self):
        payload=P.MSF7+b'fixture';opened=[];validated=[]
        def opener(request,**kwargs):opened.append(request.full_url);return Response(payload,{'Content-Length':str(len(payload))})
        def validate(path):validated.append(path);return {'id':'checked'}
        with tempfile.TemporaryDirectory() as root:
            first=P.fetch(ID,root,validate,opener);second=P.fetch(ID,root,validate,opener)
            self.assertFalse(first['cached']);self.assertTrue(second['cached'])
            self.assertEqual(len(opened),1);self.assertEqual(len(validated),2)
            self.assertEqual(validated[0].read_bytes(),payload)

    def test_404_does_not_require_pdb_or_leave_temporary_files(self):
        def opener(*args,**kwargs):raise HTTPError(P.identity(ID)[2],404,'missing',{},None)
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError,'PDB 없이'):P.fetch(ID,root,lambda p:None,opener)
            self.assertFalse(list(Path(root).rglob('*.download')))

    def test_bad_format_size_limit_and_incomplete_download_do_not_validate(self):
        for payload,headers,limit in ((b'<html>error</html>',{},1000),(P.MSF7,{'Content-Length':'500'},100),
                                      (P.MSF7+b'x'*64,{},64),(P.MSF7,{'Content-Length':'128'},1024)):
            validated=[]
            with tempfile.TemporaryDirectory() as root,patch.object(P,'MAX_BYTES',limit):
                with self.assertRaises(ValueError):P.fetch(ID,root,lambda p:validated.append(p),lambda *a,**k:Response(payload,headers))
                self.assertFalse(validated);self.assertFalse([p for p in Path(root).rglob('*.pdb') if p.is_file()])
                self.assertFalse(list(Path(root).rglob('*.download')))

    def test_mismatched_download_is_removed(self):
        def reject(path):raise ValueError('GUID mismatch')
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError,'GUID'):P.fetch(ID,root,reject,lambda *a,**k:Response(P.MSF7))
            self.assertFalse([p for p in Path(root).rglob('*.pdb') if p.is_file()])

    def test_dia_identity_is_checked_before_cache_persistence_and_on_reuse(self):
        with tempfile.TemporaryDirectory() as root:
            symbols=Symbols(root)
            with self.assertRaisesRegex(ValueError,'GUID'):symbols.load(FIXTURE.with_suffix('.pdb'),expected=ID)
            self.assertFalse(symbols.cache);self.assertFalse(list(Path(root).glob('*.json')))
            actual=symbols.load(FIXTURE.with_suffix('.pdb'))
            with self.assertRaisesRegex(ValueError,'GUID'):symbols.load(FIXTURE.with_suffix('.pdb'),expected=ID)
            expected={'guid':actual['guid'],'age':actual['age']}
            self.assertEqual(symbols.load(FIXTURE.with_suffix('.pdb'),expected=expected)['id'],actual['id'])

    def test_process_change_before_download_validation_does_not_load_symbols(self):
        with tempfile.TemporaryDirectory() as root:
            studio=Studio();symbols=Symbols(root);work=Workbench(studio,symbols)
            def fetch(codeview,root,validate):
                studio.key='replacement';return validate(FIXTURE.with_suffix('.pdb'))
            with patch('image_workbench.PS.fetch',side_effect=fetch):
                with self.assertRaisesRegex(ValueError,'변경'):work.public_symbols(88,studio.base)
            self.assertFalse(symbols.cache);self.assertFalse(studio.driver.calls)

    def test_image_codeview_without_current_process_change_is_passed_to_validator(self):
        with tempfile.TemporaryDirectory() as root:
            studio=Studio();symbols=Symbols(root);work=Workbench(studio,symbols)
            def fetch(codeview,root,validate):return validate(FIXTURE.with_suffix('.pdb'))
            with patch('image_workbench.PS.fetch',side_effect=fetch):reply=work.public_symbols(88,studio.base)
            self.assertTrue(reply['success']);self.assertEqual(symbols.get(reply['id'])['guid'],reply['guid'])
            self.assertFalse(studio.driver.calls)


if __name__=='__main__':unittest.main()
