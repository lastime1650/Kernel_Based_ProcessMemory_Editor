"""Loaded-image analysis and user-thread calls. Target access is IOCTL-only."""
from collections import OrderedDict
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import struct
import subprocess
import threading
import time
import uuid

import studio_extensions as E
import memory_images as M

OPERATIONS = ['image_catalog','image_functions','image_function_detail','dll_load_verified',
              'dll_load_check','function_call','function_calls','function_call_query','function_call_release']
MAX_FUNCTIONS=20000
MAX_PDB_BYTES=256*1024*1024
MAX_DLL_BYTES=64*1024*1024

def number(value):
    if isinstance(value,bool):raise ValueError('숫자를 입력하세요')
    text=str(value).strip()
    return int(text,16 if text.lower().startswith('0x') else 10)

def hx(value):return f'0x{value:X}'

def same_image_path(image,path):
    actual=str(image.get('path',''))
    if actual.startswith(('\\\\?\\','\\??\\')):actual=actual[4:]
    return bool(actual) and str(PureWindowsPath(actual)).casefold()==str(PureWindowsPath(path)).casefold()

class CachedImageReader:
    def __init__(self,studio,pid,base):self.studio,self.pid,self.base,self.size,self.pages=studio,pid,base,0x40000000,{}
    def read_bytes(self,pid,start,size):
        if pid!=self.pid or start<self.base or size<1 or start+size>self.base+self.size:raise ValueError('이미지 읽기 범위 오류')
        pieces=[]
        while size:
            page=start&~4095;offset=start-page
            if page not in self.pages:
                count=min(4096,self.base+self.size-page)
                self.pages[page]=self.studio.read_bytes(pid,page,count)
            count=min(size,len(self.pages[page])-offset)
            if count<=0:raise ValueError('이미지 페이지 크기 오류')
            pieces.append(self.pages[page][offset:offset+count]);size-=count;start+=count
        return b''.join(pieces)

class Symbols:
    def __init__(self,root=None):
        self.root=Path(root or Path(__file__).parent/'symbols').resolve()
        self.root.mkdir(parents=True,exist_ok=True);self.lock=threading.RLock();self.cache={}
        self.helper=Path(__file__).parent/'native/pdb_symbols.exe'
        self.dia=Path(r'C:\Program Files\Microsoft Visual Studio\2022\Professional\DIA SDK\bin\amd64\msdia140.dll')
        index=self.root/'index.json'
        if index.is_file():
            try:
                keys=json.loads(index.read_text(encoding='utf-8'))[:8]
            except (ValueError,OSError,KeyError,TypeError):keys=[]
            for key in keys:
                try:
                    if not isinstance(key,str) or len(key)!=32 or any(c not in '0123456789abcdef' for c in key):continue
                    record=json.loads((self.root/(key+'.json')).read_text(encoding='utf-8'))
                    if Path(record['path']).is_file():self.cache[key]=record
                except (ValueError,OSError,KeyError,TypeError):continue
    @staticmethod
    def digest(path):
        value=hashlib.sha256()
        with path.open('rb') as stream:
            for piece in iter(lambda:stream.read(1024*1024),b''):value.update(piece)
        return value.hexdigest()
    def persist(self):
        temp=self.root/'index.tmp'
        temp.write_text(json.dumps(list(self.cache)),encoding='utf-8');temp.replace(self.root/'index.json')
    def load(self,path,display_name=None,owned=False):
        path=Path(path).resolve()
        if path.suffix.lower()!='.pdb' or not path.is_file() or not 0<path.stat().st_size<=MAX_PDB_BYTES:raise ValueError('256MB 이하 PDB 파일이 필요합니다')
        if not self.helper.is_file() or not self.dia.is_file():raise ValueError('DIA PDB 분석 도구를 찾을 수 없습니다')
        digest=self.digest(path)
        upgrade=None
        with self.lock:
            for key,record in self.cache.items():
                if record['sha256']==digest:
                    if 'structures' in record:return self.public(key,record)
                    upgrade=key
                    if display_name is None:display_name=record['name']
                    owned=record.get('owned',owned)
            if len(self.cache)>=8 and not upgrade:raise ValueError('PDB는 최대 8개입니다. 사용하지 않는 PDB를 제거하세요')
        try:
            run=subprocess.run([str(self.helper),str(path),str(self.dia)],capture_output=True,timeout=30,
                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except (OSError,subprocess.TimeoutExpired) as exc:raise ValueError('PDB 분석 도구 실행 실패 또는 시간 초과') from exc
        if len(run.stdout)>32*1024*1024:raise ValueError('PDB 분석 결과가 32MB 상한을 초과했습니다')
        try:result=json.loads(run.stdout)
        except (ValueError,UnicodeError):raise ValueError(f'PDB 분석 도구 오류: 0x{run.returncode&0xffffffff:08X}')
        if run.returncode or not result.get('success'):raise ValueError('PDB 분석 실패: '+str(result.get('error','DIA 오류')))
        if self.digest(path)!=digest:raise ValueError('분석 중 PDB 파일이 변경되었습니다')
        result.update(name=display_name or path.name,sha256=digest,path=str(path),owned=owned,guid=result['guid'].strip('{}').lower())
        key=upgrade or uuid.uuid4().hex
        with self.lock:
            for existing,record in self.cache.items():
                if record['sha256']==digest and 'structures' in record:return self.public(existing,record)
            if len(self.cache)>=8 and not upgrade:raise ValueError('PDB 저장 상한 초과')
            self.cache[key]=result
            try:
                (self.root/(key+'.json')).write_text(json.dumps(result,ensure_ascii=False),encoding='utf-8')
                self.persist()
            except OSError:
                self.cache.pop(key,None)
                (self.root/(key+'.json')).unlink(missing_ok=True)
                raise
        return self.public(key,result)
    def public(self,key,r):return {'id':key,'name':r['name'],'guid':r['guid'],'age':r['age'],'sha256':r['sha256'],
        'function_count':len(r['functions']),'structure_count':len(r.get('structures',[])),'truncated':r.get('truncated',False)}
    def get(self,key):
        with self.lock:
            if key not in self.cache:raise ValueError('PDB를 먼저 추가하세요')
            return self.cache[key]
    def list(self):
        with self.lock:return [self.public(k,r) for k,r in self.cache.items()]
    def remove(self,key):
        with self.lock:
            record=self.cache.pop(key,None)
            try:self.persist()
            except OSError:
                if record:self.cache[key]=record
                raise
        if record:
            path=Path(record['path'])
            if record.get('owned') and path.parent==self.root:path.unlink(missing_ok=True)
            (self.root/(key+'.json')).unlink(missing_ok=True)
        return record is not None

class Workbench:
    def __init__(self,studio,symbols=None):
        self.studio=studio;self.symbols=symbols or Symbols();self.lock=threading.RLock()
        self.analyses=OrderedDict();self.calls=OrderedDict();self.loads=OrderedDict()
    def images(self,pid,regions=None,cancelled=lambda:False):
        identity=self.studio.identity(pid)
        result=regions if regions is not None else self.studio.operate('regions',{'pid':pid,'max_results':50000})
        if not result.get('success'):raise ValueError(result.get('error','커널 메모리 맵 조회 실패'))
        rows,stats=M.discover(self.studio,pid,result['results'],cancelled)
        if self.studio.identity(pid)!=identity:raise ValueError('이미지 조회 중 프로세스가 교체되었습니다')
        return {'success':True,'pid':pid,'process_start_key':identity,'results':rows,'count':len(rows),'total':len(rows),
            'truncated':result.get('truncated',False) or cancelled(),'cancelled':cancelled(),'discovery':stats,
            'note':'MEM_IMAGE와 커밋된 읽기 가능 영역 시작의 PE 헤더를 함께 조회합니다. PE 헤더 발견은 로더 등록이나 전체 코드 존재를 보장하지 않습니다.'}
    def find_image(self,pid,base):
        catalog=self.images(pid)
        image=next((x for x in catalog['results'] if number(x['base'])==base),None)
        if not image:raise ValueError('현재 이미지 목록에서 선택한 이미지 또는 PE 헤더를 찾을 수 없습니다')
        return image,catalog['process_start_key']
    @staticmethod
    def codeview(pe):
        rva,size=pe.directory(6)
        if not rva:return None
        if size%28 or size>28*4096:raise ValueError('PE Debug 디렉터리 크기 오류')
        records=pe.read(rva,size)
        for i in range(0,size,28):
            _,_,_,_,kind,length,address,_=struct.unpack_from('<IIHHIIII',records,i)
            if kind!=2 or not address or length<24:continue
            data=pe.read(address,min(length,4096))
            if data[:4]==b'RSDS':return {'guid':str(uuid.UUID(bytes_le=data[4:20])),
                'age':struct.unpack_from('<I',data,20)[0], 'pdb_path':data[24:].split(b'\0',1)[0].decode('utf-8',errors='replace')}
        return None
    def analyze(self,pid,base,pdb_id=''):
        image,identity=self.find_image(pid,base)
        reader=CachedImageReader(self.studio,pid,base);pe=E.LoadedPE(reader,pid,base);reader.size=pe.size
        header=reader.read_bytes(pid,base,4096);offset=struct.unpack_from('<I',header,0x3c)[0]
        optional=struct.unpack_from('<H',header,offset+20)[0];section_count=struct.unpack_from('<H',header,offset+6)[0]
        if section_count>96:raise ValueError('PE 섹션 개수 오류')
        sections=[]
        if section_count:
            table=pe.read(offset+24+optional,section_count*40)
            for i in range(section_count):
                part=table[i*40:(i+1)*40];size,rva,raw=struct.unpack_from('<III',part,8)
                sections.append({'name':part[:8].split(b'\0',1)[0].decode('ascii',errors='replace'),
                    'start':rva,'end':min(pe.size,rva+max(size,raw)),'executable':bool(struct.unpack_from('<I',part,36)[0]&0x20000000)})
        def executable(rva):return next((s['name'] for s in sections if s['executable'] and s['start']<=rva<s['end']),None)
        rows={};data_exports=[]
        def add(rva,end=0,source='unwind',name=''):
            section=executable(rva)
            if not section or not 0<rva<pe.size:return None
            if rva not in rows and len(rows)>=MAX_FUNCTIONS:return None
            row=rows.setdefault(rva,{'address':hx(base+rva),'rva':hx(rva),'name':f'sub_{base+rva:X}',
                'aliases':[],'size':0,'section':section,'sources':[],'parameters':'미확인 — 행을 선택해 명령어 분석',
                'parameter_source':'unknown','signature':'','typed_parameters':[],'call_compatible':None,'forwarder':''})
            if source not in row['sources']:row['sources'].append(source)
            if end>rva:row['size']=max(row['size'],min(end,pe.size)-rva)
            if name:
                if name not in row['aliases']:row['aliases'].append(name)
                if row['name'].startswith('sub_') or source=='pdb_function':row['name']=name
            return row
        exports=pe.exports();forwarders=[]
        for entry in exports:
            if entry['forwarder']:forwarders.append(entry);continue
            rva=number(entry['rva'])
            if not add(rva,source='export',name=entry['name'] or f'ordinal_{entry["ordinal"]}'):
                data_exports.append(entry)
        rva,length=pe.directory(3);unwind_truncated=False
        if rva and pe.width==8:
            if length%12:raise ValueError('x64 함수 범위 테이블 형식 오류')
            unwind_truncated=length>MAX_FUNCTIONS*12
            for begin,end,_ in struct.iter_unpack('<III',pe.read(rva,min(length,MAX_FUNCTIONS*12))):
                if not 0<begin<end<=pe.size:raise ValueError('x64 함수 범위가 이미지 밖입니다')
                add(begin,end)
        entry=struct.unpack_from('<I',header,offset+40)[0]
        add(entry,source='entry')
        cv=self.codeview(pe);symbol_record=None
        if pdb_id:
            symbol_record=self.symbols.get(pdb_id)
            if not cv or cv['guid'].lower()!=symbol_record['guid'].lower() or cv['age']!=symbol_record['age']:
                raise ValueError('PDB GUID·Age가 로드된 이미지와 일치하지 않습니다')
            for symbol in symbol_record['functions']:
                row=add(symbol['rva'],symbol['rva']+symbol.get('size',0),symbol['source'],symbol['name'])
                if not row or not symbol.get('types_available'):continue
                params=symbol['parameters'];ret=symbol.get('return',{})
                row['typed_parameters']=params;row['parameter_source']='pdb';row['calling_convention']=symbol.get('calling_convention')
                row['parameters']=', '.join(p['type']+' '+p.get('name','') for p in params) or '(void)'
                row['signature']=ret.get('type','unknown')+' '+row['name']+'('+row['parameters']+')'
                row['call_compatible']=(not symbol.get('requires_object') and len(params)<=1 and
                    all(p['kind'] in ('integer','pointer') and 0<p.get('size',0)<=8 for p in params) and
                    ret.get('kind') in ('integer','void') and ret.get('size',0)<=4)
        if self.studio.identity(pid)!=identity:raise ValueError('분석 중 프로세스가 교체되었습니다')
        key=uuid.uuid4().hex
        record={'id':key,'pid':pid,'identity':identity,'base':base,'size':pe.size,'bits':pe.width*8,
            'image':image,'header_sha256':hashlib.sha256(header).hexdigest(),'codeview':cv,'pdb_id':pdb_id,
            'rows':sorted(rows.values(),key=lambda r:number(r['rva'])),'forwarders':forwarders,'data_exports':data_exports,
            'created':time.time(),'truncated':unwind_truncated or len(rows)>=MAX_FUNCTIONS or bool(symbol_record and symbol_record.get('truncated'))}
        with self.lock:
            self.analyses[key]=record
            while len(self.analyses)>16:self.analyses.popitem(last=False)
        return self.table(record)
    def table(self,record):return {'success':True,'analysis_id':record['id'],'pid':record['pid'],
        'process_start_key':record['identity'],'image':record['image'],'bits':record['bits'],'codeview':record['codeview'],
        'pdb_id':record['pdb_id'],'count':len(record['rows']),'results':record['rows'],
        'forwarders':record['forwarders'],'data_exports':record['data_exports'],'truncated':record['truncated'],
        'note':'Export·엔트리·x64 unwind 범위를 기반으로 식별합니다. PDB 없는 leaf 함수는 누락될 수 있습니다.'}
    def checked_analysis(self,key,pid=None):
        with self.lock:
            record=self.analyses.get(str(key))
            if not record:raise ValueError('이미지를 다시 분석하세요. 분석 기록이 없습니다')
        if pid is not None and record['pid']!=pid:raise ValueError('현재 선택 프로세스와 분석 대상이 다릅니다')
        if self.studio.identity(record['pid'])!=record['identity']:raise ValueError('분석 이후 프로세스가 교체되었습니다')
        self.find_image(record['pid'],record['base'])
        header=self.studio.read_bytes(record['pid'],record['base'],4096)
        if hashlib.sha256(header).hexdigest()!=record['header_sha256']:raise ValueError('분석 이후 이미지가 변경되었습니다. 다시 분석하세요')
        return record
    def detail(self,key,addr,pid):
        record=self.checked_analysis(key,pid)
        row=next((r for r in record['rows'] if number(r['address'])==addr),None)
        if not row:raise ValueError('선택한 함수가 분석 결과에 없습니다')
        import function_views as V
        following=min((number(r['address']) for r in record['rows'] if number(r['address'])>addr),
                      default=record['base']+record['size'])
        extent=row['size'] or min(512,following-addr)
        count=min(V.MAX_BYTES,extent,record['base']+record['size']-addr)
        raw=self.studio.read_bytes(record['pid'],addr,count)
        views=V.analyze(raw,addr,record['bits'],row['name'],
                        {number(r['address']):r['name'] for r in record['rows']})
        used=set(views['argument_registers'])
        hint='진입 시 읽는 인자 후보: '+(', '.join(x for x in ('RCX','RDX','R8','R9') if x in used) or '확인되지 않음')
        if self.studio.identity(pid)!=record['identity']:raise ValueError('상세 분석 중 프로세스가 교체되었습니다')
        views['graph']['range_known']=bool(row['size'])
        views['graph']['byte_limit_applied']=extent>count
        if extent>count:views['graph']['notes'].append('함수 바이트 조회 상한 적용')
        if not row['size']:views['graph']['notes'].append('함수 크기가 미확인되어 제한된 추정 범위를 분석했습니다')
        if row.get('parameter_source')=='pdb' and row.get('signature'):
            views['pseudocode']['pdb_signature']=row['signature']
        return {'success':True,'function':row,**views,'data_hex':raw.hex(),
            'argument_hint':hint if record['bits']==64 else 'x86 매개변수는 PDB 형식을 참고하세요',
            'note':'Capstone 결과는 정적 추정이며 매개변수 개수·형식의 보장이 아닙니다.'}
    def load(self,pid,path,wait_ms=8000):
        path=Path(path).resolve()
        if path.suffix.lower()!='.dll' or not path.is_file():raise ValueError('존재하는 DLL 절대 경로가 필요합니다')
        with path.open('rb') as stream:header=stream.read(4096)
        if header[:2]!=b'MZ' or len(header)<64:raise ValueError('PE DLL 파일이 아닙니다')
        offset=struct.unpack_from('<I',header,60)[0]
        if not 64<=offset<=len(header)-26 or header[offset:offset+4]!=b'PE\0\0':raise ValueError('PE 헤더 오류')
        if struct.unpack_from('<H',header,offset+4)[0]!=0x8664 or not struct.unpack_from('<H',header,offset+22)[0]&0x2000:
            raise ValueError('현재 DLL 로드는 x64 DLL을 지원합니다')
        process=self.studio.driver.query_process_extended(pid)
        if not process.get('success') or process.get('is_wow64'):raise ValueError('대상은 살아 있는 x64 프로세스여야 합니다')
        encoded=str(path).encode('mbcs',errors='strict')
        if len(encoded)>518:raise ValueError('DLL 경로가 ABI 길이 상한을 초과했습니다')
        identity=self.studio.identity(pid);catalog=self.images(pid)
        existing=next((r for r in catalog['results'] if same_image_path(r,path)),None)
        if existing:return {'success':True,'loaded':True,'already_loaded':True,'image':existing,'results':[existing]}
        key=uuid.uuid4().hex;record={'id':key,'pid':pid,'identity':identity,'path':str(path),'name':path.name,'state':'requested'}
        with self.lock:
            self.loads[key]=record
            while len(self.loads)>32:self.loads.popitem(last=False)
        if self.studio.identity(pid)!=identity:raise ValueError('DLL 요청 전에 프로세스가 교체되었습니다')
        response=self.studio.driver.register_dll(pid,str(path));record['driver_response']=response
        if not response.get('success'):
            record['state']='failed';return dict(response,load_id=key,loaded=False,automatic_retry=False)
        deadline=time.monotonic()+min(max(wait_ms,0),15000)/1000
        while True:
            result=self.check_load(key,pid)
            if result['loaded'] or time.monotonic()>=deadline:return result
            time.sleep(.25)
    def check_load(self,key,pid):
        with self.lock:record=self.loads.get(key)
        if not record or record['pid']!=pid:raise ValueError('현재 대상의 DLL 로드 기록이 없습니다')
        if self.studio.identity(pid)!=record['identity']:raise ValueError('DLL 로드 중 프로세스가 교체되었습니다')
        catalog=self.images(pid)
        matches=[r for r in catalog['results'] if same_image_path(r,record['path'])]
        image=matches[0] if len(matches)==1 else None
        record['state']='loaded' if image else 'unverified'
        return {'success':bool(image),'loaded':bool(image),'load_id':key,'state':record['state'],'image':image,
            'driver_response':record.get('driver_response',{}),'results':[image] if image else [],'automatic_retry':False,
            'note':'MEM_IMAGE에서 요청 경로와 일치하는 이미지가 확인됐습니다.' if image else '요청 경로와 일치하는 이미지가 아직 확인되지 않았습니다. 재로드 대신 확인을 갱신하세요.'}
    def call(self,pid,key,addr,parameter=0,wait_ms=0):
        if not 0<=parameter<=0xffffffffffffffff or not 0<=wait_ms<=1000:raise ValueError('64비트 인자 또는 대기 시간 오류')
        with self.studio.driver._lock:
            version=self.studio.driver.get_driver_status()
            if not version.get('success') or (version.get('major_version',0),version.get('minor_version',0))<(2,2):
                raise ValueError('함수 호출에는 드라이버 2.2 이상이 필요합니다. 현재 장치를 다시 확인하세요')
            record=self.checked_analysis(key,pid)
            row=next((r for r in record['rows'] if number(r['address'])==addr),None)
            if not row or row['forwarder']:raise ValueError('선택한 이미지의 직접 함수 시작 주소가 필요합니다')
            if record['bits']!=64 or row['call_compatible'] is False:raise ValueError('단일 정수/포인터 인자와 32비트/void 반환 형식에 맞지 않습니다. DLL 진입 함수를 사용하세요')
            with self.lock:
                if sum(not r.get('released',False) and r.get('call_id') not in (None,'0') for r in self.calls.values())>=30:raise ValueError('추적 중인 호출을 해제한 뒤 실행하세요')
            response=self.studio.driver.create_function_call(pid,number(record['identity']),addr,parameter,wait_ms)
            call=dict(response,pid=pid,identity=record['identity'],name=row['name'],function_address=hx(addr),
                parameter=hx(parameter),analysis_id=key,created=time.time(),released=False,automatic_retry=False)
            local_id=uuid.uuid4().hex;call['id']=local_id
            with self.lock:
                self.calls[local_id]=call
                while len(self.calls)>128:
                    old=next((k for k,r in self.calls.items() if r.get('released') or r.get('call_id') in (None,'0')),None)
                    if old is None:break
                    self.calls.pop(old)
            return dict(call)
    def query_call(self,key,pid,wait_ms=0):
        with self.lock:record=self.calls.get(str(key))
        if not record or record['pid']!=pid:raise ValueError('현재 대상의 호출 기록이 없습니다')
        if record['released']:return dict(record)
        if record.get('call_id') in (None,'0'):return dict(record)
        response=self.studio.driver.query_function_call(number(record['call_id']),wait_ms)
        with self.lock:
            # PID/start key are echoed by the referenced thread record, not lookup by reused TID.
            if response.get('success') and (response.get('pid')!=pid or response.get('process_start_key')!=record['identity']):
                raise ValueError('커널 호출 기록의 소유 정보가 다릅니다')
            if response.get('success'):
                record.update(response);record['query_error']=''
            else:
                # A failed/short response contains zero output fields. Do not
                # lose the known owner, TID, CallId or last confirmed result.
                for field in ('success','transport_ok','packet_valid','error_code','result_status','execution_unknown'):
                    if field in response:record[field]=response[field]
                record['query_error']=response.get('error') or response.get('result_status') or '조회 실패'
            return dict(record)
    def release_call(self,key,pid):
        with self.lock:record=self.calls.get(str(key))
        if not record or record['pid']!=pid:raise ValueError('현재 대상의 호출 기록이 없습니다')
        if record['released']:return dict(record,success=True)
        if record.get('call_id') in (None,'0'):
            with self.lock:record['released']=True
            return dict(record,success=True,note='로컬 기록을 정리했습니다. 추적할 커널 CallId가 없습니다.')
        response=self.studio.driver.release_function_call(number(record['call_id']))
        if response.get('success'):
            with self.lock:record['released']=True
        return dict(record,release_response=response,success=response.get('success',False))
    def shutdown(self):
        with self.lock:records=list(self.calls.values())
        for record in records:
            if not record.get('released') and record.get('call_id') not in (None,'0'):
                try:self.release_call(record['id'],record['pid'])
                except Exception:pass # Device close performs kernel-side cleanup as well.
    def operate(self,operation,args):
        pid=number(args.get('pid',0))
        if not 0<pid<=0xffffffff:raise ValueError('선택한 프로세스 PID가 필요합니다')
        if operation=='image_catalog':return self.images(pid)
        if operation=='image_functions':return self.analyze(pid,number(args['base']),str(args.get('pdb_id','')))
        if operation=='image_function_detail':return self.detail(args['analysis_id'],number(args['address']),pid)
        if operation=='dll_load_verified':return self.load(pid,args['path'],number(args.get('wait_ms',8000)))
        if operation=='dll_load_check':return self.check_load(args['id'],pid)
        if operation=='function_call':return self.call(pid,args['analysis_id'],number(args['address']),number(args.get('parameter',0)),number(args.get('wait_ms',0)))
        if operation=='function_calls':
            with self.lock:return {'success':True,'results':[dict(r) for r in self.calls.values() if r['pid']==pid]}
        if operation=='function_call_query':return self.query_call(args['id'],pid,number(args.get('wait_ms',0)))
        if operation=='function_call_release':return self.release_call(args['id'],pid)
        raise ValueError('이미지 작업 이름 오류')

