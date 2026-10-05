"""Typed views, resumable projects, verified change sets and sampled timelines."""
import copy
import json
import math
from pathlib import Path
import re
import sqlite3
import struct
import threading
import time
import uuid
from contextlib import closing
from memory_editor import FORMATS, encode, location, number
from change_journal import Journal
from request_scheduler import scope

TYPES=list(FORMATS)+['pointer','utf8','utf16','bytes','struct']
NAME=re.compile(r'^[A-Za-z_][A-Za-z0-9_:$<> ]{0,119}$')
KEY=re.compile(r'^[a-f0-9]{32}$')

def atomic(path,data):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(data,ensure_ascii=False),encoding='utf-8');temp.replace(path)

def definitions(value,bits=64):
    if not isinstance(value,list) or not 1<=len(value)<=64: raise ValueError('구조체 정의는 1~64개입니다')
    result={}
    for definition in value:
        name=str(definition['name'])
        if not NAME.fullmatch(name) or name in result: raise ValueError('구조체 이름이 중복되었거나 올바르지 않습니다')
        size=number(definition['size'])
        fields=definition['fields']
        if not 1<=size<=1048576 or not isinstance(fields,list) or not 1<=len(fields)<=128: raise ValueError('구조체 크기 / 필드 상한을 확인하세요')
        names=set();out=[]
        for field in fields:
            f=copy.deepcopy(field);f['name']=str(f['name']);f['offset']=number(f['offset']);f['count']=number(f.get('count',1))
            if not NAME.fullmatch(f['name']) or f['name'] in names: raise ValueError('필드 이름을 확인하세요')
            names.add(f['name'])
            if f['type'] not in TYPES or not 0<=f['offset']<size or not 1<=f['count']<=256: raise ValueError('필드 형식 / 위치 / 배열 길이를 확인하세요')
            if f['type'] in ('utf8','utf16','bytes'):
                f['length']=number(f.get('length',16))
                if not 1<=f['length']<=4096 or (f['type']=='utf16' and f['length']%2): raise ValueError('문자열 / 바이트 길이를 확인하세요')
            out.append(f)
        result[name]={'name':name,'size':size,'fields':out}
    def width(f):
        kind=f['type']
        if kind in FORMATS:return struct.calcsize('<'+FORMATS[kind])
        if kind=='pointer':return bits//8
        if kind=='struct':
            if f.get('ref') not in result: raise ValueError('중첩 구조체 정의가 없습니다')
            return result[f['ref']]['size']
        return f['length']
    def check(name,chain):
        if name in chain: raise ValueError('인라인 구조체가 순환합니다. 포인터로 정의하세요')
        for f in result[name]['fields']:
            w=width(f);stride=number(f.get('stride',w));f['stride']=stride
            if stride<w or f['offset']+stride*(f['count']-1)+w>result[name]['size']: raise ValueError('필드가 구조체 크기를 벗어납니다')
            if f['type']=='pointer' and f.get('ref') and f['ref'] not in result: raise ValueError('포인터 대상 구조체가 없습니다')
            if f['type']=='struct': check(f['ref'],chain+[name])
    for name in result: check(name,[])
    return result

def codec(kind,value,width,bits):
    if kind in FORMATS or kind=='pointer': return encode(kind,value,bits)
    if kind=='bytes':raw=bytes.fromhex(str(value))
    elif kind in ('utf8','utf16'):
        terminator=b'\0' if kind=='utf8' else b'\0\0'
        raw=str(value).encode('utf-8' if kind=='utf8' else 'utf-16-le')+terminator
        if len(raw)>width:raise ValueError('문자열과 끝 표시가 필드 크기를 초과합니다')
        raw=raw.ljust(width,b'\0')
    else:raise ValueError('편집 형식을 확인하세요')
    if len(raw)!=width: raise ValueError('입력 바이트 길이가 필드 길이와 다릅니다')
    return raw

def decoded(kind,raw,bits):
    if kind=='pointer':return f'0x{int.from_bytes(raw,"little"):X}'
    if kind in FORMATS:
        value=struct.unpack('<'+FORMATS[kind],raw)[0]
        return str(value)
    if kind=='utf16':
        end=next((i for i in range(0,len(raw),2) if raw[i:i+2]==b'\0\0'),len(raw))
        return raw[:end].decode('utf-16-le',errors='replace')
    if kind=='utf8':return raw.split(b'\0')[0].decode('utf-8',errors='replace')
    return raw.hex(' ').upper()

class Suite:
    def __init__(self,studio,root=None):
        self.studio=studio;self.root=Path(root or Path(__file__).parent/'workspaces')
        self.root.mkdir(parents=True,exist_ok=True);self.lock=threading.RLock()
        self.previews={};self.timelines={};self.timeline_locks={};self.views={};self.limit=64
        self.journal=Journal(studio,self.root/'journal')
        self.journal.install()
        path=self.root/'structures.json'
        try:self.schemas=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError):self.schemas=[]
    def owner(self,pid,identity=None):
        key=self.studio.identity(pid)
        if identity is not None and str(identity)!=key:raise ValueError('대상 프로세스가 종료되거나 교체되었습니다')
        return key
    def bits(self,pid):
        r=self.studio.driver.query_process_extended(pid)
        if not r.get('success'):raise ValueError('커널 아키텍처 조회 실패')
        return 32 if r['is_wow64'] else 64
    def save_schemas(self,body):
        values=list(definitions(body['definitions'],number(body.get('bits',64))).values())
        with self.lock:atomic(self.root/'structures.json',values);self.schemas=values
        return {'success':True,'definitions':values}
    def view(self,body):
        pid=number(body['pid']);identity=self.owner(pid,body.get('identity'));bits=self.bits(pid)
        defs=definitions(body.get('definitions') or self.schemas,bits);root=str(body['schema'])
        if root not in defs:raise ValueError('구조체 정의를 선택하세요')
        base=self.resolve(pid,body.get('locator') or {'address':body['address'],'identity':identity},identity)
        rows=[];seen=set();bytes_read=0
        def walk(name,addr,path,depth):
            nonlocal bytes_read
            if depth>12:raise ValueError('중첩 깊이 상한은 12입니다')
            if (name,addr) in seen:
                rows.append({'path':path,'address':f'0x{addr:X}','type':'cycle','error':'순환 포인터','editable':False});return
            seen.add((name,addr))
            for f in defs[name]['fields']:
                for index in range(f['count']):
                    target=addr+f['offset']+index*f['stride'];kind=f['type']
                    label=path+'.'+f['name']+(f'[{index}]' if f['count']>1 else '')
                    if len(rows)>=2048:raise ValueError('표시 필드 상한은 2,048개입니다')
                    if kind=='struct':walk(f['ref'],target,label,depth+1);continue
                    width=bits//8 if kind=='pointer' else struct.calcsize('<'+FORMATS[kind]) if kind in FORMATS else f['length']
                    bytes_read+=width
                    if bytes_read>1048576:raise ValueError('구조체 읽기 상한은 1MiB입니다')
                    row={'path':label,'address':f'0x{location(target):X}','type':kind,'width':width,'editable':not f.get('readonly',False)}
                    try:
                        raw=self.studio.read_bytes(pid,target,width)
                        row.update(value=decoded(kind,raw,bits),data_hex=raw.hex())
                    except Exception as exc:row.update(error=str(exc),editable=False)
                    rows.append(row)
                    if kind=='pointer' and f.get('ref') and body.get('follow',True) and row.get('data_hex'):
                        pointer=int.from_bytes(raw,'little')
                        if pointer:
                            try:walk(f['ref'],location(pointer),label+'->',depth+1)
                            except ValueError as exc:rows.append({'path':label+'->','address':f'0x{pointer:X}','type':'error','error':str(exc),'editable':False})
            seen.remove((name,addr))
        walk(root,base,root,0);self.owner(pid,identity)
        key=None
        if not body.get('_validate_only'):
          with self.lock:
            self.views={k:v for k,v in self.views.items() if time.monotonic()-v['created']<900}
            while len(self.views)>=32:self.views.pop(next(iter(self.views)))
            key=uuid.uuid4().hex;self.views[key]={'body':dict(copy.deepcopy(body),definitions=list(defs.values()),identity=identity),'created':time.monotonic()}
        return {'success':True,'view_id':key,'pid':pid,'identity':identity,'bits':bits,'address':f'0x{base:X}','results':rows,'sampled_at':time.time()}
    def check_field(self,pid,item):
        with self.lock:record=self.views.get(item.get('view_id'))
        if not record or time.monotonic()-record['created']>900 or number(record['body']['pid'])!=pid:raise ValueError('구조체 화면이 만료되었습니다. 다시 읽으세요')
        fresh=self.view(dict(record['body'],_validate_only=True))
        row=next((r for r in fresh['results'] if r['path']==item['path']),None)
        if not row or not row.get('editable') or row['address']!=item['address'] or row['type']!=item['type'] or row['width']!=item['width']:raise ValueError('구조체 경로나 포인터 대상이 변경되었습니다. 다시 읽으세요')
    def capture_locator(self,pid,address,identity,images):
        addr=location(address)
        image=next((r for r in images if number(r['base'])<=addr<number(r['base'])+r['size']),None)
        if image:return {'module':image['name'],'path':image.get('path',''),'offset':f'0x{addr-number(image["base"]):X}'}
        return {'address':f'0x{addr:X}','identity':identity}
    def resolve(self,pid,locator,identity=None):
        if not isinstance(locator,dict):raise ValueError('주소 경로는 객체여야 합니다')
        if locator.get('module'):
            images=self.studio.workbench.images(pid)['results']
            found=[r for r in images if r['name'].casefold()==str(locator['module']).casefold() and
                   (not locator.get('path') or r.get('path','').casefold()==str(locator['path']).casefold())]
            if len(found)!=1:raise ValueError('모듈을 하나로 식별할 수 없습니다')
            offset=number(locator.get('offset',0))
            if not 0<=offset<found[0]['size']:raise ValueError('모듈 오프셋 범위 오류')
            addr=number(found[0]['base'])+offset
        else:
            if locator.get('identity') is not None:self.owner(pid,locator['identity'])
            addr=location(locator['address'])
        offsets=locator.get('offsets',[])
        if not isinstance(offsets,list) or len(offsets)>32:raise ValueError('포인터 경로는 최대 32단계입니다')
        bits=self.bits(pid) if offsets else 64
        for offset in offsets:
            ptr=int.from_bytes(self.studio.read_bytes(pid,addr,bits//8),'little')
            addr=location(ptr+number(offset))
        return location(addr)
    def preview(self,body):
        pid=number(body['pid']);identity=self.owner(pid,body.get('identity'));bits=self.bits(pid)
        items=body['items']
        if not isinstance(items,list) or not 1<=len(items)<=256:raise ValueError('변경 묶음은 1~256개입니다')
        rows=[];spans=[]
        for item in items:
            if item.get('view_id'):self.check_field(pid,item)
            addr=self.resolve(pid,item.get('locator') or {'address':item['address'],'identity':identity},identity)
            kind=item.get('type','bytes');width=bits//8 if kind=='pointer' else struct.calcsize('<'+FORMATS[kind]) if kind in FORMATS else number(item['width'])
            if not 1<=width<=65536 or sum(r['width'] for r in rows)+width>1048576:raise ValueError('변경 크기 상한은 항목 64KiB / 합계 1MiB입니다')
            raw=codec(kind,item['value'],width,bits)
            if any(addr<end and addr+width>start for start,end in spans):raise ValueError('변경 범위가 겹칩니다')
            spans.append((addr,addr+width));before=self.studio.read_bytes(pid,addr,width)
            if item.get('expected_hex') is not None and before.hex()!=str(item['expected_hex']).lower().replace(' ',''):raise ValueError('현재 바이트가 화면의 원본과 다릅니다. 다시 읽으세요')
            rows.append({'address':f'0x{addr:X}','type':kind,'width':width,'before':before.hex(),'after':raw.hex(),'name':str(item.get('name',''))[:160],
                         'view_id':item.get('view_id'),'path':item.get('path'),'locator':item.get('locator')})
        self.owner(pid,identity)
        with self.lock:
            self.previews={k:v for k,v in self.previews.items() if time.monotonic()-v['created']<600}
            if len(self.previews)>=64:raise ValueError('미리보기 상한입니다')
            key=uuid.uuid4().hex;self.previews[key]={'id':key,'pid':pid,'identity':identity,'created':time.monotonic(),'rows':rows,'used':False}
        return {'success':True,'id':key,'pid':pid,'identity':identity,'results':rows,'atomic':False}
    def apply(self,key):
        with scope(0,'change-set'),self.studio.driver._lock,self.lock:
            p=self.previews.get(key)
            if not p or p['used'] or time.monotonic()-p['created']>600:raise ValueError('미리보기가 만료되었거나 이미 적용했습니다')
            self.owner(p['pid'],p['identity'])
            # Preflight all entries before the first write. Kernel ABI is sequential, not atomic.
            for row in p['rows']:
                if row.get('view_id'):self.check_field(p['pid'],row)
                if row.get('locator') and self.resolve(p['pid'],row['locator'])!=number(row['address']):raise ValueError('주소 경로가 변경되었습니다')
                if self.studio.read_bytes(p['pid'],number(row['address']),row['width']).hex()!=row['before']:raise ValueError('적용 전 원본이 변경되었습니다. 미리보기를 다시 만드세요')
            p['used']=True;done=[]
            for row in p['rows']:
                try:
                    self.owner(p['pid'],p['identity'])
                    if row.get('view_id'):self.check_field(p['pid'],row)
                    if row.get('locator') and self.resolve(p['pid'],row['locator'])!=number(row['address']):raise ValueError('주소 경로가 변경되었습니다')
                    if self.studio.read_bytes(p['pid'],number(row['address']),row['width']).hex()!=row['before']:raise ValueError('해당 항목의 원본이 변경되었습니다')
                    journal_before=set(self.journal.records)
                    response=self.studio.driver.write_process_memory(p['pid'],number(row['address']),bytes.fromhex(row['after']))
                    actual=self.studio.read_bytes(p['pid'],number(row['address']),row['width']).hex()
                    if not response.get('success') or response.get('bytes_written')!=row['width'] or actual!=row['after']:raise ValueError('쓰기 후 검증 실패')
                    journal_ids=[key for key in self.journal.records if key not in journal_before]
                    done.append(dict(row,verified=True,journal_id=journal_ids[-1] if journal_ids else None))
                except Exception as exc:return {'success':False,'error':str(exc),'results':done,'failed':row,'atomic':False,'recovery':'변경 기록에서 역순 복원'}
            return {'success':True,'results':done,'atomic':False,'verified':True}
    def timeline_create(self,body):
        pid=number(body['pid']);identity=self.owner(pid);items=body['items']
        if not isinstance(items,list) or not 1<=len(items)<=32:raise ValueError('타임라인 주소는 1~32개입니다')
        out=[]
        bits=self.bits(pid)
        for item in items:
            width=number(item.get('width',4));kind=item.get('type','bytes')
            if not 1<=width<=4096 or kind not in TYPES[:-1]:raise ValueError('타임라인 형식 / 길이 오류')
            if kind in FORMATS and width!=struct.calcsize('<'+FORMATS[kind]):raise ValueError('형식과 길이가 다릅니다')
            if kind=='pointer' and width!=bits//8:raise ValueError('포인터 형식과 대상 비트 수가 다릅니다')
            out.append(dict(item,address=f'0x{location(item["address"]):X}',width=width,type=kind))
        with self.lock:
            if len(self.timelines)>=32:raise ValueError('타임라인 상한 32개입니다')
            key=uuid.uuid4().hex;self.timelines[key]={'id':key,'pid':pid,'identity':identity,'bits':bits,'items':out,'samples':[],'total':0,'last':0}
            self.timeline_locks[key]=threading.Lock()
        return {'success':True,'id':key}
    def sample(self,key):
        with self.lock: lock=self.timeline_locks[key]
        with lock:
            with self.lock:t=self.timelines[key]
            self.owner(t['pid'],t['identity'])
            if time.monotonic()-t['last']<0.05:raise ValueError('표본 간격은 최소 50ms입니다')
            values=[]
            for item in t['items']:
                row=dict(item)
                try:
                    raw=self.studio.read_bytes(t['pid'],number(item['address']),item['width']);row.update(data_hex=raw.hex(),value=decoded(item['type'],raw,t['bits']))
                except Exception as exc:row['error']=str(exc)
                values.append(row)
            self.owner(t['pid'],t['identity'])
            with self.lock:
                if key not in self.timelines:raise ValueError('타임라인이 닫혔습니다')
                t['last']=time.monotonic();t['total']+=1
                sample={'index':t['total'],'time':time.time(),'values':values};t['samples'].append(sample)
                while len(t['samples'])>512 or sum(sum(len(v.get('data_hex','')) for v in s['values']) for s in t['samples'])>16*1024*1024:t['samples'].pop(0)
                return {'success':True,**copy.deepcopy(t)}
    def timeline(self,key):
        with self.lock:return {'success':True,**copy.deepcopy(self.timelines[key])}
    def timeline_compare(self,body):
        t=self.timeline(body['id']);a=next(s for s in t['samples'] if s['index']==number(body['a']));b=next(s for s in t['samples'] if s['index']==number(body['b']))
        rows=[]
        for x,y in zip(a['values'],b['values']):
            before=bytes.fromhex(x.get('data_hex',''));after=bytes.fromhex(y.get('data_hex',''))
            rows.append({'name':x.get('name',''),'address':x['address'],'before':x.get('value'), 'after':y.get('value'),
                         'changed_offsets':[i for i,(u,v) in enumerate(zip(before,after)) if u!=v], 'error':x.get('error') or y.get('error')})
        return {'success':True,'results':rows,'a':a['time'],'b':b['time']}
    def project_save(self,body):
        pid=number(body['pid']);identity=self.owner(pid);state=copy.deepcopy(body.get('state',{}))
        if len(json.dumps(state))>4*1024*1024:raise ValueError('프로젝트 설정 상한은 4MiB입니다')
        definitions(state.get('definitions') or self.schemas or [{'name':'Memory','size':4,'fields':[{'name':'v1','offset':0,'type':'uint32'}]}],self.bits(pid))
        images=self.studio.workbench.images(pid)['results'];locators={}
        for entry in state.get('addresses',[]):
            label=str(entry['key']);locators[label]=entry.get('locator') or self.capture_locator(pid,entry['address'],identity,images)
        key=str(body.get('id') or uuid.uuid4().hex)
        if not KEY.fullmatch(key):raise ValueError('프로젝트 ID 오류')
        with self.lock:
            folder=self.root/key;folder.mkdir(exist_ok=True)
            if len(list(self.root.glob('*/project.json')))>=32 and not (folder/'project.json').is_file():raise ValueError('프로젝트 보관 상한은 32개입니다')
        scan=state.get('scan',{});session=self.studio.scans.sessions.get(scan.get('session')) if hasattr(self.studio,'scans') else None
        candidate=False
        if session:
            with session.lock:
                session.owner()
                if session.pid!=pid or session.identity!=identity or session.job:raise ValueError('검색 완료 후 프로젝트를 저장하세요')
                if session.path.stat().st_size>512*1048576:raise ValueError('프로젝트 검색 후보 보관 상한은 512MiB입니다')
                with closing(sqlite3.connect(session.path)) as src,closing(sqlite3.connect(folder/'scan.tmp.sqlite')) as dst:src.backup(dst)
                (folder/'scan.tmp.sqlite').replace(folder/'scan.sqlite')
                cfg=copy.deepcopy(session.cfg)
                if cfg:
                    for field in ('pattern','mask'):
                        if cfg[field] is not None:cfg[field]=cfg[field].hex()
                state['scan_backend']={'cfg':cfg,'count':session.count,'round':session.round,'stats':session.stats,'saved':list(session.saved.values())}
                candidate=True
        state['symbol_refs']=[]
        for item in state.get('symbols',[]):
            symbol=self.studio.workbench.symbols.get(item['id'])
            state['symbol_refs'].append({k:symbol[k] for k in ('path','sha256','guid','age','name')})
        record={'version':2,'id':key,'name':str(body.get('name','Project'))[:120],'pid':pid,'identity':identity,
                'time':time.time(),'state':state,'locators':locators,'candidate_snapshot':candidate}
        self.owner(pid,identity)
        with self.lock:atomic(folder/'project.json',record)
        return {'success':True,'project':record}
    def project_list(self):
        result=[]
        for path in self.root.glob('*/project.json'):
            try:
                r=json.loads(path.read_text(encoding='utf-8'));result.append({k:r[k] for k in ('id','name','pid','identity','time','candidate_snapshot')})
            except (ValueError,OSError,KeyError):continue
        return {'success':True,'results':sorted(result,key=lambda r:r['time'],reverse=True)}
    def project_get(self,key):
        if not KEY.fullmatch(key):raise ValueError('프로젝트 ID 오류')
        return json.loads((self.root/key/'project.json').read_text(encoding='utf-8'))
    def project_archive(self,key,restore=False):
        if not KEY.fullmatch(key):raise ValueError('프로젝트 ID 오류')
        trash=self.root/'archived';trash.mkdir(exist_ok=True)
        src,dst=(trash/key,self.root/key) if restore else (self.root/key,trash/key)
        with self.lock:
            if not (src/'project.json').is_file() or dst.exists():raise ValueError('프로젝트 이동 상태를 확인하세요')
            src.rename(dst)
        return {'success':True}
    def project_load(self,body):
        r=self.project_get(body['id']);pid=number(body['pid']);identity=self.owner(pid)
        resolved={};errors={}
        for key,locator in r['locators'].items():
            try:resolved[key]=f'0x{self.resolve(pid,locator,identity):X}'
            except Exception as exc:errors[key]=str(exc)
        state=copy.deepcopy(r['state']);state['scan_restored']=False
        if identity==r['identity'] and pid==r['pid'] and r['candidate_snapshot']:
            packet=self.studio.scans.create(pid);session=self.studio.scans.sessions[packet['session_id']]
            try:
                with session.lock:
                    with closing(sqlite3.connect(self.root/r['id']/'scan.sqlite')) as src,closing(sqlite3.connect(session.path)) as dst:src.backup(dst)
                    b=state['scan_backend'];session.cfg=copy.deepcopy(b['cfg']);session.count=b['count'];session.round=b['round'];session.stats=b['stats']
                    if session.cfg:
                        for field in ('pattern','mask'):
                            if session.cfg[field] is not None:session.cfg[field]=bytes.fromhex(session.cfg[field])
                    session.saved={x['id']:dict(x,frozen=False,frozen_hex=None) for x in b['saved']}
                    state['scan']['session']=session.id;state['scan_restored']=True
            except Exception:
                self.studio.scans.remove(session.id);raise
        self.owner(pid,identity)
        symbol_refs=[]
        for symbol in state.get('symbol_refs',[]):
            try:
                symbols=self.studio.workbench.symbols
                if symbols.digest(Path(symbol['path']))!=symbol['sha256']:raise ValueError('PDB 내용이 저장 당시와 다릅니다')
                symbol_refs.append(symbols.load(symbol['path']))
            except Exception as exc:errors['PDB:'+symbol['name']]=str(exc)
        restored_timeline=None
        saved_timeline=state.get('suite',{}).get('timeline')
        if saved_timeline and saved_timeline.get('samples'):
            items=[dict(item,address=resolved.get('timeline:'+str(i),item['address'])) for i,item in enumerate(saved_timeline['items'])]
            if all('timeline:'+str(i) in resolved for i in range(len(items))):
                key=self.timeline_create({'pid':pid,'items':items})['id']
                with self.lock:
                    t=self.timelines[key];samples=copy.deepcopy(saved_timeline['samples'][-512:])
                    if len(json.dumps(samples))>16*1048576:raise ValueError('저장 타임라인 상한을 초과했습니다')
                    t.update(samples=samples,total=max((number(s['index']) for s in samples),default=0),historical_identity=saved_timeline.get('identity'))
                    restored_timeline=self.timeline(key)
        return {'success':True,'project':r,'state':state,'resolved':resolved,'unresolved':errors,'pid':pid,'identity':identity,'symbols':symbol_refs,'timeline':restored_timeline}
    def dispatch(self,action,body):
        if action=='schemas':return {'success':True,'definitions':self.schemas}
        if action=='schemas_save':return self.save_schemas(body)
        if action=='view':return self.view(body)
        if action=='resolve':return {'success':True,'address':f'0x{self.resolve(number(body["pid"]),body["locator"]):X}'}
        if action=='preview':return self.preview(body)
        if action=='apply':return self.apply(body['id'])
        if action=='journal':return {'success':True,'results':self.journal.list(number(body.get('pid',0)))}
        if action=='restore':return self.journal.restore(body['id'])
        if action=='restore_batch':
            ids=body['ids']
            if not isinstance(ids,list) or not 1<=len(ids)<=256 or len(set(ids))!=len(ids):raise ValueError('복원할 기록을 선택하세요')
            results=[]
            with scope(0,'batch-restore'),self.studio.driver._lock:
                for key in reversed(ids):
                    try:results.append(self.journal.restore(key))
                    except Exception as exc:return {'success':False,'error':str(exc),'results':results,'failed_id':key,'atomic':False}
            return {'success':True,'results':results,'verified':True,'atomic':False}
        if action=='archive':return self.journal.archive(body['ids'])
        if action=='timeline_create':return self.timeline_create(body)
        if action=='sample':return self.sample(body['id'])
        if action=='timeline':return self.timeline(body['id'])
        if action=='timeline_compare':return self.timeline_compare(body)
        if action=='timeline_close':
            with self.lock:self.timelines.pop(body['id'],None);self.timeline_locks.pop(body['id'],None)
            return {'success':True}
        if action=='projects':return self.project_list()
        if action=='project_save':return self.project_save(body)
        if action=='project_load':return self.project_load(body)
        if action=='project_export':return {'success':True,'project':self.project_get(body['id'])}
        if action=='project_archive':return self.project_archive(body['id'])
        if action=='project_recover':return self.project_archive(body['id'],True)
        if action=='project_archives':
            rows=[]
            for path in (self.root/'archived').glob('*/project.json'):
                r=json.loads(path.read_text(encoding='utf-8'));rows.append({k:r[k] for k in ('id','name','time')})
            return {'success':True,'results':rows}
        if action=='project_import':
            r=body['project']
            if r.get('version')!=2 or not isinstance(r.get('state'),dict) or not isinstance(r.get('locators'),dict):raise ValueError('프로젝트 파일 형식 오류')
            definitions(r['state'].get('definitions') or self.schemas)
            key=uuid.uuid4().hex;r=copy.deepcopy(r);r.update(id=key,candidate_snapshot=False)
            if len(json.dumps(r))>4*1024*1024:raise ValueError('파일 크기 상한')
            folder=self.root/key;folder.mkdir();atomic(folder/'project.json',r)
            return {'success':True,'project':r}
        if action=='pdb_types':
            record=self.studio.workbench.symbols.get(body['id'])
            if not record.get('structures'):raise ValueError('이 PDB에 구조체 정보가 없습니다. 새 분석기로 다시 분석하세요')
            defs=copy.deepcopy(record['structures']);names={d['name'] for d in defs};unsupported=list(record.get('unsupported_types',[]))
            for d in defs:
                fields=[];seen=set()
                for f in d['fields']:
                    if f['name'] in seen:unsupported.append(d['name']+'.'+f['name']+' (duplicate field)');continue
                    seen.add(f['name'])
                    if f.get('ref') and f['ref'] not in names:
                        unsupported.append(d['name']+'.'+f['name']+' (referenced type unavailable)')
                        if f['type']=='pointer':f.pop('ref',None)
                        else:continue
                    if f['type']=='bytes' and (f['length']>4096 or f['offset']+f['length']*f.get('count',1)>d['size']):continue
                    fields.append(f)
                d['fields']=fields or [{'name':'opaque','offset':0,'type':'bytes','length':min(4096,d['size']),'readonly':True}]
            valid=[]
            for d in defs:
                try:definitions(defs);valid=defs;break
                except ValueError:
                    # A user can inspect unknown compiler layouts as immutable bytes.
                    d['fields']=[{'name':'opaque','offset':0,'type':'bytes','length':min(4096,d['size']),'readonly':True}]
            if not valid:valid=list(definitions(defs).values())
            return {'success':True,'definitions':valid,'unsupported':unsupported}
        raise ValueError('지원하지 않는 작업')
