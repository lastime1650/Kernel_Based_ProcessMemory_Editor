"""Legacy HexEditor port. Target metadata/read/write use the existing IOCTL bridge only."""
import math
import struct
import threading
import time
import uuid

LIMIT = 0x800000000000
FORMATS = {"int8":"b", "uint8":"B", "int16":"h", "uint16":"H", "int32":"i",
           "uint32":"I", "int64":"q", "uint64":"Q", "float32":"f", "float64":"d"}


def number(value):
    if isinstance(value, bool): raise ValueError("숫자를 입력하세요")
    text = str(value).strip()
    return int(text, 16 if text.lower().startswith(('0x','-0x')) else 10)


def location(value):
    value = number(value)
    if not 0 < value < LIMIT: raise ValueError("사용자 주소 범위를 확인하세요")
    return value


def encode(kind, value, bits):
    if kind == 'byte':
        text = str(value).strip()
        if len(text) != 2 or any(c not in '0123456789abcdefABCDEF' for c in text):
            raise ValueError("바이트는 두 자리 16진수로 입력하세요 (00~FF)")
        return bytes.fromhex(text)
    if kind == 'pointer': kind = 'uint32' if bits == 32 else 'uint64'
    if kind not in FORMATS: raise ValueError("지원하지 않는 편집 형식")
    parsed = float(str(value)) if kind.startswith('float') else number(value)
    if isinstance(parsed, float) and not math.isfinite(parsed): raise ValueError("유한한 수를 입력하세요")
    try: return struct.pack('<'+FORMATS[kind], parsed)
    except (struct.error, OverflowError) as exc: raise ValueError("이 형식의 값 범위를 초과했습니다") from exc


class Session:
    def __init__(self, studio, body):
        self.studio = studio
        self.pid = number(body['pid'])
        if not 0 < self.pid <= 0xffffffff: raise ValueError("PID 범위를 확인하세요")
        self.identity = studio.identity(self.pid)
        self.lock = threading.RLock()
        self.id = uuid.uuid4().hex
        self.touch = time.monotonic()
        self.closed = False
        self.nodes, self.history, self.hints = {}, [], {}
        self.size = number(body.get('size',128))
        if not 16 <= self.size <= 65536: raise ValueError("크기는 16~65,536바이트입니다")
        self.visible_bytes = number(body['visible_bytes']) if 'visible_bytes' in body else None
        if self.visible_bytes is not None and not 16 <= self.visible_bytes <= 4096:
            raise ValueError('표시 범위는 16~4,096바이트입니다')
        self.ranges = {}
        self.group = number(body.get('group',8))
        if self.group not in (4,8): raise ValueError("행 크기는 4 또는 8바이트입니다")
        self.origin = location(body['address'])
        if self.origin+self.size+8 > LIMIT: raise ValueError("주소 범위를 초과했습니다")
        extended = studio.driver.query_process_extended(self.pid)
        if not extended.get('success'): raise ValueError("커널에서 대상 아키텍처를 확인하지 못했습니다")
        self.bits = 32 if extended['is_wow64'] else 64
        self.metadata()
        self.root = self.node(self.origin, None, 0, str(body.get('name','Memory'))[:80])
        self.read(self.root)
        self.string_hints([self.root['id']])

    def owner(self):
        if self.closed: raise ValueError("편집 세션이 닫혔습니다. 다시 여세요")
        self.touch = time.monotonic()
        if self.studio.identity(self.pid) != self.identity: raise ValueError("대상 프로세스가 교체되었습니다. 다시 여세요")

    def metadata(self):
        result = self.studio.operate('regions', {'pid':self.pid,'max_results':50000})
        if result.get('truncated'): raise ValueError("커널 메모리 맵이 잘려 반환되었습니다")
        self.regions = result['results']
        self.map_time = time.monotonic()
        self.hints.clear()

    def region(self, addr):
        for r in self.regions:
            if number(r['address']) <= addr < number(r['address'])+r['size']: return r
        return None

    def node(self, base, parent, source, name):
        if len(self.nodes) >= 64 or (len(self.nodes)+1)*(self.size+8) > 1048576:
            raise ValueError("펼친 창은 최대 64개 / 합계 1MiB입니다")
        if base+self.size+8 > LIMIT: raise ValueError("포인터 대상 범위를 초과했습니다")
        item = {'id':uuid.uuid4().hex,'base':base,'parent':parent,'source':source,'name':name,
                'data':bytes(self.size+8),'valid':bytes(self.size+8),'changed':{},'holes':0}
        self.nodes[item['id']] = item
        return item

    def drop(self, key):
        todo = [key]
        while todo:
            current = todo.pop()
            todo.extend(n['id'] for n in list(self.nodes.values()) if n['parent']==current)
            self.nodes.pop(current,None)

    def snapshot(self, base, count):
        data, valid = bytearray(count), bytearray(count)
        offset, holes = 0, 0
        while offset < count:
            size = min(4096-(base+offset)%4096, count-offset)
            try:
                chunk = self.studio.read_bytes(self.pid,base+offset,size)
            except Exception as exc:
                # Only a target read failure denotes a hole. Cleanup/protocol failures are fatal.
                if '읽기 실패' not in str(exc): raise
                holes += 1
            else:
                if len(chunk)!=size: raise ValueError("읽기 반환 크기가 잘못되었습니다")
                data[offset:offset+size]=chunk
                valid[offset:offset+size]=b'\x01'*size
            offset += size
        return bytes(data), bytes(valid), holes

    def read(self, node):
        offset,count = self.ranges.get(node['id'], (0,min(self.size,self.visible_bytes))) if self.visible_bytes is not None else (0,self.size)
        piece, mask, holes = self.snapshot(node['base']+offset,min(count+8,self.size+8-offset))
        raw,valid=bytearray(self.size+8),bytearray(self.size+8)
        raw[offset:offset+len(piece)],valid[offset:offset+len(mask)]=piece,mask
        raw,valid=bytes(raw),bytes(valid)
        now = time.monotonic()
        changed = {i:t for i,t in node['changed'].items() if now-t<1.5}
        for i in range(self.size):
            if valid[i] and node['valid'][i] and raw[i]!=node['data'][i]: changed[i]=now
        node.update(data=raw,valid=valid,holes=holes,changed=changed)

    def set_ranges(self, body):
        ranges=body.get('ranges')
        if ranges is None:return
        if not isinstance(ranges,list) or len(ranges)>16:raise ValueError('표시 범위는 최대 16개 창입니다')
        parsed={}
        for r in ranges:
            key=r['node'];offset=number(r['offset']);count=number(r['count'])
            if not 0<=offset<self.size or not 1<=count<=4096 or offset+count>self.size:
                raise ValueError('표시 범위를 확인하세요')
            if key in self.nodes:parsed[key]=(offset,count)
        self.ranges.update(parsed)

    def validate_path(self, node):
        path, current = [], node
        while current['parent']:
            path.append(current)
            current = self.nodes.get(current['parent'])
            if current is None: raise ValueError("포인터 경로가 만료되었습니다")
        for child in reversed(path):
            parent=self.nodes[child['parent']]
            raw = self.studio.read_bytes(self.pid,parent['base']+child['source'],self.bits//8)
            if int.from_bytes(raw,'little') != child['base']:
                self.drop(child['id'])
                raise ValueError("포인터가 변경되어 펼친 창을 닫았습니다")

    def invalidate(self):
        for item in list(self.nodes.values()):
            if item['id'] not in self.nodes or not item['parent']: continue
            try: self.validate_path(item)
            except Exception as exc:
                if '포인터가 변경' in str(exc): continue
                if '읽기 실패' in str(exc): self.drop(item['id']); continue
                raise

    def pointer(self, node, offset):
        width = self.bits//8
        if not all(node['valid'][offset:offset+width]) or offset+width>len(node['data']): return 0
        return int.from_bytes(node['data'][offset:offset+width],'little')

    def packet(self):
        result=[]
        for n in self.nodes.values():
            pointers={}
            ansi={}
            for offset in range(0,self.size,self.group):
                count=min(self.group,self.size-offset)
                raw=n['data'][offset:offset+count];valid=n['valid'][offset:offset+count]
                if all(valid):
                    ansi[str(offset)]=''.join(c if c.isprintable() else '·' for c in raw.decode('mbcs',errors='replace'))
                else:
                    ansi[str(offset)]=''.join((chr(b) if 32<=b<127 else '·') if valid[i] else '?' for i,b in enumerate(raw))
                ptr=self.pointer(n,offset)
                if not ptr: continue
                r=self.region(ptr)
                if not r or not r['readable'] or r['guarded']: continue
                kind = r.get('image_name') or {'0x20000':'<Private>','0x40000':'<Mapped>','0x1000000':'<Image>'}.get(r['type'],'<Memory>')
                base=number(r.get('image_base') or 0) or number(r['allocation_base'])
                hint = self.hints.get(ptr, ('',0))[0]
                pointers[str(offset)]={'address':f'0x{ptr:X}','label':kind+(f' +0x{ptr-base:X}' if r.get('image_name') else ''),'hint':hint}
            result.append({'id':n['id'],'base':f'0x{n["base"]:X}','parent':n['parent'],'source':n['source'],
                           'name':n['name'],'data_hex':n['data'].hex(),'valid_hex':n['valid'].hex(),
                           'changed':list(n['changed']),'holes':n['holes'],'pointers':pointers,'ansi':ansi})
        return {'success':True,'id':self.id,'pid':self.pid,'identity':self.identity,'bits':self.bits,
                'origin':f'0x{self.origin:X}','size':self.size,'group':self.group,'root':self.root['id'],
                'nodes':result,'history_count':len(self.history),'metadata':'kernel VAD; heap blocks unavailable'}

    def string_hints(self, ids):
        if self.visible_bytes is not None:return # Visible-only mode never follows pointers for speculative strings.
        remaining=8
        for key in ids:
            n=self.nodes.get(key)
            if not n: continue
            for offset in range(0,self.size,self.group):
                ptr=self.pointer(n,offset)
                r=self.region(ptr)
                if not remaining: return
                if not r or not r['readable'] or r['guarded']: continue
                if ptr in self.hints and time.monotonic()-self.hints[ptr][1]<1: continue
                remaining-=1
                raw,valid,_=self.snapshot(ptr,min(128,number(r['address'])+r['size']-ptr))
                count=next((i for i,v in enumerate(valid) if not v),len(raw));raw=raw[:count]
                hint=''
                # UTF-16 first when interleaved NULs are present; ANSI uses Windows ACP.
                wide=raw[:len(raw)//2*2].decode('utf-16-le',errors='replace').split('\0')[0]
                text=raw.split(b'\0')[0].decode('mbcs',errors='replace')
                if len(text)>=3 and all(c.isprintable() for c in text): hint='ANSI "'+text+'"'
                elif len(wide)>=3 and all(c.isprintable() and c!='\ufffd' for c in wide): hint='UTF16 "'+wide+'"'
                if len(self.hints)>=2048: self.hints.clear()
                self.hints[ptr]=(hint,time.monotonic())

    def invoke(self, action, body):
        with self.lock:
            self.owner()
            self.set_ranges(body)
            if action=='refresh':
                self.invalidate()
                ids=body.get('nodes',[self.root['id']])
                if not isinstance(ids,list) or len(ids)>16: raise ValueError("갱신은 최대 16개 창입니다")
                for key in dict.fromkeys(ids):
                    if key in self.nodes: self.read(self.nodes[key])
                self.string_hints(ids)
            elif action=='metadata': self.metadata()
            elif action=='name': self.root['name']=str(body.get('name','Memory'))[:80]
            elif action=='collapse':
                key=body.get('node',self.root['id'])
                for n in list(self.nodes.values()):
                    if n['parent']==key: self.drop(n['id'])
            elif action=='group':
                group=number(body['group'])
                if group not in (4,8): raise ValueError("행 크기는 4 또는 8입니다")
                for key in list(self.nodes):
                    if key!=self.root['id']: self.drop(key)
                self.group=group
            elif action=='slide':
                delta=number(body['delta']);base=self.root['base']+delta
                if abs(delta)>65536 or not 0<base or base+self.size+8>LIMIT: raise ValueError("이동 범위를 확인하세요")
                old=self.root['base']; self.root['base']=base
                shift=base-old
                raw,valid=self.root['data'],self.root['valid']
                self.root['data']=bytes(raw[i+shift] if 0<=i+shift<len(raw) else 0 for i in range(self.size+8))
                self.root['valid']=bytes(valid[i+shift] if 0<=i+shift<len(valid) else 0 for i in range(self.size+8))
                self.root['changed']={i-shift:t for i,t in self.root['changed'].items() if 0<=i-shift<self.size}
                for n in list(self.nodes.values()):
                    if n['parent']!=self.root['id']: continue
                    n['source']-=shift
                    if not 0<=n['source']<self.size or n['source']%self.group: self.drop(n['id'])
                self.read(self.root);self.invalidate()
            elif action in ('expand','edit','edit_range'):
                node=self.nodes.get(body.get('node'))
                if not node: raise ValueError("창이 만료되었습니다. 새로 고침하세요")
                self.validate_path(node)
                offset=number(body['offset'])
                if not 0<=offset<self.size: raise ValueError("창 안의 바이트를 선택하세요")
                if action=='expand':
                    if offset%self.group: raise ValueError("행 시작 포인터를 선택하세요")
                    self.read(node);ptr=self.pointer(node,offset)
                    if str(body.get('expected','')).lower()!=f'0x{ptr:x}': raise ValueError("포인터가 변경되었습니다. 다시 선택하세요")
                    r=self.region(ptr)
                    if not r or not r['readable'] or r['guarded']:
                        self.metadata();r=self.region(ptr)
                    if not r or not r['readable'] or r['guarded']: raise ValueError("읽을 수 있는 포인터 대상이 아닙니다")
                    ancestor=node;depth=0
                    while ancestor:
                        if ancestor['base']<=ptr<ancestor['base']+self.size: raise ValueError("조상 창을 가리키는 순환 포인터입니다")
                        depth+=1;ancestor=self.nodes.get(ancestor['parent'])
                    if depth>=64: raise ValueError("포인터 깊이 상한은 64입니다")
                    existing=next((n for n in self.nodes.values() if n['parent']==node['id'] and n['source']==offset),None)
                    if existing: self.drop(existing['id'])
                    else:
                        child=self.node(ptr,node['id'],offset,f'ptr{self.bits} @ +{offset:04X}')
                        try: self.read(child)
                        except BaseException: self.drop(child['id']);raise
                else:
                    data=bytes.fromhex(str(body['data_hex'])) if action=='edit_range' else encode(str(body['kind']),body['value'],self.bits)
                    if not 1<=len(data)<=65536: raise ValueError('범위 편집은 1~65,536바이트입니다')
                    if offset+len(data)>self.size+8: raise ValueError("편집 범위를 초과했습니다")
                    expected=bytes.fromhex(str(body.get('expected_hex','')))
                    if len(expected)!=len(data): raise ValueError("편집 전 바이트 확인값이 필요합니다")
                    before=self.studio.read_bytes(self.pid,node['base']+offset,len(data))
                    if before!=expected: raise ValueError("현재 바이트가 변경되었습니다. 쓰지 않았습니다. 다시 선택하세요")
                    if len(self.history)>=256: raise ValueError("편집 이력은 최대 256개입니다. 다시 여세요")
                    self.owner();self.validate_path(node)
                    record={'address':node['base']+offset,'before':before,'after':data,'restored':False}
                    self.history.append(record)
                    response=self.studio.driver.write_process_memory(self.pid,record['address'],data)
                    actual=self.studio.read_bytes(self.pid,record['address'],len(data))
                    record['expected_restore']=actual
                    if not response.get('success') or response.get('bytes_written')!=len(data):
                        if actual==before: record['restored']=True
                        raise ValueError("쓰기 실패 또는 부분 쓰기. 복원 원본을 이력에 보관했습니다")
                    if actual!=data:
                        raise ValueError("쓰기 후 검증 실패. 복원 원본을 이력에 보관했습니다")
                    self.read(node);self.invalidate()
            elif action=='restore':
                record=next((r for r in reversed(self.history) if not r['restored']),None)
                if not record: raise ValueError("복원할 편집이 없습니다")
                expected=record.get('expected_restore',record['after'])
                if self.studio.read_bytes(self.pid,record['address'],len(expected))!=expected:
                    raise ValueError("편집 후 값이 변경되어 복원을 중단했습니다")
                response=self.studio.driver.write_process_memory(self.pid,record['address'],record['before'])
                if not response.get('success') or response.get('bytes_written')!=len(record['before']): raise ValueError("복원 쓰기 실패")
                if self.studio.read_bytes(self.pid,record['address'],len(record['before']))!=record['before']: raise ValueError("복원 검증 실패")
                record['restored']=True
                for n in self.nodes.values(): self.read(n)
                self.invalidate()
            else: raise ValueError("지원하지 않는 메모리 편집 작업")
            self.owner()
            return self.packet()


class Workspace:
    def __init__(self, studio): self.studio,self.sessions,self.lock=studio,{},threading.RLock()
    def create(self,body):
        with self.lock:
            now=time.monotonic()
            self.sessions={k:s for k,s in self.sessions.items() if now-s.touch<1800}
            if len(self.sessions)>=32: raise ValueError("편집 세션 상한 32개입니다")
            session=Session(self.studio,body);session.owner()
            self.sessions[session.id]=session
            return session.packet()
    def invoke(self,key,action,body):
        with self.lock: session=self.sessions.get(key)
        if not session: raise ValueError("편집 세션이 만료되었습니다. 다시 여세요")
        return session.invoke(action,body)
    def remove(self,key):
        with self.lock:
            session=self.sessions.get(key)
            if session:
                # A completed close response guarantees no pending session write can start later.
                with session.lock: session.closed=True
                self.sessions.pop(key,None)
        return {'success':True}
