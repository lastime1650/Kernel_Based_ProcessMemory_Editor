"""Read-only surrounding-memory snapshots and a complete kernel VAD map."""
import bisect
import struct
import threading
import time

from memory_editor import Session as EditorSession, FORMATS, LIMIT, location, number
from productivity_suite import definitions


class Session(EditorSession):
    def __init__(self, studio, body):
        count=number(body.get('size',1024))
        if not 16<=count<=4096:raise ValueError('Wide View는 한 번에 16~4,096바이트를 표시합니다')
        super().__init__(studio,dict(body,size=count,group=8))

    def metadata(self):
        super().metadata()
        self.regions=sorted(self.regions,key=lambda r:number(r['address']))
        self.starts=[number(r['address']) for r in self.regions]
        self.map_dirty=True

    def region(self, address):
        i=bisect.bisect_right(self.starts,address)-1
        if i<0:return None
        r=self.regions[i]
        return r if address<self.starts[i]+number(r['size']) else None

    def string_hints(self, ids):pass

    def read(self,node):
        data,valid,holes=self.snapshot(node['base'],self.size)
        node.update(data=data,valid=valid,holes=holes,changed={})

    def snapshot(self, base, count):
        data,valid=bytearray(count),bytearray(count)
        offset,holes=0,0
        while offset<count:
            address=base+offset;r=self.region(address)
            size=min(4096-address%4096,count-offset)
            if r:size=min(size,number(r['address'])+number(r['size'])-address)
            else:
                next_index=bisect.bisect_right(self.starts,address)
                if next_index<len(self.starts):size=min(size,self.starts[next_index]-address)
            state=number(r.get('state','0x1000')) if r else 0
            if not r or not r.get('readable') or r.get('guarded') or state!=0x1000:
                holes+=1
            else:
                try:piece=self.studio.read_bytes(self.pid,address,size)
                except Exception as exc:
                    if '읽기 실패' not in str(exc):raise
                    holes+=1
                else:
                    if len(piece)!=size:raise ValueError('Wide View 읽기 크기 불일치')
                    data[offset:offset+size]=piece;valid[offset:offset+size]=b'\x01'*size
            offset+=size
        return bytes(data),bytes(valid),holes

    def field_layout(self, body):
        name=str(body.get('schema',''))
        if not name:return []
        if body.get('definitions'):values=body['definitions']
        else:
            with self.studio.suite.lock:values=list(self.studio.suite.schemas)
        defs=definitions(values,self.bits)
        if name not in defs:raise ValueError('선택한 구조체 정의가 없습니다')
        base=location(body.get('schema_address',body['address']));out=[]
        def walk(name,addr,path,depth):
            if depth>12:raise ValueError('중첩 구조체 깊이 상한은 12입니다')
            for f in defs[name]['fields']:
                for index in range(f['count']):
                    target=addr+f['offset']+index*f['stride'];kind=f['type']
                    label=path+'.'+f['name']+(f'[{index}]' if f['count']>1 else '')
                    if len(out)>=2048:raise ValueError('구조체 필드 상한은 2,048개입니다')
                    if kind=='struct':walk(f['ref'],target,label,depth+1);continue
                    width=self.bits//8 if kind=='pointer' else struct.calcsize('<'+FORMATS[kind]) if kind in FORMATS else f['length']
                    location(target)
                    if target+width>LIMIT:raise ValueError('구조체 필드 주소 범위 오류')
                    if target<self.root['base']+self.size and target+width>self.root['base']:
                        out.append({'address':f'0x{target:X}','width':width,'type':kind,'path':label,'confirmed':True})
        walk(name,base,name,0)
        return out

    def packet(self, include_map=False):
        n=self.root
        out={'success':True,'id':self.id,'pid':self.pid,'identity':self.identity,'bits':self.bits,
             'address':f'0x{n["base"]:X}','size':self.size,'data_hex':n['data'][:self.size].hex(),
             'valid_hex':n['valid'][:self.size].hex(),'holes':n['holes'],'sampled_at':time.time()}
        if include_map or self.map_dirty:
            keys=('address','size','allocation_base','state','type','protect','readable','writable','executable','guarded','image_name')
            out.update(regions=[{k:r[k] for k in keys if k in r} for r in self.regions],map_sampled_at=self.map_time)
            self.map_dirty=False
        return out

    def invoke(self, action, body):
        with self.lock:
            self.owner()
            if action not in ('read','map'):raise ValueError('Wide View는 읽기와 맵 조회만 지원합니다')
            if action=='map':self.metadata()
            else:
                base=location(body.get('address',self.root['base']));count=number(body.get('size',self.size))
                if not 16<=count<=4096 or base+count+8>LIMIT:raise ValueError('Wide View 표시 범위를 확인하세요')
                if time.monotonic()-self.map_time>5:self.metadata()
                if count!=self.size or base!=self.root['base']:
                    self.size=count;self.root.update(base=base,data=bytes(count+8),valid=bytes(count+8),changed={})
                self.read(self.root)
            result=self.packet(action=='map' or body.get('map',False))
            result['fields']=self.field_layout(dict(body,address=body.get('address',result['address'])))
            self.owner()
            return result


class Workspace:
    def __init__(self,studio):self.studio=studio;self.sessions={};self.lock=threading.RLock()
    def create(self,body):
        with self.lock:
            now=time.monotonic()
            self.sessions={k:s for k,s in self.sessions.items() if now-s.touch<1800}
            if len(self.sessions)>=32:raise ValueError('Wide View 세션 상한은 32개입니다')
            session=Session(self.studio,body);session.owner()
            result=session.packet(True);result['fields']=session.field_layout(body)
            self.sessions[session.id]=session
            return result
    def invoke(self,key,action,body):
        with self.lock:session=self.sessions.get(key)
        if not session:raise ValueError('Wide View 세션이 만료되었습니다. 다시 여세요')
        return session.invoke(action,body)
    def remove(self,key):
        with self.lock:
            session=self.sessions.pop(key,None)
            if session:
                with session.lock:session.closed=True
        return {'success':True}
