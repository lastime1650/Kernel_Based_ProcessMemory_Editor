"""Durable write-ahead memory journal. Every target byte write uses the kernel bridge."""
from pathlib import Path
import json
import threading
import time
import uuid
import os
import re
from request_scheduler import scope, source

class Journal:
    def __init__(self, studio, root):
        self.studio=studio;self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.lock=threading.RLock();self.records={}
        for path in sorted(self.root.glob('*.json')):
            try:
                r=json.loads(path.read_text(encoding='utf-8'))
                if r['id']==path.stem: self.records[r['id']]=r
            except (OSError,ValueError,KeyError,TypeError): continue
    def persist(self,record):
        path=self.root/(record['id']+'.json');temp=path.with_suffix('.tmp')
        with temp.open('w',encoding='utf-8') as stream:
            json.dump(record,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
        temp.replace(path)
    def install(self):
        driver=self.studio.driver
        if not hasattr(driver,'write_process_memory'):return
        original=driver.write_process_memory
        def write(pid,address,data):
            data=bytes(data)
            if not data or len(data)>1048576: return original(pid,address,data)
            with scope(0),driver._lock:
                identity=self.studio.identity(pid)
                before=self.studio.read_bytes(pid,address,len(data))
                if before==data: return original(pid,address,data)
                with self.lock:
                    if len(self.records)>=2048 or sum(len(r['before'])+len(r['after']) for r in self.records.values())+len(data)*4>128*1024*1024:
                        raise ValueError('변경 기록 저장 상한입니다. 기록을 내보내고 보관 완료 기록을 정리하세요')
                    record={'id':uuid.uuid4().hex,'pid':pid,'identity':identity,'address':f'0x{address:X}',
                            'before':before.hex(),'after':data.hex(),'observed':None,'time':time.time(),
                            'source':source.get(),'status':'prepared','restored':False}
                    self.persist(record);self.records[record['id']]=record
                try:
                    if self.studio.identity(pid)!=identity: raise ValueError('쓰기 직전 대상이 교체되었습니다')
                    response=original(pid,address,data)
                    record['write_response']=response
                    actual=self.studio.read_bytes(pid,address,len(data));record['observed']=actual.hex()
                    record['status']='verified' if response.get('success') and response.get('bytes_written')==len(data) and actual==data else 'failed'
                    return response
                except BaseException as exc:
                    record['status']='uncertain';record['error']=str(exc)[:500];raise
                finally:
                    with self.lock: self.persist(record)
        driver.write_process_memory=write
        if hasattr(driver,'copy_process_memory'):
            original_copy=driver.copy_process_memory
            def copied(src_pid,src_addr,dst_pid,dst_addr,size):
                if not 1<=size<=1048576:raise ValueError('기록 가능한 복사 상한은 1MiB입니다')
                with scope(0),driver._lock:
                    identity=self.studio.identity(dst_pid)
                    before=self.studio.read_bytes(dst_pid,dst_addr,size);requested=self.studio.read_bytes(src_pid,src_addr,size)
                    record={'id':uuid.uuid4().hex,'pid':dst_pid,'identity':identity,'address':f'0x{dst_addr:X}',
                            'before':before.hex(),'after':requested.hex(),'observed':None,'time':time.time(),
                            'source':source.get()+' / copy','status':'prepared','restored':False}
                    with self.lock:
                        if len(self.records)>=2048 or sum(len(r['before'])+len(r['after']) for r in self.records.values())+size*4>128*1024*1024:raise ValueError('변경 기록 저장 상한입니다')
                        self.persist(record);self.records[record['id']]=record
                    try:
                        if self.studio.identity(dst_pid)!=identity:raise ValueError('복사 직전 대상이 교체되었습니다')
                        response=original_copy(src_pid,src_addr,dst_pid,dst_addr,size);actual=self.studio.read_bytes(dst_pid,dst_addr,size)
                        record.update(observed=actual.hex(),write_response=response,status='verified' if response.get('success') and actual==requested else 'failed')
                        return response
                    except BaseException as exc:record.update(status='uncertain',error=str(exc)[:500]);raise
                    finally:
                        with self.lock:self.persist(record)
            driver.copy_process_memory=copied
        if hasattr(driver,'free_virtual_memory'):
            original_free=driver.free_virtual_memory
            def freed(pid,address):
                with scope(0),driver._lock:
                    allocation=getattr(self.studio,'allocations',{}).get(f'{pid}:0x{address:X}')
                    extent=allocation['size'] if allocation and allocation['pid']==pid else 0
                    response=original_free(pid,address)
                    if response.get('success') and extent:
                        with self.lock:
                            for record in self.records.values():
                                if record['pid']==pid and address<=int(record['address'],16)<address+extent:
                                    record['released']=True;self.persist(record)
                    return response
            driver.free_virtual_memory=freed
    def list(self,pid=0):
        with self.lock:
            return [dict(r) for r in sorted(self.records.values(),key=lambda x:x['time'],reverse=True) if not pid or r['pid']==pid]
    def restore(self,key):
        with self.studio.driver._lock, self.lock:
            record=self.records.get(key)
            if not record or record['restored']: raise ValueError('복원할 기록이 없습니다')
            if record.get('released'):raise ValueError('이 메모리 할당은 해제되었습니다')
            if self.studio.identity(record['pid'])!=record['identity']: raise ValueError('저장 당시의 프로세스가 아닙니다')
            expected=record['observed']
            if expected is None: raise ValueError('쓰기 후 바이트를 확인하지 못한 기록입니다. 직접 비교하세요')
            if self.studio.read_bytes(record['pid'],int(record['address'],16),len(bytes.fromhex(expected))).hex()!=expected:
                raise ValueError('편집 이후 바이트가 변경되어 복원을 중단했습니다')
            response=self.studio.driver.write_process_memory(record['pid'],int(record['address'],16),bytes.fromhex(record['before']))
            if not response.get('success') or response.get('bytes_written')!=len(record['before'])//2: raise ValueError('복원 쓰기 실패')
            if self.studio.read_bytes(record['pid'],int(record['address'],16),len(record['before'])//2).hex()!=record['before']: raise ValueError('복원 검증 실패')
            record['restored']=True;record['restored_at']=time.time();self.persist(record)
            return {'success':True,'verified':True,'record':dict(record)}
    def archive(self,keys):
        if not isinstance(keys,list) or any(not isinstance(k,str) or not re.fullmatch('[a-f0-9]{32}',k) for k in keys):raise ValueError('기록 ID 오류')
        with self.lock:
            for key in keys:
                r=self.records.get(key)
                if r and not r['restored'] and not r.get('released'): raise ValueError('복원 완료 또는 할당 해제 기록만 정리할 수 있습니다')
            for key in keys:
                self.records.pop(key,None);(self.root/(str(key)+'.json')).unlink(missing_ok=True)
        return {'success':True}
