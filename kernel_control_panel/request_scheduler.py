"""Shared driver admission lock and in-flight read sharing. No cached target bytes."""
from contextvars import ContextVar
from contextlib import contextmanager
import threading
import time
import copy
import os

priority = ContextVar('kernel_priority', default=1)
source = ContextVar('kernel_source', default='panel')

@contextmanager
def scope(value=1, label=None):
    token = priority.set(value)
    other = source.set(label) if label else None
    try: yield
    finally:
        priority.reset(token)
        if other: source.reset(other)

class PriorityLock:
    """Reentrant lock. Manual writes > manual reads > live reads; bounded fairness."""
    def __init__(self):
        self.cv = threading.Condition()
        self.owner = None
        self.depth = self.sequence = self.streak = 0
        self.waiters = []
        self.admissions = self.wait_ms = 0
    def acquire(self, blocking=True, timeout=-1):
        who = threading.get_ident()
        with self.cv:
            if self.owner == who: self.depth += 1; return True
            self.sequence += 1
            item = (priority.get(), self.sequence, who)
            self.waiters.append(item)
            started = time.monotonic()
            while True:
                chosen = min(self.waiters, key=(lambda x:x[1]) if self.streak>=16 else (lambda x:(x[0],x[1])))
                if self.owner is None and chosen == item:
                    self.waiters.remove(item); self.owner=who; self.depth=1
                    self.streak = 0 if item[0]==2 or self.streak>=16 else self.streak+1
                    self.admissions += 1; self.wait_ms += (time.monotonic()-started)*1000
                    return True
                elapsed=time.monotonic()-started
                if not blocking or (timeout>=0 and elapsed>=timeout):
                    self.waiters.remove(item); self.cv.notify_all(); return False
                self.cv.wait(None if timeout<0 else timeout-elapsed)
    def release(self):
        with self.cv:
            if self.owner!=threading.get_ident(): raise RuntimeError('driver lock owner mismatch')
            self.depth-=1
            if not self.depth: self.owner=None; self.cv.notify_all()
    def __enter__(self): self.acquire(); return self
    def __exit__(self,*args): self.release()
    def _is_owned(self): return self.owner==threading.get_ident()

class Scheduler:
    def __init__(self, driver):
        self.driver=driver; self.guard=threading.Lock(); self.pending={}; self.epoch=0
        self.shared=self.reads=0
        driver._lock=PriorityLock()
        original=driver.read_process_memory_snapshot
        def read(pid, address, size):
            # Manual reads and every verification always obtain a fresh snapshot.
            if priority.get()!=2 or driver._lock._is_owned(): return original(pid,address,size)
            with self.guard:
                key=(pid,address,size,self.epoch)
                entry=self.pending.get(key)
                if entry: self.shared+=1; leader=False
                else:
                    entry={'event':threading.Event()};self.pending[key]=entry;self.reads+=1;leader=True
            if leader:
                try: entry['value']=original(pid,address,size)
                except BaseException as exc: entry['error']=exc
                finally:
                    with self.guard: self.pending.pop(key,None);entry['event'].set()
            else: entry['event'].wait()
            if 'error' in entry: raise entry['error']
            return copy.deepcopy(entry['value'])
        driver.read_process_memory_snapshot=read
        for name in ('write_process_memory','copy_process_memory','free_virtual_memory','protect_virtual_memory','alloc_virtual_memory'):
            original_mutation=getattr(driver,name)
            def mutation(*args,_method=original_mutation,_name=name,**kwargs):
                # Releasing the caller's copied response does not change target bytes.
                if _name=='free_virtual_memory' and (args[0] if args else kwargs.get('pid'))==os.getpid():return _method(*args,**kwargs)
                with scope(0), driver._lock:
                    with self.guard: self.epoch+=1
                    try: return _method(*args,**kwargs)
                    finally:
                        with self.guard: self.epoch+=1
            setattr(driver,name,mutation)
    def stats(self):
        with self.guard:
            lock=self.driver._lock
            return {'policy':'write / manual / live; fairness after 16 admissions','coalesced_reads':self.shared,
                    'live_reads':self.reads,'pending_reads':len(self.pending),'waiting':len(lock.waiters),
                    'admissions':lock.admissions,'wait_ms':round(lock.wait_ms,1),'byte_cache':False}
