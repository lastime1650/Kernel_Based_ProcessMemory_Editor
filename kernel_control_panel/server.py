"""
FastAPI Server for SampleKernel1 Windows Kernel Driver Control Panel (Enhanced Pro Edition)
Includes Cheat Engine Style Multi-Pass Memory Scanner, Live Watch Table, Hex Inspector,
Virtual Memory Map, and Structure Dissector.
"""

import os
import sys
import asyncio
import struct
import threading
import math
import uuid
from functools import wraps
from contextlib import suppress
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from driver_bridge import (
    KernelDriverBridge,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
)
from memory_scanner import dissect_structure, FORMATS
from kernel_only_bridge import KernelOnlyBridge
from kernel_scanner import KernelMemoryScannerSession
from process_catalog import KernelProcessCatalog, DiscoveryError, DEFAULT_MAX_PID, MAX_PID_LIMIT

app = FastAPI(title="SampleKernel1 Pro Kernel Studio", version="3.0.0")

@app.exception_handler(ValueError)
@app.exception_handler(struct.error)
async def invalid_input_response(request, exc):
    # Legacy routes parse numeric addresses and pack typed values directly.
    # Invalid input must remain a client error, before any driver operation.
    return JSONResponse(status_code=400, content={'success':False,
                        'error':'입력값을 확인하세요', 'detail':str(exc)[:512]})

driver = KernelOnlyBridge()
process_catalog = KernelProcessCatalog(driver)

scanner = KernelMemoryScannerSession(driver, lambda pid: studio.operate('regions', {'pid':pid,'max_results':50000}))
known_processes = {}
known_process_lock = threading.RLock()

# Real-time WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Watch List (Cheat Table) State
class WatchEntry:
    def __init__(self, entry_id: str, pid: int, address: str, address_int: int, data_type: str, description: str = "", frozen: bool = False, frozen_val: Any = None, identity=None):
        self.id = entry_id
        self.pid = pid
        self.address = address
        self.address_int = address_int
        self.data_type = data_type
        self.description = description
        self.frozen = frozen
        self.frozen_val = frozen_val
        self.current_value = "—"
        self.identity = identity
        self.error = ""

watch_table: List[WatchEntry] = []

watch_lock = threading.RLock()

def _with_watch_lock(method):
    @wraps(method)
    def invoke(*args, **kwargs):
        with watch_lock:
            return method(*args, **kwargs)
    return invoke

@_with_watch_lock
def maintain_frozen_values():
    # Removal/unfreeze cannot return before an already-started write finishes.
    for item in watch_table:
        if item.frozen and item.frozen_val is not None:
            try:
                check_watch_owner(item)
                fmt, size = FORMATS[item.data_type]
                payload = struct.pack(fmt, item.frozen_val)
                response = driver.write_process_memory(item.pid, item.address_int, payload)
                if not response or not response.get('success') or response.get('bytes_written') != size:
                    raise ValueError("고정 쓰기 실패")
            except Exception as exc:
                item.frozen = False
                item.error = str(exc)

def check_watch_owner(item):
    if item.identity is not None:
        response = driver.query_process_info(item.pid)
        if not response.get('success') or response.get('exit_status') != 259 or str(response.get('process_start_key')) != item.identity:
            item.frozen = False
            raise ValueError("대상 프로세스가 종료되거나 교체되었습니다")

def read_watch_value(item, kind=None):
    check_watch_owner(item)
    fmt, size = FORMATS[kind or item.data_type]
    response = driver.read_process_memory_snapshot(item.pid, item.address_int, size)
    if not response.get('success') or len(response.get('data_hex', '')) != size * 2:
        raise ValueError("Watch 주소 읽기 실패")
    value = struct.unpack(fmt, bytes.fromhex(response['data_hex']))[0]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("유한한 값만 고정할 수 있습니다")
    return value

# Background task for Memory Freeze
async def background_worker():
    while True:
        try:
            await asyncio.to_thread(maintain_frozen_values)
        except Exception:
            pass
        await asyncio.sleep(0.1)

@app.on_event("startup")
async def startup_event():
    studio.prepare()
    driver.open()
    app.state.background_task = asyncio.create_task(background_worker())

@app.on_event("shutdown")
async def shutdown_event():
    task = getattr(app.state, "background_task", None)
    if task is not None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    await asyncio.to_thread(studio.shutdown)
    # A cancelled to_thread await does not cancel the native freeze call.
    def wait_for_freeze():
        with watch_lock:
            for item in watch_table:
                item.frozen = False
    await asyncio.to_thread(wait_for_freeze)
    await asyncio.to_thread(driver.close)

def parse_int(val: Any) -> int:
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)

# -------------------------------------------------------------
# Request Models
# -------------------------------------------------------------

class MemoryAllocRequest(BaseModel):
    pid: int
    size: int
    protect: int = PAGE_EXECUTE_READWRITE

class MemoryFreeRequest(BaseModel):
    pid: int
    address: str

class MemoryProtectRequest(BaseModel):
    pid: int
    address: str
    size: int
    new_protect: int

class MemoryReadRequest(BaseModel):
    pid: int
    address: str
    size: int

class MemoryWriteRequest(BaseModel):
    pid: int
    address: str
    data_type: Optional[str] = "hex" # "hex", "text", "int32", "float", etc.
    value: str

class MemoryCopyRequest(BaseModel):
    src_pid: int
    src_addr: str
    dst_pid: int
    dst_addr: str
    size: int

class PatternScanRequest(BaseModel):
    pid: int
    start_address: str
    scan_length: int
    pattern_hex: str

class FirstScanRequest(BaseModel):
    pid: int
    data_type: str # "int8", "int16", "int32", "int64", "float32", "float64", "unknown"
    scan_type: str # "exact", "bigger", "smaller", "between", "unknown"
    val1: Optional[str] = ""
    val2: Optional[str] = ""
    writable_only: bool = True
    alignment: int = 0
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    max_results: int = 50000

class NextScanRequest(BaseModel):
    scan_type: str # "exact", "increased", "decreased", "changed", "unchanged", "bigger", "smaller"
    val1: Optional[str] = ""
    val2: Optional[str] = ""

class WatchAddRequest(BaseModel):
    pid: int
    address: str
    data_type: str = "int32"
    description: str = ""

class WatchUpdateRequest(BaseModel):
    id: str
    description: Optional[str] = None
    value: Optional[str] = None
    data_type: Optional[str] = None

class WatchFreezeRequest(BaseModel):
    id: str
    frozen: bool

class StructDissectRequest(BaseModel):
    pid: int
    base_address: str
    size: int = 256

class ThreadContextRequest(BaseModel):
    registers: Dict[str, str]

class HwbpSetRequest(BaseModel):
    pid: int
    address: str
    bp_type: int = 0
    bp_len: int = 0

class HwbpRemoveRequest(BaseModel):
    pid: int
    first_node: str

class DllRegisterRequest(BaseModel):
    pid: int
    dll_path: str

class MonitorControlRequest(BaseModel):
    enable_process: bool
    enable_image: bool

# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@app.get("/api/status")
def get_driver_status():
    if not driver.is_connected():
        driver.open()
    res = driver.get_driver_status()
    res["connected"] = driver.is_connected()
    return res

@app.get("/api/processes")
def get_process_list(max_pid: int = Query(DEFAULT_MAX_PID, ge=4, le=MAX_PID_LIMIT),
                     refresh: bool = False):
    with known_process_lock:
        extras = tuple(known_processes)
    try:
        return process_catalog.list(max_pid, extras, refresh)
    except DiscoveryError as exc:
        raise HTTPException(503, str(exc)) from exc

@app.get("/api/process/{pid}")
def get_process_details(pid: int):
    if not 0 < pid <= 0xffffffff: raise HTTPException(400, 'PID 범위 오류')
    pinfo = driver.query_process_info(pid)
    pex = driver.query_process_extended(pid)
    token = driver.query_process_token(pid)
    if pinfo.get('success') and pinfo.get('exit_status') == 259 and pex.get('success'):
        with known_process_lock:
            known_processes[int(pinfo['process_id'])] = str(pinfo['process_start_key'])
    return {
        "basic": pinfo,
        "extended": pex,
        "token": token,
        "identity": {"create_time": str(pex.get('create_time', 0))}
    }

@app.get("/api/process/{pid}/handles")
def get_process_handles(pid: int, max_handles: int = 128):
    result=driver.query_process_handles(pid,max_handles)
    if result.get('success'):
        count=driver.query_process_extended(pid)
        if count.get('success'):result.update(total=count['handle_count'],truncated=count['handle_count']>len(result['handles']))
    return result

@app.get("/api/process/{pid}/threads")
def get_process_threads(pid: int, max_threads: int = 64):
    result=driver.enumerate_threads(pid,max_threads)
    if result.get('success'):
        count=driver.query_process_extended(pid)
        if count.get('success'):result.update(total=count['thread_count'],truncated=count['thread_count']>len(result['threads']))
    return result

@app.get("/api/thread/{tid}/context")
def get_thread_context(tid: int):
    return driver.get_thread_context(tid)

@app.post("/api/thread/{tid}/context")
def set_thread_context(tid: int, req: ThreadContextRequest):
    owner=driver.query_thread_info(tid)
    if not owner.get('success'):return owner
    return studio.run('set_context',{'pid':owner['process_id'],'tid':tid,'registers':req.registers})

@app.post("/api/thread/{tid}/suspend")
def suspend_thread(tid: int):
    return driver.suspend_thread(tid)

@app.post("/api/thread/{tid}/resume")
def resume_thread(tid: int):
    return driver.resume_thread(tid)

@app.post("/api/thread/{tid}/hide")
def set_thread_hide(tid: int):
    return driver.set_thread_hide_from_debugger(tid)

# -------------------------------------------------------------
# Memory APIs (Read, Write, Alloc, Free, Protect, Map, Dump)
# -------------------------------------------------------------

@app.post("/api/memory/alloc")
def alloc_virtual_memory(req: MemoryAllocRequest):
    return driver.alloc_virtual_memory(req.pid, req.size, req.protect)

@app.post("/api/memory/free")
def free_virtual_memory(req: MemoryFreeRequest):
    addr = parse_int(req.address)
    return driver.free_virtual_memory(req.pid, addr)

@app.post("/api/memory/protect")
def protect_virtual_memory(req: MemoryProtectRequest):
    addr = parse_int(req.address)
    return driver.protect_virtual_memory(req.pid, addr, req.size, req.new_protect)

@app.post("/api/memory/read")
def read_virtual_memory(req: MemoryReadRequest):
    addr = parse_int(req.address)
    res = driver.read_process_memory_snapshot(req.pid, addr, req.size)
    if res.get("data_hex"):
        try:
            raw = bytes.fromhex(res["data_hex"])
            ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
            res["data_ascii"] = ascii_preview
        except Exception:
            res["data_ascii"] = ""
    return res

@app.post("/api/memory/write")
def write_virtual_memory(req: MemoryWriteRequest):
    addr = parse_int(req.address)
    t = req.data_type.lower()
    val_str = req.value.strip()

    if t == "hex":
        clean = val_str.replace(" ", "").replace("0x", "")
        payload = bytes.fromhex(clean)
    elif t in ("text", "string"):
        payload = val_str.encode("utf-8")
    elif t in FORMATS:
        fmt, sz = FORMATS[t]
        val = float(val_str) if "float" in t else parse_int(val_str)
        payload = struct.pack(fmt, val)
    else:
        payload = val_str.encode("utf-8")

    return driver.write_process_memory(req.pid, addr, payload)

@app.post("/api/memory/inspect")
def inspect_memory_data(req: MemoryReadRequest):
    """Data Inspector: Returns all numerical, float, string interpretations for a given address."""
    addr = parse_int(req.address)
    res = driver.read_process_memory_snapshot(req.pid, addr, 16)
    if not res.get("data_hex"):
        return {"success": False, "error": "Cannot read memory"}

    raw = bytes.fromhex(res["data_hex"])
    interpretations = {}

    if len(raw) >= 1:
        interpretations["int8"] = struct.unpack("<b", raw[:1])[0]
        interpretations["uint8"] = struct.unpack("<B", raw[:1])[0]
        interpretations["binary"] = bin(raw[0])
    if len(raw) >= 2:
        interpretations["int16"] = struct.unpack("<h", raw[:2])[0]
        interpretations["uint16"] = struct.unpack("<H", raw[:2])[0]
    if len(raw) >= 4:
        interpretations["int32"] = struct.unpack("<i", raw[:4])[0]
        interpretations["uint32"] = struct.unpack("<I", raw[:4])[0]
        f32 = struct.unpack("<f", raw[:4])[0]
        interpretations["float32"] = f"{f32:.7g}"
    if len(raw) >= 8:
        interpretations["int64"] = struct.unpack("<q", raw[:8])[0]
        u64 = struct.unpack("<Q", raw[:8])[0]
        interpretations["uint64"] = u64
        interpretations["pointer"] = f"0x{u64:X}"
        f64 = struct.unpack("<d", raw[:8])[0]
        interpretations["float64"] = f"{f64:.10g}"

    # ASCII and UTF-16
    try:
        interpretations["ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:16])
    except Exception:
        interpretations["ascii"] = ""

    try:
        interpretations["utf16"] = raw[:16].decode("utf-16-le", errors="ignore").replace("\x00", "")
    except Exception:
        interpretations["utf16"] = ""

    return {
        "success": True,
        "address": f"0x{addr:X}",
        "hex": raw[:8].hex().upper(),
        "interpretations": interpretations
    }

@app.post('/api/memory/copy')
def copy_virtual_memory(req: MemoryCopyRequest):
    return studio.run('copy',{'pid':req.src_pid,'address':req.src_addr,'dst_pid':req.dst_pid,
                              'dst_address':req.dst_addr,'size':req.size})

@app.get("/api/memory/map/{pid}")
def get_memory_map(pid: int, writable_only: bool = False, executable_only: bool = False):
    raw = studio.operate('regions', {'pid':pid})
    regions = []
    for row in raw['results']:
        if row['state'] != '0x1000': continue
        keep = row['readable'] and not row['guarded'] and (not writable_only or row['writable']) and (not executable_only or row['executable'])
        regions.append({'base_address':row['address'],'base_address_int':int(row['address'],16),
            'region_size':row['size'],'region_size_kb':row['size']//1024,'state':'MEM_COMMIT','protect':row['protect'],
            'type':{'0x20000':'MEM_PRIVATE','0x1000000':'MEM_IMAGE','0x40000':'MEM_MAPPED'}.get(row['type'],'OTHER'),
            'is_writable':row['writable'],'is_executable':row['executable'],'keep_for_scan':keep})
    return {"regions": regions, "total_count": len(regions),'map_total':raw['total'],
            'truncated':raw['truncated'],'note':'반환 상한이 적용된 맵은 전체 주소 공간을 나타내지 않습니다' if raw['truncated'] else ''}

@app.post("/api/memory/pattern_scan")
def pattern_scan(req: PatternScanRequest):
    start = parse_int(req.start_address)
    tokens = req.pattern_hex.strip().split()
    pattern_bytes = bytearray()
    mask_chars = []
    for t in tokens:
        if t in ("?", "??"):
            pattern_bytes.append(0)
            mask_chars.append("?")
        else:
            pattern_bytes.append(int(t, 16))
            mask_chars.append("x")
    mask_str = "".join(mask_chars)
    return driver.pattern_scan(req.pid, start, req.scan_length, bytes(pattern_bytes), mask_str)

# -------------------------------------------------------------
# Cheat Engine Style Multi-Pass Memory Scanner APIs
# -------------------------------------------------------------

@app.post("/api/scan/first")
def scan_first(req: FirstScanRequest):
    return scanner.first_scan(
        pid=req.pid,
        data_type=req.data_type,
        scan_type=req.scan_type,
        val1=req.val1,
        val2=req.val2,
        writable_only=req.writable_only,
        alignment=req.alignment, start_address=req.start_address, end_address=req.end_address,
        max_results=req.max_results
    )

@app.post("/api/scan/next")
def scan_next(req: NextScanRequest):
    return scanner.next_scan(
        scan_type=req.scan_type,
        val1=req.val1,
        val2=req.val2
    )

@app.post("/api/scan/reset")
def scan_reset():
    scanner.reset()
    return {"success": True}

@app.get("/api/scan/results")
def scan_results(page: int = 1, page_size: int = 100):
    return scanner.get_results(page=page, page_size=page_size)

# -------------------------------------------------------------
# Watch List (Cheat Table) APIs
# -------------------------------------------------------------

@app.get("/api/watch/list")
@_with_watch_lock
def get_watch_list():
    # Read current values for each watched address
    for item in watch_table:
        try:
            val = read_watch_value(item)
            item.current_value = str(val)
            item.error = ""
        except Exception as exc:
            item.current_value = "—"
            item.error = str(exc)

    return {
        "items": [
            {
                "id": w.id,
                "pid": w.pid,
                "address": w.address,
                "data_type": w.data_type,
                "description": w.description,
                "frozen": w.frozen,
                "frozen_val": w.frozen_val,
                "current_value": w.current_value,
                "error": w.error
            }
            for w in watch_table
        ]
    }

@app.post("/api/watch/add")
@_with_watch_lock
def add_watch_item(req: WatchAddRequest):
    try:
        addr_int = parse_int(req.address)
        if req.data_type not in FORMATS or not 0 < addr_int < 0x800000000000 or not 0 < req.pid <= 0xffffffff:
            raise ValueError("프로세스·주소·데이터 형식을 확인하세요")
        response = driver.query_process_info(req.pid)
        if not response.get('success') or response.get('exit_status') != 259:
            raise ValueError("실행 중인 프로세스가 필요합니다")
        if len(watch_table) >= 256:
            raise ValueError("Watch는 최대 256개입니다")
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))
    entry_id = 'watch_' + uuid.uuid4().hex
    item = WatchEntry(entry_id, req.pid, f"0x{addr_int:X}", addr_int, req.data_type, req.description, identity=str(response['process_start_key']))
    watch_table.append(item)
    return {"success": True, "item_id": entry_id}

@app.post("/api/watch/remove")
@_with_watch_lock
def remove_watch_item(req: Dict[str, str]):
    item_id = req.get("id")
    global watch_table
    watch_table = [w for w in watch_table if w.id != item_id]
    return {"success": True}

@app.post("/api/watch/update")
@_with_watch_lock
def update_watch_item(req: WatchUpdateRequest):
    for item in watch_table:
        if item.id == req.id:
            try:
                kind = req.data_type or item.data_type
                if kind not in FORMATS: raise ValueError("지원하지 않는 데이터 형식")
                check_watch_owner(item)
                fmt, size = FORMATS[kind]
                value = None
                if req.value is not None:
                    parsed_val = float(req.value) if "float" in kind else parse_int(req.value)
                    if isinstance(parsed_val, float) and not math.isfinite(parsed_val): raise ValueError("유한한 수를 입력하세요")
                    data = struct.pack(fmt, parsed_val)
                    value = struct.unpack(fmt, data)[0]
                    response = driver.write_process_memory(item.pid, item.address_int, data)
                    if not response.get('success') or response.get('bytes_written') != size:
                        item.frozen = False
                        item.error = "Watch 쓰기 실패"
                        return dict(response, success=False, error=item.error)
                elif item.frozen and kind != item.data_type:
                    value = read_watch_value(item, kind)
                item.data_type = kind
                if req.description is not None: item.description = req.description
                if value is not None: item.frozen_val = value; item.current_value = str(value)
                item.error = ""
            except (ValueError, TypeError, KeyError, struct.error, OverflowError) as exc:
                raise HTTPException(400, str(exc))
            return {"success": True}
    raise HTTPException(status_code=404, detail="Watch entry not found")

@app.post("/api/watch/freeze")
@_with_watch_lock
def freeze_watch_item(req: WatchFreezeRequest):
    for item in watch_table:
        if item.id == req.id:
            if req.frozen:
                try:
                    item.frozen_val = read_watch_value(item)
                    item.current_value = str(item.frozen_val)
                    item.error = ""
                except (ValueError, TypeError, KeyError, struct.error) as exc:
                    item.frozen = False
                    item.error = str(exc)
                    return {"success": False, "frozen": False, "error": item.error}
            item.frozen = req.frozen
            return {"success": True, "frozen": item.frozen}
    raise HTTPException(status_code=404, detail="Watch entry not found")

# -------------------------------------------------------------
# Structure Dissection API
# -------------------------------------------------------------

@app.post("/api/struct/dissect")
def dissect_memory_structure(req: StructDissectRequest):
    addr_int = parse_int(req.base_address)
    fields = dissect_structure(driver, req.pid, addr_int, total_size=req.size)
    return {"success": True, "base_address": f"0x{addr_int:X}", "fields": fields}

# -------------------------------------------------------------
# HWBP, DLL & Monitor APIs
# -------------------------------------------------------------

@app.post("/api/hwbp/set")
def set_hwbp(req: HwbpSetRequest):
    addr = parse_int(req.address)
    length={0:1,1:2,3:4,2:8}.get(req.bp_len)
    if length is None:return {'success':False,'error':'중단점 길이 오류'}
    return studio.run('hwbp_set',{'pid':req.pid,'address':hex(addr),'type':req.bp_type,'length':length})

@app.get("/api/hwbp/query/{pid}")
def query_hwbp(pid: int):
    # The raw list is owned by this server, so never leave it allocated behind a HTTP response.
    return studio.run('hwbp_query',{'pid':pid})

@app.post("/api/hwbp/remove")
def remove_hwbp(req: HwbpRemoveRequest):
    node = parse_int(req.first_node)
    with studio.lock:
        record=next((r for r in studio.breakpoints.values() if r['node']==node),None)
    if record:
        if record['pid']!=req.pid:return {'success':False,'error':'중단점 소유 프로세스가 다릅니다'}
        return studio.run('hwbp_remove',{'pid':req.pid,'id':record['id']})
    res = driver.remove_hardware_breakpoint(req.pid, node)
    if res.get("success"):
        released=driver.free_hardware_breakpoint_result(node)
        if not released.get('success'):return dict(res,success=False,free_response=released,recovery_retained=True)
    return res

@app.post("/api/dll/register")
def register_dll(req: DllRegisterRequest):
    return driver.register_dll(req.pid, req.dll_path)

@app.post("/api/monitor/control")
def monitor_control(req: MonitorControlRequest):
    return driver.event_monitor_control(req.enable_process, req.enable_image)

@app.get("/api/monitor/poll")
def monitor_poll(max_events: int = 16):
    return driver.poll_events(max_events)

@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Static Files
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

from studio_api import install as install_studio
studio = install_studio(app, driver)

@app.get("/")
def read_root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>SampleKernel1 Control Panel Backend Running</h1>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)

