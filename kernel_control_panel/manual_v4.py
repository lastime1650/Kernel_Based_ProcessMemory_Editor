"""ManualV4 web jobs backed solely by the kernel manual-map IOCTL."""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import math
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit
import uuid

from fastapi import APIRouter, HTTPException, Request
from atomic_metadata import write_json
from manual_map_protocol import (IDENTITY_NOTE, request as map_request,
                                 valid_result_addresses, valid_result_failcode, valid_result_diagnostic)
from request_scheduler import scope
from runtime_paths import data_path

ACTIVE = {'queued', 'running'}
KEY = re.compile(r'^[0-9a-f]{32}$')
# Stable job-history marker; the current IOCTL packet version is defined in the protocol module.
BACKEND = 'kernel_manual_map_v1'
MAX_JOBS = 256
JOB_FIELDS = {'id', 'backend', 'pid', 'process_start_key', 'path', 'nt_path', 'state',
              'created_at', 'started_at', 'finished_at', 'mapped_base', 'entry_point',
              'result_status', 'failcode', 'failmessage', 'output', 'error', 'execution_unknown', 'identity_check', 'note',
              'transport_ok', 'packet_valid', 'error_code', 'bytes_returned'}


def local_request(request):
    host = request.headers.get('host', '')
    try:
        parsed = urlsplit('http://' + host)
        local = parsed.hostname in ('127.0.0.1', 'localhost', '::1')
    except ValueError:
        local = False
    if not local:
        raise HTTPException(403, '로컬 패널에서 요청하세요')
    origin = request.headers.get('origin')
    if origin and origin != 'http://' + host:
        raise HTTPException(403, '다른 웹사이트의 요청은 허용하지 않습니다')


class ManualV4:
    def __init__(self, studio, root=None):
        self.studio = studio
        self.root = Path(root) if root is not None else data_path('assets') / 'manual_v4_kernel'
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='manual-v4-kernel')
        self.jobs = {}
        self.closing = False
        # This directory/marker deliberately excludes old subprocess/session jobs.
        for path in sorted(self.root.glob('*.json')):
            try:
                if path.is_symlink() or not KEY.fullmatch(path.stem) or path.stat().st_size > 16384:
                    continue
                record = json.loads(path.read_text(encoding='utf-8'))
                if (not isinstance(record, dict) or record.get('backend') != BACKEND
                        or record.get('id') != path.stem):
                    continue
                _, normalized = map_request(record['pid'], record['path'])
                self._identity_format(record['process_start_key'])
                if record.get('state') not in ACTIVE | {'mapped', 'failed', 'indeterminate'}:
                    continue
                created = record['created_at']
                if (isinstance(created, bool) or not isinstance(created, (int, float))
                        or not math.isfinite(created) or created < 0):
                    continue
                for field in ('started_at', 'finished_at'):
                    value = record.get(field)
                    if field in record and (isinstance(value, bool) or not isinstance(value, (int, float))
                                            or not math.isfinite(value) or value < 0):
                        raise ValueError('Invalid persisted timestamp')
                for field in ('output', 'error'):
                    if not isinstance(record.get(field, ''), str) or len(record.get(field, '')) > 8192:
                        raise ValueError('Invalid persisted text')
                for field in ('execution_unknown', 'transport_ok', 'packet_valid'):
                    if field in record and type(record[field]) is not bool:
                        raise ValueError('Invalid persisted flag')
                for field in ('error_code', 'bytes_returned'):
                    if field in record and (type(record[field]) is not int or not 0 <= record[field] <= 0xffffffff):
                        raise ValueError('Invalid persisted transport result')
                for field in ('mapped_base', 'entry_point'):
                    if not isinstance(record.get(field), str) or not re.fullmatch(r'0x(?:0|[1-9A-F][0-9A-F]{0,15})', record[field]):
                        raise ValueError('Invalid persisted address')
                if not valid_result_addresses(int(record['mapped_base'], 16), int(record['entry_point'], 16)):
                    raise ValueError('Invalid persisted address range')
                status = record.get('result_status')
                if status is not None and (not isinstance(status, str) or not re.fullmatch(r'0x[0-9A-F]{8}', status)):
                    raise ValueError('Invalid persisted status')
                failcode = record.get('failcode')
                if failcode is not None and (type(failcode) is not int or not 0 <= failcode <= 0xffffffff):
                    raise ValueError('Invalid persisted failcode')
                if failcode is not None and (status is None or not valid_result_failcode(int(status, 16), failcode)):
                    record.update(state='indeterminate', execution_unknown=True,
                                  error='저장된 failcode와 커널 상태가 일치하지 않습니다. 자동 재요청하지 않습니다.')
                # Historical v1/v2 records never contained this field. Preserve
                # them as history with an unknown message; never invent a cause.
                if 'failmessage' in record:
                    message = record['failmessage']
                    diagnostic_present = message is not None or failcode is not None
                    diagnostic_valid = (status is not None and valid_result_diagnostic(int(status, 16), failcode, message)
                                        and record.get('transport_ok') is True and record.get('packet_valid') is True)
                    if diagnostic_present and not diagnostic_valid:
                        record.update(state='indeterminate', execution_unknown=True, failcode=None, failmessage=None, output='',
                                      error='저장된 커널 진단 문자열이 불완전하거나 결과와 일치하지 않습니다. 자동 재요청하지 않습니다.')
                record = {field: value for field, value in record.items() if field in JOB_FIELDS}
                # Older saved jobs have no diagnostic field; do not invent success (zero).
                record.setdefault('failcode', None)
                record.setdefault('failmessage', None)
                record.setdefault('output', '')
                record.setdefault('error', '')
                record.setdefault('execution_unknown', record['state'] == 'indeterminate')
                record.update(nt_path=normalized, identity_check='preflight_only', note=IDENTITY_NOTE)
                if ((record['state'] == 'mapped' and (status != '0x00000000'
                     or record['mapped_base'] == '0x0' or not record.get('transport_ok')
                     or not record.get('packet_valid') or record['execution_unknown']))
                        or (record['state'] == 'failed' and record['execution_unknown'])):
                    record.update(state='indeterminate', execution_unknown=True,
                                  error='저장된 작업 결과가 불완전합니다. 자동 재요청하지 않습니다.')
                if record['state'] in ACTIVE:
                    record.update(state='indeterminate', execution_unknown=True,
                                  error='패널이 종료된 작업입니다. 매핑 여부를 확인할 수 없어 자동 재요청하지 않습니다.')
                    self._save_job(record)
                self.jobs[record['id']] = record
            except (OSError, ValueError, KeyError, TypeError, OverflowError):
                continue

    @staticmethod
    def _identity_format(identity):
        if (not isinstance(identity, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', identity)
                or int(identity) > 0xffffffffffffffff):
            raise ValueError('선택한 프로세스의 시작 키가 필요합니다')

    def _owner(self, pid, identity):
        if isinstance(pid, bool) or not isinstance(pid, int) or not 0 < pid <= 0xffffffff:
            raise ValueError('대상 PID를 확인하세요')
        self._identity_format(identity)
        try:
            actual = self.studio.identity(pid)
        except Exception as exc:
            raise ValueError('대상 프로세스 조회 실패: ' + str(exc)) from exc
        if str(actual) != identity:
            raise ValueError('대상 프로세스가 교체되었습니다. 다시 선택하세요')

    def _job_path(self, key):
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise ValueError('잘못된 작업 ID입니다')
        return self.root / (key + '.json')

    def _save_job(self, record):
        write_json(self._job_path(record['id']), record, durable=True)

    def prepare(self):
        with self.lock:
            if self.closing:
                if any(job['state'] in ACTIVE for job in self.jobs.values()):
                    raise RuntimeError('이전 커널 매핑 작업의 종료를 기다리세요')
                self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='manual-v4-kernel')
                self.closing = False

    def submit(self, body):
        if not isinstance(body, dict) or set(body) - {'pid', 'process_start_key', 'path'}:
            raise ValueError('PID, 프로세스 시작 키와 디스크 DLL 경로만 전달하세요')
        pid, identity, path = body.get('pid'), body.get('process_start_key'), body.get('path')
        _, normalized = map_request(pid, path)
        self._owner(pid, identity)
        with self.lock:
            if self.closing:
                raise ValueError('패널 종료 중입니다')
            if any(job['state'] == 'indeterminate' and (job['pid'], job['process_start_key']) == (pid, identity)
                   for job in self.jobs.values()):
                raise ValueError('이 대상의 이전 매핑 결과가 불확실하여 중복 요청을 차단합니다. 대상 프로세스를 종료하고 다시 선택하세요.')
            active = [job for job in self.jobs.values() if job['state'] in ACTIVE]
            for job in active:
                if (job['pid'], job['process_start_key']) == (pid, identity):
                    if job['nt_path'] == normalized:
                        return self.get(job['id'])
                    raise ValueError('해당 대상의 커널 매핑 작업이 진행 중입니다')
            if len(active) >= 4:
                raise ValueError('커널 매핑 작업 큐가 가득 찼습니다')
            if len(self.jobs) >= MAX_JOBS:
                raise ValueError('커널 매핑 작업 기록 상한에 도달했습니다')
            key = uuid.uuid4().hex
            job = dict(id=key, backend=BACKEND, pid=pid, process_start_key=identity,
                       path=path, nt_path=normalized, state='queued', created_at=time.time(),
                       mapped_base='0x0', entry_point='0x0', result_status=None, failcode=None, failmessage=None,
                       output='', error='', execution_unknown=False,
                       identity_check='preflight_only', note=IDENTITY_NOTE)
            self._save_job(job)  # Persist intent before queuing any kernel request.
            self.jobs[key] = job
            try:
                self.pool.submit(self._run, key)
            except BaseException:
                job.update(state='failed', error='작업 큐 시작 실패', finished_at=time.time())
                self._save_job(job)
                raise
            return self.get(key)

    def get(self, key):
        with self.lock:
            self._job_path(key)
            if key not in self.jobs:
                raise ValueError('작업을 찾을 수 없습니다')
            return dict(success=True, **copy.deepcopy(self.jobs[key]))

    def list(self):
        with self.lock:
            keys = sorted(self.jobs, key=lambda key: self.jobs[key]['created_at'], reverse=True)[:100]
            return dict(success=True, jobs=[self.get(key) for key in keys])

    def _run(self, key):
        attempted = False
        try:
            with self.lock:
                job = self.jobs[key]
                if self.closing:
                    job.update(state='failed', error='패널 종료 전에 시작하지 못한 작업입니다', finished_at=time.time())
                    self._save_job(job)
                    return
                job.update(state='running', started_at=time.time())
                self._save_job(job)
            # Serialize preflight and the request against this client's other
            # IOCTLs. The wire ABI cannot bind an expected process start key.
            with scope(0, 'manual-v4'), self.studio.driver._lock:
                with self.lock:
                    if self.closing:
                        raise RuntimeError('패널 종료 전에 시작하지 못한 작업입니다')
                self._owner(job['pid'], job['process_start_key'])
                with self.lock:
                    if self.closing:
                        raise RuntimeError('패널 종료 전에 시작하지 못한 작업입니다')
                    attempted = True
                result = self.studio.driver.manual_map_dll(job['pid'], job['path'])
            with self.lock:
                for field in ('transport_ok', 'packet_valid', 'execution_unknown', 'error_code',
                              'bytes_returned', 'result_status', 'failcode', 'failmessage', 'mapped_base', 'entry_point'):
                    if field in result:
                        job[field] = result[field]
                status = result.get('result_status')
                diagnostic_valid = (isinstance(status, str) and re.fullmatch(r'0x[0-9A-F]{8}', status)
                                    and valid_result_diagnostic(int(status, 16), result.get('failcode'), result.get('failmessage')))
                if not (diagnostic_valid and result.get('transport_ok') is True and result.get('packet_valid') is True):
                    job['failcode'] = None
                    job['failmessage'] = None
                uncertain = (result.get('execution_unknown') or not result.get('transport_ok')
                             or not result.get('packet_valid')
                             or not diagnostic_valid
                             or status in ('0x00000102', '0x00000103', '0xC00000B5'))
                job['execution_unknown'] = bool(uncertain)
                if uncertain:
                    state = 'indeterminate'
                elif (result.get('success') and status == '0x00000000'
                      and re.fullmatch(r'0x[1-9A-F][0-9A-F]*', result.get('mapped_base', ''))):
                    state = 'mapped'
                else:
                    state = 'failed'
                job.update(state=state, finished_at=time.time())
                job['output'] = f"IOCTL 0x878 · NTSTATUS {status or '미확인'} · failcode {job['failcode'] if job['failcode'] is not None else '미확인'} · Base {job['mapped_base']} · EntryPoint {job['entry_point']}"
                if job['failmessage']:
                    job['output'] += '\n' + job['failmessage']
                job['error'] = ('' if state == 'mapped' else
                                '커널 매핑 결과가 불확실합니다. 자동 재요청하지 않습니다.' if state == 'indeterminate' else
                                f'커널 DLL 매핑 실패 ({status or "결과 없음"}, failcode {job["failcode"]})')
                self._save_job(job)
        except BaseException as exc:
            with self.lock:
                job = self.jobs[key]
                job.update(state='indeterminate' if attempted else 'failed',
                           execution_unknown=attempted, error=str(exc)[:1024], finished_at=time.time())
                try:
                    self._save_job(job)
                except OSError:
                    job['error'] = '작업 결과 저장 실패. 자동 재요청하지 않습니다.'

    def shutdown(self):
        with self.lock:
            self.closing = True
        # Do not interrupt a synchronous IOCTL or dispatch queued mapping later.
        self.pool.shutdown(wait=True, cancel_futures=False)


def install(app, studio, manager=None):
    manager = manager or ManualV4(studio)
    router = APIRouter(prefix='/api/manual-v4')

    @router.post('/map')
    async def submit(request: Request):
        local_request(request)
        try:
            body = await request.json()
            return await asyncio.to_thread(manager.submit, body)
        except (ValueError, OSError, RuntimeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get('/jobs')
    def jobs(request: Request):
        local_request(request)
        return manager.list()

    @router.get('/jobs/{key}')
    def job(key: str, request: Request):
        local_request(request)
        try:
            return manager.get(key)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    app.include_router(router)
    return manager
