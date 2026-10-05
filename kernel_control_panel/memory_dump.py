"""Bounded-memory dump jobs; all target discovery and reads use the driver."""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
import uuid
import zipfile

PAGE_BYTES = 4096
MAX_CHUNK_BYTES = 1024 * 1024
MAX_DUMP_BYTES = 16 * 1024 ** 3
USER_LIMIT = 0x800000000000
ACTIVE_STATES = ('queued', 'running', 'packaging')


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def number(value):
    if isinstance(value, bool):
        raise ValueError('정수 값을 입력하세요')
    return int(str(value).strip(), 0 if str(value).strip().lower().startswith('0x') else 10)


class DumpCancelled(Exception):
    pass


class DumpManager:
    def __init__(self, studio, root=None):
        self.studio = studio
        self.root = Path(root or os.environ.get('KERNEL_STUDIO_DUMP_DIR') or
                         Path(__file__).parent / 'dumps').resolve()
        self.lock = threading.RLock()
        self.jobs = {}
        self.closed = False
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='kernel-dump')
        self._restore_completed()

    def _restore_completed(self):
        if not self.root.exists():
            return
        for directory in self.root.iterdir():
            if len(self.jobs) >= 128:
                break
            if (not re.fullmatch('[0-9a-f]{32}', directory.name) or directory.is_symlink()
                    or not directory.is_dir()):
                continue
            try:
                document = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
                if (document['id'] != directory.name or document['state'] != 'completed'
                        or not 0 < document['total_bytes'] <= MAX_DUMP_BYTES
                        or document['completed_bytes'] != document['total_bytes']):
                    continue
                files = document['files']
                if sum(item['size'] for item in files) != document['total_bytes']:
                    continue
                artifacts = files + ([document['bundle']] if document.get('bundle') else [])
                if not artifacts or any(
                    Path(item['name']).name != item['name'] or ':' in item['name']
                    or not re.fullmatch('[0-9a-f]{64}', item['sha256'] or '')
                    or (directory / item['name']).is_symlink()
                    or (directory / item['name']).stat().st_size != item['size']
                    for item in artifacts):
                    continue
                for key in ('success', 'progress_percent', 'manifest_url', 'dump_format'):
                    document.pop(key, None)
                for item in files:
                    item.pop('download_url', None)
                    item['_segments'] = []
                if document.get('bundle'):
                    document['bundle'].pop('download_url', None)
                self.jobs[directory.name] = document
            except (OSError, ValueError, KeyError, TypeError):
                continue

    def prepare(self):
        if self.closed:
            self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='kernel-dump')
            self.closed = False

    def _owner(self, job):
        if self.studio.identity(job['pid']) != job['identity']:
            raise ValueError('대상 프로세스가 종료되거나 교체되었습니다. 이어서 덤프할 수 없습니다')

    @staticmethod
    def _segments(base, size, regions):
        end, cursor, result = base + size, base, []
        for region in sorted(regions, key=lambda r: number(r['address'])):
            left = max(base, number(region['address']))
            right = min(end, number(region['address']) + number(region['size']))
            if right <= left:
                continue
            if left < cursor:
                raise ValueError('커널 메모리 맵에 겹치는 영역이 있습니다')
            if left > cursor:
                result.append((cursor, left, False, 'unmapped'))
            readable = (number(region['state']) == 0x1000 and region['readable']
                        and not region['guarded'])
            result.append((left, right, readable, '' if readable else 'unreadable_or_guarded'))
            cursor = right
        if cursor < end:
            result.append((cursor, end, False, 'unmapped'))
        return result

    def start(self, args):
        if not isinstance(args, dict):
            raise ValueError('덤프 인수는 객체여야 합니다')
        pid = number(args.get('pid', 0))
        if not 0 < pid <= 0xffffffff:
            raise ValueError('PID 범위를 확인하세요')
        mode = args.get('mode', 'range')
        if mode not in ('range', 'image', 'images'):
            raise ValueError('지원하지 않는 덤프 방식입니다')
        policy = args.get('policy', 'strict' if mode == 'range' else 'zero')
        if policy not in ('strict', 'zero'):
            raise ValueError('읽기 실패 처리는 strict 또는 zero여야 합니다')
        chunk = number(args.get('chunk_size', MAX_CHUNK_BYTES))
        if not PAGE_BYTES <= chunk <= MAX_CHUNK_BYTES or chunk % PAGE_BYTES:
            raise ValueError('묶음 크기는 4KiB~1MiB의 4KiB 배수여야 합니다')
        with self.lock:
            if self.closed:
                raise ValueError('덤프 작업이 종료 중입니다')
            if len(self.jobs) >= 128:
                raise ValueError('덤프 이력은 최대 128개입니다. 불필요한 이력을 삭제하세요')
            if sum(j['state'] in ACTIVE_STATES for j in self.jobs.values()) >= 4:
                raise ValueError('덤프 작업 큐가 가득 찼습니다')
            identity = self.studio.identity(pid)
            mapped = self.studio.operate('regions', {'pid': pid,'max_results':50000})
            if not mapped.get('success') or mapped.get('truncated'):
                raise ValueError('완전한 커널 메모리 맵을 가져오지 못했습니다')
            regions = mapped['results']
            images = {}
            for region in regions:
                if number(region['type']) != 0x1000000:
                    continue
                base = number(region['image_base']) or number(region['allocation_base'])
                if not base:
                    raise ValueError('이미지 기준 주소를 확인할 수 없습니다')
                image = images.setdefault(base, {'base': base, 'size': 0, 'name': '',
                    'path': '', 'main_image': False, 'regions': [], '_declared_size': 0, '_extent': 0})
                declared = number(region['image_size'])
                if declared:
                    if image['_declared_size'] and image['_declared_size'] != declared:
                        raise ValueError('같은 이미지의 커널 크기 정보가 일치하지 않습니다')
                    image['_declared_size'] = declared
                image['_extent'] = max(image['_extent'], number(region['address']) + number(region['size']) - base)
                # MEM_IMAGE allocation tails may include post-image guard pages.
                # Honor the image size; mapped extent is only a metadata fallback.
                image['size'] = image['_declared_size'] or image['_extent']
                image['name'] = image['name'] or region['image_name'] or f'image_{base:X}'
                image['path'] = image['path'] or region['image_path']
                image['main_image'] |= bool(region['main_image'])
                image['regions'].append(region)
            if mode == 'range':
                base, size = number(args['address']), number(args['size'])
                selected = [{'base': base, 'size': size, 'name': 'memory', 'regions': regions,
                             'path': '', 'main_image': False}]
            else:
                selected = sorted(images.values(), key=lambda x: x['base'])
                if mode == 'image':
                    requested = str(args.get('module', '')).strip()
                    if not requested or requested.lower() == 'main':
                        selected = [x for x in selected if x['main_image']]
                    elif requested.lower().startswith('0x'):
                        selected = [x for x in selected if x['base'] == number(requested)]
                    else:
                        selected = [x for x in selected if x['name'].lower() == requested.lower()]
                    if len(selected) != 1:
                        raise ValueError('모듈 이름 또는 기준 주소로 이미지 하나를 지정하세요')
                if not selected:
                    raise ValueError('MEM_IMAGE 영역이 없습니다')
            files, total = [], 0
            for image in selected:
                base, size = image['base'], image['size']
                if not 0 < base < USER_LIMIT or not 0 < size <= MAX_DUMP_BYTES or base + size > USER_LIMIT:
                    raise ValueError('덤프 주소 또는 크기 범위를 확인하세요')
                total += size
                safe = re.sub(r'[^A-Za-z0-9_.-]', '_', image['name'])[:100]
                filename = f'{safe}_{base:X}.{"mapped" if mode != "range" else "memory"}.bin'
                files.append({'name': filename, 'module': image['name'], 'image_path': image['path'],
                    'main_image': image['main_image'], 'address': f'0x{base:X}', 'size': size,
                    'size_source': 'kernel_image_size' if image.get('_declared_size') else 'mapped_extent' if mode != 'range' else 'requested_range',
                    'written': 0, 'sha256': None, 'prefix_sha256': hashlib.sha256().hexdigest(),
                    '_segments': self._segments(base, size, image['regions'])})
            if total > MAX_DUMP_BYTES:
                raise ValueError('전체 덤프 크기는 최대 16GiB입니다')
            job = {'id': uuid.uuid4().hex, 'pid': pid, 'identity': identity, 'mode': mode,
                'policy': policy, 'chunk_size': chunk, 'state': 'queued', 'created': stamp(),
                'updated': stamp(), 'total_bytes': total, 'completed_bytes': 0, 'zero_bytes': 0,
                'read_requests': 0, 'read_failures': 0, 'files': files, 'holes': [], 'error': '',
                'cancel_requested': False, 'resumes': 0, 'bundle': None,
                'layout': 'file offset = virtual address - image base' if mode != 'range' else
                          'file offset = virtual address - requested start',
                'consistency': 'live sequential reads; process continues running'}
            self._owner(job)
            self.root.mkdir(parents=True, exist_ok=True)
            required = total * (2 if mode == 'images' else 1) + 64 * 1024 ** 2
            if shutil.disk_usage(self.root).free < required:
                raise ValueError('덤프와 묶음 파일을 저장할 디스크 공간이 부족합니다')
            (self.root / job['id']).mkdir()
            self.jobs[job['id']] = job
            self._manifest(job)
            job['_future'] = self.executor.submit(self._work, job)
            return {'success': True, 'dump_id': job['id']}

    def _public(self, job):
        result = copy.deepcopy({k: v for k, v in job.items() if not k.startswith('_')})
        for item in result['files']:
            item.pop('_segments', None)
            if job['state'] == 'completed':
                item['download_url'] = f'/api/studio/dumps/{job["id"]}/files/{item["name"]}'
        if result.get('bundle') and job['state'] == 'completed':
            result['bundle']['download_url'] = f'/api/studio/dumps/{job["id"]}/files/images.zip'
        result['progress_percent'] = round(100 * job['completed_bytes'] / job['total_bytes'], 2)
        result['manifest_url'] = f'/api/studio/dumps/{job["id"]}/files/manifest.json'
        result['success'] = job['state'] == 'completed'
        return result

    def _manifest(self, job):
        with self.lock:
            document = self._public(job)
            document['dump_format'] = 'kernel-memory-dump-v1'
            path = self.root / job['id'] / 'manifest.json'
            temporary = path.with_suffix('.tmp')
            temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
            temporary.replace(path)

    def get(self, key):
        with self.lock:
            if key not in self.jobs:
                raise KeyError('덤프 작업을 찾을 수 없습니다')
            return self._public(self.jobs[key])

    def list(self):
        with self.lock:
            return [self._public(job) for job in reversed(self.jobs.values())]

    def cancel(self, key):
        with self.lock:
            job = self.jobs[key]
            if job['state'] in ACTIVE_STATES:
                job['cancel_requested'] = True
            return {'success': True, 'note': '진행 중인 커널 요청 완료 후 취소합니다'}

    def resume(self, key):
        with self.lock:
            job = self.jobs[key]
            if self.closed or job['state'] not in ('cancelled', 'failed'):
                raise ValueError('중단되거나 실패한 덤프만 이어서 실행할 수 있습니다')
            if sum(j['state'] in ACTIVE_STATES for j in self.jobs.values()) >= 4:
                raise ValueError('덤프 작업 큐가 가득 찼습니다')
            self._owner(job)
            required = job['total_bytes'] - job['completed_bytes']
            if job['mode'] == 'images':
                required += job['total_bytes']
            if shutil.disk_usage(self.root).free < required + 64 * 1024 ** 2:
                raise ValueError('이어쓰기 디스크 공간이 부족합니다')
            job.update(state='queued', cancel_requested=False, error='', updated=stamp())
            job['resumes'] += 1
            self._manifest(job)
            job['_future'] = self.executor.submit(self._work, job)
            return {'success': True, 'dump_id': key}

    def remove(self, key):
        with self.lock:
            job = self.jobs[key]
            if job['state'] in ACTIVE_STATES:
                raise ValueError('진행 중인 덤프는 삭제할 수 없습니다')
            if job.get('_future') and not job['_future'].done():
                raise ValueError('덤프 종료 기록을 저장 중입니다. 잠시 후 삭제하세요')
            if job.get('_downloads', 0):
                raise ValueError('다운로드 중인 덤프는 삭제할 수 없습니다')
            directory = (self.root / key).resolve()
            if directory.parent != self.root or not re.fullmatch('[0-9a-f]{32}', key):
                raise ValueError('덤프 경로 검증 실패')
            shutil.rmtree(directory)
            del self.jobs[key]
            return {'success': True}

    def artifact(self, key, name, lease=False):
        with self.lock:
            job = self.jobs[key]
            if name == 'manifest.json':
                self._manifest(job)
                if lease:
                    job['_downloads'] = job.get('_downloads', 0) + 1
                return self.root / key / name, 'application/json', None
            if job['state'] != 'completed':
                raise ValueError('완료된 덤프만 다운로드할 수 있습니다')
            for item in job['files'] + ([job['bundle']] if job['bundle'] else []):
                if item['name'] == name:
                    if lease:
                        job['_downloads'] = job.get('_downloads', 0) + 1
                    return self.root / key / name, ('application/zip' if name == 'images.zip'
                                                   else 'application/octet-stream'), item['sha256']
            raise KeyError('덤프 파일을 찾을 수 없습니다')

    def release_download(self, key):
        with self.lock:
            if key in self.jobs:
                job = self.jobs[key]
                job['_downloads'] = max(0, job.get('_downloads', 0) - 1)

    def _cancelled(self, job):
        if job['cancel_requested'] or self.closed:
            raise DumpCancelled()

    def _hole(self, job, item, offset, size, reason, status=''):
        with self.lock:
            holes = job['holes']
            if (holes and holes[-1]['file'] == item['name'] and holes[-1]['reason'] == reason
                    and holes[-1]['status'] == status and holes[-1]['offset'] + holes[-1]['size'] == offset):
                holes[-1]['size'] += size
            else:
                if len(holes) >= 50000:
                    raise ValueError('읽기 실패 기록이 너무 많습니다. 덤프를 중단합니다')
                holes.append({'file': item['name'], 'offset': offset, 'address': f'0x{number(item["address"])+offset:X}',
                              'size': size, 'reason': reason, 'status': status})

    def _file(self, job, item):
        if item['sha256']:
            return
        directory = self.root / job['id']
        part = directory / (item['name'] + '.part')
        offset = item['written']
        if offset and (not part.exists() or part.stat().st_size != offset):
            raise ValueError('이어쓰기 파일 크기가 기록과 다릅니다')
        digest = hashlib.sha256()
        with part.open('r+b' if part.exists() else 'w+b') as output:
            for _ in range(0, offset, MAX_CHUNK_BYTES):
                self._cancelled(job)
                digest.update(output.read(min(MAX_CHUNK_BYTES, offset - output.tell())))
            if digest.hexdigest() != item['prefix_sha256']:
                raise ValueError('이어쓰기 파일 내용이 SHA256 기록과 다릅니다')
            output.seek(offset)
            next_check = offset
            for left, right, readable, reason in item['_segments']:
                base = number(item['address'])
                current = max(left, base + offset)
                while current < right:
                    self._cancelled(job)
                    if offset >= next_check:
                        self._owner(job)
                        next_check = offset + job['chunk_size']
                    size = min(PAGE_BYTES - current % PAGE_BYTES, right - current)
                    hole = None
                    if readable:
                        with self.lock:
                            job['read_requests'] += 1
                        response = self.studio.driver.read_process_memory_snapshot(job['pid'], current, size)
                        if response.get('success'):
                            raw = bytes.fromhex(response['data_hex'])
                            if len(raw) != size:
                                raise ValueError('커널이 반환한 덤프 크기가 요청과 다릅니다')
                        else:
                            with self.lock:
                                job['read_failures'] += 1
                            if job['policy'] == 'strict':
                                raise ValueError(f'0x{current:X} 커널 읽기 실패: {response.get("result_status", "")}; 이어쓰기는 같은 주소부터 재시도합니다')
                            hole = ('read_failed', response.get('result_status', ''))
                            raw = bytes(size)
                    else:
                        if job['policy'] == 'strict':
                            raise ValueError(f'0x{current:X} 읽을 수 없는 영역: {reason}')
                        hole = (reason, '')
                        raw = bytes(size)
                    if output.write(raw) != size:
                        raise OSError('덤프 파일 부분 쓰기')
                    if hole:
                        self._hole(job, item, offset, size, *hole)
                        with self.lock:
                            job['zero_bytes'] += size
                    digest.update(raw)
                    current += size
                    offset += size
                    with self.lock:
                        item['written'] = offset
                        item['prefix_sha256'] = digest.hexdigest()
                        job['completed_bytes'] += size
                        job['updated'] = stamp()
                    if offset >= next_check:
                        self._owner(job)
                        output.flush()
                        self._manifest(job)
            self._owner(job)
            if offset != item['size']:
                raise ValueError('덤프 범위 크기 불일치')
            output.flush()
        part.replace(directory / item['name'])
        with self.lock:
            item['sha256'] = digest.hexdigest()
        self._manifest(job)

    def _bundle(self, job):
        with self.lock:
            job['state'] = 'packaging'
            document = self._public(job)
            document.update(state='completed', success=True)
        directory = self.root / job['id']
        part = directory / 'images.zip.part'
        with zipfile.ZipFile(part, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for item in job['files']:
                with (directory / item['name']).open('rb') as source, archive.open(item['name'], 'w', force_zip64=True) as target:
                    while data := source.read(MAX_CHUNK_BYTES):
                        self._cancelled(job)
                        target.write(data)
            archive.writestr('manifest.json', json.dumps(document, ensure_ascii=False, indent=2))
        self._cancelled(job)
        digest = hashlib.sha256()
        with part.open('rb') as source:
            while data := source.read(MAX_CHUNK_BYTES):
                self._cancelled(job)
                digest.update(data)
        part.replace(directory / 'images.zip')
        job['bundle'] = {'name': 'images.zip', 'size': (directory / 'images.zip').stat().st_size,
                         'sha256': digest.hexdigest()}

    def _work(self, job):
        try:
            self._cancelled(job)
            with self.lock:
                job['state'] = 'running'
            self._owner(job)
            for item in job['files']:
                self._cancelled(job)
                self._file(job, item)
            self._owner(job)
            if job['mode'] == 'images':
                self._bundle(job)
            self._cancelled(job)
            with self.lock:
                job.update(state='completed', error='', finished=stamp())
        except DumpCancelled:
            with self.lock:
                job.update(state='cancelled', finished=stamp())
        except Exception as exc:
            with self.lock:
                job.update(state='failed', error=str(exc), finished=stamp())
        finally:
            job['updated'] = stamp()
            self._manifest(job)

    def shutdown(self):
        with self.lock:
            self.closed = True
            for job in self.jobs.values():
                if job['state'] in ACTIVE_STATES:
                    job['cancel_requested'] = True
        # Queued jobs run briefly to persist their cancelled state and partial metadata.
        self.executor.shutdown(wait=True)

