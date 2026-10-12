"""Synchronize factual x64 EPROCESS layouts from the site's real link tree.

No driver, process-memory, or native API calls. Network synchronization is explicit.
Only facts (member/type names, offsets, sizes, bit positions) are saved, not C bodies.
Unknown composite extents are raw_span_size, never represented as sizeof.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

BASE = 'https://www.vergiliusproject.com'
ROOT_URL = BASE + '/kernels/x64'
SCHEMA_VERSION = 1
SCALARS = {
    'UCHAR': (1, False), 'CHAR': (1, True), 'BOOLEAN': (1, False),
    'BYTE': (1, False), 'USHORT': (2, False), 'SHORT': (2, True),
    'WCHAR': (2, False), 'ULONG': (4, False), 'LONG': (4, True),
    'DWORD': (4, False), 'UINT': (4, False), 'INT': (4, True),
    'ULONGLONG': (8, False), 'LONGLONG': (8, True),
    'ULONG64': (8, False), 'LONG64': (8, True),
    'ULONG_PTR': (8, False), 'LONG_PTR': (8, True),
    'SIZE_T': (8, False), 'SSIZE_T': (8, True),
    'KAFFINITY': (8, False), 'KPRIORITY': (4, True),
}
WIN11_SOURCE = 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'
WIN10_SOURCE = 'https://learn.microsoft.com/en-us/windows/release-health/release-information'
LEGACY_SOURCE = 'https://learn.microsoft.com/en-us/windows/win32/msi/operating-system-property-values'
SERVER_SOURCE = 'https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info'
XP_SOURCE = 'https://support.microsoft.com/en-us/servicing/os/windows/2018/04/ms10-015-vulnerabilities-in-windows-kernel-could-allow-elevation-of-privilege'


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.code = []
        self.type_links = {}
        self.inside = False
        self.depth = 0
        self.anchor = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
            if self.inside:
                self.anchor = [attrs['href'], []]
        if tag == 'div' and attrs.get('id') == 'copyblock':
            self.inside = True
            self.depth = 1
        elif self.inside and tag == 'div':
            self.depth += 1

    def handle_endtag(self, tag):
        if tag == 'a' and self.anchor is not None:
            href, parts = self.anchor
            self.type_links[''.join(parts).strip()] = href
            self.anchor = None
        if tag == 'div' and self.inside:
            self.depth -= 1
            if self.depth == 0:
                self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.code.append(data)
            if self.anchor is not None:
                self.anchor[1].append(data)


def parse_page(data):
    p = Page()
    p.feed(data.decode('utf-8'))
    return p


class Fetcher:
    def __init__(self, cache: Path, refresh=False):
        self.cache = cache
        self.refresh = refresh
        self.cache.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.downloaded = 0
        self.cached = 0
        self.urls = set()

    def get(self, url):
        parsed = urlparse(url)
        if (parsed.scheme != 'https' or parsed.netloc != 'www.vergiliusproject.com'
                or not (parsed.path == '/kernels/x64' or parsed.path.startswith('/kernels/x64/'))):
            raise ValueError('Only the explicit Vergilius x64 subtree may be fetched')
        key = hashlib.sha256(url.encode()).hexdigest()
        path, meta_path = self.cache / (key + '.html'), self.cache / (key + '.json')
        with self.lock:
            self.urls.add(url)
            if path.exists() and not self.refresh:
                raw = path.read_bytes()
                meta = json.loads(meta_path.read_text()) if meta_path.exists() else {
                    'source_url': url,
                    'downloaded_at_utc': datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                    'content_sha256': hashlib.sha256(raw).hexdigest()}
                self.cached += 1
                return raw, meta
        for attempt in range(3):
            try:
                req = Request(url, headers={'User-Agent': 'SampleKernelResearch/1.0 (factual layout metadata; max4workers)'})
                with urlopen(req, timeout=40) as response:
                    final = urlparse(response.url)
                    if (final.netloc != parsed.netloc
                            or not (final.path == '/kernels/x64' or final.path.startswith('/kernels/x64/'))):
                        raise ValueError('Unexpected redirect outside requested subtree')
                    raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise ValueError('Page size limit exceeded')
                meta = {'source_url': url, 'downloaded_at_utc': utc_now(), 'content_sha256': hashlib.sha256(raw).hexdigest()}
                with self.lock:
                    path.write_bytes(raw)
                    meta_path.write_text(json.dumps(meta), encoding='utf-8')
                    self.downloaded += 1
                time.sleep(.04)
                return raw, meta
            except Exception:
                if attempt == 2:
                    raise
                time.sleep(.3 * (attempt + 1))


def direct_children(page, url, depth):
    prefix = urlparse(url).path.rstrip('/') + '/'
    return sorted({urljoin(BASE, link) for link in page.links
                   if urlparse(urljoin(BASE, link)).netloc == 'www.vergiliusproject.com'
                   and urlparse(urljoin(BASE, link)).path.startswith(prefix)
                   and len(urlparse(urljoin(BASE, link)).path.strip('/').split('/')) == depth})


def sizeof_code(text):
    m = re.search(r'//\s*(0x[0-9a-fA-F]+|\d+)\s+bytes\s*\(sizeof\)', text)
    if not m:
        raise ValueError('Explicit sizeof header missing')
    return int(m.group(1), 0)


def normalize_type(text):
    text = re.sub(r'\b(struct|union)(volatile|const)\b', r'\1 \2', text)
    return ' '.join(text.split())


def field_declaration(decl, offset, parent):
    decl = normalize_type(decl.strip().rstrip(';'))
    fn = re.fullmatch(r'(.+?)\(\s*\*\s*(\w+)\s*\)\s*\((.*)\)', decl)
    if fn:
        type_name, name, args = fn.groups()
        return {'name': name, 'type': type_name + ' (*)(' + args + ')', 'offset': offset,
                'size': 8, 'size_source': 'x64_pointer', 'kind': 'pointer', 'signed': False,
                'array_count': None, 'bit_offset': None, 'bit_width': None, 'members': []}
    m = re.fullmatch(r'(.+?)\s+([A-Za-z_$][\w$]*)(\s*(?:\[\d+\])*)(?:\s*:\s*(\d+))?', decl)
    if not m:
        raise ValueError('Unsupported declaration: ' + decl)
    type_name, name, array, bit_width = m.groups()
    type_name = normalize_type(type_name)
    clean = re.sub(r'\b(const|volatile)\b', '', type_name)
    clean = ' '.join(clean.split())
    pointer = '*' in clean or clean in ('HANDLE', 'PVOID')
    if pointer:
        element_size, signed, kind, provenance = 8, False, 'pointer', 'x64_pointer'
    elif clean in SCALARS:
        element_size, signed = SCALARS[clean]
        kind, provenance = 'scalar', 'windows_scalar'
    elif clean.startswith('enum '):
        element_size, signed, kind, provenance = 4, True, 'scalar', 'windows_enum_int32'
    else:
        element_size, signed, kind, provenance = None, None, 'raw', 'unknown'
    dims = [int(n) for n in re.findall(r'\[(\d+)\]', array)]
    count = None
    if dims:
        count = 1
        for n in dims:
            count *= n
        kind = 'array'
    size = element_size * count if element_size is not None and count is not None else element_size
    bit_offset = None
    if bit_width is not None:
        if element_size is None or dims or pointer:
            raise ValueError('Unknown bitfield storage: ' + decl)
        width = int(bit_width)
        key = (offset, clean)
        bit_offset = parent['_bits'].get(key, 0)
        if bit_offset + width > element_size * 8:
            raise ValueError('Bitfield exceeds explicit storage: ' + decl)
        parent['_bits'][key] = bit_offset + width
        kind = 'bitfield'
    else:
        width = None
    return {'name': name, 'type': type_name, 'offset': offset, 'size': size,
            'size_source': provenance, 'kind': kind, 'signed': signed,
            'element_size': element_size, 'element_kind': 'pointer' if pointer else ('scalar' if element_size else 'raw'),
            'array_count': count, 'array_dimensions': dims,
            'bit_offset': bit_offset, 'bit_width': width, 'members': []}


def parse_layout(text, type_links=None):
    total = sizeof_code(text)
    root = {'name': '_EPROCESS', 'type': 'struct _EPROCESS', 'kind': 'struct', 'offset': 0,
            'size': total, 'size_source': 'source_sizeof', 'members': [], '_bits': {}}
    stack, pending, counter, opened = [root], None, 0, False
    errors = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('//'):
            continue
        if not opened:
            if stripped == '{':
                opened = True
            continue
        if stripped in ('union', 'struct'):
            pending = stripped
            continue
        if stripped == '{':
            if not pending:
                errors.append({'line': lineno, 'reason': 'opening brace without group'})
                continue
            counter += 1
            node = {'name': f'$anon_{pending}_{counter}', 'type': 'anonymous ' + pending,
                    'kind': pending, 'offset': None, 'size': None, 'size_source': 'unknown',
                    'anonymous': True, 'members': [], '_bits': {}}
            stack[-1]['members'].append(node)
            stack.append(node)
            pending = None
            continue
        if stripped.startswith('}'):
            if len(stack) == 1:
                break
            node = stack.pop()
            tail = re.match(r'}\s*([A-Za-z_$][\w$]*)?\s*;?\s*(?://\s*(0x[0-9a-fA-F]+))?', stripped)
            if tail and tail.group(1):
                node['name'], node['anonymous'] = tail.group(1), False
            if tail and tail.group(2):
                node['offset'] = int(tail.group(2), 16)
            continue
        m = re.match(r'(.+?);\s*//\s*(0x[0-9a-fA-F]+)\s*$', stripped)
        if m:
            try:
                field = field_declaration(m.group(1), int(m.group(2), 16), stack[-1])
                field['source_line'] = lineno
                clean_type = re.sub(r'\b(struct|union|enum|const|volatile)\b|\*', '', field['type']).strip()
                if type_links and clean_type in type_links:
                    field['type_url'] = type_links[clean_type]
                stack[-1]['members'].append(field)
            except ValueError as exc:
                errors.append({'line': lineno, 'reason': str(exc)})
        else:
            errors.append({'line': lineno, 'reason': 'unparsed source line'})
    if len(stack) != 1:
        errors.append({'reason': 'unclosed aggregate'})
    return root, errors


def walk_members(node):
    for field in node.get('members', []):
        yield field
        yield from walk_members(field)


def resolve_sizes(root, linked_sizes):
    for field in walk_members(root):
        url = field.get('type_url')
        if field['size'] is None and url in linked_sizes:
            size = linked_sizes[url]
            field['element_size'] = size
            field['size'] = size * (field.get('array_count') or 1)
            field['size_source'] = 'linked_type_sizeof'
            field.pop('raw_span_size',None)
            field.pop('raw_span_source',None)
            if field['kind'] == 'raw':
                field['kind'] = 'union' if re.search(r'\bunion\b',field['type']) else 'struct'
    def aggregate(node):
        for child in node.get('members', []):
            aggregate(child)
        children = node.get('members', [])
        if children and node['offset'] is None:
            known = [child['offset'] for child in children if child['offset'] is not None]
            if known:
                node['offset'] = min(known)
        if children and node.get('size') is None and node['offset'] is not None:
            ends = [c['offset'] + c['size'] for c in children if c.get('size') is not None and c['offset'] is not None]
            if len(ends) == len(children):
                node['size'] = max(ends) - node['offset']
                node['size_source'] = 'inline_member_extent'
        node.pop('_bits', None)
    aggregate(root)
    fields = list(walk_members(root))
    offsets = sorted({f['offset'] for f in fields if f['offset'] is not None} | {root['size']})
    for f in fields:
        if f['offset'] is None:
            raise ValueError('Aggregate without explicit child offset')
        if f['size'] is not None and f['offset'] + f['size'] > root['size']:
            raise ValueError('Field extends outside explicit structure sizeof: ' + f['name'])
        if f['size'] is None:
            later = [n for n in offsets if n > f['offset']]
            f['raw_span_size'] = min(later) - f['offset'] if later else None
            f['raw_span_source'] = 'next_explicit_offset_gap_not_sizeof'
    return root


def flatten_fields(root):
    result = []
    def visit(node, path, containers, unions):
        for f in node.get('members', []):
            p = path + [f['name']]
            out = {k: v for k, v in f.items() if k != 'members'}
            out.update(path='.'.join(p), container_path=list(containers), union_path=list(unions),
                       offset_hex=hex(f['offset']),
                       size_exact=f.get('size_source') not in ('unknown','inline_member_extent'))
            result.append(out)
            next_containers = containers + ['.'.join(p)] if f.get('members') else containers
            next_unions = unions + ['.'.join(p)] if f['kind'] == 'union' else unions
            visit(f, p, next_containers, next_unions)
    visit(root, [], [], [])
    return result


def mapping(family, release):
    aliases, products, sp, major, minor, sources = [family], [1], 0, 10, 0, []
    builds = []
    auto = True
    notes = ['Base build is exact; UBR/revision layout identity is not asserted by the source.']
    if family == 'windows-11':
        values = {'21h2': 22000, '22h2': 22621, '23h2': 22631, '24h2': 26100, '25h2': 26200}
        if release in values:
            builds = [values[release]]
        else:
            auto = False
            notes.append('June 2021 Insider source does not disclose an exact build; manual-only research preset.')
        sources = [WIN11_SOURCE]
    elif family == 'windows-10':
        values = dict(zip(['1507','1511','1607','1703','1709','1803','1809','1903','1909','2004','20h2','21h1','21h2','22h2'],
                          [10240,10586,14393,15063,16299,17134,17763,18362,18363,19041,19042,19043,19044,19045]))
        if release in values:
            builds = [values[release]]
        else:
            auto = False
            notes.append('Unmapped future Windows10 release requires verified build metadata.')
        sources = [WIN10_SOURCE]
    elif family == 'server-2022':
        builds, products, sources = [20348], [2,3], [SERVER_SOURCE]
    elif family == 'windows-7':
        builds, sp, major, minor = [7601 if release == 'sp1' else 7600], 1 if release == 'sp1' else 0, 6, 1
        aliases, products, sources = ['windows-7', 'server-2008-r2'], [1,2,3], [LEGACY_SOURCE]
    elif family == 'windows-8':
        builds, major, minor = [9200], 6, 2
        aliases, products, sources = ['windows-8','server-2012'], [1,2,3], [LEGACY_SOURCE]
    elif family == 'windows-8.1':
        builds, major, minor = [9600], 6, 3
        aliases, products, sources = ['windows-8.1','server-2012-r2'], [1,2,3], [LEGACY_SOURCE]
        auto = False
        notes.append('RTM and Update 1 share base build9600 and SP0 but have separate source layouts; no automatic selection without release/revision evidence.')
    elif family == 'windows-vista':
        sp = {'rtm':0,'sp1':1,'sp2':2}[release]
        builds, major, minor = [6000 + sp], 6, 0
        aliases = ['windows-vista'] if sp == 0 else ['windows-vista','server-2008']
        products, sources = ([1] if sp == 0 else [1,2,3]), [LEGACY_SOURCE]
        if sp == 1:
            notes.append('Server2008 RTM reports base6001; its service-pack designation differs from VistaSP1; inspect product-specific matching.')
    elif family == 'windows-xp':
        builds, sp, major, minor = [3790], 2, 5, 2
        aliases, products, sources = ['windows-xp-x64','server-2003'], [1,2,3], [LEGACY_SOURCE,XP_SOURCE]
    else:
        auto = False
        products, sp, major, minor = [], None, None, None
        notes.append('New family requires explicit verified mapping; no latest-version fallback.')
    return {'family': family, 'release': release, 'family_aliases': aliases,
            'architecture': 'x64', 'pointer_size': 8, 'build_numbers': builds,
            'product_types': products, 'service_pack': sp, 'nt_major': major, 'nt_minor': minor,
            'auto_select': auto, 'matching_notes': notes, 'mapping_sources': sources}


def sync(output, cache, workers=4, refresh=False, type_depth=2):
    fetcher = Fetcher(cache, refresh)
    root_raw, _ = fetcher.get(ROOT_URL)
    families = direct_children(parse_page(root_raw), ROOT_URL, 3)
    release_urls = []
    for family_url in families:
        raw, _ = fetcher.get(family_url)
        release_urls += direct_children(parse_page(raw), family_url, 4)
    releases, missing = [], []
    for url in release_urls:
        raw, _ = fetcher.get(url)
        candidate = url.rstrip('/') + '/_EPROCESS'
        linked = {urljoin(BASE,l) for l in parse_page(raw).links}
        if candidate in linked:
            releases.append(candidate)
        else:
            missing.append({'release_url': url, 'reason': 'EPROCESS not linked on actual release index'})
    def preset(url):
        raw, provenance = fetcher.get(url)
        page = parse_page(raw)
        code = ''.join(page.code)
        links = {name:urljoin(BASE,href) for name,href in page.type_links.items()}
        layout, errors = parse_layout(code, links)
        if errors:
            raise ValueError(json.dumps(errors))
        needed = {f['type_url'] for f in walk_members(layout) if f.get('type_url') and f['size'] is None}
        sizes, type_sources, failures, linked_layouts = {}, [], [], {}
        release_prefix = url.rsplit('/',1)[0] + '/'
        def collect_type(linked, depth, ancestors):
            if not linked.startswith(release_prefix):
                failures.append({'url':linked,'reason':'type link outside exact release'})
                return
            if linked in ancestors or (linked in linked_layouts and linked_layouts[linked][1] >= depth):
                return
            try:
                data, meta = fetcher.get(linked)
                linked_page = parse_page(data)
                linked_code = ''.join(linked_page.code)
                size = sizeof_code(linked_code)
                sizes[linked] = size
                if not any(s['source_url'] == linked for s in type_sources):
                    type_sources.append(dict(meta, source_url=linked, type=linked.rsplit('/',1)[-1], size=size))
                links_for_type = {name:urljoin(BASE,href) for name,href in linked_page.type_links.items()}
                typed, parse_errors = parse_layout(linked_code, links_for_type)
                if parse_errors:
                    failures.append({'url':linked,'reason':'nested type members not fully parsed','parse_errors':parse_errors})
                    return
                typed['name'] = linked.rsplit('/',1)[-1]
                typed['type'] = 'struct ' + typed['name']
                linked_layouts[linked] = (typed, depth)
                for child in walk_members(typed):
                    child_url = child.get('type_url')
                    if child_url and child['size'] is None:
                        if depth > 1:
                            collect_type(child_url,depth-1,ancestors|{linked})
                        elif child_url not in sizes and child_url.startswith(release_prefix):
                            # Verify terminal by-value sizeof without expanding or following pointers.
                            size_data, size_meta = fetcher.get(child_url)
                            child_size = sizeof_code(''.join(parse_page(size_data).code))
                            sizes[child_url] = child_size
                            if not any(s['source_url'] == child_url for s in type_sources):
                                type_sources.append(dict(size_meta,source_url=child_url,type=child_url.rsplit('/',1)[-1],size=child_size))
                resolve_sizes(typed,sizes)
            except Exception as exc:
                failures.append({'url':linked,'reason':str(exc)})
        for linked in sorted(needed):
            collect_type(linked,min(3,max(1,type_depth)),set())
        for typed, _depth in linked_layouts.values():
            resolve_sizes(typed,sizes)
        resolve_sizes(layout, sizes)
        family, release = urlparse(url).path.strip('/').split('/')[2:4]
        meta = mapping(family, release)
        pid = 'x64/' + family + '/' + release
        fields = flatten_fields(layout)
        def children(field, depth, ancestors):
            child_url = field.get('type_url')
            if (depth <= 0 or not child_url or child_url in ancestors or child_url not in linked_layouts
                    or field.get('array_count') or field.get('kind') == 'pointer'
                    or field.get('element_kind') == 'pointer'):
                return []
            rows = flatten_fields(linked_layouts[child_url][0])
            for row in rows:
                relative = row['offset']
                row['relative_offset'] = relative
                row['offset'] = field['offset'] + relative
                row['offset_hex'] = hex(row['offset'])
                row['path'] = field['path'] + '.' + row['path']
                row['container_path'] = [field['path']] + [field['path']+'.'+p for p in row['container_path']]
                row['union_path'] = list(field.get('union_path',[])) + [field['path']+'.'+p for p in row['union_path']]
                nested = children(row,depth-1,ancestors|{child_url})
                if nested:
                    row['child_fields'] = nested
            return rows
        for field in fields:
            nested = children(field,min(3,max(1,type_depth)),set())
            if nested:
                field['child_fields'] = nested
        result = dict(meta, schema_version=SCHEMA_VERSION, id=pid, structure='_EPROCESS',
                      size=layout['size'], size_hex=hex(layout['size']),
                      source_url=url, source_build_disclosed=False,
                      downloaded_at_utc=provenance['downloaded_at_utc'],
                      content_sha256=hashlib.sha256(raw).hexdigest(),
                      field_count=len(fields), fields=fields, type_sources=type_sources,
                      nested_type_depth=min(3,max(1,type_depth)),
                      unresolved_types=failures,
                      unknown_size_fields=[f['path'] for f in fields if f['size'] is None],
                      schema_notes=['Offsets are absolute within EPROCESS, including anonymous unions.',
                                    'size is scalar/pointer/linked sizeof or labeled inline member extent.',
                                    'raw_span_size is an offset gap, not proven sizeof.',
                                    'Pointers are displayed as addresses; no automatic dereference.'])
        filename = family + '-' + release + '.json'
        (output/filename).write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n', encoding='utf-8')
        entry = {key:result[key] for key in ['id','family','release','architecture','pointer_size','build_numbers','product_types','service_pack','size','source_url','content_sha256','downloaded_at_utc','family_aliases','nt_major','nt_minor','auto_select','matching_notes']}
        entry.update(file=filename, field_count=len(fields), preset_sha256=hashlib.sha256((output/filename).read_bytes()).hexdigest())
        print('OK', pid, hex(result['size']), len(fields), 'fields', flush=True)
        return entry
    output.mkdir(parents=True,exist_ok=True)
    entries, errors = [], []
    with ThreadPoolExecutor(max_workers=min(4,max(1,workers))) as executor:
        futures = [(u,executor.submit(preset,u)) for u in releases]
        for url,future in futures:
            try:
                entries.append(future.result())
            except Exception as exc:
                errors.append({'source_url':url,'reason':str(exc)})
    manifest = {'schema_version':SCHEMA_VERSION,'structure':'_EPROCESS','architecture':'x64','pointer_size':8,
                'source_root_url':ROOT_URL,'generated_at_utc':utc_now(),
                'family_count':len(families),'release_count':len(release_urls),'preset_count':len(entries),
                'families':families,'presets':sorted(entries,key=lambda e:e['id']),
                'missing':missing,'errors':errors,
                'fetch_statistics':{'unique_urls':len(fetcher.urls),'network_fetches':fetcher.downloaded,'cache_hits':fetcher.cached,'max_workers':min(4,max(1,workers))},
                'selection_policy':'Exact architecture/base build/product type/service pack only; ambiguous release and undisclosed Insider build require manual choice. Never substitute latest preset.',
                'mapping_sources':[WIN11_SOURCE,WIN10_SOURCE,LEGACY_SOURCE,SERVER_SOURCE,XP_SOURCE],
                'source_note':'Vergilius release pages expose layout size/offsets but no exact kernel revision/PDB identity; metadata build mappings come from Microsoft release documentation, not asserted symbol identity.'}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'presets/eprocess')
    parser.add_argument('--cache-dir',type=Path,required=True,help='Explicit scratch/cache directory outside project data')
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--refresh',action='store_true')
    parser.add_argument('--type-depth',type=int,choices=(1,2,3),default=2)
    args = parser.parse_args()
    manifest = sync(args.output,args.cache_dir,args.workers,args.refresh,args.type_depth)
    print(json.dumps({k:manifest[k] for k in ('family_count','release_count','preset_count','missing','errors','fetch_statistics')},indent=2))
    return 1 if manifest['missing'] or manifest['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
