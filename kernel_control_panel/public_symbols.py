"""Optional Microsoft public PDB retrieval, bound to an image's CodeView ID."""
from pathlib import Path, PureWindowsPath
import re
import threading
import time
import urllib.error
import urllib.request
import uuid

SERVER = 'https://msdl.microsoft.com/download/symbols'
MAX_BYTES = 256*1024*1024
DEADLINE_SECONDS = 25
MSF7 = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'
LOCK = threading.RLock()


def identity(codeview):
    try:
        name=PureWindowsPath(codeview['pdb_path']).name
        guid=uuid.UUID(codeview['guid'])
        age=codeview['age']
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,180}\.pdb',name,re.IGNORECASE):raise ValueError()
        if isinstance(age,bool) or not isinstance(age,int) or not 0<=age<=0xffffffff:raise ValueError()
    except (KeyError,ValueError,TypeError,AttributeError):
        raise ValueError('Microsoft 공개 심볼 조회에 유효한 CodeView PDB 이름·GUID·Age가 필요합니다')
    key=guid.hex.upper()+format(age,'X')
    return name,key,SERVER+'/'+name+'/'+key+'/'+name


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        if not newurl.lower().startswith('https://'):
            raise ValueError('공개 심볼 서버의 HTTPS 연결만 허용됩니다')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def fetch(codeview,root,validate,opener=None):
    """validate(path) must reject a PDB whose DIA GUID/Age differ from image."""
    name,key,url=identity(codeview)
    folder=Path(root)/'public'/name/key
    path=folder/name
    opener=opener or urllib.request.build_opener(HTTPSRedirect()).open
    with LOCK:
        if path.is_file():
            if not 0<path.stat().st_size<=MAX_BYTES:raise ValueError('공개 심볼 캐시 파일 크기 오류')
            with path.open('rb') as stream:
                if stream.read(len(MSF7))!=MSF7:raise ValueError('공개 심볼 캐시의 PDB 형식 오류')
            return dict(validate(path),symbol_server=SERVER,download_url=url,cached=True)
        folder.mkdir(parents=True,exist_ok=True)
        temporary=folder/(uuid.uuid4().hex+'.download')
        promoted=False
        try:
            began=time.monotonic()
            request=urllib.request.Request(url,headers={'User-Agent':'KernelStudio-PublicSymbols/1.0'})
            with opener(request,timeout=15) as response, temporary.open('wb') as stream:
                length=response.headers.get('Content-Length')
                if length is not None and (not length.isdecimal() or int(length)>MAX_BYTES):
                    raise ValueError('공개 PDB 다운로드의 256MB 크기 상한 초과 또는 헤더 오류')
                total=0
                while True:
                    if time.monotonic()-began>DEADLINE_SECONDS:raise ValueError('공개 심볼 다운로드 시간 상한 초과')
                    piece=response.read(65536)
                    if not piece:break
                    total+=len(piece)
                    if total>MAX_BYTES:raise ValueError('공개 PDB 다운로드의 256MB 크기 상한 초과')
                    stream.write(piece)
            if not total or length is not None and total!=int(length):raise ValueError('공개 PDB 다운로드가 완전하지 않습니다')
            with temporary.open('rb') as stream:
                if stream.read(len(MSF7))!=MSF7:raise ValueError('공개 심볼 응답이 지원하는 PDB 형식이 아닙니다')
            temporary.replace(path);promoted=True
            result=validate(path)
            return dict(result,symbol_server=SERVER,download_url=url,cached=False)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code in (404,410):raise ValueError('일치하는 Microsoft 공개 심볼이 없습니다. PDB 없이 분석할 수 있습니다.') from exc
            raise ValueError('Microsoft 공개 심볼 서버 응답 오류: '+str(exc.code)) from exc
        except (urllib.error.URLError,TimeoutError,OSError) as exc:
            raise ValueError('Microsoft 공개 심볼 다운로드 실패 또는 시간 초과') from exc
        finally:
            temporary.unlink(missing_ok=True)
            if promoted and 'result' not in locals():path.unlink(missing_ok=True)
