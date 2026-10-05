"""Small in-process HTTP harness using ASGI, without optional HTTP client packages."""
import asyncio
import json as JSON
from urllib.parse import urlsplit


class Reply:
    def __init__(self, status, headers, content):
        self.status_code, self.headers, self.content = status, headers, content

    def json(self):
        return JSON.loads(self.content)


class ASGIClient:
    def __init__(self, app):
        self.app = app

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def request(self, method, url, json=None, headers=None):
        async def call():
            split = urlsplit(url)
            payload = JSON.dumps(json).encode() if json is not None else b''
            request_headers = {k.lower(): v for k, v in (headers or {}).items()}
            if json is not None:
                request_headers['content-type'] = 'application/json'
            scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1',
                'method':method,'scheme':'http','path':split.path,'raw_path':split.path.encode(),
                'root_path':'','query_string':split.query.encode(),'server':('127.0.0.1',80),
                'client':('127.0.0.1',1),'headers':[(k.encode(),v.encode()) for k,v in request_headers.items()]}
            sent, received = [], False
            async def receive():
                nonlocal received
                if received:
                    await asyncio.Future()
                received = True
                return {'type':'http.request','body':payload,'more_body':False}
            async def send(message):
                sent.append(message)
            await self.app(scope, receive, send)
            head = next(x for x in sent if x['type'] == 'http.response.start')
            content = b''.join(x.get('body',b'') for x in sent if x['type'] == 'http.response.body')
            return Reply(head['status'], {k.decode():v.decode() for k,v in head['headers']}, content)
        return asyncio.run(call())

    def get(self, url, **kwargs):
        return self.request('GET',url,**kwargs)

    def post(self, url, **kwargs):
        return self.request('POST',url,**kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE',url,**kwargs)
