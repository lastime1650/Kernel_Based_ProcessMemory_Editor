"""Bounded Windows sharing-violation retry; data and permanent I/O errors stay visible."""
import json
import os
from pathlib import Path
import time
import uuid

def write_json(path, document, *, durable=False):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('w', encoding='utf-8') as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2)
            if durable:
                stream.flush()
                os.fsync(stream.fileno())
        for attempt in range(8):
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(min(0.01 * 2**attempt, 0.16))
    finally:
        temporary.unlink(missing_ok=True)
