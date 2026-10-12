"""Bundled assets are immutable; user data lives outside a frozen application's bundle."""
import os
from pathlib import Path
import sys

def bundle_root():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))

def data_root():
    configured = os.environ.get('KERNEL_STUDIO_DATA_DIR')
    if configured:
        return Path(configured).expanduser().resolve()
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent / 'data'
    return Path(__file__).resolve().parent

def data_path(name):
    if name not in ('assets','symbols','workspaces','dumps'):
        raise ValueError('지원하지 않는 데이터 경로')
    return data_root() / name
