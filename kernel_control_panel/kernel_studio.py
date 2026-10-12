"""Release launcher. Same loopback port for source and executable builds."""
import argparse
import os
from build_info import DEFAULT_PORT, PANEL_VERSION

def main(app=None):
    parser = argparse.ArgumentParser(description='Kernel Studio '+PANEL_VERSION)
    parser.add_argument('--port', type=int, default=int(os.environ.get('KERNEL_STUDIO_PORT', DEFAULT_PORT)))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('port must be between 1 and 65535')
    if app is None:
        from server import app
    import uvicorn
    print(f'Kernel Studio {PANEL_VERSION} | http://127.0.0.1:{args.port}/', flush=True)
    uvicorn.run(app, host='127.0.0.1', port=args.port, reload=False)

if __name__ == '__main__':
    main()
