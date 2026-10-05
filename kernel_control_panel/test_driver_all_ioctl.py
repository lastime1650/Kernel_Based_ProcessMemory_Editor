"""Legacy entry point: read-only diagnostics. Full IOCTL tests are in the validation package.

The former script wrote an empty thread context and marked unverified calls as passing.
This entry point deliberately uses the validated read-only diagnostic runner.
"""
import argparse
from test_driver_readonly import run_tests

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    options = parser.parse_args()
    raise SystemExit(0 if run_tests(options.output) else 1)
