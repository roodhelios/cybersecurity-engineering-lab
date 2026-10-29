"""Reproduce a retained TCP reset report from separately supplied source and requirements."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from tcp_reset_review import _constant, _pairs, _publish, _read, review_bytes

MAX_REPORT_BYTES = 16 * 1024 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def verify_report(source_data, report_data, *, scope, min_resets, window_seconds):
    """Require the full current-model report, including all references and limitations."""
    if not isinstance(report_data, bytes) or not 1 <= len(report_data) <= MAX_REPORT_BYTES:
        raise ValueError('expected a nonempty report of at most 16 MiB')
    retained = json.loads(report_data.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    if not isinstance(retained, dict):
        raise ValueError('expected one retained report object')
    rebuilt = review_bytes(source_data, scope=scope, min_resets=min_resets, window_seconds=window_seconds)
    if _canonical(retained) != _canonical(rebuilt):
        raise ValueError('retained report does not reproduce from the supplied input and requirements')
    return {'schema_version': 1, 'status': 'tcp_reset_report_reproduced',
        'input_sha256': rebuilt['input_sha256'], 'report_sha256': hashlib.sha256(report_data).hexdigest(),
        'record_count': rebuilt['record_count'], 'finding_count': len(rebuilt['findings']),
        'scope': scope, 'parameters': rebuilt['parameters'],
        'interpretation': 'The complete retained report reproduces under the current implementation from these '
            'source bytes and reviewer-supplied scope/parameters. This unsigned local result does not authenticate '
            'source collection, authorization, historical model behavior, reset injection or malicious activity.'}


def _read_report(path):
    if os.name != 'posix':
        raise ValueError('bounded local report reading requires POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError('expected a bounded regular report file')
        data = source.read(MAX_REPORT_BYTES + 1)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('--scope', required=True, choices=('synthetic', 'owned', 'authorized'))
    parser.add_argument('--min-resets', required=True, type=int)
    parser.add_argument('--window-seconds', required=True, type=int)
    parser.add_argument('--output', type=Path, help='new private unsigned verification summary')
    args = parser.parse_args(argv)
    try:
        result = verify_report(_read(args.source), _read_report(args.report), scope=args.scope,
                               min_resets=args.min_resets, window_seconds=args.window_seconds)
        rendered = json.dumps(result, sort_keys=True, indent=2) + '\n'
        if args.output:
            _publish(args.output, rendered)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: TCP reset report did not reproduce; inspect retained source and review requirements privately', file=sys.stderr)
        return 2
    print(rendered, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
