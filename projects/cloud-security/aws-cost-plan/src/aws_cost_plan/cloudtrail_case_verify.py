"""Reproduce a retained CloudTrail case from original files and recipient settings."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zlib

from .cloudtrail_case import MAX_CASE_BYTES, MAX_FILES, build_case
from .cloudtrail_handoff import _publish, _read
from .cloudtrail_import import _constant, _object


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def verify_case(data, inputs, *, account_id, case_id, scope_note, threshold, window_seconds):
    """Require every retained field to reproduce under separately supplied settings.

    This establishes current-model consistency, not source authentication, approval
    or historical replay. The returned unsigned summary omits raw event/context fields.
    """
    if type(data) is not bytes or len(data) > MAX_CASE_BYTES:
        raise ValueError('expected bounded case bytes')
    retained = json.loads(data.decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)
    expected = build_case(inputs, account_id=account_id, case_id=case_id, scope_note=scope_note,
                          threshold=threshold, window_seconds=window_seconds)
    # Canonical serialization also distinguishes booleans/floats from integer fields.
    # Python container equality alone would accept True == 1 or 1.0 == 1.
    if _canonical(retained) != _canonical(expected):
        raise ValueError('retained case does not reproduce')
    return {'schema_version': 1, 'status': 'case_reproduced',
        'case_sha256': hashlib.sha256(data).hexdigest(),
        'normalized_sha256': expected['handoff']['source_sha256'],
        'input_count': len(expected['sources']), 'unique_event_count': expected['unique_event_count'],
        'duplicate_copy_count': expected['duplicate_copy_count'],
        'finding_count': expected['handoff']['finding_count'],
        'login_candidate_count': len(expected['correlation']['candidates']),
        'containment': 'not_performed', 'recovery': 'not_verified'}


def _read_case(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CASE_BYTES:
            raise ValueError('case must be a bounded regular local file')
        data = source.read(MAX_CASE_BYTES + 1)
    if len(data) > MAX_CASE_BYTES:
        raise ValueError('case exceeds 64 MiB')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('inputs', nargs='+', type=Path, help='original ordered JSON/gzip files')
    parser.add_argument('--account-id', required=True)
    parser.add_argument('--case-id', required=True)
    parser.add_argument('--scope-note', required=True)
    parser.add_argument('--threshold', required=True, type=int)
    parser.add_argument('--window-seconds', required=True, type=int)
    parser.add_argument('--output', type=Path, help='optional new private unsigned summary')
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix' or len(args.inputs) > MAX_FILES:
            raise ValueError('expected private POSIX paths and at most 32 sources')
        summary = verify_case(_read_case(args.case), (_read(path) for path in args.inputs),
            account_id=args.account_id, case_id=args.case_id, scope_note=args.scope_note,
            threshold=args.threshold, window_seconds=args.window_seconds)
        document = json.dumps(summary, sort_keys=True, allow_nan=False) + '\n'
        if args.output is None:
            print(document, end='')
        else:
            _publish(args.output, document)
    except (OSError, ValueError, TypeError, UnicodeError, EOFError, zlib.error, RecursionError, OverflowError):
        print('error: case reproduction failed; check originals, recipient settings and local paths', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
