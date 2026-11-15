"""Retain and reproduce one original plain/gzip Zeek text-log correlation review."""

import argparse
import gzip
import hashlib
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from .correlation_cli import correlate_jsonl
from .evidence_verify import MAX_REPORT_BYTES, _canonical, _unique
from .zeek_tsv import import_conn_log

MAX_INPUT_BYTES = 16 * 1024 * 1024


def build_review(data, *, scope):
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        raise ValueError('expected at most 16 MiB of original bytes')
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('explicit input scope required')
    compressed = data.startswith(b'\x1f\x8b')
    expanded = data
    if compressed:
        with gzip.GzipFile(fileobj=BytesIO(data)) as stream:
            expanded = stream.read(MAX_INPUT_BYTES+1)
        if len(expanded) > MAX_INPUT_BYTES:
            raise ValueError('expanded input exceeds 16 MiB')
    events = import_conn_log(StringIO(expanded.decode('utf-8')))
    converted = '\n'.join(json.dumps(event, sort_keys=True, allow_nan=False) for event in events)
    correlation = correlate_jsonl(StringIO(converted), include_evidence=True)
    for finding in correlation['findings']:
        for reference in finding['evidence']:
            reference['original_line_number'] = events[reference['line_number']-1]['_zeek_tsv_line']
    return {'schema_version': 1, 'report_type': 'original-zeek-connection-review', 'scope': scope,
            'input_sha256': hashlib.sha256(data).hexdigest(), 'input_bytes': len(data),
            'compression': 'gzip' if compressed else 'none', 'expanded_bytes': len(expanded),
            'correlation': correlation,
            'interpretation': 'Current text importer and correlation model applied to supplied original '
                'bytes. Finding references identify original decompressed text lines as well as converted '
                'event positions. Source/scope remain caller claims; no Zeek service, packets, scanning, '
                'source authenticity or confirmed compromise established.'}


def verify_review(data, report_data, *, scope, expected_report_sha256):
    if not isinstance(expected_report_sha256, str) or re.fullmatch('[0-9a-f]{64}', expected_report_sha256) is None:
        raise ValueError('independently retained report SHA-256 required')
    if (type(report_data) is not bytes or len(report_data) > MAX_REPORT_BYTES or
            hashlib.sha256(report_data).hexdigest() != expected_report_sha256):
        raise ValueError('report differs from independent pin or exceeds bounds')
    report = json.loads(report_data.decode('utf-8'), object_pairs_hook=_unique)
    retained = _canonical(report)
    expected = build_review(data, scope=scope)
    if retained != _canonical(expected):
        raise ValueError('complete original-log review did not reproduce')
    result = expected['correlation']
    return {'status': 'zeek_text_review_reproduced', 'input_sha256': expected['input_sha256'],
            'report_sha256': expected_report_sha256, 'compression': expected['compression'],
            'events_read': result['events_read'], 'finding_count': result['finding_count'],
            'evidence_references': sum(len(f['evidence']) for f in result['findings'])}


def _read(path, limit):
    if os.name != 'posix': raise ValueError('private review files require POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('expected a bounded regular file')
        data = source.read(limit+1)
    if len(data) > limit: raise ValueError('file exceeds read bound')
    return data


def _publish(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.zeek-review-', delete=False) as output:
            temporary = Path(output.name)
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create', allow_abbrev=False)
    verify = commands.add_parser('verify', allow_abbrev=False)
    for sub in (create, verify):
        sub.add_argument('input', type=Path)
        sub.add_argument('--scope', choices=('synthetic', 'owned', 'authorized'), required=True)
    create.add_argument('--output', type=Path, required=True, help='new private JSON report')
    verify.add_argument('report', type=Path)
    verify.add_argument('--expected-report-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        data = _read(args.input, MAX_INPUT_BYTES)
        if args.command == 'verify':
            result = verify_review(data, _read(args.report, MAX_REPORT_BYTES), scope=args.scope,
                                   expected_report_sha256=args.expected_report_sha256)
        else:
            report = build_review(data, scope=args.scope)
            rendered = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()
            if len(rendered) > MAX_REPORT_BYTES: raise ValueError('report exceeds 16 MiB')
            _publish(args.output, rendered)
            result = {'status': 'zeek_text_review_created', 'report_sha256': hashlib.sha256(rendered).hexdigest(),
                      'events_read': report['correlation']['events_read'],
                      'finding_count': report['correlation']['finding_count']}
    except (OSError, EOFError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: original Zeek review failed; check private input, scope, report pin and new output path', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
