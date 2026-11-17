"""Review a pinned saved osquery system_info export with explicitly supplied host peers."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

from asset_review import (MAX_INPUT_BYTES, MAX_RECORDS_PER_SOURCE, _canonical, _constant,
                          _exact, _label, _pairs, _publish, _read, _record, review_sources)

MAX_CONTEXT_BYTES = 64 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _pin(data, expected, maximum):
    if (type(data) is not bytes or len(data) > maximum or not isinstance(expected, str) or
            SHA256.fullmatch(expected) is None or hashlib.sha256(data).hexdigest() != expected):
        raise ValueError("bounded input differs from independent pin")


def _decode(data):
    value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    _canonical(value)
    return value


def read_context(data, *, expected_sha256):
    # Validate exact bytes before interpreting any collection or source claim.
    _pin(data, expected_sha256, MAX_CONTEXT_BYTES)
    context = _decode(data)
    _exact(context, ('schema_version', 'export_kind', 'namespace', 'scope', 'source_id',
                     'captured_at', 'expected_export_sha256'))
    if (type(context['schema_version']) is not int or context['schema_version'] != 1 or
            context['export_kind'] != 'osquery-system-info' or
            context['scope'] not in ('synthetic', 'owned', 'authorized')):
        raise ValueError('unsupported collection context')
    _label(context['namespace']); _label(context['source_id'])
    digest = context['expected_export_sha256']
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise ValueError('expected exact export digest')
    captured = context['captured_at']
    if not isinstance(captured, str) or len(captured) > 64:
        raise ValueError('bounded capture claim required')
    instant = datetime.fromisoformat(captured.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('capture claim requires a UTC offset')
    return dict(context, captured_at=instant.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'))


def convert_export(data, context):
    _pin(data, context['expected_export_sha256'], MAX_INPUT_BYTES)
    rows = _decode(data)
    if type(rows) is not list or not 1 <= len(rows) <= MAX_RECORDS_PER_SOURCE:
        raise ValueError('expected one to one thousand system_info rows')
    assets, seen = [], set()
    for number, row in enumerate(rows, 1):
        if type(row) is not dict or not {'uuid', 'hostname'} <= set(row):
            raise ValueError('system_info row requires uuid and hostname')
        value = row['uuid']
        if not isinstance(value, str) or UUID.fullmatch(value) is None:
            raise ValueError('expected a hyphenated UUID claim')
        identifier = uuid.UUID(value)
        if identifier.int in (0, (1 << 128)-1):
            raise ValueError('nil and all-ones UUID claims are not usable identifiers')
        identifier = str(identifier)
        if identifier in seen:
            raise ValueError('duplicate UUID claims in one export are ambiguous')
        seen.add(identifier)
        assets.append(_record({'source_record_id': f'system-info-row-{number}', 'kind': 'host',
            'identifiers': {'hardware_id': identifier}, 'hostname': row['hostname'], 'ip_addresses': []}))
    return {'schema_version': 1, **{key: context[key] for key in
        ('scope', 'namespace', 'source_id', 'captured_at')}, 'assets': assets}


def review_export(export, context_data, peers, *, expected_context_sha256):
    if not 1 <= len(peers) <= 7:
        raise ValueError('one to seven explicitly supplied peer sources required')
    context = read_context(context_data, expected_sha256=expected_context_sha256)
    source = convert_export(export, context)
    derived = _canonical(source)
    if len(derived) > MAX_INPUT_BYTES:
        raise ValueError('converted source exceeds review input bound')
    report = review_sources([derived, *peers], namespace=context['namespace'], scope=context['scope'])
    return dict(report, report_type='osquery-host-identity-review', native_import={
        'export_kind': context['export_kind'], 'context_sha256': expected_context_sha256,
        'original_export_sha256': hashlib.sha256(export).hexdigest(),
        'derived_source_sha256': hashlib.sha256(derived).hexdigest(),
        'collection_context': context, 'selected_fields': ['uuid', 'hostname'],
        'original_row_count': len(source['assets']),
        'interpretation': 'Pinned supplied collection claims, not source enrollment or authentication. '
        'Row N maps to system-info-row-N in derived input 1. The first review input digest binds '
        'the derived source, not the raw export. UUIDs may be cloned or wrong; matching values '
        'do not establish physical identity. No address, freshness, permission or collection coverage '
        'is inferred. Unselected columns are omitted. No osquery process or network request runs.'})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('export', type=Path)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--expected-context-sha256', required=True)
    parser.add_argument('--peer-source', action='append', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        # The context pin is checked before reading the export or peer paths.
        context_data = _read(args.context)
        read_context(context_data, expected_sha256=args.expected_context_sha256)
        if not 1 <= len(args.peer_source) <= 7:
            raise ValueError('one to seven peers required')
        result = review_export(_read(args.export), context_data, [_read(p) for p in args.peer_source],
                               expected_context_sha256=args.expected_context_sha256)
        rendered = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode()
        if len(rendered) > MAX_REPORT_BYTES:
            raise ValueError('host review exceeds output bound')
        _publish(args.output, rendered)
        print(json.dumps({'status': 'osquery_host_review_created', **{key: result[key] for key in
            ('record_count', 'group_count', 'matched_group_count', 'unresolved_component_count')}}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: saved host review failed; check pinned context, original export, peers and new private output',
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
