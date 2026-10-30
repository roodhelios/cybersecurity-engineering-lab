"""Combine saved CloudTrail files into one private, unreviewed offline case."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import zlib

from .cloudtrail_correlation import correlate_failed_logins
from .cloudtrail_handoff import MAX_BYTES, MAX_EVENTS, _publish, _read, build_handoff
from .cloudtrail_import import convert_records

MAX_FILES = 32
MAX_CASE_BYTES = 64 * 1024 * 1024


def build_case(inputs, *, account_id, case_id, scope_note, threshold=3, window_seconds=300):
    """Deduplicate matching copies across files, rejecting conflicting event IDs.

    Inputs are already supplied local bytes, not URLs or cloud client objects.
    Source indices and record ordinals refer to the explicit ordered input list.
    """
    if type(account_id) is not str or not re.fullmatch(r"[0-9]{12}", account_id):
        raise ValueError("expected a twelve-digit recipient account scope")
    sources, lines, locations, events, seen = [], [], [], [], {}
    supplied_bytes = normalized_bytes = supplied_events = duplicates = 0
    # Validate metadata and correlation settings even for an empty collection.
    build_handoff(b'', case_id=case_id, scope_note=scope_note)
    correlate_failed_logins([], threshold=threshold, window_seconds=window_seconds)
    for index, raw in enumerate(inputs, 1):
        if index > MAX_FILES or type(raw) is not bytes:
            raise ValueError('expected at most 32 local byte inputs')
        supplied_bytes += len(raw)
        if supplied_bytes > MAX_BYTES:
            raise ValueError('combined input exceeds 16 MiB')
        rendered, receipt = convert_records(raw)
        normalized_bytes += len(rendered.encode('utf-8'))
        supplied_events += receipt['event_count']
        if normalized_bytes > MAX_BYTES or supplied_events > MAX_EVENTS:
            raise ValueError('combined expanded records exceed collection bounds')
        sources.append(dict(receipt, input_index=index, input_bytes=len(raw)))
        for record_number, line in enumerate(rendered.splitlines(), 1):
            event = json.loads(line)
            if event.get('recipientAccountID') != account_id:
                raise ValueError('event is outside the required recipient account scope')
            event_id = event['eventID']
            if event_id != event_id.strip():
                raise ValueError('event IDs must not contain surrounding whitespace')
            reference = {'input_index': index, 'record_number': record_number}
            previous = seen.get(event_id)
            if previous is not None:
                if lines[previous] != line:
                    raise ValueError('conflicting copies of an event ID')
                locations[previous]['sources'].append(reference)
                duplicates += 1
            else:
                seen[event_id] = len(lines)
                lines.append(line); events.append(event)
                locations.append({'source_line': len(lines), 'sources': [reference]})
    if not sources:
        raise ValueError('at least one CloudTrail file is required')
    normalized = ''.join(line + '\n' for line in lines)
    handoff = build_handoff(normalized.encode('utf-8'), case_id=case_id, scope_note=scope_note)
    candidates = [item.to_dict() for item in correlate_failed_logins(
        events, threshold=threshold, window_seconds=window_seconds)]
    # Candidates refer to unique IDs. Bind them to normalized lines and all input copies.
    for candidate in candidates:
        candidate['source_lines'] = [seen[event_id] + 1 for event_id in candidate['event_ids']]
    return {'schema_version': 1, 'format': 'offline-cloudtrail-case', 'account_id': account_id, 'sources': sources,
        'supplied_event_count': supplied_events, 'duplicate_copy_count': duplicates,
        'unique_event_count': len(events), 'normalized_jsonl': normalized,
        'event_sources': locations, 'handoff': handoff,
        'correlation': {'threshold': threshold, 'window_seconds': window_seconds, 'candidates': candidates}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path, help='ordered local JSON or gzip Records files')
    parser.add_argument('--account-id', required=True, help='required twelve-digit recipientAccountID')
    parser.add_argument('--case-id', required=True)
    parser.add_argument('--scope-note', required=True)
    parser.add_argument('--threshold', type=int, default=3)
    parser.add_argument('--window-seconds', type=int, default=300)
    parser.add_argument('--output', required=True, type=Path, help='new private case JSON file')
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix' or len(args.inputs) > MAX_FILES:
            raise ValueError('private collection requires POSIX and at most 32 files')
        result = build_case((_read(path) for path in args.inputs), account_id=args.account_id, case_id=args.case_id,
            scope_note=args.scope_note, threshold=args.threshold, window_seconds=args.window_seconds)
        document = json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + '\n'
        encoded = document.encode('utf-8')
        if len(encoded) > MAX_CASE_BYTES:
            raise ValueError('case document exceeds 64 MiB')
        _publish(args.output, document)
    except (OSError, ValueError, TypeError, UnicodeError, EOFError, zlib.error, RecursionError, OverflowError):
        print('error: CloudTrail case failed; check local inputs, review settings and a new output path', file=sys.stderr)
        return 2
    print(json.dumps({'schema_version': 1, 'input_count': len(result['sources']),
        'supplied_event_count': result['supplied_event_count'], 'unique_event_count': result['unique_event_count'],
        'duplicate_copy_count': result['duplicate_copy_count'], 'finding_count': result['handoff']['finding_count'],
        'login_candidate_count': len(result['correlation']['candidates']),
        'case_sha256': hashlib.sha256(encoded).hexdigest(), 'status': 'unreviewed',
        'containment': 'not_performed', 'recovery': 'not_verified'}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
