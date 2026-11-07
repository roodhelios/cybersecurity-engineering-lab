"""Compare two saved ARP input sets and reproduce every retained finding reference."""

import argparse
from datetime import timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from arp_consistency import _object_without_duplicates, parse_observation, review_lines
from neighbor_import import publish

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_INVENTORY_BYTES = 4096
KINDS = ('observations', 'leases', 'forwarding', 'port_policy')


def _canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(',', ':'))+'\n').encode('ascii')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _pin(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('expected an independent exact-byte report digest')


def _lines(data):
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ValueError('each saved input must be at most 4 MiB')
    return data.decode('utf-8').split('\n')


def _review(inputs, window_seconds, forwarding_max_age_seconds):
    if (not isinstance(inputs, dict) or not {'observations'} <= inputs.keys() or
            not inputs.keys() <= set(KINDS)):
        raise ValueError('unsupported saved review inputs')
    lines = {kind: _lines(data) for kind, data in inputs.items()}
    report = review_lines(lines['observations'], window_seconds=window_seconds,
        forwarding_max_age_seconds=forwarding_max_age_seconds, leases=lines.get('leases'),
        forwarding_entries=lines.get('forwarding'), port_policy=lines.get('port_policy'))
    events = {}
    for finding in report['findings']:
        previous = parse_observation(lines['observations'][finding['previous_line']-1], finding['previous_line'])
        current = parse_observation(lines['observations'][finding['current_line']-1], finding['current_line'])
        identity = {key: finding[key] for key in ('interface', 'ip', 'previous_mac', 'current_mac')}
        identity.update(previous_at=previous.timestamp.astimezone(timezone.utc).isoformat(),
                        current_at=current.timestamp.astimezone(timezone.utc).isoformat())
        event_id = _sha(_canonical({'purpose': 'arp-mapping-transition-v1', **identity}))
        if event_id in events:
            raise ValueError('ambiguous repeated transition identity')
        events[event_id] = dict(identity=identity, finding=finding)
    return report, events


def _check_inventory(inventory, before, after):
    """Require both saved input sets to match separately selected source digests."""
    if not isinstance(inventory, dict) or set(inventory) != {'before', 'after'}:
        raise ValueError('expected before and after inventory')
    for side, inputs in (('before', before), ('after', after)):
        expected = inventory[side]
        if (not isinstance(expected, dict) or 'observations' not in expected or
                not expected.keys() <= set(KINDS) or not isinstance(inputs, dict) or
                inputs.keys() != expected.keys()):
            raise ValueError('saved input kinds differ from expected inventory')
        for kind, data in inputs.items():
            digest = expected[kind]
            if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None:
                raise ValueError('expected an exact-byte source digest')
            if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES or _sha(data) != digest:
                raise ValueError('saved source differs from expected inventory')


def compare_reviews(before, after, *, scope, window_seconds=300, forwarding_max_age_seconds=300,
                    expected_inventory=None):
    """Replay both original input sets. Absence never implies resolution or deletion."""
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('explicit authorized scope required')
    if any(type(value) is not int for value in (window_seconds, forwarding_max_age_seconds)):
        raise ValueError('integer review requirements required')
    if expected_inventory is not None:
        _check_inventory(expected_inventory, before, after)
    old_report, old = _review(before, window_seconds, forwarding_max_age_seconds)
    new_report, new = _review(after, window_seconds, forwarding_max_age_seconds)
    counts = dict(added=0, not_observed=0, changed=0, unchanged=0)
    entries = []
    for event_id in sorted(old.keys() | new.keys()):
        prior, current = old.get(event_id), new.get(event_id)
        status = ('added' if prior is None else 'not_observed' if current is None else
                  'unchanged' if prior['finding'] == current['finding'] else 'changed')
        counts[status] += 1
        entries.append(dict(event_id=event_id, status=status, identity=(current or prior)['identity'],
                            before=prior['finding'] if prior else None,
                            after=current['finding'] if current else None))
    result = dict(schema_version=1, report_type='arp-review-comparison', scope=scope,
        parameters=dict(window_seconds=window_seconds, forwarding_max_age_seconds=forwarding_max_age_seconds),
        inputs={side: {kind: dict(sha256=_sha(data), size=len(data)) for kind, data in values.items()}
                for side, values in (('before', before), ('after', after))},
        reviews={side: {key: report[key] for key in report if key != 'findings'}
                 for side, report in (('before', old_report), ('after', new_report))},
        counts=counts, transitions=entries,
        interpretation='Original inputs replayed under the current local reviewer. Transition identity binds '
        'interface, IPv4 address, both MAC claims and both UTC times. Changed includes supporting evidence or '
        'line references. Not observed does not mean resolved, removed or safe. This unsigned comparison does '
        'not authenticate collection, scope, network ownership, completeness or ARP spoofing.')
    if expected_inventory is not None:
        result['schema_version'] = 2
        result['expected_inventory_sha256'] = _sha(_canonical(expected_inventory))
    if len(_canonical(result)) > MAX_REPORT_BYTES:
        raise ValueError('comparison exceeds 32 MiB')
    return result


def verify_comparison(before, after, retained, *, expected_report_sha256, **requirements):
    _pin(expected_report_sha256)
    if (not isinstance(retained, bytes) or not 0 < len(retained) <= MAX_REPORT_BYTES or
            _sha(retained) != expected_report_sha256):
        raise ValueError('comparison differs from the independent digest')
    document = json.loads(retained.decode('utf-8'), object_pairs_hook=_object_without_duplicates)
    rebuilt = compare_reviews(before, after, **requirements)
    if _canonical(document) != _canonical(rebuilt):
        raise ValueError('comparison does not reproduce from original inputs and requirements')
    return dict(status='arp_comparison_reproduced', report_sha256=expected_report_sha256,
                counts=rebuilt['counts'], original_inputs_replayed=True)


def _read(path, limit):
    if os.name != 'posix':
        raise ValueError('bounded saved review requires POSIX')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('expected a bounded regular input')
        with os.fdopen(descriptor, 'rb') as handle:
            descriptor = None
            data = handle.read(limit+1)
            after = os.fstat(handle.fileno())
        if (len(data) != before.st_size or len(data) > limit or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('input changed during capture')
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument('--scope', required=True, choices=('synthetic', 'owned', 'authorized'))
    parser.add_argument('--window-seconds', type=int, default=300)
    parser.add_argument('--forwarding-max-age-seconds', type=int, default=300)
    for side in ('before', 'after'):
        for kind in KINDS[1:]:
            parser.add_argument('--'+side+'-'+kind.replace('_', '-'), type=Path)
    parser.add_argument('--expected-inventory', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-report', type=Path)
    parser.add_argument('--expected-report-sha256')
    args = parser.parse_args(argv)
    try:
        retained = None
        if bool(args.verify_report) != bool(args.expected_report_sha256):
            raise ValueError('verification requires both saved report and independent pin')
        if args.verify_report:
            _pin(args.expected_report_sha256)  # Validate before any source file is opened.
            retained = _read(args.verify_report, MAX_REPORT_BYTES)
            if _sha(retained) != args.expected_report_sha256:
                raise ValueError('wrong report pin')
        inventory = None
        if args.expected_inventory is not None:
            inventory = json.loads(_read(args.expected_inventory, MAX_INVENTORY_BYTES).decode('utf-8'),
                                   object_pairs_hook=_object_without_duplicates)
            if not isinstance(inventory, dict):
                raise ValueError('expected an inventory object')
        inputs = []
        for side in ('before', 'after'):
            paths = {'observations': getattr(args, side)}
            paths.update({kind: getattr(args, side+'_'+kind) for kind in KINDS[1:]
                          if getattr(args, side+'_'+kind) is not None})
            inputs.append({kind: _read(path, MAX_INPUT_BYTES) for kind, path in paths.items()})
        requirements = dict(scope=args.scope, window_seconds=args.window_seconds,
                            forwarding_max_age_seconds=args.forwarding_max_age_seconds, expected_inventory=inventory)
        if retained is not None:
            result = verify_comparison(*inputs, retained, expected_report_sha256=args.expected_report_sha256,
                                       **requirements)
        else:
            result = compare_reviews(*inputs, **requirements)
        rendered = _canonical(result)
        if args.output:
            publish(args.output, rendered.decode('ascii'))
            if retained is None:
                result = dict(status='arp_comparison_retained', report_sha256=_sha(rendered), counts=result['counts'])
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        print('error: ARP comparison failed; inspect private originals, requirements, digest and new output', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
