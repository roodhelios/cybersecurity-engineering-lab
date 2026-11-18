"""Apply pinned source, identifier-kind and collection-time requirements before grouping hosts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from asset_review import (
    LABEL, MAX_INPUT_BYTES, MAX_RECORDS_PER_SOURCE, _canonical, _constant,
    _exact, _label, _pairs, _publish, _read, _record, review_sources,
)

MAX_REQUIREMENTS_BYTES = 16 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
KINDS = {'cloud_resource_id', 'hardware_id'}


def _pin(data, expected):
    if (type(expected) is not str or re.fullmatch(r'[0-9a-f]{64}', expected) is None or
            hashlib.sha256(data).hexdigest() != expected):
        raise ValueError('source or requirements bytes differ from independent pin')


def _parse(data):
    return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)


def _instant(value):
    if type(value) is not str or len(value) > 64:
        raise ValueError('bounded capture instant required')
    instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('capture instant requires a timezone')
    return instant.astimezone(timezone.utc)


def _requirements(data, scope, namespace):
    value = _parse(data)
    _exact(value, ('schema_version', 'scope', 'namespace', 'observed_not_before',
                   'observed_not_after', 'max_capture_skew_seconds', 'sources'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 1 or
            value['scope'] != scope or value['namespace'] != namespace):
        raise ValueError('requirements context differs from selected review')
    start, end = _instant(value['observed_not_before']), _instant(value['observed_not_after'])
    skew = value['max_capture_skew_seconds']
    if start > end or type(skew) is not int or not 0 <= skew <= 86400:
        raise ValueError('invalid reviewed time bounds')
    if type(value['sources']) is not list or not 2 <= len(value['sources']) <= 8:
        raise ValueError('two to eight expected sources required')
    seen = set()
    for source in value['sources']:
        _exact(source, ('source_id', 'expected_original_sha256', 'allowed_identifier_kinds'))
        identifier = _label(source['source_id'], LABEL)
        if identifier in seen:
            raise ValueError('duplicate expected source')
        seen.add(identifier)
        kinds = source['allowed_identifier_kinds']
        if (type(kinds) is not list or len(kinds) > 2 or any(type(kind) is not str for kind in kinds) or
                len(set(kinds)) != len(kinds) or set(kinds) - KINDS):
            raise ValueError('invalid source identifier grant')
        if type(source['expected_original_sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', source['expected_original_sha256']) is None:
            raise ValueError('expected exact source digest')
    return value, start, end


def _check_source(data, rule, scope, namespace, start, end):
    source = _parse(data)
    _exact(source, ('schema_version', 'scope', 'namespace', 'source_id', 'captured_at', 'assets'))
    if (type(source['schema_version']) is not int or source['schema_version'] != 1 or
            source['source_id'] != rule['source_id'] or source['scope'] != scope or
            source['namespace'] != namespace):
        raise ValueError('source context differs from reviewed requirements')
    captured = _instant(source['captured_at'])
    if not start <= captured <= end:
        raise ValueError('source capture claim outside reviewed window')
    if type(source['assets']) is not list or len(source['assets']) > MAX_RECORDS_PER_SOURCE:
        raise ValueError('invalid source records')
    for asset in source['assets']:
        if set(_record(asset)['identifiers']) - set(rule['allowed_identifier_kinds']):
            raise ValueError('source asserted an ungranted identifier kind')
    return captured


def review_constrained(originals, requirements_data, *, expected_requirements_sha256, scope, namespace):
    _label(namespace)
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('explicit supported scope required')
    if type(requirements_data) is not bytes or len(requirements_data) > MAX_REQUIREMENTS_BYTES:
        raise ValueError('bounded requirements bytes required')
    _pin(requirements_data, expected_requirements_sha256)
    requirements, start, end = _requirements(requirements_data, scope, namespace)
    if not 2 <= len(originals) <= 8 or len(originals) != len(requirements['sources']):
        raise ValueError('complete ordered expected source set required')
    # Every original identity is checked before parsing any original or grouping.
    for data, rule in zip(originals, requirements['sources']):
        if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
            raise ValueError('bounded original source required')
        _pin(data, rule['expected_original_sha256'])
    instants = [_check_source(data, rule, scope, namespace, start, end)
                for data, rule in zip(originals, requirements['sources'])]
    skew = (max(instants) - min(instants)).total_seconds()
    if skew > requirements['max_capture_skew_seconds']:
        raise ValueError('source capture claims exceed reviewed skew')
    review = review_sources(originals, scope=scope, namespace=namespace)
    result = {'schema_version': 1, 'report_type': 'source-constrained-asset-identity-review',
        'requirements_sha256': expected_requirements_sha256, 'capture_skew_seconds': skew,
        'reviewed_requirements': requirements, 'review': review, 'source_authenticity_verified': False,
        'interpretation': 'Pinned expected source bytes, allowed identifier kinds and supplied capture '
            'claims met reviewed bounds. Source IDs and timestamps remain unauthenticated claims. '
            'No real collector enrollment, source independence, actual coverage, clock freshness, '
            'physical identity, accepted ownership or remediation is established.'}
    if len(_canonical(result)) > MAX_REPORT_BYTES:
        raise ValueError('constrained review exceeds report bound')
    return result


def exercise():
    root = Path(__file__).resolve().parent / 'examples'
    originals = [(root / name).read_bytes() for name in ('cloud.json', 'endpoint.json')]
    requirements = (root / 'source-requirements.json').read_bytes()
    result = review_constrained(originals, requirements, expected_requirements_sha256=hashlib.sha256(requirements).hexdigest(),
                                scope='synthetic', namespace='synthetic-assets')
    restricted = _parse(requirements)
    restricted['sources'][1]['allowed_identifier_kinds'] = ['hardware_id']
    changed = _canonical(restricted)
    try:
        review_constrained(originals, changed, expected_requirements_sha256=hashlib.sha256(changed).hexdigest(),
                           scope='synthetic', namespace='synthetic-assets')
    except ValueError:
        return {'status': 'source_constrained_identity_exercise_passed',
                'record_count': result['review']['record_count'], 'group_count': result['review']['group_count'],
                'ungranted_identifier_rejected': True, 'source_authenticity_verified': False}
    raise ValueError('ungranted identity assertion accepted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('demo', help='review the synthetic source set and reject an ungranted claim')
    review = commands.add_parser('review', help='retain a constrained review from pinned ordered original sources')
    review.add_argument('sources', nargs='+', type=Path)
    review.add_argument('--requirements', required=True, type=Path)
    review.add_argument('--expected-requirements-sha256', required=True)
    review.add_argument('--scope', required=True, choices=('synthetic', 'owned', 'authorized'))
    review.add_argument('--namespace', required=True)
    review.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            result = exercise()
        else:
            if not 2 <= len(args.sources) <= 8:
                raise ValueError('two to eight sources required')
            report = review_constrained([_read(path) for path in args.sources], _read(args.requirements),
                expected_requirements_sha256=args.expected_requirements_sha256, scope=args.scope, namespace=args.namespace)
            data = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
            if len(data) > MAX_REPORT_BYTES:
                raise ValueError('rendered review exceeds bound')
            _publish(args.output, data)
            result = {'status': 'source_constrained_identity_review_created',
                'requirements_sha256': report['requirements_sha256'],
                **{key: report['review'][key] for key in ('record_count', 'group_count', 'unresolved_component_count')},
                'source_authenticity_verified': False}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: constrained identity review failed; check private sources, requirements, pins and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
