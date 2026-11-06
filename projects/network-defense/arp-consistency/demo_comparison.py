"""Reproduce a private ARP comparison using bundled original synthetic metadata."""

import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from compare_reviews import _canonical, _sha, compare_reviews, verify_comparison
from neighbor_import import publish

ROOT = Path(__file__).resolve().parent


def exercise():
    with patch('socket.socket', side_effect=AssertionError('network forbidden')):
        before = {'observations': (ROOT/'examples/arp-observations.jsonl').read_bytes()}
        after = {'observations': (ROOT/'examples/arp-observations-later.jsonl').read_bytes()}
        report = compare_reviews(before, after, scope='synthetic')
        if report['counts'] != dict(added=1, not_observed=0, changed=1, unchanged=0):
            raise ValueError('unexpected synthetic transitions')
        data = _canonical(report)
        with tempfile.TemporaryDirectory(prefix='arp-comparison-') as directory:
            path = Path(directory)/'comparison.json'
            publish(path, data.decode('ascii'))
            result = verify_comparison(before, after, path.read_bytes(),
                expected_report_sha256=_sha(data), scope='synthetic')
            changed = json.loads(data)
            changed['transitions'][0]['status'] = 'unchanged'
            changed = _canonical(changed)
            rejected = 0
            for left, right, saved, pin, scope in (
                (before, after, data, '0'*64, 'synthetic'),
                (before, after, changed, _sha(changed), 'synthetic'),
                (before, after, data, _sha(data), 'owned'),
                (before, {'observations': after['observations']+b'\n'}, data, _sha(data), 'synthetic')):
                try:
                    verify_comparison(left, right, saved, expected_report_sha256=pin, scope=scope)
                except ValueError:
                    rejected += 1
                else:
                    raise ValueError('invalid comparison accepted')
            if path.read_bytes() != data:
                raise ValueError('saved report changed')
    return dict(status='arp_comparison_exercise_passed', counts=result['counts'],
                negative_cases_rejected=rejected, original_inputs_replayed=True,
                interpretation='Original synthetic metadata and temporary private files. No network, packets, '
                'Zeek, collection, remediation or source authenticity is established.')


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: ARP comparison exercise failed; inspect fixtures and private temporary storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
