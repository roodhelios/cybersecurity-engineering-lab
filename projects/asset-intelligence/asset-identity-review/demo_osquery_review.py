"""Run the saved-export host review with inert fixtures and no collector process."""

import json
from pathlib import Path
import sys
from unittest.mock import patch

from osquery_review import review_export

ROOT = Path(__file__).resolve().parent/'examples'
CONTEXT_PIN = '6d7de76558e24c812d5d60966cdf10f6c646c9c237f81710bdd93ba53aec576d'


def exercise():
    original = (ROOT/'osquery-system-info.json').read_bytes()
    context = (ROOT/'osquery-context.json').read_bytes()
    peer = (ROOT/'osquery-peer.json').read_bytes()
    # This fixed public-fixture pin is not an operational source trust anchor.
    pin = CONTEXT_PIN
    with patch('socket.socket', side_effect=AssertionError('network forbidden')):
        result = review_export(original, context, [peer], expected_context_sha256=pin)
        if (result['record_count'], result['group_count'], result['matched_group_count'],
                result['unresolved_component_count']) != (4, 3, 1, 0):
            raise ValueError('unexpected identity review')
        rejected = 0
        for data, claimed_pin in ((original+b'\n', pin), (original, '0'*64)):
            try:
                review_export(data, context, [peer], expected_context_sha256=claimed_pin)
            except ValueError:
                rejected += 1
            else:
                raise ValueError('altered source/context accepted')
    return dict(status='osquery_host_review_exercise_passed', record_count=4, group_count=3,
        matched_group_count=1, unresolved_component_count=0, negative_cases_rejected=rejected,
        original_row_count=2, collector_executed=False,
        interpretation='Synthetic saved bytes and collection claims only. No source authentication, '
        'physical identity, current state, coverage or accepted ownership is established.')


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: saved-host exercise failed; check bundled fixtures', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
