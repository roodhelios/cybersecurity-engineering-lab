"""Exercise local conflict, replay, expiry and policy replacement with real signatures."""

import hashlib
import json
import sqlite3
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from demo_responsibility import fixture
from dns_assignment_journal import AssignmentJournal
from dns_authorized_handoff import _instant
from dns_responsibility import create_acceptance


def exercise():
    report, inputs, options, key = fixture()
    first_claim = json.loads(options['acceptance'])
    def signed(accepted, expires, *, policy=None):
        authority = options['acceptance_policy'] if policy is None else policy
        return create_acceptance(report, authority_data=authority, signing_key=key, key_id=first_claim['key_id'],
            finding_sha256=first_claim['finding_sha256'], team=first_claim['team'],
            accepted_at=accepted, expires_at=expires)
    initial = signed('2026-10-28T12:00:00Z', '2026-10-28T12:05:00Z')
    later = signed('2026-10-28T12:06:00Z', '2026-10-28T12:20:00Z')
    with tempfile.TemporaryDirectory(prefix='dns-assignment-journal-') as name:
        journal = AssignmentJournal.create(Path(name)/'journal.sqlite')
        def register(claim, at, **changes):
            return journal.register(report, *inputs, **dict(options, acceptance=claim, now=_instant(at), **changes))
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            first = register(initial, '2026-10-28T12:00:00Z')
            replay = register(initial, '2026-10-28T12:01:00Z')
            conflict = signed('2026-10-28T12:01:00Z', '2026-10-28T12:10:00Z')
            first_digest = hashlib.sha256(initial).hexdigest()
            negatives = 0
            for claim, at, changes in (
                (conflict, '2026-10-28T12:01:00Z', {'expected_predecessor': first_digest}),
                (later, '2026-10-28T12:06:00Z', {}),
                (later, '2026-10-28T12:06:00Z', {'expected_predecessor': '0'*64})):
                try:
                    register(claim, at, **changes)
                except ValueError:
                    negatives += 1
                else:
                    raise ValueError('journal negative case accepted')
            replacement = register(later, '2026-10-28T12:06:00Z', expected_predecessor=first_digest)
            reopened = AssignmentJournal(journal.path)
            current = reopened.summary(acceptance_policy=options['acceptance_policy'],
                expected_acceptance_policy_sha256=options['expected_acceptance_policy_sha256'],
                now=_instant('2026-10-28T12:07:00Z'))
            revoked_policy = json.loads(options['acceptance_policy'])
            revoked_policy['keys'][0]['status'] = 'revoked'
            revoked_data = json.dumps(revoked_policy).encode()
            before = journal.path.read_bytes()
            revoked = reopened.summary(acceptance_policy=revoked_data,
                expected_acceptance_policy_sha256=hashlib.sha256(revoked_data).hexdigest(),
                now=_instant('2026-10-28T12:07:00Z'))
            if (first['event_count'] != 1 or replay['appended'] or replacement['event_count'] != 2 or
                    current['eligible_for_reverification'] != 1 or revoked['policy_replaced'] != 1 or
                    journal.path.read_bytes() != before or negatives != 3):
                raise ValueError('local journal lifecycle did not reproduce')
    return dict(status='dns_assignment_journal_exercise_passed', events=2, tasks=1,
        idempotent_replay=True, expiry_replacement=True, policy_replacement_invalidates=True,
        negative_cases_rejected=3, native_ed25519=True, native_sqlite=True,
        interpretation='Local host-controlled conflict accounting only. Summary eligibility requires full evidence '
                       'reverification before reliance; no global exclusivity, asset ownership or remediation.')


def main():
    try:
        result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, UnicodeError, sqlite3.DatabaseError):
        print('error: local DNS assignment journal exercise failed; inspect dependencies and fixtures', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
