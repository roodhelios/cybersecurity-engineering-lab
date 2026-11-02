"""Detect a consistent journal rollback relative to independently retained fixture state."""

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from demo_responsibility import fixture
from dns_assignment_journal import AssignmentJournal
from dns_authorized_handoff import _instant
from dns_journal_checkpoint import create_checkpoint, verify_checkpoint
from dns_responsibility import create_acceptance


def exercise():
    with patch('socket.socket', side_effect=AssertionError('network forbidden')):
        report, inputs, options, key = fixture()
        claim = json.loads(options['acceptance'])
        with tempfile.TemporaryDirectory(prefix='dns-journal-checkpoint-') as name:
            root = Path(name)
            journal = AssignmentJournal.create(root/'journal.sqlite')
            first = create_acceptance(report, authority_data=options['acceptance_policy'], signing_key=key,
                key_id=claim['key_id'], finding_sha256=claim['finding_sha256'], team=claim['team'],
                accepted_at='2026-10-28T12:00:00Z', expires_at='2026-10-28T12:05:00Z')
            journal.register(report, *inputs, **dict(options, acceptance=first, now=_instant('2026-10-28T12:00:00Z')))
            old_database = journal.path.read_bytes()
            old = create_checkpoint(journal, root/'old.json')
            old_checkpoint = (root/'old.json').read_bytes()
            later = create_acceptance(report, authority_data=options['acceptance_policy'], signing_key=key,
                key_id=claim['key_id'], finding_sha256=claim['finding_sha256'], team=claim['team'],
                accepted_at='2026-10-28T12:06:00Z', expires_at='2026-10-28T12:20:00Z')
            journal.register(report, *inputs, expected_predecessor=hashlib.sha256(first).hexdigest(),
                **dict(options, acceptance=later, now=_instant('2026-10-28T12:06:00Z')))
            current = create_checkpoint(journal, root/'current.json')
            current_checkpoint = (root/'current.json').read_bytes()
            before = journal.path.read_bytes()
            verified = verify_checkpoint(journal.path, current_checkpoint, expected_sha256=current['checkpoint_sha256'])
            if journal.path.read_bytes() != before:
                raise ValueError('checkpoint verification changed the journal')
            # Restore a closed native backup. Its own internal linkage is still valid.
            journal.path.write_bytes(old_database)
            summary = journal.summary(acceptance_policy=options['acceptance_policy'],
                expected_acceptance_policy_sha256=options['expected_acceptance_policy_sha256'],
                now=_instant('2026-10-28T12:07:00Z'))
            negatives = 0
            for data, pin in ((current_checkpoint, current['checkpoint_sha256']),
                              (old_checkpoint, current['checkpoint_sha256']), (current_checkpoint, '0'*64)):
                try:
                    verify_checkpoint(journal.path, data, expected_sha256=pin)
                except ValueError:
                    negatives += 1
                else:
                    raise ValueError('rollback or incorrect pin passed')
            # An old journal and its own stale trusted pin still match. Freshness is external.
            stale = verify_checkpoint(journal.path, old_checkpoint, expected_sha256=old['checkpoint_sha256'])
            if verified['event_count'] != 2 or summary['event_count'] != 1 or stale['event_count'] != 1:
                raise ValueError('checkpoint fixture states differed')
    return dict(status='dns_journal_checkpoint_exercise_passed', checkpoint_events=2,
        rolled_back_events=1, rollback_detected=True, stale_checkpoint_can_still_match=True,
        negative_cases_rejected=negatives, verification_preserved_input=True,
        native_ed25519=True, native_sqlite=True,
        interpretation='Original synthetic signed acceptances, fixed fixture clocks and temporary local SQLite. '
        'Independent current pin retention remains external. No global ownership, historical signature '
        'reverification, trusted clock, current authorization or source authenticity claim.')


def main():
    try:
        result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, UnicodeError, sqlite3.DatabaseError):
        print('error: DNS journal checkpoint exercise failed; inspect local dependencies and fixtures', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
