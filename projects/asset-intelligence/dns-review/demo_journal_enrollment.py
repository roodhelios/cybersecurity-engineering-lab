"""Enroll a temporary DNS journal identity and reject a separately initialized substitute."""

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from demo_responsibility import fixture
from dns_assignment_lifecycle import create_release
from dns_authorized_handoff import _instant
from dns_identified_journal import IdentifiedJournal, create_checkpoint, enroll, verify_checkpoint
from dns_responsibility import accept_responsibility


def exercise():
    report, inputs, options, key = fixture()
    with tempfile.TemporaryDirectory(prefix='dns-journal-enrollment-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(directory)
            journal = IdentifiedJournal.create(root/'journal.sqlite')
            enrollment = enroll(journal, root/'enrollment.json')
            data = (root/'enrollment.json').read_bytes()
            trust = dict(enrollment_data=data, expected_enrollment_sha256=enrollment['enrollment_sha256'])
            journal = IdentifiedJournal.from_enrollment(journal.path, data,
                        expected_sha256=enrollment['enrollment_sha256'])
            journal.register(report, *inputs, **options)
            old = journal.path.read_bytes()
            target = accept_responsibility(report, *inputs, **options)
            release = create_release(target, signing_key=key, released_at='2026-10-28T12:02:00Z',
                                     expires_at='2026-10-28T12:03:00Z')
            journal.release(release, acceptance_policy=options['acceptance_policy'],
                expected_acceptance_policy_sha256=options['expected_acceptance_policy_sha256'],
                now=_instant('2026-10-28T12:02:00Z'))
            current = create_checkpoint(journal.path, root/'checkpoint.json', **trust)
            checkpoint = (root/'checkpoint.json').read_bytes()
            result = verify_checkpoint(journal.path, checkpoint,
                        expected_sha256=current['checkpoint_sha256'], **trust)
            unchanged = journal.path.read_bytes()
            substitute = IdentifiedJournal.create(root/'other.sqlite')
            rejected = 0
            for path, pin, enrollment_pin in ((substitute.path, current['checkpoint_sha256'], enrollment['enrollment_sha256']),
                    (journal.path, '0'*64, enrollment['enrollment_sha256']),
                    (journal.path, current['checkpoint_sha256'], '0'*64)):
                try:
                    verify_checkpoint(path, checkpoint, expected_sha256=pin, enrollment_data=data,
                                      expected_enrollment_sha256=enrollment_pin)
                except ValueError:
                    rejected += 1
                else:
                    raise ValueError('substitution or changed pin accepted')
            if journal.path.read_bytes() != unchanged:
                raise ValueError('verification changed journal')
            journal.path.write_bytes(old)
            try:
                verify_checkpoint(journal.path, checkpoint, expected_sha256=current['checkpoint_sha256'], **trust)
            except ValueError:
                rejected += 1
            else:
                raise ValueError('release rollback accepted')
    return dict(status='dns_journal_enrollment_exercise_passed', acceptance_count=result['acceptance_count'],
                release_count=result['release_count'], enrolled_identity_checked=True,
                negative_cases_rejected=rejected, native_ed25519=True,
                interpretation='Local unsigned identity enrollment with independent pins. '
                'No collector or human authentication, pin freshness or global exclusivity.')


def main():
    try:
        result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: DNS journal enrollment exercise failed; inspect dependencies and private storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
