"""Detect a release-only rollback against an independently retained v2 checkpoint."""

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from demo_responsibility import fixture
from dns_assignment_lifecycle import LifecycleJournal, create_release
from dns_authorized_handoff import _instant
from dns_lifecycle_checkpoint import create_checkpoint, verify_checkpoint
from dns_responsibility import accept_responsibility


def exercise():
    report, inputs, options, key = fixture()
    with tempfile.TemporaryDirectory(prefix='dns-lifecycle-checkpoint-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(directory)
            journal = LifecycleJournal.create(root/'journal.sqlite')
            journal.register(report, *inputs, **options)
            before_release = journal.path.read_bytes()
            old = create_checkpoint(journal, root/'old.json')
            target = accept_responsibility(report, *inputs, **options)
            release = create_release(target, signing_key=key,
                released_at='2026-10-28T12:02:00Z', expires_at='2026-10-28T12:03:00Z')
            journal.release(release, acceptance_policy=options['acceptance_policy'],
                expected_acceptance_policy_sha256=options['expected_acceptance_policy_sha256'],
                now=_instant('2026-10-28T12:02:00Z'))
            current = create_checkpoint(journal, root/'current.json')
            data = (root/'current.json').read_bytes()
            verify_checkpoint(journal.path, data, expected_sha256=current['checkpoint_sha256'])
            journal.path.write_bytes(before_release)
            rejected = 0
            for candidate, pin in ((data, current['checkpoint_sha256']), (data, '0'*64)):
                try: verify_checkpoint(journal.path, candidate, expected_sha256=pin)
                except ValueError: rejected += 1
                else: raise ValueError('rollback or wrong checkpoint pin accepted')
            stale = verify_checkpoint(journal.path, (root/'old.json').read_bytes(),
                expected_sha256=old['checkpoint_sha256'])
    return dict(status='dns_lifecycle_checkpoint_exercise_passed',
                acceptance_count=current['acceptance_count'], release_count=current['release_count'],
                negative_cases_rejected=rejected, stale_pair_still_matches=stale['release_count'] == 0,
                native_ed25519=True, current_authority_reverified=False,
                interpretation='Synthetic native SQLite and signatures. Both tables are pinned logical history, '
                'not authenticated history, current authority, fresh pin distribution or global exclusivity.')


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: DNS lifecycle checkpoint exercise failed', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
