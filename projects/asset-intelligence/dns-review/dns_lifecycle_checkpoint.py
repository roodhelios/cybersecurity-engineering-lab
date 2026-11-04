"""Independently pin both logical tables of a version-2 DNS lifecycle journal."""

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

from dns_assignment_lifecycle import LifecycleJournal
from dns_journal_checkpoint import MAX_CHECKPOINT_BYTES, _read_checkpoint, _render
from dns_review import publish
from dns_reviewer_handoff import _digest
from zeek_dns_workflow_verify import _canonical

HISTORY_DOMAIN = b'dns-assignment-lifecycle-history:v2\x00'


def build_checkpoint(journal):
    """Validate and capture both tables under the same read-only transaction."""
    if not isinstance(journal, LifecycleJournal):
        raise ValueError('expected a version-2 lifecycle journal')
    with journal._connection() as connection:
        acceptances, latest = journal._history(connection)
        journal._releases(connection, acceptances)
        releases = connection.execute(
            'SELECT sequence,acceptance_sha256,release_sha256,receipt_json '
            'FROM release_event ORDER BY sequence').fetchall()
    history = _canonical(dict(acceptances=acceptances, releases=releases)).encode('ascii')
    return dict(schema_version=2, checkpoint_type='dns-review-assignment-lifecycle-journal',
                acceptance_count=len(acceptances), release_count=len(releases), task_count=len(latest),
                history_sha256=hashlib.sha256(HISTORY_DOMAIN+history).hexdigest())


def _summary(checkpoint, data, status):
    return dict(status=status, acceptance_count=checkpoint['acceptance_count'],
                release_count=checkpoint['release_count'], task_count=checkpoint['task_count'],
                checkpoint_sha256=hashlib.sha256(data).hexdigest(),
                current_authority_reverified=False, historical_signatures_reverified=False)


def create_checkpoint(journal, output):
    checkpoint = build_checkpoint(journal)
    data = _render(checkpoint)
    publish(Path(output), data.decode('ascii'))
    return _summary(checkpoint, data, 'dns_lifecycle_checkpoint_created')


def verify_checkpoint(journal_path, data, *, expected_sha256):
    """Validate the independent pin before opening any candidate database."""
    _digest(expected_sha256)
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CHECKPOINT_BYTES:
        raise ValueError('expected a nonempty bounded checkpoint')
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('checkpoint differs from independently retained pin')
    checkpoint = build_checkpoint(LifecycleJournal(journal_path))
    if data != _render(checkpoint):
        raise ValueError('complete lifecycle history differs from checkpoint')
    return _summary(checkpoint, data, 'dns_lifecycle_checkpoint_matched')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('journal', type=Path)
    create.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('journal', type=Path)
    verify.add_argument('--checkpoint', type=Path, required=True)
    verify.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        result = (create_checkpoint(LifecycleJournal(args.journal), args.output) if args.command == 'create' else
                  verify_checkpoint(args.journal, _read_checkpoint(args.checkpoint), expected_sha256=args.expected_sha256))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, sqlite3.DatabaseError,
            RecursionError, OverflowError):
        print('error: DNS lifecycle checkpoint failed; inspect private journal, independent pin and output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
