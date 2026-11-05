"""Pin the complete logical DNS acceptance history independently of its SQLite file."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from dns_assignment_journal import AssignmentJournal
from dns_review import publish
from dns_reviewer_handoff import _digest
from zeek_dns_workflow_verify import _canonical

MAX_CHECKPOINT_BYTES = 4096
HISTORY_DOMAIN = b'dns-assignment-journal-history:v1\x00'


def build_checkpoint(journal):
    """Capture all validated event rows in one read-only SQLite transaction."""
    if not isinstance(journal, AssignmentJournal) or journal.VERSION != 1:
        raise ValueError('expected a version-1 assignment journal')
    with journal._connection() as connection:
        rows, latest = journal._history(connection)
    history = _canonical(rows).encode('ascii')
    return dict(schema_version=1, checkpoint_type='dns-review-assignment-journal',
                event_count=len(rows), task_count=len(latest),
                history_sha256=hashlib.sha256(HISTORY_DOMAIN+history).hexdigest())


def _render(checkpoint):
    data = (_canonical(checkpoint)+'\n').encode('ascii')
    if len(data) > MAX_CHECKPOINT_BYTES:
        raise ValueError('checkpoint exceeds 4 KiB')
    return data


def _summary(checkpoint, data, status):
    return dict(status=status, event_count=checkpoint['event_count'], task_count=checkpoint['task_count'],
                checkpoint_sha256=hashlib.sha256(data).hexdigest(),
                current_authority_reverified=False, historical_signatures_reverified=False)


def create_checkpoint(journal, output):
    checkpoint = build_checkpoint(journal)
    data = _render(checkpoint)
    publish(Path(output), data.decode('ascii'))
    return _summary(checkpoint, data, 'dns_journal_checkpoint_created')


def verify_checkpoint(journal_path, data, *, expected_sha256):
    """Check the independent checkpoint pin before opening the candidate journal."""
    _digest(expected_sha256)
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CHECKPOINT_BYTES:
        raise ValueError('expected a nonempty bounded checkpoint')
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('checkpoint differs from independently retained pin')
    checkpoint = build_checkpoint(AssignmentJournal(journal_path))
    # Compare the complete canonical document, not selected claimed fields or counts.
    # No candidate-controlled JSON is needed to determine the expected state.
    if data != _render(checkpoint):
        raise ValueError('complete journal history differs from checkpoint')
    return _summary(checkpoint, data, 'dns_journal_checkpoint_matched')


def _read_checkpoint(path):
    if os.name != 'posix':
        raise ValueError('private checkpoint files require POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CHECKPOINT_BYTES:
            raise ValueError('expected a bounded regular checkpoint file')
        data = source.read(MAX_CHECKPOINT_BYTES+1)
    if len(data) > MAX_CHECKPOINT_BYTES:
        raise ValueError('checkpoint exceeds 4 KiB')
    return data


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
        result = (create_checkpoint(AssignmentJournal(args.journal), args.output) if args.command == 'create' else
                  verify_checkpoint(args.journal, _read_checkpoint(args.checkpoint), expected_sha256=args.expected_sha256))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, sqlite3.DatabaseError,
            RecursionError, OverflowError):
        print('error: DNS journal checkpoint failed; inspect private journal, independent pin and output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
