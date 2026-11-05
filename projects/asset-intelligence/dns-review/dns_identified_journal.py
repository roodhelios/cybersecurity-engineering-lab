"""Version-3 DNS lifecycle journals with separately pinned persistent identity."""

import argparse
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import uuid

from dns_assignment_lifecycle import LifecycleJournal, main as lifecycle_main
from dns_journal_checkpoint import MAX_CHECKPOINT_BYTES, _read_checkpoint, _render
from dns_review import _fields, _load, publish
from dns_reviewer_handoff import _digest
from zeek_dns_workflow_verify import _canonical

DOMAIN = b'dns-identified-lifecycle-history:v3\x00'
IDENTITY_SQL = """
CREATE TABLE journal_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), journal_id TEXT NOT NULL);
CREATE TRIGGER identity_no_update BEFORE UPDATE ON journal_identity
 BEGIN SELECT RAISE(ABORT,'journal identity is fixed'); END;
CREATE TRIGGER identity_no_delete BEFORE DELETE ON journal_identity
 BEGIN SELECT RAISE(ABORT,'journal identity is fixed'); END;
"""


def _identifier(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{32}', value) is None:
        raise ValueError('expected a separately retained journal identifier')


def _pinned(data, expected):
    _digest(expected)
    if (not isinstance(data, bytes) or not 0 < len(data) <= MAX_CHECKPOINT_BYTES or
            hashlib.sha256(data).hexdigest() != expected):
        raise ValueError('metadata differs from independently retained pin')


class IdentifiedJournal(LifecycleJournal):
    VERSION = 3
    SQL = LifecycleJournal.SQL.replace('PRAGMA user_version=2;', 'PRAGMA user_version=3;')+IDENTITY_SQL

    def __init__(self, path, *, expected_journal_id):
        _identifier(expected_journal_id)
        self.journal_id = expected_journal_id
        super().__init__(path)
        with self._connection():
            pass

    @classmethod
    def create(cls, path):
        path = Path(path)
        cls._parent(path)
        identity = uuid.uuid4().hex
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(path)) as connection:
                connection.execute('PRAGMA journal_mode=DELETE')
                connection.execute('PRAGMA synchronous=FULL')
                connection.executescript(cls.SQL)
                with connection:
                    connection.execute('INSERT INTO journal_identity VALUES(1,?)', (identity,))
            return cls(path, expected_journal_id=identity)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    @contextmanager
    def _connection(self, *, write=False):
        # The identity check shares the transaction used by every inherited operation.
        with super()._connection(write=write) as connection:
            schema = connection.execute("SELECT type,sql FROM sqlite_schema WHERE name='journal_identity'").fetchall()
            columns = tuple(row[1] for row in connection.execute('PRAGMA table_info(journal_identity)'))
            if (len(schema) != 1 or schema[0][0] != 'table' or
                    not schema[0][1].lstrip().upper().startswith('CREATE TABLE ') or
                    columns != ('singleton', 'journal_id')):
                raise ValueError('unsupported journal identity table')
            rows = connection.execute('SELECT singleton,journal_id FROM journal_identity').fetchmany(2)
            if rows != [(1, self.journal_id)]:
                raise ValueError('journal differs from enrolled identity')
            yield connection

    @classmethod
    def from_enrollment(cls, path, data, *, expected_sha256):
        _pinned(data, expected_sha256)
        enrollment = _load(data)
        _fields(enrollment, {'schema_version', 'enrollment_type', 'journal_version', 'journal_id'})
        if (type(enrollment['schema_version']) is not int or enrollment['schema_version'] != 1 or
                type(enrollment['journal_version']) is not int or enrollment['journal_version'] != 3 or
                enrollment['enrollment_type'] != 'dns-review-local-journal' or _render(enrollment) != data):
            raise ValueError('unsupported canonical enrollment')
        return cls(path, expected_journal_id=enrollment['journal_id'])


def build_checkpoint(journal):
    if not isinstance(journal, IdentifiedJournal):
        raise ValueError('expected an enrolled version-3 journal')
    with journal._connection() as connection:
        rows, latest = journal._history(connection)
        journal._releases(connection, rows)
        releases = connection.execute('SELECT sequence,acceptance_sha256,release_sha256,receipt_json '
                                      'FROM release_event ORDER BY sequence').fetchall()
    history = _canonical(dict(journal_id=journal.journal_id, acceptances=rows, releases=releases)).encode('ascii')
    return dict(schema_version=3, checkpoint_type='dns-review-identified-lifecycle-journal',
                journal_id=journal.journal_id, acceptance_count=len(rows), release_count=len(releases),
                task_count=len(latest), history_sha256=hashlib.sha256(DOMAIN+history).hexdigest())


def enroll(journal, output):
    build_checkpoint(journal)  # Do not enroll an invalid logical store.
    data = _render(dict(schema_version=1, enrollment_type='dns-review-local-journal',
                        journal_version=3, journal_id=journal.journal_id))
    publish(Path(output), data.decode('ascii'))
    return dict(status='dns_journal_enrollment_created', enrollment_sha256=hashlib.sha256(data).hexdigest())


def create_checkpoint(path, output, *, enrollment_data, expected_enrollment_sha256):
    journal = IdentifiedJournal.from_enrollment(path, enrollment_data, expected_sha256=expected_enrollment_sha256)
    checkpoint = build_checkpoint(journal)
    data = _render(checkpoint)
    publish(Path(output), data.decode('ascii'))
    return _summary(checkpoint, data, 'dns_identified_checkpoint_created')


def _summary(checkpoint, data, status):
    return dict(status=status, acceptance_count=checkpoint['acceptance_count'],
                release_count=checkpoint['release_count'], task_count=checkpoint['task_count'],
                checkpoint_sha256=hashlib.sha256(data).hexdigest(), enrolled_identity_checked=True,
                current_authority_reverified=False, historical_signatures_reverified=False)


def verify_checkpoint(path, data, *, expected_sha256, enrollment_data, expected_enrollment_sha256):
    _pinned(data, expected_sha256)
    journal = IdentifiedJournal.from_enrollment(path, enrollment_data, expected_sha256=expected_enrollment_sha256)
    checkpoint = build_checkpoint(journal)
    if data != _render(checkpoint):
        raise ValueError('complete identified lifecycle history differs from checkpoint')
    return _summary(checkpoint, data, 'dns_identified_checkpoint_matched')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ('register', 'release', 'summary'):
        return lifecycle_main(argv, journal_type=IdentifiedJournal)
    parser = argparse.ArgumentParser(description=__doc__,
        epilog='register, release and summary also require --enrollment and --expected-enrollment-sha256. '
               'Use COMMAND --help for their existing evidence and authority arguments. No migration is performed.')
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init')
    init.add_argument('journal', type=Path)
    enrollment = commands.add_parser('enroll')
    enrollment.add_argument('journal', type=Path)
    enrollment.add_argument('--expected-journal-id', required=True)
    enrollment.add_argument('--output', type=Path, required=True)
    for name in ('checkpoint', 'verify'):
        command = commands.add_parser(name)
        command.add_argument('journal', type=Path)
        command.add_argument('--enrollment', type=Path, required=True)
        command.add_argument('--expected-enrollment-sha256', required=True)
        if name == 'checkpoint':
            command.add_argument('--output', type=Path, required=True)
        else:
            command.add_argument('--checkpoint', type=Path, required=True)
            command.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            journal = IdentifiedJournal.create(args.journal)
            result = dict(status='dns_identified_journal_created', journal_id=journal.journal_id)
        elif args.command == 'enroll':
            result = enroll(IdentifiedJournal(args.journal, expected_journal_id=args.expected_journal_id), args.output)
        else:
            options = dict(enrollment_data=_read_checkpoint(args.enrollment),
                           expected_enrollment_sha256=args.expected_enrollment_sha256)
            result = (create_checkpoint(args.journal, args.output, **options) if args.command == 'checkpoint' else
                      verify_checkpoint(args.journal, _read_checkpoint(args.checkpoint),
                                        expected_sha256=args.expected_sha256, **options))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, sqlite3.DatabaseError,
            RecursionError, OverflowError):
        print('error: identified DNS journal operation failed; inspect private journal, enrollment, pins and output',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
