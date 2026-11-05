"""Serialize fully verified DNS task acceptances in one private local journal."""

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from dns_authorized_handoff import _identifier, _instant
from dns_responsibility import accept_responsibility, read_acceptors
from dns_review import _fields, _load, read_input
from dns_reviewer_handoff import _digest
from zeek_dns_workflow_verify import _canonical, read_report

MAX_DATABASE_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 2000
RECEIPT_FIELDS = {'schema_version', 'receipt_type', 'status', 'finding_sha256', 'team', 'key_id',
    'audience', 'accepted_at', 'expires_at', 'verified_at', 'workflow_sha256', 'acceptance_sha256',
    'acceptance_policy_sha256', 'reviewer_policy_sha256', 'interpretation'}
SCHEMA = """
CREATE TABLE acceptance_event(
 sequence INTEGER PRIMARY KEY,
 audience TEXT NOT NULL,
 finding_sha256 TEXT NOT NULL,
 acceptance_sha256 TEXT NOT NULL UNIQUE,
 predecessor_sha256 TEXT,
 receipt_json TEXT NOT NULL
);
CREATE TRIGGER event_no_update BEFORE UPDATE ON acceptance_event
 BEGIN SELECT RAISE(ABORT,'journal is append-only'); END;
CREATE TRIGGER event_no_delete BEFORE DELETE ON acceptance_event
 BEGIN SELECT RAISE(ABORT,'journal is append-only'); END;
PRAGMA user_version=1;
"""


def _now(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('verification time must be timezone-aware')
    return value.astimezone(timezone.utc)


def _receipt(value):
    _fields(value, RECEIPT_FIELDS)
    if (type(value['schema_version']) is not int or value['schema_version'] != 1 or
            value['receipt_type'] != 'dns-review-responsibility' or value['status'] != 'accepted_review_responsibility'):
        raise ValueError('unsupported acceptance receipt')
    for name in ('audience', 'key_id'):
        _identifier(value[name])
    for name in ('finding_sha256', 'workflow_sha256', 'acceptance_sha256',
                 'acceptance_policy_sha256', 'reviewer_policy_sha256'):
        _digest(value[name])
    team = value['team']
    if not isinstance(team, str) or not 1 <= len(team) <= 64 or not team.strip() or any(ord(c) < 32 for c in team):
        raise ValueError('invalid review team')
    verified = _now(datetime.fromisoformat(value['verified_at']))
    accepted, expires = _instant(value['accepted_at']), _instant(value['expires_at'])
    if not accepted <= verified < expires or not isinstance(value['interpretation'], str):
        raise ValueError('invalid receipt validity')
    if len(_canonical(value).encode()) > 8192:
        raise ValueError('receipt exceeds journal bound')
    return verified


def _policy(data, pin):
    _digest(pin)
    if hashlib.sha256(data).hexdigest() != pin:
        raise ValueError('current authority policy does not match independent pin')
    return read_acceptors(data)


def _state(receipt, *, policy, pin, now):
    # Replacement of any policy bytes invalidates the old registration conservatively.
    # This also handles key revocation without trusting a retained receipt as current authority.
    if receipt['acceptance_policy_sha256'] != pin:
        return 'policy_replaced'
    if receipt['audience'] != policy['audience']:
        return 'policy_replaced'
    key = next((k for k in policy['keys'] if k['key_id'] == receipt['key_id']), None)
    if key is None or key['status'] != 'active' or dict(finding_sha256=receipt['finding_sha256'], team=receipt['team']) not in key['grants']:
        return 'authority_inactive'
    if now < _instant(receipt['accepted_at']):
        raise ValueError('clock precedes acceptance')
    return 'expired' if now >= _instant(receipt['expires_at']) else 'eligible_for_reverification'


class AssignmentJournal:
    """Host-controlled local history, not a transferable approval or global ownership registry."""
    VERSION = 1
    SQL = SCHEMA
    def __init__(self, path):
        self.path = Path(path)
        self._check()

    @staticmethod
    def _parent(path):
        if os.name != 'posix' or not path.is_absolute():
            raise ValueError('journal requires an absolute private POSIX path')
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(fd)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError('journal parent must be owned mode0700')
        finally:
            os.close(fd)

    def _check(self):
        path = self.path
        self._parent(path)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_DATABASE_BYTES):
                raise ValueError('journal must be a bounded owned mode0600 file')
        finally:
            os.close(fd)

    @classmethod
    def create(cls, path):
        path = Path(path)
        cls._parent(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('PRAGMA journal_mode=DELETE')
            connection.execute('PRAGMA synchronous=FULL')
            connection.executescript(cls.SQL)
        return cls(path)

    @contextmanager
    def _connection(self, *, write=False):
        self._check()
        with closing(sqlite3.connect(self.path.as_uri()+('?mode=rw' if write else '?mode=ro'),
                                     uri=True, timeout=1)) as connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('PRAGMA busy_timeout=1000')
            if not write:
                connection.execute('PRAGMA query_only=ON')
            if (connection.execute('PRAGMA user_version').fetchone() != (self.VERSION,) or
                    connection.execute('PRAGMA journal_mode').fetchone() != ('delete',)):
                raise ValueError('unsupported journal database')
            schema = connection.execute("SELECT type,sql FROM sqlite_schema WHERE name='acceptance_event'").fetchall()
            if (len(schema) != 1 or schema[0][0] != 'table' or
                    not schema[0][1].lstrip().upper().startswith('CREATE TABLE ')):
                raise ValueError('expected an ordinary journal table')
            columns = tuple(row[1] for row in connection.execute('PRAGMA table_info(acceptance_event)'))
            if columns != ('sequence','audience','finding_sha256','acceptance_sha256','predecessor_sha256','receipt_json'):
                raise ValueError('unsupported journal columns')
            page_size = connection.execute('PRAGMA page_size').fetchone()[0]
            if write:
                connection.execute('PRAGMA max_page_count='+str(MAX_DATABASE_BYTES//page_size))
            with connection:
                connection.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
                yield connection

    @staticmethod
    def _history(connection):
        rows = connection.execute('SELECT sequence,audience,finding_sha256,acceptance_sha256,'
                                  'predecessor_sha256,receipt_json FROM acceptance_event ORDER BY sequence').fetchmany(MAX_EVENTS+1)
        if len(rows) > MAX_EVENTS:
            raise ValueError('journal event limit exceeded')
        latest, seen = {}, set()
        for expected, (sequence, audience, finding, acceptance, predecessor, raw) in enumerate(rows, 1):
            if type(sequence) is not int or sequence != expected or not isinstance(raw, str) or len(raw.encode()) > 8192:
                raise ValueError('invalid journal sequence or record')
            receipt = _load(raw.encode())
            verified = _receipt(receipt)
            identity = (audience, finding)
            previous = latest.get(identity)
            if (audience != receipt['audience'] or finding != receipt['finding_sha256'] or
                    acceptance != receipt['acceptance_sha256'] or acceptance in seen or
                    predecessor != (previous['acceptance_sha256'] if previous else None) or
                    previous is not None and verified < _receipt(previous)):
                raise ValueError('invalid journal linkage')
            latest[identity] = receipt
            seen.add(acceptance)
        return rows, latest

    def register(self, report, previous, current, scope, review_policy, *, expected_predecessor=None, **options):
        """Verify all original evidence first, then serialize conflict checking and append."""
        if expected_predecessor is not None:
            _digest(expected_predecessor)
        receipt = accept_responsibility(report, previous, current, scope, review_policy, **options)
        now = _receipt(receipt)
        pin = options['expected_acceptance_policy_sha256']
        policy = _policy(options['acceptance_policy'], pin)
        with self._connection(write=True) as connection:
            rows, latest = self._history(connection)
            prior = latest.get((receipt['audience'], receipt['finding_sha256']))
            if prior is not None and now < _receipt(prior):
                raise ValueError('journal clock moved backwards')
            prior_digest = prior['acceptance_sha256'] if prior else None
            if prior_digest == receipt['acceptance_sha256']:
                # Full verification just ran again. An old event cannot supersede a newer one.
                return {'status': 'already_registered', 'event_count': len(rows), 'appended': False}
            if prior_digest != expected_predecessor:
                raise ValueError('explicit predecessor differs from current journal state')
            if prior is not None and _state(prior, policy=policy, pin=pin, now=now) == 'eligible_for_reverification':
                raise ValueError('competing unexpired current-policy acceptance')
            if len(rows) >= MAX_EVENTS:
                raise ValueError('journal event limit exceeded')
            connection.execute('INSERT INTO acceptance_event VALUES(?,?,?,?,?,?)',
                (len(rows)+1, receipt['audience'], receipt['finding_sha256'], receipt['acceptance_sha256'],
                 prior_digest, _canonical(receipt)))
        return {'status': 'review_acceptance_registered', 'event_count': len(rows)+1, 'appended': True}

    def summary(self, *, acceptance_policy, expected_acceptance_policy_sha256, now):
        now = _now(now)
        pin = expected_acceptance_policy_sha256
        policy = _policy(acceptance_policy, pin)
        with self._connection() as connection:
            rows, latest = self._history(connection)
        counts = dict(eligible_for_reverification=0, expired=0, policy_replaced=0, authority_inactive=0)
        for receipt in latest.values():
            if now < _receipt(receipt):
                raise ValueError('journal clock moved backwards')
            counts[_state(receipt, policy=policy, pin=pin, now=now)] += 1
        return dict(status='local_acceptance_journal_summary', event_count=len(rows), task_count=len(latest), **counts)


def main(argv=None, *, journal_type=AssignmentJournal):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init')
    init.add_argument('journal', type=Path)
    for name in ('register', 'summary'):
        sub = commands.add_parser(name)
        sub.add_argument('journal', type=Path)
        sub.add_argument('--acceptance-policy', type=Path, required=True)
        sub.add_argument('--expected-acceptance-policy-sha256', required=True)
        sub.add_argument('--at', help='explicit UTC fixture instant; omit for current UTC')
        if name == 'register':
            for field in ('report', 'previous', 'current', 'scope', 'policy', 'requirements', 'approval',
                          'authority-policy', 'reviewer-policy', 'attestations', 'assessment',
                          'ownership-responses', 'acceptance'):
                sub.add_argument('--'+field, type=Path, required=True)
            sub.add_argument('--expected-reviewer-policy-sha256', required=True)
            sub.add_argument('--expected-predecessor')
            if journal_type.VERSION in (2, 3):
                sub.add_argument('--expected-release-sha256')
        if journal_type.VERSION == 3:
            sub.add_argument('--enrollment', required=True, type=Path)
            sub.add_argument('--expected-enrollment-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            journal_type.create(args.journal)
            result = {'status': 'local_acceptance_journal_created'}
        else:
            now = _instant(args.at) if args.at else datetime.now(timezone.utc)
            journal = (journal_type.from_enrollment(args.journal, read_input(args.enrollment),
                       expected_sha256=args.expected_enrollment_sha256) if journal_type.VERSION == 3 else
                       journal_type(args.journal))
            options = dict(acceptance_policy=read_input(args.acceptance_policy),
                           expected_acceptance_policy_sha256=args.expected_acceptance_policy_sha256, now=now)
            if args.command == 'summary':
                result = journal.summary(**options)
            else:
                for name, field in (('requirements','requirements'), ('approval','approval'),
                    ('authority_policy','authority_policy'), ('reviewer_policy','reviewer_policy'),
                    ('attestations','attestations'), ('assessment_data','assessment'),
                    ('ownership_data','ownership_responses'), ('acceptance','acceptance')):
                    options[name] = read_input(getattr(args, field))
                options['expected_reviewer_policy_sha256'] = args.expected_reviewer_policy_sha256
                if journal_type.VERSION in (2, 3):
                    options['expected_release_sha256'] = args.expected_release_sha256
                result = journal.register(read_report(args.report), read_input(args.previous), read_input(args.current),
                    read_input(args.scope), read_input(args.policy), expected_predecessor=args.expected_predecessor, **options)
            result['verification_time_source'] = 'explicit_fixture' if args.at else 'current_utc_clock'
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, sqlite3.DatabaseError,
            RecursionError, OverflowError):
        print('error: local DNS acceptance journal operation failed; inspect private evidence, trust, time and predecessor', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
