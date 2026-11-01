"""Synthetic signed evidence and native SQLite local-journal contracts."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_responsibility import fixture
from dns_assignment_journal import AssignmentJournal, main
from dns_authorized_handoff import _instant
from dns_responsibility import create_acceptance


class AssignmentJournalTests(unittest.TestCase):
    def setUp(self):
        self.report, self.inputs, self.options, self.key = fixture()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = AssignmentJournal.create(self.root/'journal.sqlite')
        self.initial = self.sign('2026-10-28T12:00:00Z', '2026-10-28T12:05:00Z')
        self.later = self.sign('2026-10-28T12:06:00Z', '2026-10-28T12:20:00Z')
        self.first_digest = hashlib.sha256(self.initial).hexdigest()

    def sign(self, accepted, expires, *, policy=None):
        claim = json.loads(self.options['acceptance'])
        return create_acceptance(self.report, authority_data=policy or self.options['acceptance_policy'],
            signing_key=self.key, key_id=claim['key_id'], finding_sha256=claim['finding_sha256'],
            team=claim['team'], accepted_at=accepted, expires_at=expires)

    def register(self, claim=None, at='2026-10-28T12:00:00Z', **changes):
        options = dict(self.options, acceptance=claim or self.initial, now=_instant(at))
        options.update(changes)
        return self.journal.register(self.report, *self.inputs, **options)

    def summary(self, at='2026-10-28T12:00:00Z', **changes):
        options = dict(acceptance_policy=self.options['acceptance_policy'],
            expected_acceptance_policy_sha256=self.options['expected_acceptance_policy_sha256'], now=_instant(at))
        options.update(changes)
        return self.journal.summary(**options)

    def test_persist_reopen_idempotent_replay_and_minimized_records(self):
        before = (self.report, list(self.inputs), dict(self.options))
        self.assertTrue(self.register()['appended'])
        self.assertFalse(self.register(at='2026-10-28T12:01:00Z')['appended'])
        self.journal = AssignmentJournal(self.journal.path)
        self.assertEqual(self.summary()['event_count'], 1)
        self.assertEqual(self.summary()['eligible_for_reverification'], 1)
        self.assertEqual(before, (self.report, self.inputs, self.options))
        self.assertEqual(stat.S_IMODE(self.journal.path.stat().st_mode), 0o600)
        with sqlite3.connect(self.journal.path) as connection:
            receipt = json.loads(connection.execute('SELECT receipt_json FROM acceptance_event').fetchone()[0])
        for field in ('signature_b64','hostname','addresses','risk','responses','private_key'):
            self.assertNotIn(field, receipt)
        self.assertNotIn(bytes(self.key), self.journal.path.read_bytes())

    def test_full_verification_runs_again_before_idempotent_replay(self):
        self.register()
        before = self.journal.path.read_bytes()
        invalid = json.loads(self.options['attestations'])
        invalid['attestations'].pop()
        with self.assertRaises(ValueError):
            self.register(attestations=json.dumps(invalid).encode())
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_conflicting_unexpired_acceptance_cannot_replace_even_with_exact_predecessor(self):
        self.register()
        other = self.sign('2026-10-28T12:01:00Z', '2026-10-28T12:10:00Z')
        before = self.journal.path.read_bytes()
        with self.assertRaises(ValueError):
            self.register(other, '2026-10-28T12:01:00Z', expected_predecessor=self.first_digest)
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_expiry_boundary_and_explicit_predecessor(self):
        self.register()
        self.assertEqual(self.summary('2026-10-28T12:05:00Z')['expired'], 1)
        for predecessor in (None, '0'*64):
            with self.assertRaises(ValueError):
                self.register(self.later, '2026-10-28T12:06:00Z', expected_predecessor=predecessor)
        self.assertEqual(self.register(self.later, '2026-10-28T12:06:00Z',
            expected_predecessor=self.first_digest)['event_count'], 2)
        self.assertEqual(self.summary('2026-10-28T12:06:00Z')['task_count'], 1)
        with sqlite3.connect(self.journal.path) as connection:
            self.assertEqual(connection.execute('SELECT predecessor_sha256 FROM acceptance_event ORDER BY sequence').fetchall(),
                             [(None,), (self.first_digest,)])

    def test_policy_replacement_including_revocation_invalidates_without_rewriting_history(self):
        self.register()
        policy = json.loads(self.options['acceptance_policy'])
        policy['keys'][0]['status'] = 'revoked'
        data = json.dumps(policy).encode()
        before = self.journal.path.read_bytes()
        summary = self.summary(acceptance_policy=data, expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(summary['policy_replaced'], 1)
        self.assertEqual(summary['eligible_for_reverification'], 0)
        self.assertEqual(self.journal.path.read_bytes(), before)
        # The old signed acceptance does not become a registration under a new revoked policy.
        with self.assertRaises(ValueError):
            self.register(acceptance_policy=data, expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_active_replacement_policy_requires_fresh_signature_and_predecessor(self):
        self.register()
        # Even harmless byte re-encoding changes the independently distributed policy pin.
        data = self.options['acceptance_policy']+b'\n'
        new = self.sign('2026-10-28T12:02:00Z', '2026-10-28T12:20:00Z', policy=data)
        result = self.register(new, '2026-10-28T12:02:00Z', acceptance_policy=data,
            expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest(), expected_predecessor=self.first_digest)
        self.assertTrue(result['appended'])
        self.assertEqual(result['event_count'], 2)
        self.assertEqual(self.summary('2026-10-28T12:02:00Z', acceptance_policy=data,
            expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest())['eligible_for_reverification'], 1)

    def test_stale_and_backward_clock_rejected(self):
        self.register(at='2026-10-28T12:01:00Z')
        with self.assertRaises(ValueError):
            self.register(at='2026-10-28T12:00:00Z')
        with self.assertRaises(ValueError):
            self.summary('2026-10-28T12:00:00Z')
        self.register(self.later, '2026-10-28T12:06:00Z', expected_predecessor=self.first_digest)
        with self.assertRaises(ValueError):
            self.register(self.initial, '2026-10-28T12:07:00Z', expected_predecessor=self.first_digest)

    def test_two_competing_native_connections_append_only_one(self):
        competitor = self.sign('2026-10-28T12:00:00Z', '2026-10-28T12:04:00Z')
        def attempt(claim):
            try:
                self.register(claim)
                return 'registered'
            except ValueError:
                return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(attempt, (self.initial, competitor)))
        self.assertCountEqual(results, ['registered', 'conflict'])
        self.assertEqual(self.summary()['event_count'], 1)

    def test_event_limit_preserves_existing_history(self):
        self.register()
        with patch('dns_assignment_journal.MAX_EVENTS', 1):
            with self.assertRaises(ValueError):
                self.register(self.later, '2026-10-28T12:06:00Z', expected_predecessor=self.first_digest)
        self.assertEqual(self.summary()['event_count'], 1)

    def test_busy_writer_fails_without_bypassing_journal_conflict_checks(self):
        with sqlite3.connect(self.journal.path) as writer:
            writer.execute('BEGIN IMMEDIATE')
            with self.assertRaises(sqlite3.OperationalError):
                self.register()
            self.assertEqual(writer.execute('SELECT count(*) FROM acceptance_event').fetchone()[0], 0)
        self.assertTrue(self.register()['appended'])

    def test_exclusive_create_private_parent_symlink_hardlink_and_size_limits(self):
        with self.assertRaises(FileExistsError):
            AssignmentJournal.create(self.journal.path)
        alias = self.root/'alias.sqlite'
        alias.symlink_to(self.journal.path)
        with self.assertRaises(OSError):
            AssignmentJournal(alias)
        alias.unlink()
        alias.hardlink_to(self.journal.path)
        with self.assertRaises(ValueError):
            AssignmentJournal(self.journal.path)
        alias.unlink()
        with patch('dns_assignment_journal.MAX_DATABASE_BYTES', 1):
            with self.assertRaises(ValueError):
                self.summary()
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            AssignmentJournal.create(self.root/'bad.sqlite')
        self.assertFalse((self.root/'bad.sqlite').exists())
        self.root.chmod(0o700)

    def test_sql_append_only_and_edited_linkage_rejected(self):
        self.register()
        with sqlite3.connect(self.journal.path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE acceptance_event SET audience='other-recipient'")
            connection.execute('DROP TRIGGER event_no_update')
            connection.execute("UPDATE acceptance_event SET predecessor_sha256=?", ('0'*64,))
        with self.assertRaises(ValueError):
            self.summary()

    def test_cli_aggregate_output_errors_and_fixture_clock(self):
        policy = self.root/'policy.json'
        policy.write_bytes(self.options['acceptance_policy'])
        args = ['summary', str(self.journal.path), '--acceptance-policy', str(policy),
            '--expected-acceptance-policy-sha256', self.options['expected_acceptance_policy_sha256'],
            '--at','2026-10-28T12:00:00Z']
        self.register()
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(args), 0)
        value = json.loads(out.getvalue())
        self.assertEqual(value['event_count'], 1)
        self.assertEqual(value['verification_time_source'], 'explicit_fixture')
        self.assertNotIn(self.first_digest, out.getvalue())
        self.assertNotIn(str(self.root), out.getvalue())
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(args[:-4]+['--expected-acceptance-policy-sha256','0'*64]), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn(str(self.root), err.getvalue())

    def test_register_cli_uses_complete_original_inputs_and_prints_no_identifiers(self):
        data = dict(report=self.report, previous=self.inputs[0], current=self.inputs[1], scope=self.inputs[2],
            policy=self.inputs[3], requirements=self.options['requirements'], approval=self.options['approval'],
            authority_policy=self.options['authority_policy'], reviewer_policy=self.options['reviewer_policy'],
            attestations=self.options['attestations'], assessment=self.options['assessment_data'],
            ownership_responses=self.options['ownership_data'], acceptance=self.initial,
            acceptance_policy=self.options['acceptance_policy'])
        args = ['register', str(self.journal.path)]
        for name, value in data.items():
            path = self.root/(name+'.json')
            path.write_bytes(value)
            args += ['--'+name.replace('_','-'), str(path)]
        args += ['--expected-reviewer-policy-sha256', self.options['expected_reviewer_policy_sha256'],
                 '--expected-acceptance-policy-sha256', self.options['expected_acceptance_policy_sha256'],
                 '--at','2026-10-28T12:00:00Z']
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(args), 0)
        self.assertEqual(json.loads(out.getvalue())['event_count'], 1)
        self.assertNotIn(self.first_digest, out.getvalue())

    def test_fresh_process_signed_walkthrough(self):
        script = Path(__file__).resolve().parents[1]/'demo_assignment_journal.py'
        result = subprocess.run([sys.executable, str(script)], check=True, capture_output=True, text=True)
        value = json.loads(result.stdout)
        self.assertEqual(value['status'], 'dns_assignment_journal_exercise_passed')
        self.assertEqual(value['events'], 2)
        self.assertEqual(value['negative_cases_rejected'], 3)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
