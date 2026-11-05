"""Persistent journal identity, independent enrollment and complete native lifecycle checks."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_responsibility import fixture
from dns_assignment_journal import AssignmentJournal
from dns_assignment_lifecycle import LifecycleJournal, create_release
from dns_authorized_handoff import _instant
from dns_identified_journal import IdentifiedJournal, build_checkpoint, create_checkpoint, enroll, main, verify_checkpoint
from dns_journal_checkpoint import build_checkpoint as build_v1
from dns_lifecycle_checkpoint import build_checkpoint as build_v2
from dns_responsibility import accept_responsibility


class IdentifiedJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.journal = IdentifiedJournal.create(self.root/'journal.sqlite')
        result = enroll(self.journal, self.root/'enrollment.json')
        self.enrollment = (self.root/'enrollment.json').read_bytes()
        self.pin = result['enrollment_sha256']
        self.report, self.inputs, self.options, self.key = fixture()

    def trust(self):
        return dict(enrollment_data=self.enrollment, expected_enrollment_sha256=self.pin)

    def register(self):
        self.journal.register(self.report, *self.inputs, **self.options)

    def release(self):
        target = accept_responsibility(self.report, *self.inputs, **self.options)
        claim = create_release(target, signing_key=self.key, released_at='2026-10-28T12:02:00Z',
                               expires_at='2026-10-28T12:03:00Z')
        self.journal.release(claim, acceptance_policy=self.options['acceptance_policy'],
            expected_acceptance_policy_sha256=self.options['expected_acceptance_policy_sha256'],
            now=_instant('2026-10-28T12:02:00Z'))
        return claim

    def checkpoint(self):
        output = self.root/'checkpoint.json'
        result = create_checkpoint(self.journal.path, output, **self.trust())
        return output.read_bytes(), result['checkpoint_sha256']

    def test_separate_initializations_differ_even_with_identical_event_history(self):
        # The previous logical-state checkpoints cannot distinguish two empty stores.
        legacy_a = LifecycleJournal.create(self.root/'legacy-a.sqlite')
        legacy_b = LifecycleJournal.create(self.root/'legacy-b.sqlite')
        self.assertEqual(build_v2(legacy_a), build_v2(legacy_b))
        other = IdentifiedJournal.create(self.root/'other.sqlite')
        self.assertNotEqual(self.journal.journal_id, other.journal_id)
        self.register()
        other.register(self.report, *self.inputs, **self.options)
        first, second = build_checkpoint(self.journal), build_checkpoint(other)
        self.assertEqual(first['acceptance_count'], second['acceptance_count'])
        self.assertNotEqual(first['history_sha256'], second['history_sha256'])
        data, pin = self.checkpoint()
        with self.assertRaises(ValueError):
            verify_checkpoint(other.path, data, expected_sha256=pin, **self.trust())

    def test_enrolled_registered_released_checkpoint_and_copy_match(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.register()
            self.release()
            data, pin = self.checkpoint()
            before = self.journal.path.read_bytes()
            result = verify_checkpoint(self.journal.path, data, expected_sha256=pin, **self.trust())
        self.assertEqual((result['acceptance_count'], result['release_count']), (1, 1))
        self.assertTrue(result['enrolled_identity_checked'])
        self.assertFalse(result['current_authority_reverified'])
        self.assertFalse(result['historical_signatures_reverified'])
        self.assertEqual(before, self.journal.path.read_bytes())
        copy = self.root/'copy.sqlite'
        copy.write_bytes(before)
        copy.chmod(0o600)
        self.assertEqual(verify_checkpoint(copy, data, expected_sha256=pin, **self.trust()), result)

    def test_invalid_metadata_pins_precede_candidate_open(self):
        data, pin = self.checkpoint()
        for override in ({'expected_sha256': '0'*64}, {'expected_enrollment_sha256': 'bad'},
                         {'enrollment_data': b'x'*4097}):
            with patch.object(IdentifiedJournal, '__init__', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError):
                    verify_checkpoint(self.journal.path, data, **(dict(expected_sha256=pin, **self.trust()) | override))

    def test_enrollment_has_exact_canonical_fields_and_bounded_identity(self):
        document = json.loads(self.enrollment)
        for candidate in (json.dumps(document, indent=2).encode(),
                          json.dumps(dict(document, extra=True)).encode(),
                          self.enrollment[:-2]+b',"journal_version":3}\n',
                          json.dumps(dict(document, journal_id='invalid')).encode()):
            with self.assertRaises(ValueError):
                IdentifiedJournal.from_enrollment(self.journal.path, candidate,
                    expected_sha256=hashlib.sha256(candidate).hexdigest())

    def test_release_only_rollback_still_rejected_under_same_enrollment(self):
        self.register()
        older = self.journal.path.read_bytes()
        self.release()
        data, pin = self.checkpoint()
        self.journal.path.write_bytes(older)
        with self.assertRaises(ValueError):
            verify_checkpoint(self.journal.path, data, expected_sha256=pin, **self.trust())

    def test_identity_checked_on_each_operation_after_path_replacement(self):
        other = IdentifiedJournal.create(self.root/'other.sqlite')
        self.journal.path.write_bytes(other.path.read_bytes())
        with self.assertRaises(ValueError): self.register()
        with self.assertRaises(ValueError): build_checkpoint(self.journal)
        with sqlite3.connect(self.journal.path) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM acceptance_event').fetchone(), (0,))

    def test_identity_table_is_fixed_and_must_be_ordinary_and_singleton(self):
        with sqlite3.connect(self.journal.path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute('UPDATE journal_identity SET journal_id=?', ('0'*32,))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute('DELETE FROM journal_identity')
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute('INSERT INTO journal_identity VALUES(2,?)', ('0'*32,))
            connection.execute('DROP TABLE journal_identity')
            connection.execute('CREATE VIEW journal_identity AS SELECT 1 singleton, ? journal_id'.replace('?', "'"+self.journal.journal_id+"'"))
        with self.assertRaises(ValueError): build_checkpoint(self.journal)

    def test_version_separation_keeps_legacy_stores_and_checkpoint_types_distinct(self):
        for factory in (AssignmentJournal, LifecycleJournal):
            old = factory.create(self.root/f'v{factory.VERSION}.sqlite')
            with self.assertRaises(ValueError):
                IdentifiedJournal(old.path, expected_journal_id=self.journal.journal_id)
            with self.assertRaises(ValueError):
                factory(self.journal.path).summary(acceptance_policy=self.options['acceptance_policy'],
                    expected_acceptance_policy_sha256=self.options['expected_acceptance_policy_sha256'],
                    now=self.options['now'])
        with self.assertRaises(ValueError): build_v1(self.journal)
        with self.assertRaises(ValueError): build_v2(self.journal)

    def test_private_modes_links_and_existing_outputs(self):
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root/'enrollment.json').stat().st_mode & 0o777, 0o600)
        before = self.journal.path.read_bytes()
        with self.assertRaises(FileExistsError): IdentifiedJournal.create(self.journal.path)
        with self.assertRaises(OSError): enroll(self.journal, self.root/'enrollment.json')
        self.assertEqual(before, self.journal.path.read_bytes())
        alias = self.root/'alias.sqlite'
        alias.symlink_to(self.journal.path)
        with self.assertRaises(OSError): IdentifiedJournal(alias, expected_journal_id=self.journal.journal_id)

    def test_failed_initialization_cleans_only_its_new_file(self):
        path = self.root/'failed.sqlite'
        with patch.object(IdentifiedJournal, 'SQL', 'invalid synthetic SQL'):
            with self.assertRaises(sqlite3.DatabaseError): IdentifiedJournal.create(path)
        self.assertFalse(path.exists())
        self.assertTrue(self.journal.path.exists())

    def test_identity_and_both_histories_share_one_checkpoint_transaction(self):
        self.register()
        self.release()
        connections = []
        history, releases = self.journal._history, self.journal._releases
        def capture_history(connection):
            self.assertTrue(connection.in_transaction)
            self.assertEqual(connection.execute('SELECT journal_id FROM journal_identity').fetchone(), (self.journal.journal_id,))
            connections.append(connection)
            return history(connection)
        def capture_releases(connection, rows):
            self.assertTrue(connection.in_transaction)
            connections.append(connection)
            return releases(connection, rows)
        with patch.object(self.journal, '_history', side_effect=capture_history), patch.object(
                self.journal, '_releases', side_effect=capture_releases):
            build_checkpoint(self.journal)
        self.assertIs(connections[0], connections[1])

    def test_cli_register_release_summary_checkpoint_and_verify_require_enrollment(self):
        data = dict(report=self.report, previous=self.inputs[0], current=self.inputs[1], scope=self.inputs[2],
                    policy=self.inputs[3], requirements=self.options['requirements'], approval=self.options['approval'],
                    authority_policy=self.options['authority_policy'], reviewer_policy=self.options['reviewer_policy'],
                    attestations=self.options['attestations'], assessment=self.options['assessment_data'],
                    ownership_responses=self.options['ownership_data'], acceptance=self.options['acceptance'],
                    acceptance_policy=self.options['acceptance_policy'])
        register = ['register', str(self.journal.path)]
        for name, value in data.items():
            path = self.root/(name+'.fixture')
            path.write_bytes(value)
            register += ['--'+name.replace('_', '-'), str(path)]
        trust = ['--enrollment', str(self.root/'enrollment.json'), '--expected-enrollment-sha256', self.pin]
        register += trust+['--expected-reviewer-policy-sha256', self.options['expected_reviewer_policy_sha256'],
            '--expected-acceptance-policy-sha256', self.options['expected_acceptance_policy_sha256'],
            '--at', '2026-10-28T12:00:00Z']
        with redirect_stdout(StringIO()): self.assertEqual(main(register), 0)
        target = accept_responsibility(self.report, *self.inputs, **self.options)
        release = create_release(target, signing_key=self.key, released_at='2026-10-28T12:02:00Z',
                                 expires_at='2026-10-28T12:03:00Z')
        path = self.root/'release.json'
        path.write_bytes(release)
        policy = ['--acceptance-policy', str(self.root/'acceptance_policy.fixture'),
                  '--expected-acceptance-policy-sha256', self.options['expected_acceptance_policy_sha256']]
        with redirect_stdout(StringIO()):
            self.assertEqual(main(['release', str(self.journal.path), '--release', str(path),
                '--at', '2026-10-28T12:02:00Z']+trust+policy), 0)
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(['summary', str(self.journal.path), '--at', '2026-10-28T12:02:00Z']+trust+policy), 0)
        self.assertEqual(json.loads(out.getvalue())['released'], 1)
        out = StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(['checkpoint', str(self.journal.path), '--output', str(self.root/'cli-checkpoint.json')]+trust), 0)
        pin = json.loads(out.getvalue())['checkpoint_sha256']
        with redirect_stdout(StringIO()):
            self.assertEqual(main(['verify', str(self.journal.path), '--checkpoint', str(self.root/'cli-checkpoint.json'),
                '--expected-sha256', pin]+trust), 0)
        err = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(['verify', str(self.journal.path), '--checkpoint', str(self.root/'cli-checkpoint.json'),
                '--expected-sha256', '0'*64]+trust), 2)
        self.assertNotIn(str(self.root), err.getvalue())
        self.assertNotIn(self.journal.journal_id, err.getvalue())

    def test_fresh_process_enrollment_walkthrough(self):
        result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1]/'demo_journal_enrollment.py')],
                                check=True, capture_output=True, text=True, timeout=30)
        value = json.loads(result.stdout)
        self.assertEqual(value['status'], 'dns_journal_enrollment_exercise_passed')
        self.assertEqual(value['negative_cases_rejected'], 4)
        self.assertTrue(value['enrolled_identity_checked'])
        self.assertEqual(result.stderr, '')

    def test_standard_library_only_init_enroll_and_checkpoint_commands(self):
        script = str(Path(__file__).resolve().parents[1]/'dns_identified_journal.py')
        def command(*args):
            result = subprocess.run([sys.executable, '-S', script, *map(str, args)],
                                    check=True, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.stderr, '')
            return json.loads(result.stdout)
        journal, enrollment, checkpoint = self.root/'stdlib.sqlite', self.root/'stdlib.json', self.root/'stdlib-checkpoint.json'
        created = command('init', journal)
        enrolled = command('enroll', journal, '--expected-journal-id', created['journal_id'], '--output', enrollment)
        trust = ['--enrollment', enrollment, '--expected-enrollment-sha256', enrolled['enrollment_sha256']]
        saved = command('checkpoint', journal, '--output', checkpoint, *trust)
        checked = command('verify', journal, '--checkpoint', checkpoint,
                          '--expected-sha256', saved['checkpoint_sha256'], *trust)
        self.assertTrue(checked['enrolled_identity_checked'])
        self.assertEqual(checked['acceptance_count'], 0)


if __name__ == '__main__':
    unittest.main()
