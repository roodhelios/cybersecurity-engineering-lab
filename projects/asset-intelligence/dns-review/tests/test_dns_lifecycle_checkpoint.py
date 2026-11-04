"""Independent exact-state pins cover acceptance and voluntary-release rows."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_responsibility import fixture
from demo_lifecycle_checkpoint import exercise
from dns_assignment_journal import AssignmentJournal
from dns_assignment_lifecycle import LifecycleJournal, create_release
from dns_authorized_handoff import _instant
from dns_journal_checkpoint import verify_checkpoint as verify_v1
from dns_lifecycle_checkpoint import build_checkpoint, create_checkpoint, main, verify_checkpoint
from dns_responsibility import accept_responsibility


class LifecycleCheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.journal = LifecycleJournal.create(self.root/'journal.sqlite')
        self.report, self.inputs, self.options, self.key = fixture()
        self.output = self.root/'checkpoint.json'

    def register(self):
        self.journal.register(self.report, *self.inputs, **self.options)

    def release(self):
        target = accept_responsibility(self.report, *self.inputs, **self.options)
        claim = create_release(target, signing_key=self.key,
            released_at='2026-10-28T12:02:00Z', expires_at='2026-10-28T12:03:00Z')
        self.journal.release(claim, acceptance_policy=self.options['acceptance_policy'],
            expected_acceptance_policy_sha256=self.options['expected_acceptance_policy_sha256'],
            now=_instant('2026-10-28T12:02:00Z'))

    def checkpoint(self):
        result = create_checkpoint(self.journal, self.output)
        return self.output.read_bytes(), result['checkpoint_sha256']

    def verify(self, data, pin):
        return verify_checkpoint(self.journal.path, data, expected_sha256=pin)

    def test_empty_registered_and_released_states_match_without_writes(self):
        for operation, counts in ((lambda: None, (0, 0)), (self.register, (1, 0)), (self.release, (1, 1))):
            operation()
            before = self.journal.path.read_bytes()
            data, pin = self.checkpoint()
            result = self.verify(data, pin)
            self.assertEqual((result['acceptance_count'], result['release_count']), counts)
            self.assertFalse(result['historical_signatures_reverified'])
            self.assertFalse(result['current_authority_reverified'])
            self.assertEqual(self.journal.path.read_bytes(), before)
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
            self.output.unlink()

    def test_release_only_rollback_is_detected_with_same_acceptance_count(self):
        self.register(); older = self.journal.path.read_bytes()
        self.release(); data, pin = self.checkpoint()
        self.journal.path.write_bytes(older)
        self.assertEqual(build_checkpoint(self.journal)['acceptance_count'], 1)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_acceptance_rollback_and_valid_append_require_a_new_pin(self):
        older = self.journal.path.read_bytes(); data, pin = self.checkpoint()
        self.register()
        with self.assertRaises(ValueError): self.verify(data, pin)
        self.output.unlink(); current, current_pin = self.checkpoint()
        self.journal.path.write_bytes(older)
        with self.assertRaises(ValueError): self.verify(current, current_pin)
        self.assertEqual(self.verify(data, pin)['acceptance_count'], 0)

    def test_valid_same_count_release_receipt_change_is_detected(self):
        self.register(); self.release(); data, pin = self.checkpoint()
        with sqlite3.connect(self.journal.path) as connection:
            connection.execute('DROP TRIGGER release_no_update')
            receipt = json.loads(connection.execute('SELECT receipt_json FROM release_event').fetchone()[0])
            receipt['verified_at'] = '2026-10-28T12:02:01+00:00'
            connection.execute('UPDATE release_event SET receipt_json=?', (json.dumps(receipt),))
        self.assertEqual(build_checkpoint(self.journal)['release_count'], 1)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_acceptance_metadata_and_raw_receipt_format_are_bound(self):
        self.register(); self.release(); data, pin = self.checkpoint()
        with sqlite3.connect(self.journal.path) as connection:
            connection.execute('DROP TRIGGER event_no_update')
            receipt = json.loads(connection.execute('SELECT receipt_json FROM acceptance_event').fetchone()[0])
            connection.execute('UPDATE acceptance_event SET receipt_json=?', (json.dumps(receipt, indent=2),))
        self.assertEqual(build_checkpoint(self.journal)['acceptance_count'], 1)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_wrong_pin_invalid_bytes_and_size_fail_before_open(self):
        data, pin = self.checkpoint()
        for candidate, digest in ((data, '0'*64), (data, 'bad'), (b'', pin), (b'x'*4097, pin), ('text', pin)):
            with patch('dns_lifecycle_checkpoint.LifecycleJournal', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError): self.verify(candidate, digest)

    def test_pinned_noncanonical_or_unknown_checkpoint_claims_are_rejected(self):
        data, _ = self.checkpoint(); document = json.loads(data)
        for candidate in (json.dumps(document, indent=2).encode(),
                          json.dumps(dict(document, extra=True)).encode(),
                          data[:-2] + b',"schema_version":2}\n'):
            with self.assertRaises(ValueError): self.verify(candidate, hashlib.sha256(candidate).hexdigest())

    def test_version_separation_and_logically_identical_copy(self):
        self.register(); self.release(); data, pin = self.checkpoint()
        with self.assertRaises(ValueError): verify_v1(self.journal.path, data, expected_sha256=pin)
        v1 = AssignmentJournal.create(self.root/'v1.sqlite')
        with self.assertRaises(ValueError): build_checkpoint(v1)
        with self.assertRaises(ValueError): verify_checkpoint(v1.path, data, expected_sha256=pin)
        with sqlite3.connect(self.journal.path) as connection: connection.execute('VACUUM')
        copy = self.root/'copy.sqlite'; copy.write_bytes(self.journal.path.read_bytes()); copy.chmod(0o600)
        self.assertEqual(verify_checkpoint(copy, data, expected_sha256=pin)['release_count'], 1)

    def test_both_validators_share_the_same_read_transaction(self):
        self.register(); self.release(); connections = []
        history, releases = self.journal._history, self.journal._releases
        def capture_history(connection):
            self.assertTrue(connection.in_transaction); connections.append(connection)
            return history(connection)
        def capture_releases(connection, rows):
            self.assertTrue(connection.in_transaction); connections.append(connection)
            return releases(connection, rows)
        with patch.object(self.journal, '_history', side_effect=capture_history), patch.object(
                self.journal, '_releases', side_effect=capture_releases):
            self.assertEqual(build_checkpoint(self.journal)['release_count'], 1)
        self.assertEqual(len(connections), 2); self.assertIs(connections[0], connections[1])

    def test_invalid_linkage_and_missing_release_table_are_rejected(self):
        self.register(); self.release()
        with sqlite3.connect(self.journal.path) as connection:
            connection.execute('DROP TRIGGER release_no_update')
            connection.execute('UPDATE release_event SET acceptance_sha256=?', ('0'*64,))
        with self.assertRaises(ValueError): build_checkpoint(self.journal)
        with sqlite3.connect(self.journal.path) as connection: connection.execute('DROP TABLE release_event')
        with self.assertRaises(ValueError): build_checkpoint(self.journal)

    def test_cli_private_output_collision_and_sanitized_failure(self):
        self.register(); self.release(); out, err = StringIO(), StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(['create', str(self.journal.path), '--output', str(self.output)]), 0)
        summary = json.loads(out.getvalue()); self.assertEqual(summary['release_count'], 1)
        data = self.output.read_bytes()
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(['create', str(self.journal.path), '--output', str(self.output)]), 2)
        self.assertEqual(data, self.output.read_bytes())
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(['verify', str(self.journal.path), '--checkpoint', str(self.output),
                                   '--expected-sha256', '0'*64]), 2)
        self.assertNotIn(str(self.root), out.getvalue() + err.getvalue())

    def test_complete_temporary_exercise_reports_stale_pin_limit(self):
        result = exercise()
        self.assertEqual(result['status'], 'dns_lifecycle_checkpoint_exercise_passed')
        self.assertEqual(result['negative_cases_rejected'], 2)
        self.assertTrue(result['stale_pair_still_matches'])


if __name__ == '__main__': unittest.main()
