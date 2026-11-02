"""Bind every logical event while preserving private, read-only checkpoint verification."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
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
from dns_authorized_handoff import _instant
from dns_journal_checkpoint import build_checkpoint, create_checkpoint, main, verify_checkpoint, _read_checkpoint
from dns_responsibility import create_acceptance


class JournalCheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.journal = AssignmentJournal.create(self.root/'journal.sqlite')
        self.report, self.inputs, self.options, self.key = fixture()
        self.first = self.sign('2026-10-28T12:00:00Z', '2026-10-28T12:05:00Z')
        self.later = self.sign('2026-10-28T12:06:00Z', '2026-10-28T12:20:00Z')
        self.output = self.root/'checkpoint.json'

    def sign(self, start, end):
        claim = json.loads(self.options['acceptance'])
        return create_acceptance(self.report, authority_data=self.options['acceptance_policy'], signing_key=self.key,
            key_id=claim['key_id'], finding_sha256=claim['finding_sha256'], team=claim['team'],
            accepted_at=start, expires_at=end)

    def register(self, later=False):
        return self.journal.register(self.report, *self.inputs, **dict(self.options,
            acceptance=self.later if later else self.first,
            now=_instant('2026-10-28T12:06:00Z' if later else '2026-10-28T12:00:00Z')),
            expected_predecessor=hashlib.sha256(self.first).hexdigest() if later else None)

    def checkpoint(self):
        result = create_checkpoint(self.journal, self.output)
        return self.output.read_bytes(), result['checkpoint_sha256']

    def verify(self, data, pin):
        return verify_checkpoint(self.journal.path, data, expected_sha256=pin)

    def test_empty_and_registered_journals_match_without_modification(self):
        for count in (0, 1):
            if count:
                self.register(); self.output.unlink()
            before = self.journal.path.read_bytes()
            data, pin = self.checkpoint()
            result = self.verify(data, pin)
            self.assertEqual(result['event_count'], count)
            self.assertFalse(result['historical_signatures_reverified'])
            self.assertFalse(result['current_authority_reverified'])
            self.assertEqual(self.journal.path.read_bytes(), before)
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_valid_older_backup_rejected_by_current_checkpoint(self):
        self.register(); old = self.journal.path.read_bytes()
        self.register(later=True); data, pin = self.checkpoint()
        self.journal.path.write_bytes(old)
        self.assertEqual(build_checkpoint(self.journal)['event_count'], 1)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_valid_append_requires_new_checkpoint_and_old_pair_can_match(self):
        self.register(); old = self.journal.path.read_bytes(); data, pin = self.checkpoint()
        self.register(later=True)
        with self.assertRaises(ValueError): self.verify(data, pin)
        self.journal.path.write_bytes(old)
        self.assertEqual(self.verify(data, pin)['event_count'], 1)

    def test_internally_valid_same_count_receipt_change_is_detected(self):
        self.register(); data, pin = self.checkpoint()
        with sqlite3.connect(self.journal.path) as connection:
            connection.execute('DROP TRIGGER event_no_update')
            raw = connection.execute('SELECT receipt_json FROM acceptance_event').fetchone()[0]
            receipt = json.loads(raw); receipt['interpretation'] = 'changed local metadata'
            connection.execute('UPDATE acceptance_event SET receipt_json=?', (json.dumps(receipt),))
        self.assertEqual(build_checkpoint(self.journal)['event_count'], 1)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_every_event_not_only_latest_receipt_is_bound(self):
        self.register(); self.register(later=True); data, pin = self.checkpoint()
        with sqlite3.connect(self.journal.path) as connection:
            connection.execute('DROP TRIGGER event_no_update')
            raw = connection.execute('SELECT receipt_json FROM acceptance_event WHERE sequence=1').fetchone()[0]
            receipt = json.loads(raw); receipt['interpretation'] = 'changed earlier event'
            connection.execute('UPDATE acceptance_event SET receipt_json=? WHERE sequence=1', (json.dumps(receipt),))
        self.assertEqual(build_checkpoint(self.journal)['event_count'], 2)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_bad_pin_empty_oversized_or_nonbytes_fail_before_journal_open(self):
        data, pin = self.checkpoint()
        for candidate, digest in ((data, '0'*64), (data, 'invalid'), (b'', pin), (b'x'*4097, pin), ('text', pin)):
            with patch('dns_journal_checkpoint.AssignmentJournal', side_effect=AssertionError('must not open')):
                with self.assertRaises(ValueError): self.verify(candidate, digest)

    def test_pinned_unknown_fields_noncanonical_and_duplicate_fields_rejected(self):
        data, _ = self.checkpoint()
        document = json.loads(data)
        candidates = [json.dumps(dict(document, extra=True)).encode(),
                      json.dumps(document, indent=2).encode(), data[:-2]+b',"schema_version":1}\n']
        for candidate in candidates:
            with self.assertRaises(ValueError): self.verify(candidate, hashlib.sha256(candidate).hexdigest())

    def test_single_transaction_history_read_and_matching_copy_ignores_layout(self):
        self.register(); data, pin = self.checkpoint()
        with patch.object(self.journal, '_history', wraps=self.journal._history) as history:
            self.assertEqual(build_checkpoint(self.journal)['event_count'], 1)
        self.assertEqual(history.call_count, 1)
        with sqlite3.connect(self.journal.path) as connection: connection.execute('VACUUM')
        self.assertEqual(self.verify(data, pin)['status'], 'dns_journal_checkpoint_matched')
        copy = self.root/'copy.sqlite'; copy.write_bytes(self.journal.path.read_bytes()); copy.chmod(0o600)
        self.assertEqual(verify_checkpoint(copy, data, expected_sha256=pin)['event_count'], 1)

    def test_failed_or_existing_output_preserves_files(self):
        data, pin = self.checkpoint(); before = self.journal.path.read_bytes()
        with self.assertRaises(FileExistsError): create_checkpoint(self.journal, self.output)
        self.assertEqual(self.output.read_bytes(), data)
        with patch('dns_journal_checkpoint.MAX_CHECKPOINT_BYTES', 1):
            with self.assertRaises(ValueError): create_checkpoint(self.journal, self.root/'none.json')
        self.assertFalse((self.root/'none.json').exists())
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_private_paths_limits_and_reader_reject_symlinks_and_special_files(self):
        data, pin = self.checkpoint()
        alias = self.root/'alias.json'; alias.symlink_to(self.output)
        with self.assertRaises(OSError): _read_checkpoint(alias)
        alias.unlink(); alias.mkdir()
        with self.assertRaises((OSError, ValueError)): _read_checkpoint(alias)
        self.output.write_bytes(b'x'*4097)
        with self.assertRaises(ValueError): _read_checkpoint(self.output)
        self.journal.path.chmod(0o644)
        with self.assertRaises(ValueError): self.verify(data, pin)

    def test_cli_counts_and_fixed_errors_do_not_expose_identifiers(self):
        self.register(); out, err = StringIO(), StringIO()
        args = ['create', str(self.journal.path), '--output', str(self.output)]
        with redirect_stdout(out), redirect_stderr(err): self.assertEqual(main(args), 0)
        summary = json.loads(out.getvalue())
        self.assertEqual(summary['event_count'], 1)
        for value in (str(self.root), 'finding_sha256', 'team', 'key_id', 'audience', 'history_sha256'):
            self.assertNotIn(value, out.getvalue())
        verify = ['verify', str(self.journal.path), '--checkpoint', str(self.output),
                  '--expected-sha256', summary['checkpoint_sha256']]
        with redirect_stdout(StringIO()): self.assertEqual(main(verify), 0)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err): self.assertEqual(main(verify[:-1]+['0'*64]), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn(str(self.root), err.getvalue())

    def test_fresh_native_signature_walkthrough(self):
        script = Path(__file__).resolve().parents[1]/'demo_journal_checkpoint.py'
        result = subprocess.run([sys.executable, str(script)], check=True, capture_output=True, text=True)
        value = json.loads(result.stdout)
        self.assertEqual(value['checkpoint_events'], 2)
        self.assertEqual(value['negative_cases_rejected'], 3)
        self.assertTrue(value['stale_checkpoint_can_still_match'])
        self.assertTrue(value['verification_preserved_input'])
        self.assertEqual(result.stderr, '')


if __name__ == '__main__': unittest.main()
