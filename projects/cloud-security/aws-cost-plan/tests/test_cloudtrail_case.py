"""Native local collection, duplicate handling and private complete-case publication."""

import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from aws_cost_plan.cloudtrail_case import build_case, main
from aws_cost_plan.cloudtrail_correlation import correlate_failed_logins
from aws_cost_plan.cloudtrail_handoff import build_handoff


class CloudTrailCaseTests(unittest.TestCase):
    def setUp(self):
        self.raw = [(ROOT/f'examples/cloudtrail-collection-{name}.json').read_bytes() for name in ('a', 'b')]
        self.events = [json.loads(raw)['Records'] for raw in self.raw]

    def build(self, inputs=None, **options):
        return build_case(self.raw if inputs is None else inputs, account_id='111122223333', case_id='collection-test',
                          scope_note='synthetic only', **options)

    def test_existing_correlator_rejects_overlap_but_collection_counts_three_unique_failures(self):
        with self.assertRaisesRegex(ValueError, 'duplicate eventID'):
            correlate_failed_logins(self.events[0] + self.events[1])
        result = self.build()
        self.assertEqual((result['supplied_event_count'], result['unique_event_count'], result['duplicate_copy_count']), (5, 4, 1))
        self.assertEqual(result['handoff']['finding_count'], 5)
        candidate, = result['correlation']['candidates']
        self.assertEqual(candidate['failure_count'], 3)
        self.assertEqual(candidate['source_lines'], [1, 2, 3])
        self.assertEqual(result['event_sources'][1], {'source_line': 2, 'sources': [
            {'input_index': 1, 'record_number': 2}, {'input_index': 2, 'record_number': 1}]})

    def test_gzip_and_reordered_object_keys_deduplicate_with_exact_source_receipts(self):
        second = json.dumps(json.loads(self.raw[1]), sort_keys=True).encode()
        compressed = gzip.compress(second, mtime=0)
        result = self.build([self.raw[0], compressed])
        self.assertEqual(result['duplicate_copy_count'], 1)
        self.assertEqual(result['sources'][1]['compression'], 'gzip')
        self.assertEqual(result['sources'][1]['input_sha256'], hashlib.sha256(compressed).hexdigest())
        self.assertEqual(result['sources'][1]['input_bytes'], len(compressed))
        self.assertEqual(result['normalized_jsonl'], self.build()['normalized_jsonl'])

    def test_conflicting_duplicate_never_chooses_a_preferred_copy(self):
        events = copy.deepcopy(self.events[1])
        for change in ({'eventTime': '2026-10-30T12:09:00Z'}, {'unreviewed_extension': 'synthetic-change'}):
            changed = copy.deepcopy(events); changed[0].update(change)
            with self.subTest(field=list(change)), self.assertRaisesRegex(ValueError, 'conflicting copies'):
                self.build([self.raw[0], json.dumps({'Records': changed}).encode()])

    def test_unknown_fields_and_source_record_locations_survive_without_path_names(self):
        events = copy.deepcopy(self.events[1]); events[-1]['extension'] = {'opaque': ['synthetic', 3]}
        result = self.build([self.raw[0], json.dumps({'Records': events}).encode()])
        records = [json.loads(line) for line in result['normalized_jsonl'].splitlines()]
        self.assertEqual(records[-1]['extension'], events[-1]['extension'])
        self.assertEqual(result['event_sources'][-1]['sources'], [{'input_index': 2, 'record_number': 3}])
        self.assertFalse(any('path' in source for source in result['sources']))

    def test_handoff_and_correlation_recompute_from_retained_normalized_lines(self):
        result = self.build()
        raw = result['normalized_jsonl'].encode()
        self.assertEqual(result['handoff'], build_handoff(raw, case_id='collection-test', scope_note='synthetic only'))
        self.assertEqual(result['handoff']['source_sha256'], hashlib.sha256(raw).hexdigest())
        for candidate in result['correlation']['candidates']:
            for event_id, number in zip(candidate['event_ids'], candidate['source_lines']):
                self.assertEqual(json.loads(result['normalized_jsonl'].splitlines()[number-1])['eventID'], event_id)
        self.assertEqual((result['handoff']['status'], result['handoff']['containment'], result['handoff']['recovery']),
                         ('unreviewed', 'not_performed', 'not_verified'))

    def test_timeline_chronology_preserves_first_seen_normalized_line_references(self):
        result = self.build(list(reversed(self.raw)))
        self.assertEqual([row['source_line'] for row in result['handoff']['timeline']], [4, 1, 2, 3])
        self.assertEqual(result['event_sources'][-1]['sources'], [{'input_index': 2, 'record_number': 1}])
        self.assertEqual(result, self.build(list(reversed(self.raw))))

    def test_missing_or_other_recipient_account_cannot_be_correlated_with_scope(self):
        for account in (None, '999988887777'):
            events = copy.deepcopy(self.events[1])
            if account is None: events[0].pop('recipientAccountID')
            else: events[0]['recipientAccountID'] = account
            with self.subTest(account=account), self.assertRaisesRegex(ValueError, 'account scope'):
                self.build([self.raw[0], json.dumps({'Records': events}).encode()])
        for account in ('', '11112222333', 111122223333):
            with self.assertRaises(ValueError):
                build_case(self.raw, account_id=account, case_id='test', scope_note='synthetic')

    def test_empty_sources_and_all_duplicate_sources_remain_unreviewed(self):
        empty = self.build([b'{"Records":[]}'])
        self.assertEqual(empty['unique_event_count'], 0)
        self.assertEqual(empty['correlation']['candidates'], [])
        repeated = self.build([self.raw[0]] * 3)
        self.assertEqual((repeated['unique_event_count'], repeated['duplicate_copy_count']), (2, 4))
        self.assertEqual(repeated['correlation']['candidates'], [])
        self.assertEqual(len(repeated['event_sources'][0]['sources']), 3)

    def test_source_bounds_include_duplicates_and_expanded_records(self):
        for constant, limit, inputs in [('MAX_FILES', 1, self.raw), ('MAX_BYTES', len(self.raw[0]), self.raw),
                                        ('MAX_EVENTS', 4, self.raw)]:
            with self.subTest(bound=constant), patch('aws_cost_plan.cloudtrail_case.'+constant, limit):
                with self.assertRaises(ValueError): self.build(inputs)
        with patch('aws_cost_plan.cloudtrail_case.MAX_BYTES', 500):
            with self.assertRaisesRegex(ValueError, 'expanded records'):
                self.build([gzip.compress(self.raw[0], mtime=0), gzip.compress(self.raw[1], mtime=0)])

    def test_invalid_envelopes_duplicate_fields_ids_and_settings_fail(self):
        for inputs in ([], [b'{'], [b'{"Records":[],"Records":[]}'], [b'\x1f\x8btruncated'], ['not bytes'],
                       [json.dumps({'Records': self.events[0]*2}).encode()]):
            with self.subTest(types=[type(x).__name__ for x in inputs]):
                with self.assertRaises((ValueError, OSError, EOFError)): self.build(inputs)
        changed = copy.deepcopy(self.events[0]); changed[0]['eventID'] = ' padded-id '
        with self.assertRaises(ValueError): self.build([json.dumps({'Records': changed}).encode()])
        for settings in ({'threshold': True}, {'threshold': 1}, {'window_seconds': 0}):
            with self.assertRaises(ValueError): self.build(**settings)

    @unittest.skipUnless(os.name == 'posix', 'exclusive private publication requires POSIX')
    def test_cli_complete_private_case_minimized_stdout_and_unchanged_sources(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); paths = [root/'private-a.json', root/'private-b.gz']; output = root/'case.json'
            supplied = [self.raw[0], gzip.compress(self.raw[1], mtime=0)]
            for path, raw in zip(paths, supplied): path.write_bytes(raw)
            stdout = io.StringIO()
            with patch('socket.socket.connect', side_effect=AssertionError('network forbidden')), redirect_stdout(stdout):
                self.assertEqual(main([*map(str, paths), '--account-id', '111122223333', '--case-id', 'native-case', '--scope-note', 'synthetic', '--output', str(output)]), 0)
            summary = json.loads(stdout.getvalue()); saved = output.read_bytes()
            self.assertEqual(summary['case_sha256'], hashlib.sha256(saved).hexdigest())
            self.assertEqual(summary['login_candidate_count'], 1)
            self.assertNotIn(str(root), stdout.getvalue()); self.assertNotIn('fixture-analyst', stdout.getvalue())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual([path.read_bytes() for path in paths], supplied)
            document = json.loads(saved); self.assertEqual(document['unique_event_count'], 4)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['case.json', 'private-a.json', 'private-b.gz'])

    @unittest.skipUnless(os.name == 'posix', 'exclusive private publication requires POSIX')
    def test_late_invalid_source_collision_and_publish_failure_leave_no_partial_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); first = root/'first.json'; second = root/'second.json'; output = root/'case.json'
            first.write_bytes(self.raw[0]); second.write_bytes(b'{"private":"synthetic invalid"}')
            args = [str(first), str(second), '--account-id', '111122223333', '--case-id', 'case', '--scope-note', 'synthetic', '--output', str(output)]
            def rejected():
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err): self.assertEqual(main(args), 2)
                self.assertEqual(out.getvalue(), ''); self.assertNotIn(str(root), err.getvalue())
            rejected(); self.assertFalse(output.exists())
            second.write_bytes(self.raw[1]); output.write_bytes(b'existing')
            rejected(); self.assertEqual(output.read_bytes(), b'existing'); output.unlink()
            with patch('aws_cost_plan.cloudtrail_handoff.os.link', side_effect=OSError('private detail')): rejected()
            self.assertFalse(output.exists())
            with patch('aws_cost_plan.cloudtrail_case.MAX_CASE_BYTES', 1): rejected()
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['first.json', 'second.json'])

    def test_fresh_process_quickstart(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)/'case.json'
            env = dict(os.environ, PYTHONPATH=str(ROOT/'src'))
            result = subprocess.run([sys.executable, '-m', 'aws_cost_plan.cloudtrail_case',
                str(ROOT/'examples/cloudtrail-collection-a.json'), str(ROOT/'examples/cloudtrail-collection-b.json'),
                '--account-id', '111122223333', '--case-id', 'quickstart', '--scope-note', 'synthetic', '--output', str(output)],
                env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['unique_event_count'], 4)
            self.assertEqual(json.loads(output.read_text())['duplicate_copy_count'], 1)


if __name__ == '__main__': unittest.main()
