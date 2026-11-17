"""Pinned original claims reach host correlation without a collector or sample execution."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import osquery_review as review
from demo_osquery_review import CONTEXT_PIN


class SavedOsqueryReviewTests(unittest.TestCase):
    def setUp(self):
        self.export = (ROOT/'examples/osquery-system-info.json').read_bytes()
        self.context = (ROOT/'examples/osquery-context.json').read_bytes()
        self.peer = (ROOT/'examples/osquery-peer.json').read_bytes()

    def run_review(self, export=None, context=None, peers=None, pin=None):
        return review.review_export(self.export if export is None else export,
            self.context if context is None else context, [self.peer] if peers is None else peers,
            expected_context_sha256=CONTEXT_PIN if pin is None else pin)

    def changed_context(self, **fields):
        data = json.loads(self.context); data.update(fields)
        raw = json.dumps(data).encode()
        return raw, hashlib.sha256(raw).hexdigest()

    def supplied_rows(self, rows):
        export = json.dumps(rows).encode()
        context, pin = self.changed_context(expected_export_sha256=hashlib.sha256(export).hexdigest())
        return self.run_review(export=export, context=context, pin=pin)

    def test_fixture_lineage_and_shared_hostnames_remain_explicit(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.run_review()
        self.assertEqual((result['record_count'], result['group_count'], result['matched_group_count']), (4, 3, 1))
        lineage = result['native_import']
        self.assertEqual(lineage['context_sha256'], CONTEXT_PIN)
        self.assertEqual(lineage['original_export_sha256'], hashlib.sha256(self.export).hexdigest())
        self.assertEqual(result['inputs'][0]['original_sha256'], lineage['derived_source_sha256'])
        self.assertNotEqual(lineage['original_export_sha256'], lineage['derived_source_sha256'])
        self.assertEqual(lineage['selected_fields'], ['uuid', 'hostname'])
        self.assertNotIn('omitted-fixture-serial', json.dumps(result))
        self.assertNotIn('cpu_logical_cores', json.dumps(result))
        native = [observation for group in result['groups'] for observation in group['observations']
                  if observation['source_record_id'].startswith('system-info-row-')]
        self.assertEqual([x['source_record_id'] for x in native], ['system-info-row-1', 'system-info-row-2'])
        self.assertTrue(all(x['ip_addresses'] == [] for x in native))
        self.assertEqual(native[0]['hostname'], 'web.example.test')
        self.assertEqual(result, self.run_review())

    def test_pins_precede_context_and_export_parsing(self):
        with patch.object(review, '_decode', side_effect=AssertionError('must not parse')):
            with self.assertRaises(ValueError): self.run_review(context=b'not json')
            with self.assertRaises(ValueError): self.run_review(pin='0'*64)
        original = review._decode
        calls = []
        def decode(data):
            calls.append(data)
            return original(data)
        with patch.object(review, '_decode', side_effect=decode):
            with self.assertRaises(ValueError): self.run_review(export=b'not json')
        self.assertEqual(calls, [self.context])
        with self.assertRaises(ValueError): self.run_review(export=self.export+b'\n')

    def test_context_types_scope_and_capture_requirements(self):
        for fields in ({'schema_version': True}, {'schema_version': 2}, {'export_kind': 'live-query'},
                       {'namespace': '../other'}, {'source_id': 'bad source'}, {'scope': 'public'},
                       {'captured_at': '2026-11-17T12:00:00'}, {'captured_at': False},
                       {'expected_export_sha256': 'A'*64}, {'unexpected': 'field'}):
            with self.subTest(fields=fields):
                context, pin = self.changed_context(**fields)
                with self.assertRaises((ValueError, TypeError)): self.run_review(context=context, pin=pin)
        context, pin = self.changed_context(captured_at='2026-11-17T07:00:00-05:00')
        self.assertEqual(self.run_review(context=context, pin=pin)['inputs'][0]['captured_at'], '2026-11-17T12:00:00Z')

    def test_uuid_normalization_and_invalid_or_ambiguous_rows(self):
        rows = json.loads(self.export)
        rows[0]['uuid'] = rows[0]['uuid'].upper()
        self.assertEqual(self.supplied_rows(rows)['matched_group_count'], 1)
        invalid = [[], {}, [None], [{'hostname': 'host.example.test'}]]
        for value in ('0'*8+'-0000-0000-0000-'+'0'*12, 'ffffffff-ffff-ffff-ffff-ffffffffffff',
                      'not-a-uuid', True, {}, '123456781234423482341234567890ab'):
            invalid.append([dict(rows[0], uuid=value)])
        invalid.extend(([rows[0], dict(rows[0], uuid=rows[0]['uuid'].lower())],
                        [dict(rows[0], hostname='https://host.example.test')]))
        for case in invalid:
            with self.subTest(case=case), self.assertRaises((ValueError, TypeError)):
                self.supplied_rows(case)

    def test_strict_json_and_bounds_reject_before_review(self):
        for export in (b'[{"uuid":"x","uuid":"y","hostname":"host"}]', b'[NaN]', b'{', b'\xff'):
            context, pin = self.changed_context(expected_export_sha256=hashlib.sha256(export).hexdigest())
            with self.subTest(export=export), self.assertRaises((ValueError, UnicodeError)):
                self.run_review(export=export, context=context, pin=pin)
        for setting in ('MAX_CONTEXT_BYTES', 'MAX_INPUT_BYTES', 'MAX_RECORDS_PER_SOURCE'):
            with patch.object(review, setting, 1), self.assertRaises(ValueError): self.run_review()
        for peers in ([], [self.peer]*8):
            with self.assertRaises(ValueError): self.run_review(peers=peers)
        for fields in ({'source_id': 'reviewed-cloud-fixture'}, {'scope': 'owned'}, {'namespace': 'other-assets'}):
            context, pin = self.changed_context(**fields)
            with self.assertRaises(ValueError): self.run_review(context=context, pin=pin)

    def test_same_uuid_conflicts_keep_all_observations(self):
        peer = json.loads(self.peer)
        first = peer['assets'][0]
        peer['assets'].append(dict(first, source_record_id='conflicting-cloud', identifiers={
            **first['identifiers'], 'cloud_resource_id':
            'arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef1'}))
        result = self.run_review(peers=[json.dumps(peer).encode()])
        self.assertEqual(result['unresolved_component_count'], 1)
        self.assertEqual(result['matched_group_count'], 0)
        self.assertEqual(len(result['findings'][0]['source_records']), 3)
        self.assertEqual(sum(len(g['observations']) for g in result['groups']), 5)

    @unittest.skipUnless(os.name == 'posix', 'private no-follow publication requires POSIX')
    def test_real_cli_read_only_private_exclusive_and_fixed_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); export, context, peer, output = [root/name for name in
                ('export.json', 'context.json', 'peer.json', 'review.json')]
            for path, raw in ((export, self.export), (context, self.context), (peer, self.peer)):
                path.write_bytes(raw)
            args = [str(export), '--context', str(context), '--expected-context-sha256', CONTEXT_PIN,
                    '--peer-source', str(peer), '--output', str(output)]
            stdout = StringIO()
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), redirect_stdout(stdout):
                self.assertEqual(review.main(args), 0)
            self.assertEqual(json.loads(stdout.getvalue())['matched_group_count'], 1)
            for value in ('example.test', '12345678', '111122223333', str(root), CONTEXT_PIN):
                self.assertNotIn(value, stdout.getvalue())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_bytes()), self.run_review())
            saved = output.read_bytes()
            with redirect_stderr(StringIO()): self.assertEqual(review.main(args), 2)
            self.assertEqual(saved, output.read_bytes())
            self.assertEqual([p.read_bytes() for p in (export, context, peer)], [self.export, self.context, self.peer])
            output.unlink()
            for changed in (context, export, peer):
                original = changed.read_bytes(); changed.write_bytes(original+b'\n' if changed != peer else b'{')
                with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                    self.assertEqual(review.main(args), 2)
                self.assertEqual(out.getvalue(), '')
                self.assertNotIn(str(root), err.getvalue())
                self.assertFalse(output.exists()); changed.write_bytes(original)
            with patch.object(review, 'MAX_REPORT_BYTES', 1), redirect_stderr(StringIO()):
                self.assertEqual(review.main(args), 2)
            self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == 'posix', 'no-follow regular-file boundary requires POSIX')
    def test_context_pin_precedes_other_paths_and_special_inputs_do_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); ctx = root/'context.json'; ctx.write_bytes(self.context)
            output = root/'out.json'; fifo = root/'fifo'; os.mkfifo(fifo)
            link = root/'link'; link.symlink_to(ctx)
            args = [str(fifo), '--context', str(ctx), '--expected-context-sha256', '0'*64,
                    '--peer-source', str(fifo), '--output', str(output)]
            calls = []
            def read(path):
                calls.append(path)
                self.assertEqual(path, ctx)
                return self.context
            with patch.object(review, '_read', side_effect=read), redirect_stderr(StringIO()):
                self.assertEqual(review.main(args), 2)
            self.assertEqual(calls, [ctx]); self.assertFalse(output.exists())
            for path in (fifo, link, root):
                args[2] = str(path)
                with redirect_stderr(StringIO()): self.assertEqual(review.main(args), 2)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
