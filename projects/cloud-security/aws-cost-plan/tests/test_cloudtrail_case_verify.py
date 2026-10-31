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
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from aws_cost_plan.cloudtrail_case import build_case
from aws_cost_plan.cloudtrail_case_verify import verify_case, main


class CaseReproductionTests(unittest.TestCase):
    def setUp(self):
        self.inputs = [(ROOT/f'examples/cloudtrail-collection-{name}.json').read_bytes() for name in ('a', 'b')]
        self.settings = dict(account_id='111122223333', case_id='retained-case', scope_note='synthetic',
                             threshold=3, window_seconds=300)
        self.case = build_case(self.inputs, **self.settings)
        self.raw = json.dumps(self.case, sort_keys=True).encode()

    def verify(self, data=None, inputs=None, **settings):
        return verify_case(self.raw if data is None else data, self.inputs if inputs is None else inputs,
                           **dict(self.settings, **settings))

    def test_complete_case_reproduces_with_minimized_unsigned_summary(self):
        with patch('socket.socket.connect', side_effect=AssertionError('network forbidden')):
            summary = self.verify()
        self.assertEqual(summary['status'], 'case_reproduced')
        self.assertEqual(summary['case_sha256'], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(summary['normalized_sha256'], self.case['handoff']['source_sha256'])
        self.assertEqual((summary['unique_event_count'], summary['finding_count'], summary['login_candidate_count']), (4, 5, 1))
        for value in ('111122223333', 'retained-case', 'synthetic', 'fixture-analyst', '192.0.2.'):
            self.assertNotIn(value, json.dumps(summary))
        self.assertEqual((summary['containment'], summary['recovery']), ('not_performed', 'not_verified'))

    def test_changed_findings_sources_references_payload_and_state_are_rejected(self):
        mutations = [lambda c: c['handoff'].update(finding_count=0),
            lambda c: c['handoff']['timeline'][0]['findings'][0].update(severity='low'),
            lambda c: c['event_sources'][1]['sources'].pop(),
            lambda c: c['sources'][0].update(input_sha256='0'*64),
            lambda c: c.update(normalized_jsonl=''),
            lambda c: c['correlation']['candidates'][0].update(source_lines=[3, 2, 1]),
            lambda c: c['handoff'].update(containment='performed'),
            lambda c: c.update(extra='synthetic'), lambda c: c.pop('duplicate_copy_count')]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(self.case); mutate(changed)
            with self.subTest(mutation=index), self.assertRaises(ValueError): self.verify(json.dumps(changed).encode())

    def test_case_cannot_select_recipient_threshold_or_context(self):
        changed_settings = dict(self.settings, threshold=4)
        alternate = build_case(self.inputs, **changed_settings)
        self.assertEqual(alternate['correlation']['candidates'], [])
        with self.assertRaises(ValueError): self.verify(json.dumps(alternate).encode())
        for settings in ({'threshold': 4}, {'window_seconds': 60}, {'case_id': 'other-case'},
                         {'scope_note': 'other-scope'}, {'account_id': '999988887777'}):
            with self.subTest(settings=list(settings)), self.assertRaises(ValueError): self.verify(**settings)

    def test_changed_original_bytes_reject_even_when_normalized_events_match(self):
        reformatted = json.dumps(json.loads(self.inputs[0]), separators=(',', ':')).encode()
        self.assertEqual(build_case([reformatted, self.inputs[1]], **self.settings)['normalized_jsonl'], self.case['normalized_jsonl'])
        with self.assertRaises(ValueError): self.verify(inputs=[reformatted, self.inputs[1]])
        for sources in (self.inputs[:1], list(reversed(self.inputs)), self.inputs + [self.inputs[0]]):
            with self.assertRaises(ValueError): self.verify(inputs=sources)

    def test_gzip_requires_exact_original_compressed_bytes(self):
        sources = [self.inputs[0], gzip.compress(self.inputs[1], mtime=0)]
        raw = json.dumps(build_case(sources, **self.settings)).encode()
        self.assertEqual(self.verify(raw, inputs=sources)['status'], 'case_reproduced')
        with self.assertRaises(ValueError):
            self.verify(raw, inputs=[sources[0], gzip.compress(self.inputs[1], mtime=1)])

    def test_json_formatting_is_ignored_but_duplicate_fields_and_numeric_types_are_not(self):
        pretty = json.dumps(self.case, indent=4).encode()
        self.assertEqual(self.verify(pretty)['case_sha256'], hashlib.sha256(pretty).hexdigest())
        for value in (True, 1.0):
            changed = dict(self.case, schema_version=value)
            with self.assertRaises(ValueError): self.verify(json.dumps(changed).encode())
        for raw in (b'{}', b'[]', b'null', b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'\xff'):
            with self.assertRaises((ValueError, UnicodeError)): self.verify(raw)
        with patch('aws_cost_plan.cloudtrail_case_verify.MAX_CASE_BYTES', 1):
            with self.assertRaises(ValueError): self.verify()

    def test_empty_case_still_binds_the_recipient_context(self):
        inputs = [b'{"Records":[]}']; raw = json.dumps(build_case(inputs, **self.settings)).encode()
        self.assertEqual(self.verify(raw, inputs=inputs)['unique_event_count'], 0)
        with self.assertRaises(ValueError): self.verify(raw, inputs=inputs, account_id='999988887777')

    @unittest.skipUnless(os.name == 'posix', 'private publication requires POSIX')
    def test_cli_preserves_inputs_and_publishes_only_complete_private_summary(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); case = root/'case.json'; paths = [root/'a.json', root/'b.json']; output = root/'summary.json'
            case.write_bytes(self.raw)
            for path, raw in zip(paths, self.inputs): path.write_bytes(raw)
            args = [str(case), *map(str, paths), '--account-id', '111122223333', '--case-id', 'retained-case',
                '--scope-note', 'synthetic', '--threshold', '3', '--window-seconds', '300', '--output', str(output)]
            with redirect_stdout(io.StringIO()): self.assertEqual(main(args), 0)
            saved = output.read_bytes(); self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(saved)['status'], 'case_reproduced')
            with redirect_stderr(io.StringIO()): self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), saved)
            self.assertEqual(case.read_bytes(), self.raw)
            self.assertEqual([p.read_bytes() for p in paths], self.inputs)
            output.unlink(); changed = copy.deepcopy(self.case); changed['sources'][0]['input_bytes'] += 1
            case.write_text(json.dumps(changed)); stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr): self.assertEqual(main(args), 2)
            self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(str(root), stderr.getvalue())
            case.write_bytes(self.raw)
            with patch('aws_cost_plan.cloudtrail_handoff.os.link', side_effect=OSError('private detail')):
                with redirect_stderr(io.StringIO()): self.assertEqual(main(args), 2)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['a.json', 'b.json', 'case.json'])

    @unittest.skipUnless(os.name == 'posix', 'no-follow local reads require POSIX')
    def test_cli_rejects_case_symlinks_and_nonregular_files(self):
        from aws_cost_plan.cloudtrail_case_verify import _read_case
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); target = root/'case.json'; target.write_bytes(self.raw)
            link = root/'link'; link.symlink_to(target)
            for path in (link, root):
                with self.assertRaises((OSError, ValueError)): _read_case(path)
            fifo = root/'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): _read_case(fifo)

    def test_fresh_process_documented_recipient_command(self):
        with tempfile.TemporaryDirectory() as name:
            case = Path(name)/'case.json'; case.write_bytes(self.raw)
            result = subprocess.run([sys.executable, '-m', 'aws_cost_plan.cloudtrail_case_verify', str(case),
                str(ROOT/'examples/cloudtrail-collection-a.json'), str(ROOT/'examples/cloudtrail-collection-b.json'),
                '--account-id', '111122223333', '--case-id', 'retained-case', '--scope-note', 'synthetic',
                '--threshold', '3', '--window-seconds', '300'], env=dict(os.environ, PYTHONPATH=str(ROOT/'src')),
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'case_reproduced')
            self.assertNotIn(str(case), result.stdout)


if __name__ == '__main__': unittest.main()
