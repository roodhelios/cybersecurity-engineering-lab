import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tcp_reset_review as review
import verify_report as verifier

FIXTURE = Path(__file__).resolve().parents[1] / 'examples' / 'connections.jsonl'
OPTIONS = {'scope': 'synthetic', 'min_resets': 3, 'window_seconds': 60}


class ReportReproductionTests(unittest.TestCase):
    def setUp(self):
        self.source = FIXTURE.read_bytes()
        self.report = review.review_bytes(self.source, **OPTIONS)
        self.raw = json.dumps(self.report).encode()

    def test_complete_reproduction_uses_source_and_returns_no_operational_ids(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = verifier.verify_report(self.source, self.raw, **OPTIONS)
        self.assertEqual(result['status'], 'tcp_reset_report_reproduced')
        self.assertEqual((result['record_count'], result['finding_count']), (6, 1))
        self.assertEqual(result['report_sha256'], hashlib.sha256(self.raw).hexdigest())
        for value in ('198.51.100.20', 'Cfixture1', 'evidence', 'line_sha256'):
            self.assertNotIn(value, json.dumps(result))

    def test_every_retained_field_is_checked_not_just_input_digest(self):
        for field in ('count', 'missing-finding', 'line', 'uid', 'line-digest', 'direction', 'state-count',
                      'limitation', 'unknown', 'schema-bool', 'schema-float'):
            report = copy.deepcopy(self.report)
            if field == 'count': report['findings'][0]['connection_count'] = 99
            if field == 'missing-finding': report['findings'] = []
            if field == 'line': report['findings'][0]['evidence'][0]['line'] = 2
            if field == 'uid': report['findings'][0]['evidence'][0]['uid'] = 'Invented'
            if field == 'line-digest': report['findings'][0]['evidence'][0]['line_sha256'] = '0' * 64
            if field == 'direction': report['findings'][0]['reported_reset_side'] = 'originator'
            if field == 'state-count': report['tcp_state_counts']['REJ'] = 0
            if field == 'limitation': report['limitations'] = []
            if field == 'unknown': report['trusted'] = True
            if field == 'schema-bool': report['schema_version'] = True
            if field == 'schema-float': report['schema_version'] = 1.0
            with self.subTest(field=field), self.assertRaises(ValueError):
                verifier.verify_report(self.source, json.dumps(report).encode(), **OPTIONS)

    def test_scope_and_parameters_are_independent_reviewer_requirements(self):
        for changes in ({'scope': 'owned'}, {'min_resets': 4}, {'window_seconds': 59},
                        {'min_resets': True}, {'window_seconds': 0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verifier.verify_report(self.source, self.raw, **dict(OPTIONS, **changes))
        # A self-consistent report for a different threshold still fails this recipient's requirement.
        altered = json.dumps(review.review_bytes(self.source, **dict(OPTIONS, min_resets=2))).encode()
        with self.assertRaises(ValueError): verifier.verify_report(self.source, altered, **OPTIONS)

    def test_changed_source_and_forged_source_digest_fail(self):
        changed = self.source.replace(b'1793235660', b'1793235661')
        with self.assertRaises(ValueError): verifier.verify_report(changed, self.raw, **OPTIONS)
        report = copy.deepcopy(self.report); report['input_sha256'] = hashlib.sha256(changed).hexdigest()
        with self.assertRaises(ValueError): verifier.verify_report(changed, json.dumps(report).encode(), **OPTIONS)
        with self.assertRaises(ValueError): verifier.verify_report(self.source + b' ', self.raw, **OPTIONS)

    def test_report_whitespace_is_semantic_but_original_source_bytes_are_exact(self):
        pretty = json.dumps(self.report, indent=4).encode() + b'\n'
        result = verifier.verify_report(self.source, pretty, **OPTIONS)
        self.assertNotEqual(result['report_sha256'], hashlib.sha256(self.raw).hexdigest())
        crlf = self.source.replace(b'\n', b'\r\n')
        with self.assertRaises(ValueError): verifier.verify_report(crlf, self.raw, **OPTIONS)

    def test_malformed_duplicate_nonfinite_and_bounded_reports(self):
        for data in (b'', b'[]', b'{}', b'\xff', b'{"schema_version":1,' + self.raw[1:],
                     self.raw.replace(b'"schema_version": 1', b'"schema_version": NaN'),
                     self.raw.replace(b'"schema_version": 1', b'"schema_version": 1e999')):
            with self.subTest(data=data[:20]), self.assertRaises((ValueError, UnicodeError)):
                verifier.verify_report(self.source, data, **OPTIONS)
        with patch.object(verifier, 'MAX_REPORT_BYTES', 1), self.assertRaises(ValueError):
            verifier.verify_report(self.source, self.raw, **OPTIONS)

    @unittest.skipUnless(os.name == 'posix', 'POSIX file workflow required')
    def test_fresh_process_generate_verify_private_summary_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); report, summary = root / 'review.json', root / 'summary.json'
            generated = subprocess.run([sys.executable, review.__file__, str(FIXTURE), '--scope', 'synthetic',
                                        '--output', str(report)], capture_output=True, timeout=10)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            before = (FIXTURE.read_bytes(), report.read_bytes())
            args = [str(FIXTURE), str(report), '--scope', 'synthetic', '--min-resets', '3',
                    '--window-seconds', '60', '--output', str(summary)]
            verified = subprocess.run([sys.executable, verifier.__file__, *args], capture_output=True, timeout=10)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout), json.loads(summary.read_bytes()))
            self.assertEqual(summary.stat().st_mode & 0o777, 0o600)
            self.assertEqual(before, (FIXTURE.read_bytes(), report.read_bytes()))
            saved = summary.read_bytes()
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()): self.assertEqual(verifier.main(args), 2)
            self.assertEqual(summary.read_bytes(), saved)

    @unittest.skipUnless(os.name == 'posix', 'POSIX file workflow required')
    def test_invalid_cli_is_private_and_does_not_publish_summary(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); report, summary = root / 'bad.json', root / 'no-summary.json'
            report.write_text('{}')
            args = [str(FIXTURE), str(report), '--scope', 'synthetic', '--min-resets', '3',
                    '--window-seconds', '60', '--output', str(summary)]
            output, error = StringIO(), StringIO()
            with redirect_stdout(output), redirect_stderr(error), patch.object(verifier, '_publish') as publish:
                self.assertEqual(verifier.main(args), 2); publish.assert_not_called()
            self.assertEqual(output.getvalue(), '')
            self.assertNotIn(str(root), error.getvalue()); self.assertFalse(summary.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX reader required')
    def test_report_reader_rejects_final_symlinks_fifo_and_large_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); target = root / 'report.json'; target.write_bytes(self.raw)
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaises(OSError): verifier._read_report(link)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): verifier._read_report(fifo)
            with patch.object(verifier, 'MAX_REPORT_BYTES', 1), self.assertRaises(ValueError): verifier._read_report(target)


if __name__ == '__main__': unittest.main()
