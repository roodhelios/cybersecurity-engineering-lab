"""One saved text log reproduces complete findings and original-line provenance."""

from contextlib import redirect_stderr, redirect_stdout
import gzip
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from event_normalizer import zeek_review as review

FIXTURE = Path(__file__).parent/'fixtures/repeated_attempts.log'


class OriginalZeekReviewTests(unittest.TestCase):
    def setUp(self):
        self.original = FIXTURE.read_bytes()

    @staticmethod
    def pin(data): return hashlib.sha256(data).hexdigest()

    def test_plain_and_gzip_produce_same_findings_with_original_text_lines(self):
        plain = review.build_review(self.original, scope='synthetic')
        compressed = gzip.compress(self.original, mtime=0)
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            zipped = review.build_review(compressed, scope='synthetic')
        self.assertEqual(plain['correlation'], zipped['correlation'])
        self.assertEqual((plain['compression'], zipped['compression']), ('none', 'gzip'))
        self.assertEqual(zipped['input_sha256'], self.pin(compressed))
        evidence = zipped['correlation']['findings'][0]['evidence']
        self.assertEqual([x['original_line_number'] for x in evidence], [8, 9, 10, 11])
        self.assertEqual([x['line_number'] for x in evidence], [1, 2, 3, 4])
        self.assertEqual(zipped['expanded_bytes'], len(self.original))

    def test_changed_original_header_or_gzip_bytes_reject_even_if_events_are_identical(self):
        compressed = gzip.compress(self.original, mtime=0)
        data = json.dumps(review.build_review(compressed, scope='synthetic')).encode()
        with self.assertRaises(ValueError):
            review.verify_review(gzip.compress(self.original, mtime=1), data,
                                 scope='synthetic', expected_report_sha256=self.pin(data))
        plain = json.dumps(review.build_review(self.original, scope='synthetic')).encode()
        with self.assertRaises(ValueError):
            review.verify_review(self.original+b'\n', plain, scope='synthetic', expected_report_sha256=self.pin(plain))

    def test_every_report_field_and_scope_must_reproduce_under_independent_pin(self):
        report = review.build_review(self.original, scope='synthetic')
        data = json.dumps(report).encode()
        result = review.verify_review(self.original, data, scope='synthetic', expected_report_sha256=self.pin(data))
        self.assertEqual((result['events_read'], result['finding_count'], result['evidence_references']), (4, 1, 4))
        self.assertNotIn('192.0.2.10', json.dumps(result))
        for path, value in ((['schema_version'], True), (['schema_version'], 1.0), (['extra'], 1),
                            (['input_sha256'], '0'*64), (['correlation','finding_count'], 0),
                            (['correlation','findings',0,'evidence',0,'original_line_number'], 1)):
            changed = json.loads(data); node = changed
            for key in path[:-1]: node = node[key]
            node[path[-1]] = value
            saved = json.dumps(changed).encode()
            with self.subTest(path=path), self.assertRaises(ValueError):
                review.verify_review(self.original, saved, scope='synthetic', expected_report_sha256=self.pin(saved))
        with self.assertRaises(ValueError):
            review.verify_review(self.original, data, scope='owned', expected_report_sha256=self.pin(data))

    def test_report_pin_bounds_and_json_fail_before_import(self):
        data = json.dumps(review.build_review(self.original, scope='synthetic')).encode()
        with patch.object(review, 'build_review', side_effect=AssertionError('must not import')):
            for pin in ('invalid', '0'*64):
                with self.assertRaises(ValueError): review.verify_review(self.original, data, scope='synthetic', expected_report_sha256=pin)
            with patch.object(review, 'MAX_REPORT_BYTES', 1), self.assertRaises(ValueError):
                review.verify_review(self.original, data, scope='synthetic', expected_report_sha256=self.pin(data))
            for invalid in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff'):
                with self.assertRaises(ValueError):
                    review.verify_review(self.original, invalid, scope='synthetic', expected_report_sha256=self.pin(invalid))

    def test_bounded_expansion_invalid_tail_and_valid_header_only(self):
        header = b'\n'.join(self.original.splitlines()[:7])+b'\n'
        self.assertEqual(review.build_review(header, scope='synthetic')['correlation']['events_read'], 0)
        with patch.object(review, 'MAX_INPUT_BYTES', 100), self.assertRaises(ValueError):
            review.build_review(gzip.compress(b'x'*1000, mtime=0), scope='synthetic')
        for data in (self.original+b'invalid-tail\n', gzip.compress(self.original, mtime=0)[:-4]):
            with self.assertRaises((ValueError, EOFError, OSError)): review.build_review(data, scope='synthetic')

    @unittest.skipUnless(os.name == 'posix', 'private files require POSIX')
    def test_cli_private_exclusive_roundtrip_and_failures_leave_no_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, output = root/'conn.log.gz', root/'report.json'
            source.write_bytes(gzip.compress(self.original, mtime=0)); before = source.read_bytes()
            create = ['create', str(source), '--scope', 'synthetic', '--output', str(output)]
            with redirect_stdout(StringIO()) as stdout: self.assertEqual(review.main(create), 0)
            pin = json.loads(stdout.getvalue())['report_sha256']
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            retained = output.read_bytes()
            verify = ['verify', str(source), str(output), '--scope', 'synthetic', '--expected-report-sha256', pin]
            with redirect_stdout(StringIO()) as stdout: self.assertEqual(review.main(verify), 0)
            self.assertEqual(json.loads(stdout.getvalue())['status'], 'zeek_text_review_reproduced')
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                self.assertEqual(review.main(create), 2)
            self.assertEqual(stdout.getvalue(), ''); self.assertNotIn(str(root), stderr.getvalue())
            self.assertEqual((source.read_bytes(), output.read_bytes()), (before, retained))
            output.unlink(); source.write_bytes(gzip.compress(self.original+b'bad-tail\n', mtime=0))
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()): self.assertEqual(review.main(create), 2)
            self.assertEqual(stdout.getvalue(), ''); self.assertFalse(output.exists())
            source.unlink(); source.symlink_to(FIXTURE.resolve())
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()): self.assertEqual(review.main(create), 2)
            self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
