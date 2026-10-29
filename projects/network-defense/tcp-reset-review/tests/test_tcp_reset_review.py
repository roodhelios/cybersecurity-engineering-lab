from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
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

FIXTURE = Path(__file__).resolve().parents[1] / 'examples' / 'connections.jsonl'


def record(uid='C1', ts=1000, state='RSTR', **changes):
    value = {'ts': ts, 'uid': uid, 'proto': 'tcp', 'id.orig_h': '192.0.2.1', 'id.orig_p': 50000,
             'id.resp_h': '198.51.100.1', 'id.resp_p': 443, 'conn_state': state}
    value.update(changes)
    return value


def run(rows, **options):
    return review.review_bytes(('\n'.join(json.dumps(r) for r in rows) + '\n').encode(), scope='synthetic', **options)


class ResetReviewTests(unittest.TestCase):
    def test_fixture_exact_counts_and_original_line_evidence_without_raw_fields(self):
        raw = FIXTURE.read_bytes()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = review.review_bytes(raw, scope='synthetic')
        self.assertEqual(result['record_count'], 6)
        self.assertEqual(result['tcp_state_counts'], {'REJ': 1, 'RSTOS0': 1, 'RSTR': 3, 'SF': 1})
        self.assertEqual(result['input_sha256'], hashlib.sha256(raw).hexdigest())
        finding, = result['findings']
        self.assertEqual(finding['connection_count'], 3)
        self.assertEqual(finding['reported_reset_side'], 'responder')
        self.assertEqual([r['line'] for r in finding['evidence']], [1, 3, 5])
        for evidence in finding['evidence']:
            self.assertEqual(evidence['line_sha256'], hashlib.sha256(raw.splitlines()[evidence['line']-1]).hexdigest())
        self.assertNotIn('history', json.dumps(result))
        self.assertNotIn('192.0.2.10', json.dumps(result))

    def test_precise_inclusive_window_and_just_outside(self):
        rows = [record('C1', 1000.000001), record('C2', 1030), record('C3', 1060.000001)]
        self.assertEqual(run(rows)['findings'][0]['connection_count'], 3)
        rows[-1]['ts'] = 1060.000002
        self.assertEqual(run(rows)['findings'], [])

    def test_maximum_window_not_fixed_bucket_and_only_one_per_service_state(self):
        rows = [record('C' + str(i), ts) for i, ts in enumerate([59, 60, 61, 200, 201, 202, 203])]
        finding, = run(rows)['findings']
        self.assertEqual(finding['connection_count'], 4)
        self.assertEqual(finding['first_epoch'], '200.000000')
        self.assertEqual([e['uid'] for e in finding['evidence']], ['C3', 'C4', 'C5', 'C6'])

    def test_equal_count_chooses_earliest_window_and_unsorted_input_keeps_line_refs(self):
        rows = [record('C6', 202), record('C2', 60), record('C3', 61), record('C4', 200),
                record('C5', 201), record('C1', 59)]
        finding, = run(rows)['findings']
        self.assertEqual([e['line'] for e in finding['evidence']], [6, 2, 3])
        self.assertEqual(run(rows), run(rows))

    def test_direction_partial_states_rejections_and_ports_do_not_mix(self):
        rows = [record('C' + str(i), 1000 + i, state) for i, state in enumerate(['RSTR', 'RSTO', 'RSTOS0', 'RSTRH', 'REJ'])]
        self.assertEqual(run(rows, min_resets=2)['findings'], [])
        rows += [record('C6', 1010, **{'id.resp_p': 80}), record('C7', 1011, proto='udp')]
        result = run(rows, min_resets=2)
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['non_tcp_records'], 1)
        for state, (side, context) in review.RESET_STATES.items():
            finding, = run([record('Ca', state=state), record('Cb', 1001, state)], min_resets=2)['findings']
            self.assertEqual((finding['reported_reset_side'], finding['connection_context']), (side, context))

    def test_ipv6_normalization_unknown_metadata_omitted(self):
        rows = [record('Ca', **{'id.orig_h': '2001:db8::1', 'id.resp_h': '2001:0db8::2', 'private_metadata': 'hidden'}),
                record('Cb', 1001, **{'id.orig_h': '2001:db8::3', 'id.resp_h': '2001:db8::2'})]
        result = run(rows, min_resets=2)
        self.assertEqual(result['findings'][0]['responder_ip'], '2001:db8::2')
        self.assertNotIn('hidden', json.dumps(result))

    def test_duplicate_uids_fail_instead_of_inflating_counts(self):
        with self.assertRaises(ValueError): run([record(), record()])

    def test_invalid_record_fields_fail_whole_batch(self):
        for field, value in [('ts', True), ('ts', -1), ('ts', '1000'), ('ts', 1e20), ('ts', 0.0000001),
            ('id.orig_p', True), ('id.resp_p', 65536), ('id.resp_p', '443'), ('id.orig_h', 'host.example'),
            ('id.resp_h', 'fe80::1%eth0'), ('id.resp_h', '2001:db8::1'), ('conn_state', 'INVENTED'),
            ('conn_state', []), ('proto', 'sctp'), ('uid', '\n')]:
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, TypeError)):
                run([record('good'), record('bad', **{field: value})])

    def test_malformed_nonfinite_duplicate_json_and_empty_lines_fail(self):
        for raw in [b'', b'\n', b'{}\n', b'not-json', b'[]', json.dumps(record()).encode()+b'\n\n',
                    json.dumps(record()).replace('1000', 'NaN').encode(),
                    json.dumps(record()).replace('1000', '1e999999999999999999999999999').encode(),
                    b'{"uid":"duplicate",'+json.dumps(record()).encode()[1:], b'\xff']:
            with self.subTest(raw=raw[:20]), self.assertRaises((ValueError, UnicodeError)):
                review.review_bytes(raw, scope='synthetic')

    def test_bounds_and_explicit_scope(self):
        for settings in [dict(min_resets=True), dict(min_resets=1), dict(window_seconds=True),
                         dict(window_seconds=0), dict(window_seconds=86401)]:
            with self.assertRaises(ValueError): run([record()], **settings)
        with self.assertRaises(ValueError): review.review_bytes(FIXTURE.read_bytes(), scope='unspecified')
        for constant in ('MAX_BYTES', 'MAX_LINE_BYTES', 'MAX_RECORDS'):
            with patch.object(review, constant, 1), self.assertRaises(ValueError):
                review.review_bytes(FIXTURE.read_bytes(), scope='synthetic')

    def test_crlf_and_no_final_newline_hashes_are_defined(self):
        raw = FIXTURE.read_bytes()
        result = review.review_bytes(raw.replace(b'\n', b'\r\n'), scope='synthetic')
        self.assertEqual(result['findings'], review.review_bytes(raw.rstrip(b'\n'), scope='synthetic')['findings'])
        self.assertNotEqual(result['input_sha256'], hashlib.sha256(raw).hexdigest())

    @unittest.skipUnless(os.name == 'posix', 'POSIX publication required')
    def test_native_cli_private_output_no_overwrite_and_invalid_batch_no_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); output = root / 'review.json'
            args = [str(FIXTURE), '--scope', 'synthetic', '--output', str(output)]
            process = subprocess.run([sys.executable, str(Path(review.__file__)), *args], capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout, b'')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            saved = output.read_bytes()
            with redirect_stderr(StringIO()): self.assertEqual(review.main(args), 2)
            self.assertEqual(output.read_bytes(), saved)
            invalid = root / 'invalid.jsonl'; invalid.write_bytes(FIXTURE.read_bytes()+b'{}\n')
            target = root / 'invalid-output.json'; stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(review.main([str(invalid), '--scope', 'owned', '--output', str(target)]), 2)
            self.assertFalse(target.exists()); self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(str(root), stderr.getvalue())

    @unittest.skipUnless(os.name == 'posix', 'POSIX reader required')
    def test_reader_rejects_final_symlink_and_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as name:
            link = Path(name) / 'alias'; link.symlink_to(FIXTURE)
            with self.assertRaises(OSError): review._read(link)
            fifo = Path(name) / 'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): review._read(fifo)


if __name__ == '__main__': unittest.main()
