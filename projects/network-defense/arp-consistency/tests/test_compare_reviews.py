"""Original synthetic network metadata only. No sockets, packets or services."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import compare_reviews as comparison


def observation(minute, mac, ip='192.0.2.10'):
    return json.dumps(dict(timestamp=f'2026-10-21T12:{minute:02d}:00Z', interface='lab0', ip=ip, mac=mac))


def source(lines):
    return {'observations': ('\n'.join(lines)+'\n').encode()}


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.lines = [observation(0, '02:00:00:00:00:10'), observation(1, '02:00:00:00:00:99')]
        self.before = source(self.lines)

    def compare(self, after=None, **options):
        return comparison.compare_reviews(self.before, after or self.before, scope='synthetic', **options)

    def test_expected_inventory_rejects_missing_context_and_empty_substitute(self):
        after = self.before | {'leases': b''}
        inventory = {
            'before': {'observations': comparison._sha(self.before['observations'])},
            'after': {kind: comparison._sha(data) for kind, data in after.items()},
        }
        report = self.compare(after, expected_inventory=inventory)
        self.assertEqual(report['schema_version'], 2)
        for substitute in (self.before, after | {'observations': b''},
                           after | {'forwarding': b''}):
            with self.subTest(kinds=list(substitute)), self.assertRaises(ValueError):
                self.compare(substitute, expected_inventory=inventory)
        self.assertEqual(self.compare(after)['schema_version'], 1)

    def test_expected_inventory_is_required_again_when_replaying(self):
        pins = {'observations': comparison._sha(self.before['observations'])}
        inventory = {'before': pins, 'after': pins.copy()}
        retained = comparison._canonical(self.compare(expected_inventory=inventory))
        options = dict(expected_report_sha256=comparison._sha(retained), scope='synthetic')
        comparison.verify_comparison(self.before, self.before, retained,
                                     expected_inventory=inventory, **options)
        with self.assertRaises(ValueError):
            comparison.verify_comparison(self.before, self.before, retained, **options)
        with self.assertRaises(ValueError):
            self.compare(expected_inventory={'before': pins, 'after': {'observations': 'invalid'}})

    def test_inventory_cli_rejects_bad_inventory_without_creating_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root/'original'
            original.write_bytes(self.before['observations'])
            inventory = root/'inventory.json'
            report = root/'report.json'
            args = [str(original), str(original), '--scope', 'synthetic',
                    '--expected-inventory', str(inventory), '--output', str(report)]
            for invalid in (b'null', b'{"before":{},"before":{},"after":{}}',
                            b' '*4097, b'{"before":{},"after":{}}'):
                inventory.write_bytes(invalid)
                with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                    self.assertEqual(comparison.main(args), 2)
                self.assertFalse(report.exists())

    def test_neighbor_receipt_cli_round_trip_and_changed_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root/'snapshot.json'
            snapshot.write_bytes((ROOT/'examples/neighbors-after.json').read_bytes())
            when = '2026-10-21T12:00:00Z'
            from neighbor_import import import_snapshots
            observations, receipt = import_snapshots([(when, snapshot)])
            paths = {name: root/name for name in ('receipt', 'observations', 'inventory', 'report')}
            paths['receipt'].write_bytes(comparison._canonical(receipt))
            paths['observations'].write_bytes(observations.encode())
            pins = {'observations': comparison._sha(paths['observations'].read_bytes())}
            inventory = {'before': pins, 'after': pins | {
                'neighbor_receipt': comparison._sha(paths['receipt'].read_bytes())}}
            paths['inventory'].write_bytes(comparison._canonical(inventory))
            args = [str(paths['observations'])]*2 + [
                '--scope', 'synthetic', '--expected-inventory', str(paths['inventory']),
                '--after-neighbor-receipt', str(paths['receipt']),
                '--after-neighbor-snapshot', when, str(snapshot),
            ]
            with redirect_stdout(StringIO()):
                self.assertEqual(comparison.main(args + ['--output', str(paths['report'])]), 0)
            saved = paths['report'].read_bytes()
            self.assertEqual(json.loads(saved)['schema_version'], 3)
            verify = ['--verify-report', str(paths['report']), '--expected-report-sha256',
                      comparison._sha(saved)]
            with redirect_stdout(StringIO()):
                self.assertEqual(comparison.main(args + verify), 0)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(comparison.main(args[:-5] + verify), 2)
                snapshot.write_bytes(snapshot.read_bytes() + b' ')
                self.assertEqual(comparison.main(args + verify), 2)

    def test_neighbor_receipt_cannot_certify_unrelated_observation_bytes(self):
        from neighbor_import import import_snapshots
        snapshots = [('2026-10-21T12:00:00Z', ROOT/'examples/neighbors-after.json')]
        _, receipt = import_snapshots(snapshots)
        saved = comparison._canonical(receipt)
        pins = {'observations': comparison._sha(self.before['observations'])}
        inventory = {'before': pins, 'after': pins | {'neighbor_receipt': comparison._sha(saved)}}
        with self.assertRaisesRegex(ValueError, 'observations differ'):
            self.compare(expected_inventory=inventory, neighbor_sources={'after': (saved, snapshots)})
        with self.assertRaisesRegex(ValueError, 'requires an independent'):
            self.compare(neighbor_sources={'after': (saved, snapshots)})

    def test_unchanged_review_retains_both_original_line_references(self):
        result = self.compare()
        self.assertEqual(result['counts'], dict(added=0, not_observed=0, changed=0, unchanged=1))
        event = result['transitions'][0]
        self.assertEqual(event['before']['previous_line'], 1)
        self.assertEqual(event['after']['current_line'], 2)
        self.assertEqual(result, self.compare())

    def test_inserted_unrelated_row_changes_references_without_new_identity(self):
        result = self.compare(source([observation(0, '02:00:00:00:00:20', '192.0.2.20')]+self.lines))
        event = result['transitions'][0]
        self.assertEqual(result['counts']['changed'], 1)
        self.assertEqual(event['event_id'], self.compare()['transitions'][0]['event_id'])
        self.assertEqual((event['before']['current_line'], event['after']['current_line']), (2, 3))

    def test_absence_is_not_observed_and_new_transition_is_added(self):
        result = self.compare(source([observation(0, '02:00:00:00:00:20', '192.0.2.20'),
                                      observation(1, '02:00:00:00:00:21', '192.0.2.20')]))
        self.assertEqual((result['counts']['not_observed'], result['counts']['added']), (1, 1))
        self.assertNotIn('resolved', result['counts'])
        self.assertIn('does not mean resolved', result['interpretation'])

    def test_repeated_mapping_at_different_times_has_distinct_identities(self):
        later = source(self.lines+[observation(2, '02:00:00:00:00:10'), observation(3, '02:00:00:00:00:99')])
        result = self.compare(later)
        self.assertEqual(result['counts']['unchanged'], 1)
        self.assertEqual(result['counts']['added'], 2)
        self.assertEqual(len({e['event_id'] for e in result['transitions']}), 3)

    def test_equivalent_time_offsets_preserve_identity(self):
        after = {'observations': self.before['observations'].replace(b'12:00:00Z', b'13:00:00+01:00')
                 .replace(b'12:01:00Z', b'13:01:00+01:00')}
        result = self.compare(after)
        self.assertEqual(result['counts']['unchanged'], 1)
        self.assertNotEqual(result['inputs']['before'], result['inputs']['after'])

    def test_lease_context_change_retains_original_support_references(self):
        lease = dict(starts_at='2026-10-21T12:00:30Z', ends_at='2026-10-21T12:02:00Z',
                     interface='lab0', ip='192.0.2.10', mac='02:00:00:00:00:99')
        before = self.before | {'leases': (json.dumps(lease)+'\n').encode()}
        result = comparison.compare_reviews(before, self.before | {'leases': b''}, scope='synthetic')
        event = result['transitions'][0]
        self.assertEqual(event['status'], 'changed')
        self.assertEqual(event['before']['lease_status'], 'expected_reassignment')
        self.assertEqual(event['before']['lease_line'], 1)
        self.assertEqual(event['after']['lease_status'], 'unexplained_change')

    def test_empty_observations_and_optional_context_are_explicit(self):
        result = comparison.compare_reviews({'observations': b''}, {'observations': b'', 'leases': b''}, scope='owned')
        self.assertEqual(sum(result['counts'].values()), 0)
        self.assertNotEqual(result['inputs']['before'], result['inputs']['after'])

    def test_ambiguous_same_time_repeated_transition_rejects(self):
        data = source([observation(0, '02:00:00:00:00:10'), observation(0, '02:00:00:00:00:99')]*2)
        with self.assertRaises(ValueError): self.compare(data)

    def test_invalid_scope_parameters_and_source_fields_reject(self):
        for options in ({'scope': 'public'}, {'scope': 'synthetic', 'window_seconds': True},
                        {'scope': 'synthetic', 'window_seconds': 0}):
            with self.assertRaises(ValueError): comparison.compare_reviews(self.before, self.before, **options)
        for after in ({'extra': b''}, {'observations': b'not JSON'},
                      {'observations': b'{"x":1,"x":2}'}, self.before | {'port_policy': b''}):
            with self.assertRaises(ValueError): self.compare(after)

    def test_pinned_report_reproduces_every_field(self):
        data = comparison._canonical(self.compare())
        result = comparison.verify_comparison(self.before, self.before, data,
            expected_report_sha256=comparison._sha(data), scope='synthetic')
        self.assertEqual(result['status'], 'arp_comparison_reproduced')
        self.assertNotIn('192.0.2.', json.dumps(result))
        changed = json.loads(data)
        changed['transitions'][0]['after']['current_line'] = 99
        changed = comparison._canonical(changed)
        with self.assertRaises(ValueError):
            comparison.verify_comparison(self.before, self.before, changed,
                expected_report_sha256=comparison._sha(changed), scope='synthetic')

    def test_wrong_requirements_or_original_bytes_reject(self):
        data = comparison._canonical(self.compare())
        for inputs, options in ((self.before, {'scope': 'owned'}),
                                (self.before, {'scope': 'synthetic', 'window_seconds': 61}),
                                ({'observations': self.before['observations']+b'\n'}, {'scope': 'synthetic'})):
            with self.assertRaises(ValueError):
                comparison.verify_comparison(self.before, inputs, data,
                    expected_report_sha256=comparison._sha(data), **options)

    def test_wrong_pin_before_parse_or_replay(self):
        with patch.object(comparison, 'compare_reviews', side_effect=AssertionError('must not replay')):
            with self.assertRaises(ValueError):
                comparison.verify_comparison(self.before, self.before, b'invalid',
                    expected_report_sha256='0'*64, scope='synthetic')

    def test_input_and_report_byte_bounds(self):
        with patch.object(comparison, 'MAX_INPUT_BYTES', 1):
            with self.assertRaises(ValueError): self.compare()
        with patch.object(comparison, 'MAX_REPORT_BYTES', 1):
            with self.assertRaises(ValueError): self.compare()

    def test_cli_private_retention_verification_and_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before, after, report = root/'before', root/'after', root/'report'
            before.write_bytes(self.before['observations']); after.write_bytes(self.before['observations'])
            args = [str(before), str(after), '--scope', 'synthetic', '--output', str(report)]
            out = StringIO()
            with redirect_stdout(out): self.assertEqual(comparison.main(args), 0)
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            digest = json.loads(out.getvalue())['report_sha256']
            self.assertNotIn('192.0.2.', out.getvalue())
            original = report.read_bytes()
            out, err = StringIO(), StringIO()
            with redirect_stdout(out), redirect_stderr(err): self.assertEqual(comparison.main(args), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertEqual(report.read_bytes(), original)
            args = args[:4]+['--verify-report', str(report), '--expected-report-sha256', digest]
            result = subprocess.run([sys.executable, '-S', str(ROOT/'compare_reviews.py'), *args],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['original_inputs_replayed'])

    def test_cli_bad_pin_before_any_file_read_and_sanitized_errors(self):
        out, err = StringIO(), StringIO()
        with patch.object(comparison, '_read', side_effect=AssertionError('must not read')):
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(comparison.main(['private-before', 'private-after', '--scope', 'synthetic',
                    '--verify-report', 'private-report', '--expected-report-sha256', 'invalid']), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('private-before', err.getvalue())

    def test_reader_rejects_links_and_special_files(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'original'; path.write_bytes(b'original')
            alias = root/'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): comparison._read(alias, 100)
            with self.assertRaises(ValueError): comparison._read(root, 100)
            with self.assertRaises(ValueError): comparison._read(path, 1)
            fifo = root/'fifo'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): comparison._read(fifo, 100)

    def test_policy_change_preserves_forwarding_and_policy_references(self):
        before = self.before | {kind: (ROOT/'examples'/name).read_bytes() for kind, name in (
            ('forwarding', 'switch-forwarding.jsonl'), ('port_policy', 'expected-ports.jsonl'))}
        changed = json.loads(before['port_policy'])
        changed['allowed_ports'] = ['swp99']
        after = before | {'port_policy': (json.dumps(changed)+'\n').encode()}
        result = comparison.compare_reviews(before, after, scope='synthetic')
        event = result['transitions'][0]
        self.assertEqual(event['status'], 'changed')
        self.assertEqual(event['before']['port_policy_status'], 'expected_port')
        self.assertEqual(event['after']['port_policy_status'], 'unexpected_port')
        self.assertEqual(event['after']['port_policy_line'], 1)
        self.assertEqual(event['before']['forwarding_line'], event['after']['forwarding_line'])

    def test_fresh_process_synthetic_walkthrough(self):
        result = subprocess.run([sys.executable, '-S', str(ROOT/'demo_comparison.py')],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary['negative_cases_rejected'], 4)
        self.assertEqual(summary['counts']['changed'], 1)


if __name__ == '__main__':
    unittest.main()
