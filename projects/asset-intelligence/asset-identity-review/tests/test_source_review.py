"""Reviewed source requirements constrain identifier assertions before grouping."""

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
import source_review as constrained
from asset_review import _canonical, review_sources


class SourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.sources = [(ROOT / 'examples' / name).read_bytes() for name in ('cloud.json', 'endpoint.json')]
        self.policy = json.loads((ROOT / 'examples/source-requirements.json').read_bytes())

    def review(self, policy=None, sources=None):
        data = _canonical(self.policy if policy is None else policy)
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            return constrained.review_constrained(self.sources if sources is None else sources, data,
                expected_requirements_sha256=hashlib.sha256(data).hexdigest(), scope='synthetic', namespace='synthetic-assets')

    def test_unconstrained_match_reproduces_but_ungranted_kind_rejects_before_grouping(self):
        self.assertEqual(review_sources(self.sources, scope='synthetic', namespace='synthetic-assets')['matched_group_count'], 1)
        self.policy['sources'][1]['allowed_identifier_kinds'] = ['hardware_id']
        with patch.object(constrained, 'review_sources', side_effect=AssertionError('grouping forbidden')):
            with self.assertRaises(ValueError): self.review()

    def test_valid_complete_review_keeps_original_groups_and_conflicts(self):
        result = self.review()
        self.assertEqual(result, self.review())
        self.assertEqual(result['review'], review_sources(self.sources, scope='synthetic', namespace='synthetic-assets'))
        self.assertEqual(result['capture_skew_seconds'], 0)
        self.assertFalse(result['source_authenticity_verified'])
        self.assertEqual(result['review']['unresolved_component_count'], 1)

    def test_all_source_pins_precede_source_parsing(self):
        policy = _canonical(self.policy)
        for index in (0, 1):
            changed = list(self.sources); changed[index] += b'\n'
            with self.subTest(index=index), patch.object(constrained, '_check_source', side_effect=AssertionError('parsing forbidden')):
                with self.assertRaises(ValueError):
                    constrained.review_constrained(changed, policy, expected_requirements_sha256=hashlib.sha256(policy).hexdigest(),
                        scope='synthetic', namespace='synthetic-assets')
        with patch.object(constrained, '_parse', side_effect=AssertionError('requirements parsed before pin')):
            with self.assertRaises(ValueError):
                constrained.review_constrained(self.sources, policy, expected_requirements_sha256='0' * 64,
                    scope='synthetic', namespace='synthetic-assets')

    def test_complete_ordered_set_and_source_labels_are_required(self):
        for sources in (self.sources[:1], self.sources[::-1], self.sources + self.sources):
            with self.subTest(count=len(sources)), self.assertRaises(ValueError): self.review(sources=sources)
        self.policy['sources'][0]['source_id'] = 'other-cloud'
        with self.assertRaises(ValueError): self.review()

    def test_time_window_and_cross_source_skew_are_independent(self):
        document = json.loads(self.sources[1]); document['captured_at'] = '2026-11-17T00:01:00Z'
        changed = list(self.sources); changed[1] = _canonical(document)
        self.policy['sources'][1]['expected_original_sha256'] = hashlib.sha256(changed[1]).hexdigest()
        with self.assertRaises(ValueError): self.review(sources=changed)
        self.policy['max_capture_skew_seconds'] = 60
        self.assertEqual(self.review(sources=changed)['capture_skew_seconds'], 60)
        self.policy['observed_not_after'] = '2026-11-17T00:00:59Z'
        with self.assertRaises(ValueError): self.review(sources=changed)

    def test_timezone_equivalence_and_inclusive_boundaries(self):
        self.policy['observed_not_before'] = '2026-11-16T19:00:00-05:00'
        self.policy['observed_not_after'] = '2026-11-17T00:00:00Z'
        self.assertEqual(self.review()['capture_skew_seconds'], 0)

    def test_invalid_requirement_types_fields_times_and_grants_reject(self):
        changes = [('schema_version', True), ('namespace', 'other-assets'), ('scope', 'owned'),
            ('max_capture_skew_seconds', True), ('max_capture_skew_seconds', -1),
            ('max_capture_skew_seconds', 86401), ('observed_not_before', '2026-11-19T00:00:00Z'),
            ('observed_not_after', '2026-11-17T00:00:00'), ('sources', []), ('extra', True)]
        for key, value in changes:
            policy = dict(self.policy, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.review(policy=policy)
        for value in (['*'], ['hardware_id', 'hardware_id'], [True], 'hardware_id', [['nested']]):
            policy = json.loads(json.dumps(self.policy)); policy['sources'][0]['allowed_identifier_kinds'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.review(policy=policy)
        self.policy['sources'][1]['source_id'] = self.policy['sources'][0]['source_id']
        with self.assertRaises(ValueError): self.review()

    def test_empty_sources_are_not_real_inventory_coverage(self):
        sources = []
        for index, data in enumerate(self.sources):
            document = json.loads(data); document['assets'] = []
            sources.append(_canonical(document))
            self.policy['sources'][index]['expected_original_sha256'] = hashlib.sha256(sources[-1]).hexdigest()
            self.policy['sources'][index]['allowed_identifier_kinds'] = []
        self.assertEqual(self.review(sources=sources)['review']['record_count'], 0)

    def test_malformed_and_oversized_requirements_reject(self):
        for data in (b'{}', b'[]', b'\xff', b'{"scope":1,"scope":2}', b'{"scope":NaN}',
                     b' ' * (constrained.MAX_REQUIREMENTS_BYTES + 1)):
            with self.subTest(size=len(data)), self.assertRaises((ValueError, UnicodeError)):
                constrained.review_constrained(self.sources, data,
                    expected_requirements_sha256=hashlib.sha256(data).hexdigest(), scope='synthetic', namespace='synthetic-assets')

    @unittest.skipUnless(os.name == 'posix', 'private CLI requires POSIX')
    def test_cli_private_exclusive_output_and_no_raw_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'review.json'
            policy_path = ROOT / 'examples/source-requirements.json'
            args = ['review', *[str(ROOT / 'examples' / name) for name in ('cloud.json', 'endpoint.json')],
                '--requirements', str(policy_path), '--expected-requirements-sha256', hashlib.sha256(policy_path.read_bytes()).hexdigest(),
                '--scope', 'synthetic', '--namespace', 'synthetic-assets', '--output', str(output)]
            with redirect_stdout(StringIO()) as stdout:
                self.assertEqual(constrained.main(args), 0)
            self.assertEqual(json.loads(stdout.getvalue())['group_count'], 6)
            self.assertNotIn('mock-cloud', stdout.getvalue())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            saved = output.read_bytes()
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                self.assertEqual(constrained.main(args), 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(str(output), stderr.getvalue())
            self.assertEqual(output.read_bytes(), saved)

    def test_demo(self):
        self.assertTrue(constrained.exercise()['ungranted_identifier_rejected'])


if __name__ == '__main__':
    unittest.main()
