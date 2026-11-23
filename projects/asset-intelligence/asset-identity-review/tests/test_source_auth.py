import base64
import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import source_auth as auth
from source_review import _canonical, _parse


def digest(data):
    return hashlib.sha256(data).hexdigest()


class SourceAuthenticationTests(unittest.TestCase):
    def setUp(self):
        try:
            from nacl.signing import SigningKey
        except ImportError:
            self.skipTest('optional PyNaCl required')
        self.originals = [(ROOT / 'examples' / name).read_bytes() for name in ('cloud.json', 'endpoint.json')]
        self.requirements = (ROOT / 'examples/source-requirements.json').read_bytes()
        self.rules = _parse(self.requirements)['sources']
        self.signers = [SigningKey.generate(), SigningKey.generate()]
        self.policy = {'schema_version': 1, 'scope': 'synthetic', 'namespace': 'synthetic-assets',
            'maximum_validity_seconds': 3600, 'sources': [
                {'source_id': r['source_id'], 'key_id': 'collector-' + str(i),
                 'public_key_b64': base64.b64encode(k.verify_key.encode()).decode('ascii'),
                 'status': 'active', 'not_before': '2026-11-17T00:00:00Z', 'not_after': '2026-11-18T00:00:00Z'}
                for i, (r, k) in enumerate(zip(self.rules, self.signers))]}
        self.policy_data = _canonical(self.policy)
        self.options = dict(expected_requirements_sha256=digest(self.requirements),
            expected_authority_sha256=digest(self.policy_data), scope='synthetic',
            namespace='synthetic-assets', at='2026-11-17T00:02:00Z')
        self.claims = [auth.create_claim(data, self.requirements, self.policy_data, **self.options,
            source_id=rule['source_id'], signing_key=key, issued_at='2026-11-17T00:01:00Z',
            expires_at='2026-11-17T00:31:00Z') for data, rule, key in zip(self.originals, self.rules, self.signers)]
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)

    def bundle(self):
        return _canonical({'schema_version': 1, 'claims': self.claims})

    def review(self, *, policy=None, originals=None, requirements=None, **changes):
        authority = self.policy_data if policy is None else _canonical(policy)
        requirements = self.requirements if requirements is None else requirements
        options = self.options | {'expected_authority_sha256': digest(authority),
            'expected_requirements_sha256': digest(requirements), 'expected_bundle_sha256': digest(self.bundle())} | changes
        return auth.review_authenticated(self.originals if originals is None else originals,
            requirements, authority, self.bundle(), **options)

    def resign(self, index):
        self.claims[index]['signature_b64'] = base64.b64encode(
            self.signers[index].sign(auth._message(self.claims[index])).signature).decode('ascii')

    def test_real_per_source_signatures_preserve_unresolved_identity_component(self):
        result = self.review()
        self.assertEqual(result, self.review())
        self.assertTrue(result['collector_key_claims_verified'])
        self.assertFalse(result['source_truth_verified'])
        self.assertFalse(result['collector_independence_verified'])
        self.assertFalse(result['constrained_review']['source_authenticity_verified'])
        self.assertEqual(result['constrained_review']['review']['unresolved_component_count'], 1)
        self.assertEqual(result['constrained_review']['review']['group_count'], 6)

    def test_one_source_key_cannot_sign_for_another(self):
        self.claims[1]['signature_b64'] = base64.b64encode(
            self.signers[0].sign(auth._message(self.claims[1])).signature).decode('ascii')
        with patch.object(auth, 'review_constrained', side_effect=AssertionError('grouping forbidden')):
            with self.assertRaises(ValueError): self.review()

    def test_substituted_reordered_and_incomplete_originals_reject(self):
        for originals in ([self.originals[0] + b' ', self.originals[1]],
                          list(reversed(self.originals)), self.originals[:1]):
            with self.subTest(count=len(originals)), self.assertRaises(ValueError): self.review(originals=originals)

    def test_missing_duplicate_unknown_and_wrong_key_claims_reject(self):
        original = copy.deepcopy(self.claims)
        for claims in (original[:1], [original[0], original[0]],
                       [original[0], original[1] | {'source_id': 'unexpected'}],
                       [original[0], original[1] | {'key_id': original[0]['key_id']}]):
            self.claims = claims
            with self.assertRaises(ValueError): self.review()
        self.claims = original

    def test_modified_signed_context_cannot_be_repinned_without_resigning(self):
        for field, value in [('issued_at', '2026-11-17T00:00:30Z'), ('source_sha256', '0' * 64),
                             ('purpose', 'other-purpose'), ('scope', 'owned')]:
            old = self.claims[0][field]; self.claims[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.review()
            self.claims[0][field] = old

    def test_revocation_and_reused_public_key_across_sources_reject(self):
        policy = copy.deepcopy(self.policy); policy['sources'][0]['status'] = 'revoked'
        # Re-sign against the selected policy so rejection exercises revocation,
        # rather than an unrelated authority digest mismatch.
        for i in range(2):
            self.claims[i]['authority_sha256'] = digest(_canonical(policy))
            self.resign(i)
        with self.assertRaises(ValueError): self.review(policy=policy)
        policy = copy.deepcopy(self.policy)
        policy['sources'][1]['public_key_b64'] = policy['sources'][0]['public_key_b64']
        with self.assertRaises(ValueError): self.review(policy=policy)

    def test_window_edges_and_maximum_validity_are_enforced(self):
        self.assertTrue(self.review(at='2026-11-17T00:01:00Z')['collector_key_claims_verified'])
        for at in ('2026-11-17T00:00:59Z', '2026-11-17T00:31:00Z'):
            with self.subTest(at=at), self.assertRaises(ValueError): self.review(at=at)
        self.claims[0]['expires_at'] = '2026-11-17T02:00:00Z'; self.resign(0)
        with self.assertRaises(ValueError): self.review()

    def test_signed_capture_after_issuance_rejects_before_grouping(self):
        self.claims[0]['issued_at'] = '2026-11-16T23:59:00Z'; self.resign(0)
        # Extend the trusted key window so the capture/issuance relation is the failing condition.
        policy = copy.deepcopy(self.policy); policy['sources'][0]['not_before'] = '2026-11-16T23:00:00Z'
        data = _canonical(policy)
        for i in range(2): self.claims[i]['authority_sha256'] = digest(data); self.resign(i)
        with patch.object(auth, 'review_constrained', side_effect=AssertionError('grouping forbidden')):
            with self.assertRaises(ValueError): self.review(policy=policy)

    def test_valid_signatures_do_not_bypass_identifier_grants(self):
        requirements = _parse(self.requirements)
        requirements['sources'][1]['allowed_identifier_kinds'] = ['hardware_id']
        data = _canonical(requirements)
        for i in range(2): self.claims[i]['requirements_sha256'] = digest(data); self.resign(i)
        with self.assertRaises(ValueError): self.review(requirements=data)

    def test_all_three_input_pins_precede_parsing(self):
        options = self.options | {'expected_bundle_sha256': digest(self.bundle())}
        for name in ('requirements', 'authority', 'bundle'):
            changed = options | {'expected_' + name + '_sha256': '0' * 64}
            with patch.object(auth, '_parse', side_effect=AssertionError('must not parse')):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    auth.review_authenticated(self.originals, self.requirements, self.policy_data, self.bundle(), **changed)

    def test_signer_api_refuses_other_source_key_and_revoked_policy(self):
        for signer, policy in [(self.signers[1], self.policy),
                               (self.signers[0], self.policy | {'sources': [self.policy['sources'][0] | {'status': 'revoked'}, self.policy['sources'][1]]})]:
            data = _canonical(policy)
            with self.assertRaises(ValueError):
                auth.create_claim(self.originals[0], self.requirements, data,
                    **(self.options | {'expected_authority_sha256': digest(data)}), source_id=self.rules[0]['source_id'],
                    signing_key=signer, issued_at='2026-11-17T00:01:00Z', expires_at='2026-11-17T00:31:00Z')

    def test_new_input_and_report_bounds_reject_without_partial_review(self):
        for limit in ('AUTHORITY_LIMIT', 'BUNDLE_LIMIT', 'MAX_REPORT_BYTES'):
            with self.subTest(limit=limit), patch.object(auth, limit, 1), self.assertRaises(ValueError):
                self.review()

    def test_real_cli_is_private_read_only_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); originals = []
            for i, data in enumerate(self.originals):
                path = root / ('source' + str(i) + '.json'); path.write_bytes(data); originals.append(path)
            args = ['review', *(str(path) for path in originals)]
            for name, data in [('requirements', self.requirements), ('authority', self.policy_data), ('bundle', self.bundle())]:
                path = root / (name + '.json'); path.write_bytes(data)
                args += ['--' + name, str(path), '--expected-' + name + '-sha256', digest(data)]
            target = root / 'review.json'
            args += ['--scope', 'synthetic', '--namespace', 'synthetic-assets', '--at', self.options['at'], '--output', str(target)]
            with redirect_stdout(StringIO()) as out: self.assertEqual(auth.main(args), 0)
            for private in ('mock-cloud', 'collector-0', str(root)):
                self.assertNotIn(private, out.getvalue())
            saved = target.read_bytes(); self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                self.assertEqual(auth.main(args), 2)
            self.assertEqual(out.getvalue(), ''); self.assertNotIn(str(root), err.getvalue())
            self.assertEqual(target.read_bytes(), saved)
            for path, data in zip(originals, self.originals): self.assertEqual(path.read_bytes(), data)
            target.unlink(); originals[0].unlink(); originals[0].symlink_to(originals[1])
            with redirect_stderr(StringIO()): self.assertEqual(auth.main(args), 2)
            self.assertFalse(target.exists())

    def test_demo(self):
        result = auth.exercise()
        self.assertEqual(result['unresolved_component_count'], 1)
        self.assertFalse(result['source_truth_verified'])


if __name__ == '__main__': unittest.main()
