import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    from nacl.signing import SigningKey
except ImportError:
    SigningKey = None

from dns_authorized_handoff import create_approval, verify_approval, verify_authorized_workflow, read_authorities, main
from zeek_dns_workflow import review_logs


@unittest.skipUnless(SigningKey is not None, 'native Ed25519 checks require PyNaCl')
class AuthorizedHandoffTests(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.authority = {'schema_version': 1, 'authority_type': 'dns-recipient-authorities',
            'audience': 'synthetic-recipient', 'maximum_validity_seconds': 86400,
            'keys': [{'key_id': 'recipient-lab', 'status': 'active',
                      'public_key_b64': base64.b64encode(bytes(self.key.verify_key)).decode()}]}
        names = ('zeek-dns-before.jsonl', 'zeek-dns.jsonl', 'scope.json', 'review-policy.json')
        self.inputs = [(ROOT/'examples'/name).read_bytes() for name in names]
        self.requirements = (ROOT/'examples/handoff-requirements-complete.json').read_bytes()
        self.reviews = {'assessment_data': (ROOT/'examples/risk-assessments.json').read_bytes(),
                        'ownership_data': (ROOT/'examples/ownership-responses.json').read_bytes()}
        self.now = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
        self.report = review_logs(*self.inputs, previous_observed_at='2026-10-23T00:00:00Z',
            current_observed_at='2026-10-24T00:00:00Z', record_type='A', include_queue=True, **self.reviews)

    def authority_data(self):
        return json.dumps(self.authority).encode()

    def approve(self, **options):
        values = dict(signing_key=self.key, key_id='recipient-lab', issued_at='2026-10-27T00:00:00Z',
                      expires_at='2026-10-28T00:00:00Z')
        values.update(options)
        return create_approval(self.requirements, *self.inputs[2:], self.authority_data(), **values)

    def check(self, approval=None, **options):
        values = dict(requirements=self.requirements, scope=self.inputs[2], review_policy=self.inputs[3],
                      authority_data=self.authority_data(), now=self.now)
        values.update(options)
        return verify_approval(self.approve() if approval is None else approval, **values)

    def handoff(self, *, report=None, approval=None, requirements=None, reviews=None):
        return verify_authorized_workflow(json.dumps(self.report if report is None else report).encode(),
            *self.inputs, requirements=self.requirements if requirements is None else requirements,
            approval=self.approve() if approval is None else approval, authority_policy=self.authority_data(),
            now=self.now, **(self.reviews if reviews is None else reviews))

    def test_native_approval_and_complete_reproduction_without_network_or_mutation(self):
        before = copy.deepcopy(self.report); approval = self.approve()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.handoff(approval=approval)
        self.assertTrue(result['recipient_authority_checked'])
        self.assertTrue(result['requirements_checked'])
        self.assertEqual(result['finding_count'], 1)
        self.assertEqual(result['recipient_authority']['key_id'], 'recipient-lab')
        self.assertEqual(self.report, before)

    def test_exact_requirement_scope_and_policy_bytes_are_bound(self):
        approval = self.approve()
        for name, data in (('requirements', self.requirements), ('scope', self.inputs[2]), ('review_policy', self.inputs[3])):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'bytes changed'):
                self.check(approval, **{name: data+b'\n'})

    def test_changed_signature_metadata_and_domain_are_rejected(self):
        original = json.loads(self.approve())
        for name, value in (('signature_b64', base64.b64encode(bytes(64)).decode()),
                            ('issued_at', '2026-10-27T01:00:00Z'), ('key_id', 'unknown-authority'),
                            ('audience', 'another-recipient'), ('scope_sha256', '0'*64)):
            changed = dict(original); changed[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.check(json.dumps(changed).encode())
        core = {key: value for key, value in original.items() if key != 'signature_b64'}
        message = json.dumps(core, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
        original['signature_b64'] = base64.b64encode(self.key.sign(message).signature).decode()
        with self.assertRaises(ValueError): self.check(json.dumps(original).encode())

    def test_unknown_public_key_and_inactive_authorities_fail(self):
        approval = self.approve()
        for status in ('retired', 'revoked'):
            self.authority['keys'][0]['status'] = status
            with self.subTest(status=status), self.assertRaises(ValueError): self.check(approval)
        self.authority['keys'][0]['status'] = 'active'
        self.authority['keys'][0]['public_key_b64'] = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()
        with self.assertRaises(ValueError): self.check(approval)

    def test_expiry_is_exclusive_issuance_is_inclusive_and_future_is_rejected(self):
        approval = self.approve()
        self.assertEqual(self.check(approval, now=datetime(2026, 10, 27, tzinfo=timezone.utc))['key_id'], 'recipient-lab')
        for instant in (datetime(2026, 10, 26, 23, 59, 59, tzinfo=timezone.utc),
                        datetime(2026, 10, 28, tzinfo=timezone.utc), datetime(2026, 10, 29, tzinfo=timezone.utc)):
            with self.subTest(instant=instant), self.assertRaises(ValueError): self.check(approval, now=instant)
        with self.assertRaises(ValueError): self.check(approval, now=datetime(2026, 10, 27))

    def test_long_lifetime_noncanonical_times_and_wrong_signer_are_not_issued(self):
        for options in (dict(expires_at='2026-10-29T00:00:00Z'), dict(expires_at='2026-10-27T00:00:00Z'),
                        dict(issued_at='2026-10-27T00:00:00+00:00'), dict(issued_at='2026-10-27T00:00:00.0Z'),
                        dict(signing_key=SigningKey.generate())):
            with self.subTest(options=list(options)), self.assertRaises(ValueError): self.approve(**options)

    def test_duplicate_fields_unknown_fields_and_noncanonical_base64_fail(self):
        approval = self.approve()
        with self.assertRaises(ValueError): self.check(approval.replace(b'{', b'{"schema_version":1,', 1))
        original = json.loads(approval)
        for change in ({'embedded_key': self.authority['keys'][0]['public_key_b64']},
                       {'signature_b64': original['signature_b64']+'\n'}, {'schema_version': True}):
            bad = dict(original); bad.update(change)
            with self.subTest(change=list(change)), self.assertRaises(ValueError): self.check(json.dumps(bad).encode())

    def test_authority_policy_contract_and_bounds_are_strict(self):
        original = copy.deepcopy(self.authority)
        for change in ({'maximum_validity_seconds': True}, {'maximum_validity_seconds': 0},
                       {'maximum_validity_seconds': 604801}, {'keys': []}, {'keys': original['keys']*2},
                       {'keys': original['keys']+[dict(original['keys'][0], key_id='alias-lab', status='revoked')]},
                       {'keys': original['keys']*17}, {'schema_version': True}, {'extra': 'not-supported'}):
            bad = dict(original); bad.update(change)
            with self.subTest(change=list(change)), self.assertRaises(ValueError): read_authorities(json.dumps(bad).encode())

    def test_signed_invalid_requirements_and_oversized_inputs_are_rejected(self):
        self.requirements = b'{"schema_version":2,"record_type":"A","required_layers":[],"finding_coverage":{"risk_assessed":true,"team_responded":false}}'
        with self.assertRaises(ValueError): self.approve()
        with self.assertRaises(ValueError): read_authorities(b' '*(1024*1024+1))

    def test_valid_approval_does_not_authorize_forged_report_or_missing_coverage(self):
        changed = copy.deepcopy(self.report); changed['review']['finding_count'] = 0
        with self.assertRaisesRegex(ValueError, 'reproduce'): self.handoff(report=changed)
        reviews = dict(self.reviews); reviews['assessment_data'] = b'{"schema_version":1,"assessments":[]}'
        report = review_logs(*self.inputs, previous_observed_at='2026-10-23T00:00:00Z',
            current_observed_at='2026-10-24T00:00:00Z', record_type='A', include_queue=True, **reviews)
        with self.assertRaisesRegex(ValueError, 'every finding'): self.handoff(report=report, reviews=reviews)

    def test_invalid_approval_fails_before_report_reproduction(self):
        with patch('dns_authorized_handoff.verify_workflow', side_effect=AssertionError('must authenticate first')):
            with self.assertRaises(ValueError): self.handoff(approval=b'{}')

    def test_version_one_requirements_remain_supported_with_explicit_approval(self):
        self.requirements = b'{"schema_version":1,"record_type":"A","required_layers":["risk_review"]}'
        self.assertTrue(self.handoff()['recipient_authority_checked'])

    def test_missing_crypto_fails_closed(self):
        approval = self.approve()
        with patch.dict(sys.modules, {'nacl.signing': None}), patch(
            'dns_authorized_handoff.verify_workflow', side_effect=AssertionError('no unsigned fallback')):
            with self.assertRaises(ValueError): self.handoff(approval=approval)

    @unittest.skipUnless(os.name == 'posix', 'bounded CLI files require POSIX')
    def test_cli_aggregate_output_explicit_time_and_failure_privacy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = dict(report=json.dumps(self.report).encode(), previous=self.inputs[0], current=self.inputs[1],
                scope=self.inputs[2], policy=self.inputs[3], requirements=self.requirements, approval=self.approve(),
                authority=self.authority_data(), assessment=self.reviews['assessment_data'], ownership=self.reviews['ownership_data'])
            paths = {}
            for name, content in data.items():
                paths[name] = root/(name+'.json'); paths[name].write_bytes(content)
            saved = {path: path.read_bytes() for path in paths.values()}
            args = [str(paths[name]) for name in ('report', 'previous', 'current')]
            for flag, name in (('scope','scope'), ('policy','policy'), ('requirements','requirements'),
                ('approval','approval'), ('authority-policy','authority'), ('assessment','assessment'), ('ownership-responses','ownership')):
                args.extend(['--'+flag, str(paths[name])])
            args.extend(['--at', '2026-10-27T12:00:00Z'])
            stdout = StringIO()
            with redirect_stdout(stdout): self.assertEqual(main(args), 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result['verification_time_source'], 'explicit_fixture')
            for private in ('api.lab.example', '198.51.100.', 'cloud-platform', 'public_key_b64', 'signature_b64', str(root)):
                self.assertNotIn(private, stdout.getvalue())
            self.assertEqual(saved, {path: path.read_bytes() for path in saved})
            args[-1] = '2026-10-28T00:00:00Z'; stdout, error = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(error): self.assertEqual(main(args), 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(str(root), error.getvalue())


if __name__ == '__main__':
    unittest.main()
