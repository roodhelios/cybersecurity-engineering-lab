import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from demo_reviewer_handoff import exercise, fixture
from dns_authorized_handoff import verify_authorized_workflow
from dns_review import publish
from dns_reviewer_handoff import create_attestation, read_reviewers, verify_reviewed_handoff, main
from zeek_dns_workflow import review_logs

try:
    import nacl.signing
except ImportError:
    nacl = None


@unittest.skipUnless(os.name == 'posix' and nacl is not None, 'requires POSIX and optional PyNaCl')
class ReviewerHandoffTests(unittest.TestCase):
    def setUp(self):
        self.report, self.inputs, self.options, self.keys = fixture()

    def verify(self, report=None, **changes):
        return verify_reviewed_handoff(report or self.report, *self.inputs, **dict(self.options, **changes))

    def trusted_policy(self, policy):
        data = json.dumps(policy).encode()
        return dict(reviewer_policy=data, expected_reviewer_policy_sha256=hashlib.sha256(data).hexdigest())

    def test_complete_native_verification_preserves_claims_and_inputs_without_keys(self):
        saved = list(self.inputs); options = dict(self.options); del self.keys
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.verify()
        self.assertTrue(result['recipient_authority_checked'])
        self.assertTrue(result['reviewer_authority_checked'])
        self.assertEqual(result['reviewer_authority']['attestation_count'], 2)
        self.assertEqual(self.inputs, saved); self.assertEqual(self.options, options)
        self.assertEqual(json.loads(self.report)['ownership_review']['findings'][0]['ownership_response']['status'],
                         'accepted_claim')
        self.assertNotIn('web.example.test', json.dumps(result))

    def test_existing_handoff_accepts_revised_claim_but_reviewer_signature_rejects_it(self):
        for field in ('assessment_data', 'ownership_data'):
            changed = json.loads(self.options[field])
            if field == 'assessment_data': changed['assessments'][0]['business_impact'] = 'low'
            else: changed['responses'][0]['decision'] = 'declined'
            changes = {field: json.dumps(changed).encode()}
            reviews = {key: changes.get(key, self.options[key]) for key in ('assessment_data', 'ownership_data')}
            report = json.dumps(review_logs(*self.inputs, previous_observed_at='2026-10-23T00:00:00Z',
                current_observed_at='2026-10-24T00:00:00Z', record_type='A', include_queue=True, **reviews)).encode()
            legacy = {key: self.options[key] for key in ('requirements', 'approval', 'authority_policy', 'now')}
            self.assertEqual(verify_authorized_workflow(report, *self.inputs, **legacy, **reviews)['finding_count'], 1)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'record or claimed chronology'):
                self.verify(report, **changes)

    def test_exact_finding_role_and_routed_team_grants_are_required(self):
        for field, value in (('finding_sha256', '0'*64), ('role', 'risk'), ('team', 'other-team')):
            policy = json.loads(self.options['reviewer_policy'])
            policy['keys'][1]['grants'][0][field] = value
            if field == 'role': policy['keys'][1]['grants'][0]['team'] = None
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify(**self.trusted_policy(policy))

    def test_missing_duplicate_extra_and_cross_role_attestations_fail(self):
        bundle = json.loads(self.options['attestations'])
        first, second = bundle['attestations']
        for values in ([first], [first, first], [first, second, first],
                       [dict(first, role='team-response'), second], [dict(first, finding_sha256='0'*64), second]):
            data = json.dumps(dict(bundle, attestations=values)).encode()
            with self.subTest(size=len(values)), self.assertRaises(ValueError): self.verify(attestations=data)

    def test_tampered_signed_fields_and_wrong_private_signer_fail(self):
        bundle = json.loads(self.options['attestations'])
        for field, value in (('audience', 'another-recipient'), ('attestation_type', 'dns-recipient-requirements'),
                             ('signature_b64', 'A'*88), ('review_record_sha256', '0'*64),
                             ('schema_version', True), ('key_id', 'unknown-lab')):
            changed = json.loads(json.dumps(bundle)); changed['attestations'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(attestations=json.dumps(changed).encode())
        record = json.loads(self.options['assessment_data'])['assessments'][0]
        with self.assertRaises(ValueError):
            create_attestation(record, finding_sha256=bundle['attestations'][0]['finding_sha256'], role='risk',
                team=None, authority_data=self.options['reviewer_policy'], signing_key=self.keys['team-response'],
                key_id='risk-lab', issued_at='2026-10-28T00:00:00Z', expires_at='2026-10-29T00:00:00Z')

    def test_pin_is_mandatory_and_checked_before_workflow(self):
        for pin in (None, '', '0'*64, 'A'*64):
            with patch('dns_reviewer_handoff.verify_authorized_workflow', side_effect=AssertionError('workflow read')):
                with self.subTest(pin=pin), self.assertRaises(ValueError):
                    self.verify(expected_reviewer_policy_sha256=pin)
        with patch('dns_reviewer_handoff.verify_authorized_workflow', side_effect=AssertionError('workflow read')):
            with self.assertRaises(ValueError): self.verify(reviewer_policy=self.options['reviewer_policy']+b'\n')

    def test_retired_revoked_expired_future_and_recipient_policy_mismatch_fail(self):
        for status in ('retired', 'revoked'):
            policy = json.loads(self.options['reviewer_policy']); policy['keys'][0]['status'] = status
            with self.subTest(status=status), self.assertRaises(ValueError): self.verify(**self.trusted_policy(policy))
        # Recipient approval lasts a day; shorten only reviewer validity to test its own boundary.
        bundle = json.loads(self.options['attestations'])
        proof = bundle['attestations'][0]
        record = json.loads(self.options['assessment_data'])['assessments'][0]
        bundle['attestations'][0] = create_attestation(record, finding_sha256=proof['finding_sha256'], role='risk',
            team=None, authority_data=self.options['reviewer_policy'], signing_key=self.keys['risk'], key_id='risk-lab',
            issued_at='2026-10-28T00:00:00Z', expires_at='2026-10-28T01:00:00Z')
        with self.assertRaises(ValueError): self.verify(attestations=json.dumps(bundle).encode())
        bundle['attestations'][0] = create_attestation(record, finding_sha256=proof['finding_sha256'], role='risk',
            team=None, authority_data=self.options['reviewer_policy'], signing_key=self.keys['risk'], key_id='risk-lab',
            issued_at='2026-10-28T13:00:00Z', expires_at='2026-10-28T14:00:00Z')
        with self.assertRaises(ValueError): self.verify(attestations=json.dumps(bundle).encode())
        with self.assertRaises(ValueError): self.verify(now=datetime(2026, 10, 27, 23, tzinfo=timezone.utc))
        policy = json.loads(self.options['reviewer_policy']); policy['audience'] = 'other-recipient'
        with self.assertRaises(ValueError): self.verify(**self.trusted_policy(policy))

    def test_attestation_cannot_precede_claimed_review_time(self):
        record = json.loads(self.options['ownership_data'])['responses'][0]
        bundle = json.loads(self.options['attestations'])
        with self.assertRaises(ValueError):
            create_attestation(record, finding_sha256=bundle['attestations'][1]['finding_sha256'], role='team-response',
                team=record['team'], authority_data=self.options['reviewer_policy'], signing_key=self.keys['team-response'],
                key_id='team-response-lab', issued_at='2026-10-24T00:00:00Z', expires_at='2026-10-25T00:00:00Z')

    def test_policy_validates_all_grants_keys_types_and_limits(self):
        for case in ('duplicate-key', 'duplicate-grant', 'role', 'team', 'keys', 'lifetime', 'version', 'extra', 'grants'):
            policy = json.loads(self.options['reviewer_policy'])
            if case == 'duplicate-key': policy['keys'].append(dict(policy['keys'][0], key_id='third-key'))
            elif case == 'duplicate-grant': policy['keys'][0]['grants'] *= 2
            elif case == 'role': policy['keys'][0]['grants'][0]['role'] = 'administrator'
            elif case == 'team': policy['keys'][0]['grants'][0]['team'] = 'not-null'
            elif case == 'keys': policy['keys'] = []
            elif case == 'lifetime': policy['maximum_validity_seconds'] = True
            elif case == 'version': policy['schema_version'] = True
            elif case == 'extra': policy['keys'][1]['private_seed'] = 'dummy-placeholder'
            else: policy['keys'][1]['grants'] *= 2001
            with self.subTest(case=case), self.assertRaises(ValueError): read_reviewers(json.dumps(policy).encode())

    def test_bundle_json_bounds_types_and_incomplete_review_layers_fail(self):
        for data in (b'[]', b'{}', b'{"schema_version":1,"schema_version":1,"attestations":[]}',
                     b'{"x":NaN}', b'x'*(1024*1024+1), b'{"schema_version":true,"attestations":[]}'):
            with self.subTest(size=len(data)), self.assertRaises(ValueError): self.verify(attestations=data)
        with self.assertRaises(ValueError): self.verify(assessment_data=None)
        with self.assertRaises(ValueError): self.verify(ownership_data=None)
        with self.assertRaises(ValueError): self.verify(assessment_data=b'{"schema_version":1,"assessments":[]}')

    def test_cli_is_private_aggregate_only_and_inputs_stay_unchanged(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            data = dict(report=self.report, previous=self.inputs[0], current=self.inputs[1], scope=self.inputs[2],
                policy=self.inputs[3], requirements=self.options['requirements'], approval=self.options['approval'],
                authority=self.options['authority_policy'], reviewers=self.options['reviewer_policy'],
                attestations=self.options['attestations'], assessment=self.options['assessment_data'],
                ownership=self.options['ownership_data'])
            paths = {key: root/(key+'.json') for key in data}
            for key, value in data.items(): publish(paths[key], value.decode())
            args = [str(paths[key]) for key in ('report', 'previous', 'current')]
            for flag, key in (('scope','scope'), ('policy','policy'), ('requirements','requirements'),
                ('approval','approval'), ('authority-policy','authority'), ('reviewer-policy','reviewers'),
                ('attestations','attestations'), ('assessment','assessment'), ('ownership-responses','ownership')):
                args.extend(['--'+flag, str(paths[key])])
            args.extend(['--expected-reviewer-policy-sha256', self.options['expected_reviewer_policy_sha256'],
                         '--at', '2026-10-28T12:00:00Z'])
            output = StringIO()
            with redirect_stdout(output): self.assertEqual(main(args), 0)
            result = json.loads(output.getvalue()); self.assertEqual(result['reviewer_authority']['attestation_count'], 2)
            for private in ('web.example.test', 'web-platform', '192.0.2.11', str(root), 'signature_b64'):
                self.assertNotIn(private, output.getvalue())
            self.assertEqual(data, {key: path.read_bytes() for key, path in paths.items()})
            paths['attestations'].write_bytes(b'{}'); error = StringIO(); output = StringIO()
            with redirect_stdout(output), redirect_stderr(error): self.assertEqual(main(args), 2)
            self.assertEqual(output.getvalue(), ''); self.assertNotIn(str(root), error.getvalue())

    def test_complete_exercise(self):
        result = exercise()
        self.assertEqual(result['status'], 'reviewer_handoff_exercise_passed')
        self.assertEqual(result['negative_cases_rejected'], 4)
        self.assertTrue(result['inputs_unchanged'])


if __name__ == '__main__':
    unittest.main()
