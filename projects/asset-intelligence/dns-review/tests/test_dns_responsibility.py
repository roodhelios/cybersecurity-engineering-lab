import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_responsibility import exercise, fixture
from demo_reviewer_handoff import fixture as reviewed_fixture
from dns_responsibility import (DOMAIN, _message, accept_responsibility, create_acceptance, main, read_acceptors)
from dns_reviewer_handoff import create_attestation, verify_reviewed_handoff
from dns_review import publish
from zeek_dns_workflow import review_logs


class ResponsibilityTests(unittest.TestCase):
    def setUp(self):
        self.report, self.inputs, self.options, self.key = fixture()

    def accept(self, **changes):
        return accept_responsibility(self.report, *self.inputs, **dict(self.options, **changes))

    def sign(self, claim):
        claim = dict(claim)
        claim['signature_b64'] = base64.b64encode(self.key.sign(_message(claim)).signature).decode('ascii')
        return json.dumps(claim).encode()

    def test_explicit_acceptance_has_own_purpose_and_preserves_all_inputs(self):
        before = (self.report, list(self.inputs), dict(self.options))
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            receipt = self.accept()
        self.assertEqual(receipt['status'], 'accepted_review_responsibility')
        self.assertEqual(receipt['workflow_sha256'], hashlib.sha256(self.report).hexdigest())
        self.assertEqual(receipt['acceptance_sha256'], hashlib.sha256(self.options['acceptance']).hexdigest())
        self.assertIn('not a durable assignment registry', receipt['interpretation'])
        self.assertEqual(before, (self.report, self.inputs, self.options))
        self.assertIn(b'dns-review-responsibility', DOMAIN)

    def test_pin_is_independent_and_checked_before_source_reproduction(self):
        for pin in (None, '', 'A'*64, '0'*64):
            with patch('dns_responsibility.verify_reviewed_handoff', side_effect=AssertionError('must not reproduce')):
                with self.assertRaises(ValueError): self.accept(expected_acceptance_policy_sha256=pin)

    def test_signed_wrong_purpose_team_finding_audience_and_context_fail(self):
        claim = json.loads(self.options['acceptance'])
        for field, changed in dict(action='approve-remediation', team='another-team', finding_sha256='0'*64,
                                   audience='other-recipient', workflow_sha256='0'*64,
                                   authority_policy_sha256='0'*64, key_id='unknown-key').items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.accept(acceptance=self.sign(dict(claim, **{field: changed})))
        # Re-encoding an otherwise equivalent workflow is a different acceptance context.
        with self.assertRaises(ValueError):
            accept_responsibility(self.report+b'\n', *self.inputs, **self.options)

    def test_signature_time_boundaries_and_naive_clock_fail(self):
        claim = json.loads(self.options['acceptance'])
        bad = dict(claim, signature_b64='A'*88)
        with self.assertRaises(ValueError): self.accept(acceptance=json.dumps(bad).encode())
        for delta in (-1, 3600):
            with self.assertRaises(ValueError): self.accept(now=self.options['now']+timedelta(seconds=delta))
        with self.assertRaises(ValueError): self.accept(now=self.options['now'].replace(tzinfo=None))
        for changed in ({'expires_at':'2026-10-28T13:00:01Z'}, {'expires_at':claim['accepted_at']},
                        {'accepted_at':'2026-10-28T12:00:00+00:00'}):
            with self.assertRaises(ValueError): self.accept(acceptance=self.sign(dict(claim, **changed)))

    def test_reviewer_attestations_and_recipient_approval_cannot_be_skipped(self):
        for field in ('attestations', 'approval', 'requirements', 'assessment_data', 'ownership_data'):
            with self.subTest(field=field), self.assertRaises((ValueError, TypeError, KeyError)):
                self.accept(**{field:b'{}'})
        with self.assertRaises(ValueError): self.accept(acceptance=self.options['approval'])
        with self.assertRaises(ValueError): self.accept(acceptance=self.options['attestations'])

    def test_acceptance_cannot_precede_verified_team_review(self):
        policy=json.loads(self.options['acceptance_policy']);policy['maximum_validity_seconds']=604800
        data=json.dumps(policy).encode();claim=json.loads(self.options['acceptance'])
        claim.update(accepted_at='2026-10-24T00:00:00Z',authority_policy_sha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ValueError,'accepted team response'):
            self.accept(acceptance_policy=data,expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest(),
                        acceptance=self.sign(claim))

    def test_old_reviewer_authority_is_not_an_acceptance_policy(self):
        data=self.options['reviewer_policy']
        with self.assertRaises(ValueError):
            self.accept(acceptance_policy=data, expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest())

    def test_revoked_retired_wrong_grant_and_policy_replacement_fail(self):
        original = json.loads(self.options['acceptance_policy'])
        for case in ('revoked','retired','grant','team','audience'):
            policy=json.loads(json.dumps(original))
            if case in ('revoked','retired'): policy['keys'][0]['status']=case
            elif case=='grant': policy['keys'][0]['grants'][0]['finding_sha256']='0'*64
            elif case=='team': policy['keys'][0]['grants'][0]['team']='other-team'
            else: policy['audience']='other-recipient'
            data=json.dumps(policy).encode(); claim=json.loads(self.options['acceptance'])
            claim['authority_policy_sha256']=hashlib.sha256(data).hexdigest()
            if case=='audience': claim['audience']='other-recipient'
            with self.assertRaises(ValueError):
                self.accept(acceptance_policy=data, expected_acceptance_policy_sha256=hashlib.sha256(data).hexdigest(),
                            acceptance=self.sign(claim))

    def test_valid_signed_decline_cannot_become_accepted_responsibility(self):
        report, inputs, options, keys=reviewed_fixture()
        ownership=json.loads(options['ownership_data']); ownership['responses'][0]['decision']='declined'
        data=json.dumps(ownership).encode()
        workflow=review_logs(*inputs, previous_observed_at='2026-10-23T00:00:00Z',
            current_observed_at='2026-10-24T00:00:00Z', record_type='A', include_queue=True,
            assessment_data=options['assessment_data'], ownership_data=data)
        report=json.dumps(workflow).encode(); bundle=json.loads(options['attestations'])
        proof=next(x for x in bundle['attestations'] if x['role']=='team-response')
        replacement=create_attestation(ownership['responses'][0], finding_sha256=proof['finding_sha256'],
            role='team-response', team=ownership['responses'][0]['team'], authority_data=options['reviewer_policy'],
            signing_key=keys['team-response'], key_id='team-response-lab', issued_at='2026-10-28T00:00:00Z',
            expires_at='2026-10-29T00:00:00Z')
        bundle['attestations']=[replacement if x['role']=='team-response' else x for x in bundle['attestations']]
        options.update(ownership_data=data, attestations=json.dumps(bundle).encode())
        self.assertTrue(verify_reviewed_handoff(report,*inputs,**options)['reviewer_authority_checked'])
        claim=json.loads(self.options['acceptance']); claim['workflow_sha256']=hashlib.sha256(report).hexdigest()
        with self.assertRaisesRegex(ValueError, 'accepted team response'):
            accept_responsibility(report,*inputs,**dict(options,acceptance=self.sign(claim),
                acceptance_policy=self.options['acceptance_policy'],
                expected_acceptance_policy_sha256=self.options['expected_acceptance_policy_sha256']))

    def test_policy_and_claim_schema_bounds_fail(self):
        for data in (b'{}',b'[]',b'{"x":NaN}',b'x'*(1024*1024+1)):
            with self.assertRaises(ValueError): read_acceptors(data)
            with self.assertRaises(ValueError): self.accept(acceptance=data)
        for case in ('version','duplicate-key','duplicate-grant','extra','lifetime','grants'):
            policy=json.loads(self.options['acceptance_policy'])
            if case=='version': policy['schema_version']=True
            elif case=='duplicate-key': policy['keys']*=2
            elif case=='duplicate-grant': policy['keys'][0]['grants']*=2
            elif case=='extra': policy['keys'][0]['private_key']='dummy'
            elif case=='lifetime': policy['maximum_validity_seconds']=True
            else: policy['keys'][0]['grants']=[]
            with self.assertRaises(ValueError): read_acceptors(json.dumps(policy).encode())

    def test_cli_retains_private_receipt_only_after_all_checks(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name); output=root/'receipt.json'
            data=dict(report=self.report,previous=self.inputs[0],current=self.inputs[1],scope=self.inputs[2],
                policy=self.inputs[3],requirements=self.options['requirements'],approval=self.options['approval'],
                authority_policy=self.options['authority_policy'],reviewer_policy=self.options['reviewer_policy'],
                attestations=self.options['attestations'],assessment=self.options['assessment_data'],
                ownership_responses=self.options['ownership_data'],acceptance=self.options['acceptance'],
                acceptance_policy=self.options['acceptance_policy'])
            paths={k:root/(k+'.json') for k in data}
            for k,v in data.items(): publish(paths[k],v.decode())
            args=[str(paths[k]) for k in ('report','previous','current')]
            for k in data:
                if k not in ('report','previous','current'):args+=['--'+k.replace('_','-'),str(paths[k])]
            args+=['--output',str(output),'--at','2026-10-28T12:00:00Z',
                   '--expected-reviewer-policy-sha256',self.options['expected_reviewer_policy_sha256'],
                   '--expected-acceptance-policy-sha256',self.options['expected_acceptance_policy_sha256']]
            captured=StringIO()
            with redirect_stdout(captured): self.assertEqual(main(args),0)
            for value in ('web-platform','web.example.test',str(root),'signature_b64','acceptance-lab'):
                self.assertNotIn(value,captured.getvalue())
            self.assertEqual(output.stat().st_mode&0o777,0o600); before=output.read_bytes()
            with redirect_stderr(StringIO()):self.assertEqual(main(args),2)
            self.assertEqual(output.read_bytes(),before)
            self.assertEqual(data,{k:p.read_bytes() for k,p in paths.items()})
            output.unlink();paths['acceptance'].write_bytes(b'{}');captured=StringIO()
            with redirect_stdout(captured),redirect_stderr(StringIO()):self.assertEqual(main(args),2)
            self.assertEqual(captured.getvalue(),'');self.assertFalse(output.exists())

    def test_complete_fresh_process_walkthrough(self):
        run=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'demo_responsibility.py')],
                           capture_output=True,text=True,timeout=20)
        self.assertEqual(run.returncode,0,run.stderr)
        result=json.loads(run.stdout);self.assertEqual(result['accepted_findings'],1)
        self.assertEqual(result['negative_cases_rejected'],3);self.assertTrue(result['inputs_unchanged'])


if __name__=='__main__':unittest.main()
