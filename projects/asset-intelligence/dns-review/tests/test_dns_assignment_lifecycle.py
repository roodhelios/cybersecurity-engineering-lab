"""Native signature and serialized local release/successor boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from demo_responsibility import fixture
from demo_assignment_lifecycle import exercise
from dns_assignment_journal import AssignmentJournal
from dns_assignment_lifecycle import LifecycleJournal,create_release,main
from dns_authorized_handoff import _instant
from dns_responsibility import accept_responsibility,create_acceptance


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.report,self.inputs,self.options,self.key=fixture()
        temporary=tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.root=Path(temporary.name)
        self.journal=LifecycleJournal.create(self.root/'lifecycle.sqlite')
        self.journal.register(self.report,*self.inputs,**self.options)
        self.target=accept_responsibility(self.report,*self.inputs,**self.options)
        self.release=create_release(self.target,signing_key=self.key,released_at='2026-10-28T12:02:00Z',expires_at='2026-10-28T12:03:00Z')
        self.at=_instant('2026-10-28T12:02:00Z')
        self.policy=dict(acceptance_policy=self.options['acceptance_policy'],expected_acceptance_policy_sha256=self.options['expected_acceptance_policy_sha256'],now=self.at)

    def successor(self,accepted='2026-10-28T12:02:00Z',expires='2026-10-28T12:30:00Z',**changes):
        data=create_acceptance(self.report,authority_data=self.options['acceptance_policy'],signing_key=self.key,
            key_id=self.target['key_id'],finding_sha256=self.target['finding_sha256'],team=self.target['team'],accepted_at=accepted,expires_at=expires)
        options=dict(self.options,acceptance=data,now=self.at,expected_predecessor=self.target['acceptance_sha256'],
            expected_release_sha256=hashlib.sha256(self.release).hexdigest())
        options.update(changes)
        return self.journal.register(self.report,*self.inputs,**options)

    def test_release_reopen_and_fresh_successor_before_old_expiry(self):
        self.assertTrue(self.journal.release(self.release,**self.policy)['appended'])
        self.journal=LifecycleJournal(self.journal.path)
        self.assertEqual(self.journal.summary(**self.policy)['released'],1)
        self.assertFalse(self.journal.release(self.release,**self.policy)['appended'])
        self.assertTrue(self.successor()['appended'])
        summary=self.journal.summary(**self.policy)
        self.assertEqual((summary['event_count'],summary['release_count'],summary['released'],summary['eligible_for_reverification']),(2,1,0,1))

    def test_release_does_not_grant_a_successor_or_reactivate_old_claim(self):
        self.journal.release(self.release,**self.policy)
        for operation in (lambda:self.journal.register(self.report,*self.inputs,**dict(self.options,now=self.at)),
            lambda:self.successor(expected_release_sha256=None),lambda:self.successor(expected_release_sha256='0'*64),
            lambda:self.successor(accepted='2026-10-28T12:01:00Z')):
            with self.assertRaises(ValueError): operation()
        self.assertEqual(self.journal.summary(**self.policy)['event_count'],1)

    def test_wrong_key_purpose_target_or_signature_cannot_release(self):
        from nacl.signing import SigningKey
        before=self.journal.path.read_bytes()
        changes=[dict(action='accept-dns-review-responsibility'),dict(audience='other'),dict(finding_sha256='0'*64),
            dict(acceptance_sha256='0'*64),dict(workflow_sha256='0'*64),dict(signature_b64='A'*88)]
        for change in changes:
            claim=dict(json.loads(self.release),**change)
            with self.assertRaises(ValueError): self.journal.release(json.dumps(claim).encode(),**self.policy)
        other=create_release(self.target,signing_key=SigningKey.generate(),released_at='2026-10-28T12:02:00Z',expires_at='2026-10-28T12:03:00Z')
        with self.assertRaises(ValueError): self.journal.release(other,**self.policy)
        self.assertEqual(self.journal.path.read_bytes(),before)

    def test_current_policy_pin_revocation_and_expiry_are_required(self):
        policy=json.loads(self.policy['acceptance_policy']); policy['keys'][0]['status']='revoked'; raw=json.dumps(policy).encode()
        for changes in ({'expected_acceptance_policy_sha256':'0'*64},
            {'acceptance_policy':raw,'expected_acceptance_policy_sha256':hashlib.sha256(raw).hexdigest()},
            {'now':_instant('2026-10-28T12:03:00Z')},{'now':_instant('2026-10-28T12:01:59Z')}):
            with self.assertRaises(ValueError): self.journal.release(self.release,**dict(self.policy,**changes))
        self.assertEqual(self.journal.summary(**self.policy)['release_count'],0)

    def test_old_release_cannot_release_a_later_acceptance(self):
        self.journal.release(self.release,**self.policy); self.successor()
        with self.assertRaises(ValueError): self.journal.release(self.release,**self.policy)
        self.assertEqual(self.journal.summary(**self.policy)['eligible_for_reverification'],1)

    def test_new_registration_still_requires_complete_original_verification(self):
        self.journal.release(self.release,**self.policy)
        missing=json.loads(self.options['attestations']); missing['attestations'].pop()
        with self.assertRaises(ValueError): self.successor(attestations=json.dumps(missing).encode())
        self.assertEqual(self.journal.summary(**self.policy)['event_count'],1)

    def test_two_successors_after_release_only_one_wins(self):
        self.journal.release(self.release,**self.policy)
        def attempt(expires):
            try: self.successor(expires=expires); return 'registered'
            except ValueError: return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(attempt,['2026-10-28T12:30:00Z','2026-10-28T12:31:00Z']))
        self.assertCountEqual(result,['registered','conflict'])

    def test_v1_store_and_checkpoint_are_not_silently_reinterpreted(self):
        old=AssignmentJournal.create(self.root/'old.sqlite')
        with self.assertRaises(ValueError): LifecycleJournal(old.path).summary(**self.policy)
        with self.assertRaises(ValueError): AssignmentJournal(self.journal.path).summary(**self.policy)

    def test_edited_release_linkage_and_sql_update_rejected(self):
        self.journal.release(self.release,**self.policy)
        with sqlite3.connect(self.journal.path) as connection:
            with self.assertRaises(sqlite3.IntegrityError): connection.execute("UPDATE release_event SET release_sha256='bad'")
            connection.execute('DROP TRIGGER release_no_update'); connection.execute("UPDATE release_event SET acceptance_sha256=?",('0'*64,))
        with self.assertRaises(ValueError): self.journal.summary(**self.policy)

    def test_cli_aggregate_receipt_and_fixed_failure(self):
        release=self.root/'release.json'; release.write_bytes(self.release)
        policy=self.root/'policy.json'; policy.write_bytes(self.policy['acceptance_policy'])
        args=['release',str(self.journal.path),'--release',str(release),'--acceptance-policy',str(policy),
            '--expected-acceptance-policy-sha256',self.policy['expected_acceptance_policy_sha256'],'--at','2026-10-28T12:02:00Z']
        out,err=StringIO(),StringIO()
        with redirect_stdout(out),redirect_stderr(err): self.assertEqual(main(args),0)
        self.assertEqual(json.loads(out.getvalue())['release_count'],1)
        self.assertNotIn(self.target['acceptance_sha256'],out.getvalue()); self.assertNotIn(str(self.root),out.getvalue())
        args[-1]='2026-10-28T12:03:00Z'
        with redirect_stderr(err): self.assertEqual(main(args),2)
        self.assertNotIn(str(self.root),err.getvalue())

    def test_complete_temporary_walkthrough(self):
        result=exercise(); self.assertEqual(result['acceptance_events'],2); self.assertEqual(result['negative_cases_rejected'],3)

    def test_cli_successor_requires_release_and_complete_original_inputs(self):
        self.journal.release(self.release,**self.policy)
        successor=create_acceptance(self.report,authority_data=self.options['acceptance_policy'],signing_key=self.key,
            key_id=self.target['key_id'],finding_sha256=self.target['finding_sha256'],team=self.target['team'],
            accepted_at='2026-10-28T12:02:00Z',expires_at='2026-10-28T12:30:00Z')
        data=dict(report=self.report,previous=self.inputs[0],current=self.inputs[1],scope=self.inputs[2],policy=self.inputs[3],
            requirements=self.options['requirements'],approval=self.options['approval'],authority_policy=self.options['authority_policy'],
            reviewer_policy=self.options['reviewer_policy'],attestations=self.options['attestations'],
            assessment=self.options['assessment_data'],ownership_responses=self.options['ownership_data'],
            acceptance=successor,acceptance_policy=self.options['acceptance_policy'])
        args=['register',str(self.journal.path)]
        for name,value in data.items():
            path=self.root/(name+'.json'); path.write_bytes(value); args+=['--'+name.replace('_','-'),str(path)]
        args+=['--expected-reviewer-policy-sha256',self.options['expected_reviewer_policy_sha256'],
            '--expected-acceptance-policy-sha256',self.options['expected_acceptance_policy_sha256'],
            '--expected-predecessor',self.target['acceptance_sha256'],
            '--expected-release-sha256',hashlib.sha256(self.release).hexdigest(),'--at','2026-10-28T12:02:00Z']
        out=StringIO()
        with redirect_stdout(out): self.assertEqual(main(args),0)
        self.assertEqual(json.loads(out.getvalue())['event_count'],2)

    def test_writer_lock_and_release_event_cap_fail_without_append(self):
        with sqlite3.connect(self.journal.path) as writer:
            writer.execute('BEGIN IMMEDIATE')
            with self.assertRaises(sqlite3.OperationalError): self.journal.release(self.release,**self.policy)
        with patch('dns_assignment_lifecycle.MAX_EVENTS',0):
            with self.assertRaises(ValueError): self.journal.release(self.release,**self.policy)
        self.assertEqual(self.journal.summary(**self.policy)['release_count'],0)


if __name__=='__main__': unittest.main()
