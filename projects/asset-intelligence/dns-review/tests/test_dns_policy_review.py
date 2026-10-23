import copy
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT))
from dns_policy_review import review, main


class DNSPolicyReviewTests(unittest.TestCase):
    def setUp(self):
        self.before=(PROJECT/'examples/before.json').read_bytes()
        self.after=(PROJECT/'examples/after.json').read_bytes()
        self.scope=(PROJECT/'examples/scope.json').read_bytes()
        self.policy=json.loads((PROJECT/'examples/review-policy.json').read_bytes())

    def review(self):
        return review(self.before,self.after,self.scope,json.dumps(self.policy).encode())

    def test_fixture_mismatch_routes_review_without_assuming_missing_assets(self):
        result=self.review()
        self.assertEqual(result['finding_count'],1)
        finding=result['findings'][0]
        self.assertEqual(finding['hostname'],'web.example.test')
        self.assertEqual(finding['review_team'],'web-platform')
        self.assertEqual(finding['unexpected_addresses'],['192.0.2.11'])
        self.assertEqual(finding['expected_not_observed'],['192.0.2.10'])
        self.assertEqual((finding['current_record'],finding['policy_rule']),(1,1))
        states={item['hostname']:item['status'] for item in result['reviews']}
        self.assertEqual(states['new.example.test'],'no_review_rule')
        self.assertEqual(states['worker.example.test'],'not_observed_current')
        self.assertEqual(states['unseen.example.test'],'not_observed_current')
        self.assertNotIn('severity',finding)

    def test_matching_rule_is_not_a_finding(self):
        self.policy['rules'][0]['expected_addresses']=['192.0.2.11']
        result=self.review()
        self.assertEqual(result['finding_count'],0)
        row=next(item for item in result['reviews'] if item['hostname']=='web.example.test')
        self.assertEqual(row['status'],'matches_reviewed_addresses')

    def test_scope_duplicates_and_invalid_rule_fields_fail(self):
        original=copy.deepcopy(self.policy)
        for field,value in [('hostname','outside.example.test'),('review_team','bad\nteam'),
                            ('expected_addresses',[]),('expected_addresses',['fe80::1%eth0']),
                            ('expected_addresses',['192.0.2.10','192.0.2.10'])]:
            self.policy=copy.deepcopy(original);self.policy['rules'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.review()
        self.policy=original
        self.policy['rules'].append(copy.deepcopy(original['rules'][0]))
        with self.assertRaises(ValueError): self.review()

    def test_duplicate_unknown_and_boolean_schema_fail(self):
        for policy in (b'{"schema_version":1,"schema_version":1}',
                       json.dumps(dict(self.policy,extra='private-fixture-marker')).encode(),
                       json.dumps(dict(self.policy,schema_version=True)).encode()):
            with self.assertRaises(ValueError): review(self.before,self.after,self.scope,policy)

    @unittest.skipUnless(os.name=='posix','private local files require POSIX')
    def test_private_cli_roundtrip_and_no_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); output=root/'review.json'; policy=root/'policy.json'
            policy.write_text(json.dumps(self.policy))
            args=[str(PROJECT/'examples/before.json'),str(PROJECT/'examples/after.json'),
                  '--scope',str(PROJECT/'examples/scope.json'),'--policy',str(policy),'--output',str(output)]
            self.assertEqual(main(args),0)
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            before=output.read_bytes()
            with redirect_stderr(StringIO()): self.assertEqual(main(args),2)
            self.assertEqual(output.read_bytes(),before)
            output.unlink();policy.write_text('private-fixture-marker')
            stdout,stderr=StringIO(),StringIO()
            with redirect_stdout(stdout),redirect_stderr(stderr): self.assertEqual(main(args),2)
            self.assertFalse(output.exists());self.assertEqual(stdout.getvalue(),'')
            self.assertNotIn('private-fixture-marker',stderr.getvalue())


if __name__=='__main__': unittest.main()
