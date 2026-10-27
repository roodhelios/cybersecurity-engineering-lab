import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from zeek_dns_workflow import review_logs
from zeek_dns_workflow_verify import main, verify_workflow


class FindingCoverageRequirementsTests(unittest.TestCase):
    def setUp(self):
        self.inputs=[(ROOT/'examples'/name).read_bytes() for name in
                     ('zeek-dns-before.jsonl','zeek-dns.jsonl','scope.json','review-policy.json')]
        self.options={'assessment_data':(ROOT/'examples/risk-assessments.json').read_bytes(),
                      'ownership_data':(ROOT/'examples/ownership-responses.json').read_bytes()}
        self.policy={'schema_version':2,'record_type':'A',
                     'required_layers':['risk_review','ownership_review','review_queue'],
                     'finding_coverage':{'risk_assessed':True,'team_responded':True}}

    def report(self,**options):
        return review_logs(*self.inputs,previous_observed_at='2026-10-23T00:00:00Z',
                          current_observed_at='2026-10-24T00:00:00Z',record_type='A',include_queue=True,**options)

    def verify(self,report,policy=None,**options):
        return verify_workflow(json.dumps(report).encode(),*self.inputs,
                               requirements_data=json.dumps(self.policy if policy is None else policy).encode(),**options)

    def test_complete_fixture_meets_coverage_without_network_or_mutation(self):
        report=self.report(**self.options);before=copy.deepcopy(report)
        with patch('socket.socket',side_effect=AssertionError('network forbidden')):
            result=self.verify(report,**self.options)
        self.assertTrue(result['requirements_checked']);self.assertEqual(result['finding_count'],1)
        self.assertEqual(report,before)

    def test_present_but_empty_risk_or_response_fails_only_when_coverage_required(self):
        for field,empty in (('assessment_data',b'{"schema_version":1,"assessments":[]}'),
                            ('ownership_data',b'{"schema_version":1,"responses":[]}')):
            options=dict(self.options);options[field]=empty;report=self.report(**options)
            legacy={key:value for key,value in self.policy.items() if key!='finding_coverage'};legacy['schema_version']=1
            self.assertEqual(self.verify(report,legacy,**options)['status'],'workflow_reproduced')
            with self.subTest(field=field),self.assertRaises(ValueError):self.verify(report,**options)

    def test_false_flags_keep_presence_only_behavior_and_decline_is_a_response(self):
        options={'assessment_data':b'{"schema_version":1,"assessments":[]}',
                 'ownership_data':b'{"schema_version":1,"responses":[]}'}
        policy=copy.deepcopy(self.policy);policy['finding_coverage']={'risk_assessed':False,'team_responded':False}
        self.assertTrue(self.verify(self.report(**options),policy,**options)['requirements_checked'])
        options=dict(self.options);responses=json.loads(options['ownership_data'])
        responses['responses'][0]['decision']='declined';options['ownership_data']=json.dumps(responses).encode()
        self.assertTrue(self.verify(self.report(**options),**options)['requirements_checked'])

    def test_empty_finding_set_is_complete_but_still_requires_layers(self):
        inputs=[self.inputs[0],self.inputs[0],*self.inputs[2:]]
        options={'assessment_data':b'{"schema_version":1,"assessments":[]}',
                 'ownership_data':b'{"schema_version":1,"responses":[]}'}
        report=review_logs(*inputs,previous_observed_at='2026-10-23T00:00:00Z',
                          current_observed_at='2026-10-24T00:00:00Z',record_type='A',include_queue=True,**options)
        self.assertEqual(report['review']['finding_count'],0)
        result=verify_workflow(json.dumps(report).encode(),*inputs,
            requirements_data=json.dumps(self.policy).encode(),**options)
        self.assertTrue(result['requirements_checked'])

    def test_strict_contract_and_layer_dependencies(self):
        invalid=[]
        for value in ({},[],{'risk_assessed':True},{'risk_assessed':1,'team_responded':True},
                      {'risk_assessed':True,'team_responded':'yes'},
                      {'risk_assessed':True,'team_responded':True,'extra':False}):
            policy=copy.deepcopy(self.policy);policy['finding_coverage']=value;invalid.append(policy)
        for layer in ('risk_review','ownership_review'):
            policy=copy.deepcopy(self.policy);policy['required_layers'].remove(layer);invalid.append(policy)
        invalid.extend([dict(self.policy,schema_version=3),dict(self.policy,schema_version=True)])
        for policy in invalid:
            with self.subTest(policy=policy),self.assertRaises(ValueError):self.verify(self.report(**self.options),policy,**self.options)

    def test_full_reproduction_precedes_coverage_evaluation(self):
        report=self.report(**self.options);report['risk_review']['findings'][0]['assessment_status']='unassessed'
        with patch('zeek_dns_workflow_verify.check_requirements') as check:
            with self.assertRaisesRegex(ValueError,'did not reproduce'):self.verify(report,**self.options)
            check.assert_not_called()

    @unittest.skipUnless(os.name=='posix','bounded file readers require POSIX')
    def test_cli_incomplete_coverage_has_no_success_or_private_detail(self):
        options=dict(self.options);options['assessment_data']=b'{"schema_version":1,"assessments":[]}'
        docs=[json.dumps(self.report(**options)).encode(),*self.inputs,json.dumps(self.policy).encode(),
              options['assessment_data'],options['ownership_data']]
        with tempfile.TemporaryDirectory() as name:
            files=[]
            for index,data in enumerate(docs):
                p=Path(name)/str(index);p.write_bytes(data);files.append(p)
            args=[str(files[0]),str(files[1]),str(files[2]),'--scope',str(files[3]),'--policy',str(files[4]),
                  '--requirements',str(files[5]),'--assessment',str(files[6]),'--ownership-responses',str(files[7])]
            out,error=StringIO(),StringIO()
            with redirect_stdout(out),redirect_stderr(error):self.assertEqual(main(args),2)
            self.assertEqual(out.getvalue(),'')
            for private in (name,'web.example.test','risk assessment'):self.assertNotIn(private,error.getvalue())
            self.assertEqual([p.read_bytes() for p in files],docs)


if __name__=='__main__':unittest.main()
