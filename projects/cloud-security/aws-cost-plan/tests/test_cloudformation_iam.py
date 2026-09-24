from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_cost_plan.cloudformation_iam import (
    CloudFormationPolicyError,
    review_cloudformation_template,
)
from aws_cost_plan.cloudformation_iam_cli import main


class CloudFormationIamTests(unittest.TestCase):
    def test_reviews_role_policy_and_managed_policy(self) -> None:
        template = {
            "Resources": {
                "LabRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [
                    {"PolicyName": "Broad", "PolicyDocument": {
                        "Version": "2012-10-17", "Statement": {
                            "Effect": "Allow", "Action": "s3:*", "Resource": "*"
                        }
                    }}
                ]}},
                "LabManagedPolicy": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
                    "PolicyDocument": {
                        "Version": "2012-10-17", "Statement": {
                            "Effect": "Allow", "Action": "iam:PassRole",
                            "Resource": "arn:aws:iam::111122223333:role/lab"
                        }
                    }
                }},
                "Unrelated": {"Type": "AWS::S3::Bucket", "Properties": {}},
            }
        }
        findings = review_cloudformation_template(template)
        self.assertEqual(
            [(item.logical_id, item.code) for item in findings],
            [("LabRole", "IAM001"), ("LabRole", "IAM002"),
             ("LabManagedPolicy", "IAM003")],
        )

    def test_dynamic_policy_expression_fails_closed(self) -> None:
        template = {"Resources": {"Dynamic": {
            "Type": "AWS::IAM::ManagedPolicy", "Properties": {
                "PolicyDocument": {"Fn::Transform": "not evaluated"}
            }
        }}}
        with self.assertRaisesRegex(CloudFormationPolicyError, "unsupported policy fields"):
            review_cloudformation_template(template)

    def test_malformed_role_inline_policy_fails_closed(self) -> None:
        with self.assertRaisesRegex(CloudFormationPolicyError, "Policies must be a list"):
            review_cloudformation_template({"Resources": {"Role": {
                "Type": "AWS::IAM::Role", "Properties": {"Policies": {}}
            }}})

    def test_cli_emits_findings_and_uses_nonzero_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text(json.dumps({"Resources": {"Broad": {
                "Type": "AWS::IAM::Policy", "Properties": {
                    "PolicyDocument": {
                        "Version": "2012-10-17", "Statement": {
                            "Effect": "Allow", "Action": "*", "Resource": "*"
                        }
                    }
                }
            }}}), encoding="utf-8")
            self.assertEqual(main([str(path)]), 1)

    def test_cli_accepts_scoped_synthetic_template(self) -> None:
        path = ROOT / "examples" / "iam-cloudformation-template.json"
        self.assertEqual(main([str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
