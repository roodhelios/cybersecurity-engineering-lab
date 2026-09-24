from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_cost_plan.iam_policy import IamPolicyError, review_identity_policy


FIXTURE = ROOT / "examples" / "iam-identity-policy.json"


class IamPolicyTests(unittest.TestCase):
    def test_scoped_mfa_fixture_has_no_findings(self) -> None:
        policy = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(review_identity_policy(policy), ())

    def test_wildcard_action_and_resource_are_reported(self) -> None:
        findings = review_identity_policy({
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        })
        self.assertEqual([item.code for item in findings], ["IAM001", "IAM002"])

    def test_iam_permission_requires_explicit_mfa_condition(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "iam:PassRole",
                          "Resource": "arn:aws:iam::111122223333:role/lab"},
        }
        self.assertEqual([item.code for item in review_identity_policy(policy)], ["IAM003"])

    def test_mfa_ifexists_does_not_satisfy_the_guardrail(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "iam:PassRole",
                          "Resource": "arn:aws:iam::111122223333:role/lab",
                          "Condition": {"BoolIfExists": {
                              "aws:MultiFactorAuthPresent": "true"
                          }}},
        }
        self.assertEqual([item.code for item in review_identity_policy(policy)], ["IAM003"])

    def test_denies_do_not_produce_allow_findings(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"},
        }
        self.assertEqual(review_identity_policy(policy), ())

    def test_unsupported_policy_grammar_fails_closed(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "NotAction": "s3:Delete*",
                          "Resource": "*"},
        }
        with self.assertRaisesRegex(IamPolicyError, "unsupported fields"):
            review_identity_policy(policy)

    def test_malformed_effect_is_a_policy_error(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": [], "Action": "s3:GetObject", "Resource": "arn:aws:s3:::lab/key"},
        }
        with self.assertRaisesRegex(IamPolicyError, "Effect must be a string"):
            review_identity_policy(policy)


if __name__ == "__main__":
    unittest.main()
