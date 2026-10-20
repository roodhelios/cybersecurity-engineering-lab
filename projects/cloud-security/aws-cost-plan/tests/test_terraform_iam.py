from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_cost_plan.terraform_iam import TerraformPolicyError, review_terraform_plan
from aws_cost_plan.terraform_iam_cli import main


def plan(resources: list[object], child_modules: list[object] | None = None) -> dict:
    root: dict[str, object] = {"resources": resources}
    if child_modules is not None:
        root["child_modules"] = child_modules
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.0",
        "planned_values": {"root_module": root},
    }


def resource(
    address: str,
    policy: object,
    name: object = "review-policy",
    resource_type: str = "aws_iam_policy",
) -> dict:
    return {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "name": address.rsplit(".", 1)[-1],
        "values": {"name": name, "policy": policy},
    }


class TerraformIamTests(unittest.TestCase):
    def test_reviews_root_and_nested_module_policies(self) -> None:
        broad = json.dumps({
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
        })
        scoped = json.dumps({
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:111122223333:review",
            },
        })
        value = plan(
            [resource("aws_iam_policy.broad", broad)],
            [{
                "address": "module.queue",
                "resources": [resource(
                    "module.queue.aws_iam_role_policy.scoped",
                    scoped,
                    resource_type="aws_iam_role_policy",
                )],
            }],
        )
        findings = review_terraform_plan(value)
        self.assertEqual(
            [(item.address, item.code) for item in findings],
            [
                ("aws_iam_policy.broad", "IAM001"),
                ("aws_iam_policy.broad", "IAM002"),
                ("aws_iam_policy.broad", "IAM003"),
            ],
        )

    def test_ignores_unrelated_resources(self) -> None:
        value = plan([{
            "address": "aws_s3_bucket.example",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "values": {"bucket": "synthetic-example"},
        }])
        self.assertEqual(review_terraform_plan(value), ())

    def test_unknown_policy_value_fails_closed(self) -> None:
        with self.assertRaisesRegex(TerraformPolicyError, "non-empty JSON string"):
            review_terraform_plan(plan([resource("aws_iam_policy.pending", None)]))

    def test_malformed_nested_module_fails_closed(self) -> None:
        with self.assertRaisesRegex(TerraformPolicyError, "child module 1 must be an object"):
            review_terraform_plan(plan([], [None]))

    def test_module_count_is_bounded_without_recursive_walk(self) -> None:
        root: dict[str, object] = {"resources": []}
        current = root
        for index in range(1_001):
            child: dict[str, object] = {
                "address": f"module.level_{index}",
                "resources": [],
            }
            current["child_modules"] = [child]
            current = child
        value = {
            "format_version": "1.0",
            "planned_values": {"root_module": root},
        }
        with self.assertRaisesRegex(TerraformPolicyError, "module limit"):
            review_terraform_plan(value)

    def test_unsupported_format_version_fails_closed(self) -> None:
        value = plan([])
        value["format_version"] = "2.0"
        with self.assertRaisesRegex(TerraformPolicyError, "supported 1.x"):
            review_terraform_plan(value)

    def test_duplicate_supported_address_fails_closed(self) -> None:
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        })
        item = resource("aws_iam_policy.duplicate", policy)
        with self.assertRaisesRegex(TerraformPolicyError, "duplicate supported"):
            review_terraform_plan(plan([item, item]))

    def test_duplicate_policy_json_field_fails_closed(self) -> None:
        duplicate = (
            '{"Version":"2012-10-17","Statement":'
            '{"Effect":"Deny","Action":"*","Resource":"*"},'
            '"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}'
        )
        with self.assertRaisesRegex(TerraformPolicyError, "duplicate JSON field"):
            review_terraform_plan(plan([resource("aws_iam_policy.ambiguous", duplicate)]))

    def test_cli_accepts_scoped_fixture(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            status = main([str(ROOT / "examples" / "terraform-plan-iam.json")])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), {"findings": []})

    def test_cli_reports_findings_without_policy_payload(self) -> None:
        marker = "do-not-copy-policy-payload"
        policy = json.dumps({
            "Version": "2012-10-17",
            "Id": marker,
            "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tfplan.json"
            path.write_text(json.dumps(plan([resource("aws_iam_policy.broad", policy)])))
            output = StringIO()
            with redirect_stdout(output):
                status = main([str(path)])
        self.assertEqual(status, 1)
        self.assertNotIn(marker, output.getvalue())
        self.assertEqual(
            [item["code"] for item in json.loads(output.getvalue())["findings"]],
            ["IAM001", "IAM002"],
        )

    def test_cli_rejects_oversize_file_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
            error = StringIO()
            with redirect_stderr(error):
                status = main([str(path)])
        self.assertEqual(status, 2)
        self.assertIn("8 MiB", error.getvalue())

    def test_cli_rejects_duplicate_plan_fields(self) -> None:
        payload = '{"format_version":"1.0","format_version":"1.2"}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ambiguous.json"
            path.write_text(payload)
            error = StringIO()
            with redirect_stderr(error):
                status = main([str(path)])
        self.assertEqual(status, 2)
        self.assertIn("duplicate JSON field", error.getvalue())


if __name__ == "__main__":
    unittest.main()
