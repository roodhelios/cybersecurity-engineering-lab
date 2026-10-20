# AWS Cost Plan Guardrail

This module validates an offline monthly budget and teardown plan before an AWS lab is
started. It does not authenticate to AWS, create resources, read billing data, or prove
that an account-level budget actually exists.

The version 1 contract requires:

- exact USD string amounts so floating-point rounding cannot hide a cap
- alert thresholds that start at or below 50 percent and include 100 percent
- confirmed root MFA, a configured budget alert, and no unbounded usage
- a unique identifier, monthly cap, termination condition, teardown steps, and
  post-teardown check for every planned resource
- combined resource caps that do not exceed the monthly budget

The same project includes an offline review aid for IAM identity policy JSON. It flags
wildcard Allow actions, unrestricted `Resource: "*"`, and IAM or role-assumption
permissions without an explicit MFA condition. Unsupported policy grammar is rejected
so the tool does not guess at resource policies or `NotAction` semantics.
`BoolIfExists` does not satisfy the MFA check because a missing MFA context key can make
that condition pass without proving MFA. AWS documents that `BoolIfExists` with
`aws:MultiFactorAuthPresent: "true"` can allow requests made with long-term access
keys. See [AWS condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
and [AWS global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html).

```bash
PYTHONPATH=src python -m aws_cost_plan.iam_cli examples/iam-identity-policy.json
python -m unittest discover -s tests -v
```

This is a conservative static review, not an AWS IAM simulator. It does not establish
that a principal has MFA, that an ARN exists, or that a condition behaves as intended
for every caller type. Review the policy in the owned account before use.

Embedded policies in local CloudFormation JSON can use the same checks:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudformation_iam_cli examples/iam-cloudformation-template.json
```

The scanner recognizes inline policies on `AWS::IAM::Role`, `AWS::IAM::Policy`, and
`AWS::IAM::ManagedPolicy`. It does not parse YAML, evaluate `Ref` or other intrinsic
functions, inspect role trust documents, or resolve effective permissions. A dynamic
policy document fails closed instead of being silently skipped. See the AWS
[role policy reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-iam-role-policy.html),
[inline policy resource reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-policy.html),
and [managed policy reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-managedpolicy.html).

## Review IAM policies in a Terraform plan

Export a saved local plan with Terraform, then review the JSON without contacting AWS:

```bash
terraform show -json SAVED_PLAN > /tmp/tfplan.json
PYTHONPATH=src python -m aws_cost_plan.terraform_iam_cli /tmp/tfplan.json
PYTHONPATH=src python -m aws_cost_plan.terraform_iam_cli examples/terraform-plan-iam.json
```

The included synthetic example exits 0 with an empty findings list. The reviewer walks
the root module and nested child modules, then checks planned managed
`aws_iam_policy` and `aws_iam_role_policy` resources with the same IAM rules used by
the JSON and CloudFormation entry points. A supported resource with an unknown,
missing, non-JSON, or unsupported policy fails closed instead of being skipped.

Input is limited to a local regular UTF-8 JSON file of at most 8 MiB, 1,000 modules,
and 20,000 resources. The command does not print policy payloads in findings. Duplicate
JSON fields and excessive nesting fail closed. It does not run Terraform, parse
configuration files, inspect prior state, review role trust policies or attachments, evaluate
provider behavior, or calculate effective permissions. Other resource types are
outside this reviewed subset. A clean result means no current rule matched the supplied
planned values. It does not approve the plan or prove least privilege.

Terraform documents that `show -json` emits a machine-readable plan representation and
can expose sensitive values in plain text. Keep saved plan files private, outside Git,
and delete them according to the review process after use. See the HashiCorp
[JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
and [`terraform show` warning](https://developer.hashicorp.com/terraform/cli/commands/show).

Validate the synthetic example from this directory:

```bash
PYTHONPATH=src python -m aws_cost_plan examples/aws-cost-plan.json
python -m unittest discover -s tests -v
```

The command emits a deterministic summary with the budget, planned cap, remaining
headroom, resource identifiers, and SHA-256 digest of the reviewed plan. The digest can
show that a later copy differs, but it does not authenticate who approved the plan.

Review the local synthetic CloudTrail fixture without contacting AWS:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_triage examples/cloudtrail-events.jsonl
```

The rules flag failed console sign-in, successful console sign-in without explicit
MFA evidence, CloudTrail logging disruption, and root identity activity. These are
triage signals that need account context and other telemetry, not proof of compromise.

Distinguish logging-change outcomes before planning restoration:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_triage examples/cloudtrail-logging-outcomes.jsonl
```

Expect CT003 severities `medium`, `critical`, `medium`, in that order, and exit 1.
StopLogging and DeleteTrail with a non-empty `errorCode` or `errorMessage`,
at the top level or inside `responseElements`, are recorded failed attempts.
Their error text is not copied to findings. With neither error field, the event is
critical for review, not proof that logging is currently disabled. Null, empty, or
non-string error fields fail validation rather than being interpreted as success.
Root identity still independently matches CT004, even on a failed attempt.
These severity choices are local triage policy, not an AWS severity assessment.
See the AWS [event record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
for the error-field locations. Supplied logs are untrusted claims; verify account
state and collection completeness through the authorized response process.

Correlate repeated failures using a bounded local JSON Lines file:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_correlation_cli \
  examples/cloudtrail-events.jsonl --threshold 3 --window-seconds 300
```

The command groups CT001 failures by principal and source address, rejects duplicate
CloudTrail event IDs, and includes the contributing IDs in each candidate. Input is
limited to 16 MiB, 20,000 records, and 65,536 characters per record. `--output` writes
to a new local file and refuses to overwrite one. Empty input is a successful empty
result. This is a triage aid for supplied data; it does not contact AWS, enrich network
indicators, or establish that an account was compromised.

`cloudtrail_correlation.py` can group failed console sign-ins by principal and source
address inside a bounded window. The default candidate threshold is three failures in
five minutes. Missing identity or source keys fail closed, and separate principals or
sources are never combined. A candidate still requires analyst review and does not
prove password guessing or account compromise.

## Import a local CloudTrail Records file

AWS documents delivered log files as gzip-compressed JSON with a `Records` array:
[CloudTrail file examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html).
The existing commands consume JSON Lines, not that envelope. Convert one already
downloaded, owned or authorized file locally before triage. From this project directory:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_import examples/cloudtrail-records.json \
  --output /tmp/cloudtrail-import.jsonl
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_handoff /tmp/cloudtrail-import.jsonl \
  --case-id native-import-review --scope-note synthetic --output /tmp/cloudtrail-import-handoff.json
```

Use fresh output paths on POSIX. The importer reports `event_count: 2`, the exact input
digest, normalized-output digest, and compression mode. The handoff shows two events,
three triage findings, `containment: not_performed`, and `recovery: not_verified`.
The same importer recognizes gzip by its magic bytes, independent of filename. It
does not download files, load AWS credentials, or call an API.

The full batch is validated before publication. Both supplied and expanded bytes
are capped at 16 MiB, with at most 20,000 events and 65,536 characters per normalized
record. Each event must satisfy the current triage contract and have a unique non-empty
`eventID`. Duplicate JSON fields, non-finite numbers, malformed gzip/UTF-8, unexpected
envelope fields, and invalid records fail with exit 2 and no success document or new
output. Empty `Records` creates an empty JSONL file. Output is a complete private
file published exclusively; existing files are never overwritten.

Unknown event fields and original order are preserved, not interpreted or redacted.
Logs can contain credentials or sensitive identifiers. Keep both original and converted
files private and outside Git. Receipt digests are integrity references, not CloudTrail
log-signature validation, provenance, or authorization proof. Handoff line numbers refer
to the converted file: retain that file and both digests alongside the original.
This accepts the reviewed local subset, not every AWS event variant or CloudTrail Lake
export. Passing import does not prove that a record is authentic or a finding correct.

## Teardown procedure

For a complete offline response exercise, follow the
[account-response runbook](docs/account-response.md). Its `cloudtrail_handoff` command
preserves the exact input digest, line-linked timeline, event and finding counts,
and explicit unreviewed response state in a new private JSON file. It does not call
AWS or certify containment and recovery.

Before creating anything, review each resource's termination condition and teardown
steps. When the lab ends, perform the steps in order, complete the stated verification,
and inspect AWS billing and Cost Explorer through the owned account. The fixture uses
small planning caps only. It is not a price quote and does not guarantee AWS charges.

## Limits

- The validator checks a plan, not live AWS configuration or billing state.
- Service pricing, taxes, data transfer, free-tier eligibility, and region pricing can
  change independently of this fixture.
- A budget alert reports cost. It does not automatically stop every billable service.
- Root MFA and budget configuration are explicit assertions supplied by the reviewer.
- No cloud resource should be created until those assertions are verified in the owned
  account.
