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

Validate the synthetic example from this directory:

```bash
PYTHONPATH=src python -m aws_cost_plan examples/aws-cost-plan.json
python -m unittest discover -s tests -v
```

The command emits a deterministic summary with the budget, planned cap, remaining
headroom, resource identifiers, and SHA-256 digest of the reviewed plan. The digest can
show that a later copy differs, but it does not authenticate who approved the plan.

## Teardown procedure

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
