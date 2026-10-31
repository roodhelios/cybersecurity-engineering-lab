# Accept responsibility for one DNS review task

An accepted team-response claim is useful review evidence, but the older handoff
does not ask a separately authorized key to accept responsibility for a task. This
workflow adds that explicit action after the existing complete source reproduction,
recipient approval and finding-scoped risk/team signature checks.

## Run the temporary exercise

From the repository root, with Python 3.11 or newer and the existing optional PyNaCl
dependency from `requirements-auth.txt`:

```bash
python projects/asset-intelligence/dns-review/demo_responsibility.py
```

Expect `dns_responsibility_exercise_passed`, `accepted_findings: 1`,
`negative_cases_rejected: 3`, `inputs_unchanged: true` and `native_ed25519: true`.
The example uses original synthetic saved logs, ephemeral recipient/risk/team keys
and a separate ephemeral acceptance key. It retains a private receipt temporarily,
then removes all generated files. No private key is written or printed. The fixed
verification instant is October 28, 2026 at 12:00 UTC; it is a fixture clock, not a
current approval. Python socket creation is forbidden during the API exercise.

The negative walkthrough rejects the wrong action, wrong authority pin and missing
reviewer evidence. Regression tests additionally exercise expiry, revoked keys,
wrong teams/findings/audiences, context changes and a correctly signed declined team
response that must remain unaccepted.

## Trust and signed action

Supply a separately trusted public policy with exactly `schema_version: 1`,
`authority_type: dns-review-responsibility-authorities`, `audience`,
`maximum_validity_seconds` and `keys`. Each key has exactly `key_id`, canonical
`public_key_b64`, `status` and `grants`. Every grant has an exact lowercase
`finding_sha256` and an explicit routed `team`. There are no hostname/team wildcards.
The existing reviewer key, lifetime, team and duplicate validation is reused, but a
reviewer-authority policy is not accepted as a responsibility-authority policy.

There must be 1 to 16 unique enrolled keys and at most 2,000 total grants. Each key
needs at least one grant. Validity policy is 1 to 604,800 seconds. Retired/revoked keys
cannot accept work. The complete policy is bounded to 1 MiB like other DNS inputs.
Its exact byte digest must match `--expected-acceptance-policy-sha256`, obtained
independently from the candidate bundle. Never trust a pin merely because it arrived
beside the file it is meant to authenticate. Distribution, human enrollment, policy
freshness and a trusted clock remain external responsibilities.

The new signature uses its own `dns-review-responsibility:v1` domain and action
`accept-dns-review-responsibility`. It binds audience, acceptance-key ID, exact
workflow-file digest, exact acceptance-policy digest, finding revision, routed team,
acceptance time and expiry. Whole-second UTC timestamps are required. Acceptance
time must not precede the signed team review. The verifier requires
`accepted_at <= now < expires_at` and the policy's maximum lifetime.

Issuer integrations can use `dns_responsibility.create_acceptance(...)` with an
in-memory signing key. That helper signs supplied bytes, not source truth. It checks
the intended policy and signature before returning. The receiver must independently
run `accept_responsibility(...)` with all original inputs and pinned policies. There
is deliberately no command that prints a private key or loads arbitrary signing
seeds from a supplied workflow.

## Retain a receipt from owned or authorized evidence

Use the same original inputs required by `dns_reviewer_handoff.py`, plus the signed
acceptance and separately trusted acceptance policy. The paths and pins below are
placeholders; choose a new output in a trusted private directory:

```bash
python projects/asset-intelligence/dns-review/dns_responsibility.py \
  /private/review/workflow.json /private/review/before.jsonl /private/review/after.jsonl \
  --scope /private/review/scope.json --policy /private/review/review-policy.json \
  --requirements /private/review/requirements.json --approval /private/review/approval.json \
  --authority-policy /private/review/recipient-authorities.json \
  --reviewer-policy /private/review/reviewer-authorities.json \
  --expected-reviewer-policy-sha256 INDEPENDENT_REVIEWER_POLICY_PIN \
  --attestations /private/review/attestations.json \
  --assessment /private/review/risk.json --ownership-responses /private/review/responses.json \
  --acceptance /private/review/acceptance.json \
  --acceptance-policy /private/review/acceptance-authorities.json \
  --expected-acceptance-policy-sha256 INDEPENDENT_ACCEPTANCE_POLICY_PIN \
  --output /private/review/new-responsibility-receipt.json
```

Omitting `--at` uses the current UTC clock. `--at` exists only for an explicitly
chosen fixture instant and is marked `explicit_fixture` in the retained receipt.
The complete existing handoff must reproduce first, with every finding's required
risk and team signatures. Exactly one selected finding is accepted by each invocation.
Its response must say `accepted`, name the routed team and bind the exact current
finding revision. A valid signature over `declined` does not satisfy that condition.

Exit 0 prints only `status: accepted_review_responsibility` and `receipt_created: true`.
The private receipt includes the finding digest, team, key ID, audience, validity,
verification time and relevant context digests. It contains no hostnames, addresses,
raw source logs, signatures or private keys. These labels/digests can still be
sensitive: retain receipts and original evidence outside Git. Exit 2 prints a fixed
diagnostic, without a success document or new receipt. Existing output files are
preserved. The existing bounded no-follow inputs and exclusive 0600 POSIX publisher
are used; no directory is created for the caller.

## What acceptance does not mean

The receipt authenticates an enrolled key accepting review responsibility at the
recorded verification instant. It does not enroll a person, establish source truth,
prove asset ownership, grant access, dismiss a finding, change risk, approve a repair
or perform remediation. Existing `accepted_claim` labels and review queues remain
unchanged. Signed policy distribution and current trust remain the receiver's job.

There is no persistent assignment registry, exclusivity, atomic multi-finding
acceptance, reassignment or revocation broadcast. Repeating verification may create
another receipt in another new file; this is not once-only task execution. Retained
receipts are unsigned local verification results, not transferable approvals.
Re-run full verification with current trust and time before relying on acceptance;
an old receipt cannot establish that an authority is still active. Re-encoded or
changed workflow bytes require a new acceptance even when the JSON values match.

Next: design an append-only assignment/reassignment history with explicit conflict,
revocation and current-state rules before claiming durable ownership workflow.
Prepared with assistant support and synthetic local evidence, not manual acceptance
by a real team.

```bash
python -m unittest discover -s projects/asset-intelligence/dns-review/tests -v
```
