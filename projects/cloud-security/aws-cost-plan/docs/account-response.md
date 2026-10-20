# Offline account-compromise triage runbook

Use this exercise to turn local CloudTrail evidence into a reviewable response plan.
It performs no AWS API calls and changes no accounts. Live containment requires an
authorized responder, a trusted session, and the organization's incident procedure.

## 1. Establish the evidence boundary

Record the case ID, analyst, authorized account scope, collection source, collection
time, and covered UTC interval. Preserve an original read-only copy separately from
working files. Record a SHA-256 digest and the tool version or commit used for review.
Keep access keys, session tokens, personal data, and real account identifiers out of Git.

An absent event is not evidence that the action did not occur. Record collection gaps,
time-zone conversions, missing regions, and whether management or data events are present.
This parser consumes JSON Lines records, not an unconverted CloudTrail Records envelope.

## 2. Reproduce the synthetic case

From the repository root:

```bash
PYTHONPATH=projects/cloud-security/aws-cost-plan/src python -m aws_cost_plan.cloudtrail_triage \
  projects/cloud-security/aws-cost-plan/examples/cloudtrail-events.jsonl
```

Expected result: three findings from two events. Exit code 1 means findings were
emitted; exit code 2 means input failed validation. A finding is a triage signal,
not proof of compromise.

| Evidence | Signal | First question | Proposed response for an authorized owner to approve |
| --- | --- | --- | --- |
| Successful ConsoleLogin without explicit MFA evidence | CT002, high | Is this event consistent with the identity type and approved sign-in activity? | Review identity, session context, and other activity before proposing session containment |
| StopLogging | CT003, critical | Was the change approved, and what coverage was lost? | Preserve available evidence, identify the actor, and plan restoration of logging with the logging owner |
| Root identity on the same StopLogging event | CT004, high | Is root use expected under an approved emergency process? | Escalate promptly to the account owner and incident lead using a trusted channel |

CT003 and CT004 describe the same event. Do not count them as two independent attacks.
Check outcome fields first: CT003 is medium for a recorded error and critical when
no error is recorded. A failed attempt does not establish lost coverage; absence of
an error does not independently verify the current logging state. Correlate with
approved changes and authorized state evidence before proposing restoration.
MFAUsed without Yes is insufficient MFA evidence in this fixture rule; it does not
establish that a user lacks MFA enrollment or that every federated session is unsafe.

Create a structured handoff from the same fixture without taking response actions:

```bash
PYTHONPATH=projects/cloud-security/aws-cost-plan/src python -m aws_cost_plan.cloudtrail_handoff \
  projects/cloud-security/aws-cost-plan/examples/cloudtrail-events.jsonl \
  --case-id synthetic-001 --scope-note "Synthetic fixture only, no live account" \
  --output /tmp/cloudtrail-handoff.json
```

The new private JSON file reports `event_count: 2`, `finding_count: 3`, and
`flagged_event_count: 2`. The UTC timeline keeps original line numbers and groups
multiple signals on their source event. `source_sha256` covers the exact input bytes;
preserve those bytes separately to reproduce the review. Raw identities and addresses
are not copied into the handoff. Scope is a supplied note, not verified authorization.

The case remains `unreviewed`, with `containment: not_performed` and
`recovery: not_verified`, even if no rule matches. Exit 0 means a handoff was built,
not that the account is safe. Exit 2 means validation or publication failed. Existing
output paths are never replaced. Inputs are limited to 16 MiB, 20,000 records, and
65,536 characters per line. File publication requires local hard-link support and
does not establish crash durability. Keep case metadata and outputs outside Git;
never put credentials in the case ID or scope note.

## 3. Build a timeline and check alternatives

Keep the event time, event name, identity, source address, original line number, and
finding IDs together. Compare with change approvals and the owner's expected activity.
Separate direct observations, analyst inference, and unresolved questions in the notes.

For failed-login bursts, the separate correlation command can review local records:

```bash
PYTHONPATH=projects/cloud-security/aws-cost-plan/src python -m aws_cost_plan.cloudtrail_correlation_cli \
  projects/cloud-security/aws-cost-plan/examples/cloudtrail-events.jsonl
```

The supplied fixture has no failed logins, so its candidates list is empty. This is
not a clean bill of health: successful sign-in and logging changes still need review.

## 4. Propose containment without destroying evidence

For each proposed action, record the approving owner, affected identity or workload,
dependency impact, preservation requirement, rollback plan, and verification method.
Possible decisions include suspending affected credentials, addressing active sessions,
reviewing privilege changes, and restoring telemetry. Credential replacement alone
does not establish that every active session or persistence mechanism is gone.

Do not delete evidence or disable a shared production identity merely because a fixture
rule matched. Resolve operational ownership and preserve access to recovery channels.
This runbook supplies decision prompts, not executable live-remediation instructions.

## 5. Recovery and handoff

Before closure, record what was changed, which controls were verified, the post-change
observation window, remaining collection gaps, and who accepted the residual risk.
Keep unverified conclusions explicitly open. Pass the case owner the following record:

- Case ID, approved scope, collection interval, original artifact location and digest.
- Timeline and finding IDs with event references, including duplicate signals.
- Approved actions and their outcome evidence, or an explicit no-action decision.
- Recovery owner, rollback readiness, monitoring window, and unresolved questions.

## Exercise limits

Only the local parser commands and synthetic outputs are reproducible here. No live
containment, AWS control verification, or account recovery has been performed.
The runbook is an assistant-supported extension of the lab's detection and risk work.
