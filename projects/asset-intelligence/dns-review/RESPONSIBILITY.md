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

The receipt command alone has no persistent assignment registry, exclusivity,
atomic multi-finding acceptance, reassignment or revocation broadcast. The separate
local journal below adds conflict accounting within one host-controlled database. Repeating verification may create
another receipt in another new file; this is not once-only task execution. Retained
receipts are unsigned local verification results, not transferable approvals.
Re-run full verification with current trust and time before relying on acceptance;
an old receipt cannot establish that an authority is still active. Re-encoded or
changed workflow bytes require a new acceptance even when the JSON values match.

The local journal below starts append-only conflict accounting. Independent history
continuity and explicit release/transfer authority remain necessary before claiming
a durable ownership workflow.
Prepared with assistant support and synthetic local evidence, not manual acceptance
by a real team.

```bash
python -m unittest discover -s projects/asset-intelligence/dns-review/tests -v
```

## Serialize acceptances in one private local journal

The separate `dns_assignment_journal.py` command now retains verified receipts in a
native SQLite journal and checks competing registrations transactionally. The older
receipt command above remains independent and does not consult this journal.

From the repository root, after the same optional PyNaCl installation:

```bash
python projects/asset-intelligence/dns-review/demo_assignment_journal.py
```

Expect `dns_assignment_journal_exercise_passed`, two retained events for one task,
`idempotent_replay: true`, `expiry_replacement: true`,
`policy_replacement_invalidates: true` and three rejected negative cases. Native
Ed25519, complete source reproduction and SQLite transactions run in a temporary
private directory with socket creation forbidden. Keys stay in memory. All claims
use the explicit October 28 fixture clock, not a real team's acceptance.

The exercise registers one short-lived acceptance, verifies its replay without
adding another event, rejects a competing unexpired acceptance, and requires the
exact predecessor before replacing the expired acceptance. A separately pinned
policy with its key marked revoked then makes the latest registration ineligible
without changing the database. No revocation is broadcast or externally performed.

### Retained commands

Choose an absolute path inside an owned mode-0700 directory. Initialization never
creates a directory or replaces an existing file:

```bash
python projects/asset-intelligence/dns-review/dns_assignment_journal.py init \
  /absolute/private/assignment.sqlite
```

Register with the same complete original evidence required by the receipt command:

```bash
python projects/asset-intelligence/dns-review/dns_assignment_journal.py register \
  /absolute/private/assignment.sqlite \
  --report /absolute/private/workflow.json \
  --previous /absolute/private/before.jsonl --current /absolute/private/after.jsonl \
  --scope /absolute/private/scope.json --policy /absolute/private/review-policy.json \
  --requirements /absolute/private/requirements.json --approval /absolute/private/approval.json \
  --authority-policy /absolute/private/recipient-authorities.json \
  --reviewer-policy /absolute/private/reviewer-authorities.json \
  --expected-reviewer-policy-sha256 INDEPENDENT_REVIEWER_POLICY_PIN \
  --attestations /absolute/private/attestations.json \
  --assessment /absolute/private/risk.json --ownership-responses /absolute/private/responses.json \
  --acceptance /absolute/private/acceptance.json \
  --acceptance-policy /absolute/private/acceptance-authorities.json \
  --expected-acceptance-policy-sha256 INDEPENDENT_ACCEPTANCE_POLICY_PIN
```

Initial registration requires no predecessor. A replacement must add
`--expected-predecessor SHA256_OF_LAST_REGISTERED_ACCEPTANCE_FILE`. This is the
exact digest of the previously retained signed acceptance bytes, not the database
or receipt digest. Retain that file privately. An independently reviewed current
policy pin must come from outside the candidate bundle. A predecessor is a host
concurrency condition; the acceptance signature does not itself authorize transfer
from that predecessor or establish the previous signer's consent.

Inspect minimized counts with the current independently pinned acceptance policy:

```bash
python projects/asset-intelligence/dns-review/dns_assignment_journal.py summary \
  /absolute/private/assignment.sqlite \
  --acceptance-policy /absolute/private/acceptance-authorities.json \
  --expected-acceptance-policy-sha256 INDEPENDENT_ACCEPTANCE_POLICY_PIN
```

`register` returns `review_acceptance_registered`, `appended: true` and the total
event count. An exact replay returns `already_registered`, `appended: false` only
after full verification succeeds again. `summary` returns `event_count`,
`task_count`, `eligible_for_reverification`, `expired`, `policy_replaced` and
`authority_inactive`. It never returns team/key labels or finding/acceptance digests.
These summaries are unsigned local accounting, not current authorization evidence.
Omitting `--at` captures current UTC once; an explicit whole-second UTC fixture time
is labeled `explicit_fixture`. Exit 2 uses a fixed diagnostic without private
identifiers, paths or a success document. An initialization error can leave a new
incomplete private database; inspect it privately rather than overwriting it.

### State and conflict rules

| Condition | Local result |
| --- | --- |
| First fully verified acceptance for `(audience, finding revision)` | Append an event with no predecessor |
| Exact latest acceptance replay, still fully verifiable | Return idempotently without another event |
| Different acceptance while the latest is unexpired under the same policy | Reject even when the predecessor matches |
| Latest acceptance expired at `now >= expires_at` | Require a fresh fully verified acceptance and exact predecessor |
| Any current acceptance-policy byte change | Old registration becomes `policy_replaced`, including key revocation or harmless re-encoding |
| Replacement after policy change | Require a fresh acceptance signed for the new policy and exact predecessor |
| Missing/stale predecessor, rollback in the task's verification clock or invalid original evidence | Reject without adding an event |

The identity omits the team so a second team cannot create a parallel registration
for the same audience and exact finding revision in this journal. Different finding
revisions are separate tasks. Replacement is deliberately conservative: a policy
edit invalidates every registration under its old exact-byte digest. No in-place
rekeying, selective exception or forced takeover of an eligible task is supported.

`BEGIN IMMEDIATE` serializes the history read, conflict decision and insert on one
SQLite database. Tests use two concurrent native connections and require one winner
for competing initial registrations. Append-only triggers prevent ordinary SQL
updates/deletes, while bounded reads recheck contiguous sequence, predecessor links
and receipt fields. This is not tamper-evident history: a same-user editor can forge
internally consistent receipts or remove protections. The separate
[exact-state checkpoint](JOURNAL_CHECKPOINT.md) can detect a changed or older logical
history against an independently retained pin; it does not authenticate that history
or establish checkpoint freshness. Separate databases can accept the same task.

The journal accepts owned mode-0600 regular files with one hard link, up to 8 MiB
and 2,000 events. It stores the existing unsigned verification receipt, including
team/key labels, digests and time claims, but no source logs, hostnames, addresses,
private keys or signatures. Treat the database, SQLite sidecars, original evidence
and backups as sensitive plaintext outside Git. Parent privacy protects transient
SQLite journal files. File checks do not prevent same-user path replacement.
Use only trusted owned directories; this is not a database-import sandbox.

Eligibility considers the acceptance policy and its validity window only. Other
recipient/reviewer policies, signatures or evidence may have changed or expired.
`summary` does not reproduce them. Run full verification again before reliance.
Clock checks use one caller-supplied instant before lock acquisition, not a trusted
clock service or an execution-time deadline. Busy lock acquisition fails rather
than bypassing conflict checks. File fsync/SQLite FULL synchronous settings do not
establish external backup, parent-directory crash durability or secure erasure.

This implements local conflict accounting and expiry/policy replacement, not global
exclusive assignments, asset ownership, human enrollment, revocation distribution,
consensual reassignment or remediation. Next: independently enroll journal
identity and design explicit release/transfer authority before permitting
forced reassignment. Implemented with assistant support and synthetic local evidence.
