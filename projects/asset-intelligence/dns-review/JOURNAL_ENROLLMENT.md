# Enroll one persistent local DNS journal identity

Version-1 and version-2 checkpoints describe logical history. Two independently
initialized journals with identical rows can therefore produce the same checkpoint.
The separate version-3 lifecycle journal stores a random 128-bit identifier and
requires an independently selected identity before each read or write operation.
It preserves the existing acceptance/release checks and adds identity-bound
checkpoints. It does not migrate older databases.

## Run the complete temporary exercise

From the repository root, with Python 3.11 or newer on POSIX and the existing
optional PyNaCl dependency installed:

```bash
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python projects/asset-intelligence/dns-review/demo_journal_enrollment.py
```

Expect `dns_journal_enrollment_exercise_passed`, `acceptance_count: 1`,
`release_count: 1`, `enrolled_identity_checked: true` and
`negative_cases_rejected: 4`. This uses native SQLite and Ed25519, ephemeral
in-memory keys, synthetic saved DNS observations and fixed October fixture times.
It enrolls a new journal, verifies and records an acceptance and same-key release,
then checkpoints both tables. A separate journal, wrong checkpoint pin, wrong
enrollment pin and release-only rollback are rejected. Socket creation is forbidden.
No DNS requests, real team enrollment, cloud resources or remediation occur.

## Initialize and explicitly enroll a new store

Choose owned absolute paths with mode-0700 immediate parent directories and trusted
ancestors. Existing files are never overwritten:

```bash
python projects/asset-intelligence/dns-review/dns_identified_journal.py init \
  /private/dns-v3/journal.sqlite
```

Expect `dns_identified_journal_created` and `journal_id`. This initialization output
is the only command that prints the identifier. Retain the identifier through your
trusted local setup process, independently of any later candidate database.

```bash
python projects/asset-intelligence/dns-review/dns_identified_journal.py enroll \
  /private/dns-v3/journal.sqlite --expected-journal-id INDEPENDENT_JOURNAL_ID \
  --output /private/trust/enrollment.json
```

Expect `dns_journal_enrollment_created` and `enrollment_sha256`. Enroll checks the
selected identity and both logical tables before writing a new mode-0600 document.
The canonical document contains exactly schema version 1, enrollment type
`dns-review-local-journal`, journal version 3 and the identifier. It is unsigned
local metadata. Independently retain its exact digest through your trusted process.
Reading an identifier or deriving a pin from an untrusted candidate does not enroll
that candidate safely. No human or collector identity is authenticated by this step.

## Use the enrolled lifecycle and checkpoint

For `register`, `release` and `summary`, use the same evidence, authority policy,
clock and predecessor arguments documented in [the lifecycle guide](ASSIGNMENT_LIFECYCLE.md),
but select `dns_identified_journal.py` and add both:

```text
--enrollment /private/trust/enrollment.json
--expected-enrollment-sha256 INDEPENDENT_ENROLLMENT_SHA256
```

For example, inspect current local eligibility without printing task identities:

```bash
python projects/asset-intelligence/dns-review/dns_identified_journal.py summary \
  /private/dns-v3/journal.sqlite --enrollment /private/trust/enrollment.json \
  --expected-enrollment-sha256 INDEPENDENT_ENROLLMENT_SHA256 \
  --acceptance-policy /private/trust/current-acceptors.json \
  --expected-acceptance-policy-sha256 INDEPENDENT_ACCEPTANCE_POLICY_SHA256
```

This is still eligibility for full evidence reverification, not a transferable
current-authority approval. Registration and release retain all existing signature,
current policy, audience, finding, time, conflict and predecessor checks. Identity
is checked in the same transaction used by each inherited lifecycle operation,
including when a previously opened object's database path is replaced.

```bash
python projects/asset-intelligence/dns-review/dns_identified_journal.py checkpoint \
  /private/dns-v3/journal.sqlite --enrollment /private/trust/enrollment.json \
  --expected-enrollment-sha256 INDEPENDENT_ENROLLMENT_SHA256 \
  --output /private/trust/selected-checkpoint.json

python projects/asset-intelligence/dns-review/dns_identified_journal.py verify \
  /private/dns-v3/journal.sqlite --enrollment /private/trust/enrollment.json \
  --expected-enrollment-sha256 INDEPENDENT_ENROLLMENT_SHA256 \
  --checkpoint /private/trust/selected-checkpoint.json \
  --expected-sha256 INDEPENDENT_CHECKPOINT_SHA256
```

Paths and identifier/digest labels are placeholders. Creation emits
`dns_identified_checkpoint_created`; verification emits
`dns_identified_checkpoint_matched`. Retain the checkpoint digest independently.
The version-3 document binds the journal ID and every ordered acceptance/release
column, including complete retained receipt strings, under a distinct hash domain.
Identity and both table validators share one SQLite read transaction. A valid
append or release requires a newly selected checkpoint, not silent pin advancement.

## Compatibility and limits

| Candidate | Result under the enrolled identity and exact-state pin |
| --- | --- |
| Same identity and complete logical history | Match |
| Independently initialized journal, even with identical events | Reject |
| Exact backup or SQLite layout change retaining the same identity/history | Can match |
| Same identity with release-only rollback | Reject against the selected current checkpoint |
| Version-1 or version-2 store/checkpoint | Reject, no migration |
| Old journal with its own stale enrollment/checkpoint pins | Can match; freshness remains external |

The ID is a correlation label, not a secret, signature or unforgeable device ID.
Copies intentionally retain the same identity. A same-user editor can copy or forge
it. Acceptance signatures are still task-bound, not journal-bound, and separate
journals can accept the same task. This does not authenticate a collector, establish
global exclusivity, prove ownership or grant remediation. Enrollment is a local
explicit trust selection, not a key directory or independently authenticated service.

Metadata is bounded at 4 KiB and exact canonical fields. Identity rows must form an
ordinary singleton table. Creation uses mode-0600 files and exclusive publication.
The existing owned/private/regular/single-link 8 MiB and 2,000-event journal limits
remain. Trusted ancestors and cooperative writers remain required. SQLite read
transactions do not prevent later path replacement. Checkpoints do not reverify
historical signatures or current authority, bind arbitrary schema/trigger text,
sync parent directories or establish power-loss durability. Abrupt creation failure
may leave sidecars; inspect private storage after a crash.

Existing version-1 and version-2 CLI commands keep their original contracts and
cannot open version-3 files. The new init/enroll/checkpoint/verify path uses only
the standard library for existing journals. Signature registration/release and the
complete walkthrough require the existing PyNaCl dependency. Failures return exit 2
with a fixed diagnostic; successful commands return exit 0. Except init's intended
identifier output, commands emit aggregate counts/pins without identities or paths.
Keep those operational digests and metadata private and outside Git.

Next: independently authenticated, fresh checkpoint distribution. Manual enrollment
and two matching pins do not establish which checkpoint is latest.

Prepared with assistant support and original synthetic validation.
