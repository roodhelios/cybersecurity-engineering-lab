# Voluntarily release a DNS review task

Version 1 rejects competing unexpired acceptances even when the current assignee
wants to stop reviewing. This separate version-2 journal records an explicit signed
release, then requires a fresh fully verified successor before the original expiry.
It does not confer asset ownership or remediation authority.

## Run the complete temporary exercise

From the repository root, on POSIX with Python 3.11 or newer:

```bash
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python projects/asset-intelligence/dns-review/demo_assignment_lifecycle.py
```

Expect `dns_assignment_lifecycle_exercise_passed`, two acceptance events, one release,
one eligible task and three rejected negative cases. Native SQLite and ephemeral
in-memory Ed25519 keys register, release and replace a synthetic review task. Python
sockets are forbidden. No private key is written or printed. Fixed October 28 times
are fixture claims, not current authorization. Temporary files are removed.

## Use a separate version-2 store

```bash
umask 077
mkdir -m 700 /private/dns-lifecycle
python projects/asset-intelligence/dns-review/dns_assignment_lifecycle.py init \
  /private/dns-lifecycle/journal.sqlite
```

Paths here are placeholders for an owned private directory with trusted ancestors.
The existing mode-0700 parent, mode-0600 file, single-link/no-symlink, DELETE journal,
8 MiB bound and serialized-transaction checks remain active. Initialization is
exclusive. At most 2,000 acceptance and 2,000 release events are supported.

Version-1 databases and `dns_journal_checkpoint.py` checkpoints are unchanged. Each
reader rejects the other database version. There is no migration or silent copying
of old acceptances. Use the complete `register` command from the
[version-1 guide](RESPONSIBILITY.md#serialize-acceptances-in-one-private-local-journal),
but invoke `dns_assignment_lifecycle.py` and the new database. Original source,
recipient, reviewer, risk and accepted team-response checks still run. Retain the
private acceptance receipt and exact signed acceptance bytes.

## Sign and receive a release

An issuer integration imports `create_release` from `dns_assignment_lifecycle` with
the project directory on Python's import path:

```python
release_bytes = create_release(
    retained_receipt,
    signing_key=already_loaded_private_key,
    released_at="2026-10-28T12:02:00Z",
    expires_at="2026-10-28T12:03:00Z",
)
```

These variable names and dates are integration placeholders. Use trusted private key
handling. This helper signs the exact target in memory, not source truth or current
journal state. No seed belongs in workflow JSON. Retain the public signed claim in a
private file. The receiver must independently check policy, signature, time and state.

The new domain/action binds key ID, audience, finding revision, team, workflow,
exact acceptance digest, exact authority-policy digest, release time and expiry.
Only the same currently active enrolled key that accepted the task can release it,
under the same independently pinned policy and exact finding/team grant. Another
active key cannot release its work. Revoked keys, replaced policies and expired
acceptances cannot release through this path. Administrative recovery is unfinished.

```bash
python projects/asset-intelligence/dns-review/dns_assignment_lifecycle.py release \
  /private/dns-lifecycle/journal.sqlite \
  --release /private/review/signed-release.json \
  --acceptance-policy /private/trust/acceptors.json \
  --expected-acceptance-policy-sha256 TRUSTED_POLICY_SHA256
```

Normal commands use current UTC. `--at` selects and labels an explicit fixture clock.
Release must follow retained acceptance verification, respect the policy lifetime
and satisfy `released_at <= now < expires_at` before the original acceptance expires.
Signature and exact-current-target checks run inside the same `BEGIN IMMEDIATE`
transaction as the append. A still-valid exact release replay is idempotent; a
different release or stale target fails. Release expiry prevents late use of the
command, not reactivation of a release already retained.

## Register a successor

Release does not assign a key or change permissions. Supply the complete fresh
`register` inputs again and both additional arguments:

```text
--expected-predecessor EXACT_OLD_ACCEPTANCE_SHA256
--expected-release-sha256 EXACT_SIGNED_RELEASE_BYTES_SHA256
```

The release digest covers exact signed bytes, including formatting, not its receipt.
The successor's claimed acceptance time must be at or after release verification.
All original evidence and recipient/reviewer signatures must verify again. The old
acceptance cannot reactivate, and its release cannot affect the successor. Native
concurrent connections admit one successor for the predecessor/release state.
Expiry or policy replacement without release keeps the earlier predecessor behavior.

Use the same version-2 command with `summary`, the acceptance policy and its expected
pin for aggregate current state. A released latest task reports `released`, not
eligible. Output omits signatures, evidence, paths and task/key identifiers. Exit 0
means success, including valid idempotent replay; exit 2 is a fixed-diagnostic failure.

## Limits and next work

This is host-controlled local accounting. Receipts omit raw signatures and do not
reverify historical signatures. A database owner can rewrite or roll back files.
Version-1 checkpoints do not cover version-2 releases. A separate
[version-2 checkpoint](JOURNAL_CHECKPOINT.md#checkpoint-a-version-2-lifecycle-journal)
now binds both tables and detects changed state relative to an independently
retained pin. It does not establish the freshest pin or authenticated history.
Do not claim tamper-proof or globally exclusive state. Other databases can still
hold conflicting assignments.
Trusted clocks, policy freshness, pin distribution and human/key enrollment remain
external. Local SQLite tests do not establish power-loss or deployed-service behavior.

Voluntary task release and separate acceptance are not cross-team asset ownership
transfer, forced reassignment, delivery acknowledgement, remediation or proof that a
person stopped acting. No finding, risk score, source input or access right changes.
Next: independently enroll journals and distribute fresh pins, then design
administrative recovery and cross-team consent separately. Implemented with
assistant support and synthetic tests.
