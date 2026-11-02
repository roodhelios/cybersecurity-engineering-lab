# Check a local DNS journal against separately retained history

The assignment journal validates receipt fields, ordering and predecessor links.
Those internal checks cannot distinguish the latest file from a consistent older
backup. The separate checkpoint command binds the complete logical history to a
small canonical document whose exact SHA-256 must be retained independently.

This checks equality with a selected retained state. It does not authenticate the
history's original signatures, establish which checkpoint is latest or authorize
the current task holder. Continue full evidence verification before relying on an
acceptance. The checkpoint is unsigned local metadata, not a transferable approval.

## Run the complete local exercise

Use Python 3.11 or newer on POSIX. From the repository root, install the existing
optional signature dependency if needed:

```bash
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python projects/asset-intelligence/dns-review/demo_journal_checkpoint.py
```

Expect `dns_journal_checkpoint_exercise_passed`, `checkpoint_events: 2`,
`rolled_back_events: 1`, `rollback_detected: true` and
`negative_cases_rejected: 3`. Verification preserves input bytes. The walkthrough
also deliberately shows `stale_checkpoint_can_still_match: true`.

The fixture uses ephemeral in-memory keys, real Ed25519 acceptance verification,
fixed October 28, 2026 clocks and temporary native SQLite. It checkpoints two
registered acceptances, restores a valid one-event backup and rejects it against
the two-event checkpoint. The old backup still passes internal journal checks.
The old backup and its own old checkpoint/pin can still match. No network socket
creation, DNS lookup, real team acceptance or remediation occurs.

## Retain a checkpoint

First create and register your owned or authorized evidence through the
[private journal workflow](RESPONSIBILITY.md#serialize-acceptances-in-one-private-local-journal).
Then choose a new checkpoint output:

```bash
python projects/asset-intelligence/dns-review/dns_journal_checkpoint.py create \
  /absolute/private/assignment.sqlite \
  --output /absolute/private/new-checkpoint.json
```

The journal retains its existing requirement for an owned absolute mode-0600
regular file with one hard link and an owned mode-0700 parent. No directory is
created and existing outputs are preserved. The new checkpoint is mode 0600.

Stdout includes `dns_journal_checkpoint_created`, event/task counts and
`checkpoint_sha256`. Independently retain that exact digest through your trusted
process, separately from a candidate journal/backup. Keeping a fresh pin beside a
candidate and deriving trust from it is insufficient. Checkpoint issuance and
distribution are explicit external responsibilities.

The document contains exactly:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer 1 |
| `checkpoint_type` | `dns-review-assignment-journal` |
| `event_count` | Every event in the captured logical history |
| `task_count` | Distinct audience/finding identities in that history |
| `history_sha256` | Domain-separated digest of every complete ordered event row |

The history digest covers sequence, audience, finding, acceptance, predecessor and
the complete retained receipt JSON text for every row, including superseded events.
It is not only the latest acceptance digest or a count. Receipt re-encoding changes
the history identity. The hash domain is `dns-assignment-journal-history:v1`
followed by a zero byte, then the existing ASCII canonical JSON encoding of the
ordered SQL-row arrays. The checkpoint itself uses canonical JSON plus one newline.

## Verify a candidate without changing it

Use the checkpoint file and its independently retained exact-byte pin:

```bash
python projects/asset-intelligence/dns-review/dns_journal_checkpoint.py verify \
  /absolute/private/assignment.sqlite \
  --checkpoint /absolute/private/trust/checkpoint.json \
  --expected-sha256 INDEPENDENT_CHECKPOINT_SHA256
```

Paths and digest strings are placeholders for private local evidence. The pin must
be lowercase SHA-256. It is checked before the candidate journal is opened. The
verifier captures a validated history in one read-only SQLite transaction, rebuilds
the full canonical checkpoint and requires exact document-byte equality. Unknown,
duplicate, re-encoded or missing checkpoint fields cannot pass even with a newly
calculated pin, unless they equal the expected complete generated document.

Exit 0 prints `dns_journal_checkpoint_matched`, counts and the checkpoint digest.
`current_authority_reverified` and `historical_signatures_reverified` remain false.
Exit 2 prints a fixed diagnostic without a success document. Stdout never prints
team/key/audience labels, finding/acceptance/history digests, receipt timestamps or
paths. Digests and counts can still be sensitive operational metadata. Keep the
checkpoint, journal, original evidence and independent pins private and outside Git.

### Exact-state behavior

| Candidate relative to the independently selected checkpoint | Result |
| --- | --- |
| Same complete logical event rows | Match |
| Consistent older backup or empty reset | Reject |
| Same counts and latest event, changed earlier receipt | Reject |
| Valid appended event | Reject until a new checkpoint is explicitly selected |
| SQLite VACUUM or a different physical file with identical logical rows | Match |
| Old journal plus old checkpoint and its own stale trusted pin | Can match; freshness is external |

This command intentionally checks an exact state, not a prefix or automatic advance.
After legitimate appends, explicitly create and independently retain a new checkpoint.
An old verification result does not authorize a new state. Checkpoint verification
does not gate journal registration automatically and does not prevent replacement
after the read transaction finishes.

## Boundaries and next work

Existing 8 MiB/2,000-event journal limits and internal history validation apply.
Checkpoint files are bounded at 4 KiB; symlinks, nonregular and oversized files fail.
No signature dependency is needed to create/verify a checkpoint of an existing
journal; the complete signed demonstration uses PyNaCl. The checkpoint reader does
not import original evidence, re-run signatures or consult current authority policy.

Logical equality is not physical file identity, collector authenticity or a globally
current head. An independently named persistent journal identity is not implemented.
A same-user editor can still create self-consistent records and issue a different
checkpoint. The protection depends on independently retaining and selecting a trusted
pin that the editor cannot replace. Fresh policy/revocation state and clock trust
remain external. Separate databases can accept the same task. No asset ownership,
global exclusivity, consensual release/transfer or remediation is established.

Use trusted local paths and cooperative writers. Read transactions provide one
SQLite snapshot, not an atomic filesystem snapshot, a tamper-proof import sandbox
or protection against same-user path replacement. Exclusive publication syncs the
file, not its parent directory. Retain the trusted implementation checkout;
version-specific historical dispatch is absent. Existing journal schema and signed
acceptance semantics are unchanged.

Next: independently identify/enroll journals and define explicit signed release or
transfer consent before permitting reassignment of an eligible task. Prepared with
assistant support and original synthetic evidence.
