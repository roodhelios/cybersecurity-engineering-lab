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
current head. Version-1 and version-2 journals do not carry a persistent identity. The separate
[version-3 enrollment workflow](JOURNAL_ENROLLMENT.md) now provides an explicitly
selected local identity; it does not authenticate a machine or collector.
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

Next: independently identify/enroll journals and distribute fresh pins, then design
administrative recovery and cross-team consent. Same-key voluntary release now works
in the separate version-2 journal. Prepared with assistant support and original
synthetic evidence.

## Checkpoint a version-2 lifecycle journal

Version 1 does not capture release events. Use the separate version-2 command for
the store created by `dns_assignment_lifecycle.py`:

```bash
python projects/asset-intelligence/dns-review/demo_lifecycle_checkpoint.py
```

Expect `dns_lifecycle_checkpoint_exercise_passed`, `acceptance_count: 1`,
`release_count: 1`, `negative_cases_rejected: 2` and `stale_pair_still_matches: true`.
The temporary synthetic exercise uses native SQLite and real Ed25519 signatures,
with sockets forbidden and private keys kept only in memory. It restores the
pre-release database and detects that rollback even though the acceptance count
is unchanged. The other rejection uses a wrong independent pin. Finally it shows
the old database matching its own stale checkpoint and pin. This is evidence of
the freshness limit, not a bypass of a current independently selected pin.

For your owned, closed or cooperatively written private version-2 database:

```bash
python projects/asset-intelligence/dns-review/dns_lifecycle_checkpoint.py create \
  /private/dns-lifecycle/journal.sqlite --output /private/review/lifecycle-checkpoint.json
python projects/asset-intelligence/dns-review/dns_lifecycle_checkpoint.py verify \
  /private/dns-lifecycle/journal.sqlite --checkpoint /private/review/lifecycle-checkpoint.json \
  --expected-sha256 INDEPENDENTLY_RETAINED_CHECKPOINT_SHA256
```

Paths and the digest label are placeholders. Creation prints
`dns_lifecycle_checkpoint_created` and a digest that must be retained through an
independent trusted channel. Verification prints `dns_lifecycle_checkpoint_matched`
only for the complete exact state. Both commands emit aggregate acceptance, release
and task counts without identities, receipt contents, signatures or paths. Exit 2
is a fixed-diagnostic failure. Output is a fresh private mode-0600 file and cannot
overwrite an existing checkpoint. Reader and journal path bounds remain as above.

The version-2 document has schema version 2 and a separate checkpoint type/hash
domain. Its history digest covers every ordered column of both tables, including
all retained receipt strings. Both existing table validators run under the same
read-only SQLite transaction before capture. This catches changed older acceptance
or release rows, removed releases, modified receipt formatting, valid appends and
rollback relative to the selected exact-state pin. SQLite layout changes and
identical logical copies can still match. Neither command migrates or accepts the
other journal version. Existing v1 commands are unchanged.

The checkpoint does not bind physical file identity, schema/trigger text, unrelated
tables or a current authorization decision. It does not reverify historical
signatures, prove collection truth, prevent a same-user editor from rewriting files,
establish the latest trusted pin or gate future registration. The existing private
path, cooperative-writer and current trusted-checkout requirements still apply.
It is not a history signature, global assignment registry or power-loss test.


For an identity-bound checkpoint, use the separate [version-3 workflow](JOURNAL_ENROLLMENT.md).
It requires a new store and independently pinned enrollment. This v2 command remains
an exact logical-history check and does not migrate older stores.
