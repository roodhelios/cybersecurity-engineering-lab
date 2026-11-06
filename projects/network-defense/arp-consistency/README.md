# Offline ARP consistency review

This exercise reviews saved JSON Lines observations and reports when the same IPv4
address moves to another MAC address on the same interface within a bounded window.
It is passive and offline. It does not capture packets, send ARP traffic, or connect
to a network.

## Quickstart

From the repository root, use Python 3.11 or newer:

```bash
python projects/network-defense/arp-consistency/arp_consistency.py \
  projects/network-defense/arp-consistency/examples/arp-observations.jsonl
```

The synthetic fixture contains three observations. The report contains one
medium-confidence mapping change for `192.0.2.10`, linking lines 1 and 3 with an
elapsed time of 60 seconds. Output is deterministic JSON.

## Import saved Linux neighbor snapshots

For retained IPv4 neighbor JSON in the shape produced by `ip -4 -j neigh show`,
import two files without manually rewriting rows. The supplied files are synthetic:

```bash
python projects/network-defense/arp-consistency/neighbor_import.py \
  --snapshot 2026-10-23T05:00:00Z \
  projects/network-defense/arp-consistency/examples/neighbors-before.json \
  --snapshot 2026-10-23T05:01:00Z \
  projects/network-defense/arp-consistency/examples/neighbors-after.json \
  --output /tmp/neighbor-observations.jsonl
python projects/network-defense/arp-consistency/arp_consistency.py \
  /tmp/neighbor-observations.jsonl
```

Use a fresh output path on POSIX. Expect two imported observations, one skipped
unresolved row, and one finding for `192.0.2.10` after 60 seconds. Import counts go to
stderr; stdout, when requested instead of `--output`, contains only JSON Lines.
The output file is private (0600), complete before publication, and never overwrites
an existing path. The importer reads local files and does not run `ip` or contact hosts.

Each resolved row needs `dst`, `dev`, and `lladdr`. Other neighbor metadata is ignored;
an absent MAC is skipped only for an explicit `INCOMPLETE` or `FAILED` state. A saved
MAC in a `STALE` record remains a cache observation, not a live reachability claim.
IPv6, malformed rows, duplicate JSON fields, and duplicate interface/IP pairs within
one snapshot fail the entire import. Use the IPv4 export subset, with at most 32
strictly chronological snapshots, 4 MiB per snapshot, and 10,000 combined observations.

The capture times are caller claims, normalized to UTC. They are not derived from
filesystem times or authenticated by this tool. Keep the original snapshots for review;
finding line numbers refer to the normalized JSON Lines, not the original JSON arrays.
The field mapping follows [iproute2's neighbor JSON output](https://github.com/iproute2/iproute2/blob/main/ip/ipneigh.c).

Retain a receipt before publishing observations, then reproduce it from the same
snapshots in another process:

```bash
python projects/network-defense/arp-consistency/neighbor_import.py \
  --snapshot 2026-10-23T05:00:00Z \
  projects/network-defense/arp-consistency/examples/neighbors-before.json \
  --snapshot 2026-10-23T05:01:00Z \
  projects/network-defense/arp-consistency/examples/neighbors-after.json \
  --format receipt --output /tmp/neighbor-receipt.json
python projects/network-defense/arp-consistency/neighbor_import.py \
  --snapshot 2026-10-23T05:00:00Z \
  projects/network-defense/arp-consistency/examples/neighbors-before.json \
  --snapshot 2026-10-23T05:01:00Z \
  projects/network-defense/arp-consistency/examples/neighbors-after.json \
  --verify-receipt /tmp/neighbor-receipt.json --output /tmp/verified-observations.jsonl
```

Use fresh output paths. The receipt contains each input's SHA-256, claimed time,
resolved/unresolved counts, and the exact generated JSON Lines digest. Each generated
observation line maps to a snapshot index and one-based row index in its original
JSON array. It omits file paths, IPs, and MACs. For these fixtures, observation lines
1 and 2 map to row 1 in snapshots 1 and 2. An edited reference or changed source byte
prevents verified publication, even if parsed observations would be unchanged.
Receipt verification is bounded to 4 MiB and compares the complete recomputed receipt.
Hashes establish consistency, not source authenticity, authorization, or capture time.

Reconcile the changed mapping with a separately retained DHCP lease export:

```bash
python projects/network-defense/arp-consistency/arp_consistency.py \
  projects/network-defense/arp-consistency/examples/arp-observations.jsonl \
  --leases projects/network-defense/arp-consistency/examples/dhcp-leases.jsonl
```

The synthetic lease covers the new MAC at the observation time, so the finding is
marked `expected_reassignment` and linked to lease line 1. A change without exactly
one matching active lease is marked `unexplained_change`. Without `--leases`, the
original report shape remains unchanged and makes no DHCP claim.

Add a saved switch forwarding-table snapshot as a second evidence source:

```bash
python projects/network-defense/arp-consistency/arp_consistency.py \
  projects/network-defense/arp-consistency/examples/arp-observations.jsonl \
  --leases projects/network-defense/arp-consistency/examples/dhcp-leases.jsonl \
  --forwarding-table \
  projects/network-defense/arp-consistency/examples/switch-forwarding.jsonl
```

The included history records the current MAC on `swp3`, then `swp7`, before the ARP
observation. The finding is marked `current_mac_observed` and `port_move_observed`,
with both forwarding source lines, both ports, and 30 elapsed seconds. When the two
most recent eligible snapshots agree, the status is `stable_port`. One eligible
snapshot becomes `insufficient_history`. A missing, future, or stale current record
becomes `no_recent_current_mac`; absence from a saved table is not proof that the
device was absent. Without
`--forwarding-table`, no forwarding fields or summary are added.

Compare the current saved port with a reviewed local policy:

```bash
python projects/network-defense/arp-consistency/arp_consistency.py \
  projects/network-defense/arp-consistency/examples/arp-observations.jsonl \
  --leases projects/network-defense/arp-consistency/examples/dhcp-leases.jsonl \
  --forwarding-table \
  projects/network-defense/arp-consistency/examples/switch-forwarding.jsonl \
  --port-policy \
  projects/network-defense/arp-consistency/examples/expected-ports.jsonl
```

The current `swp7` record matches the fixture policy, so the finding reports
`expected_port` and links policy line 1. A current port outside the matching rule
reports `unexpected_port`. A current record with no rule reports `no_matching_rule`,
while missing recent forwarding evidence remains distinct. The report does not copy
the allowlist into its output.

Each non-empty input line must contain exactly `timestamp`, `interface`, `ip`, and
`mac`. Timestamps need an explicit UTC offset, IPv4 addresses must be canonical, and
MAC addresses use six colon-separated octets. The command rejects duplicate JSON
fields, records above 16 KiB, more than 10,000 records, and time moving backward for
one interface and IP. Set a review window from 1 to 3,600 seconds with
`--window-seconds`.

Lease lines contain exactly `starts_at`, `ends_at`, `interface`, `ip`, and `mac`.
Both timestamps require UTC offsets, and `ends_at` cannot precede `starts_at`.
Overlapping leases for the same mapping fail the review instead of silently selecting
one. Lease schedules are indexed so each finding does not rescan the whole lease file.

Forwarding lines contain exactly `captured_at`, `interface`, `mac`, and `port`. The
latest two records at or before the changed observation are eligible when each is no
more than 300 seconds old. Set a limit from 1 to 3,600 seconds with
`--forwarding-max-age-seconds`. Duplicate capture times for one interface and MAC are
rejected instead of selecting an arbitrary port. Forwarding schedules are indexed.

Port policy lines contain exactly `interface`, `mac`, and `allowed_ports`. Rules match
one interface and MAC pair. Each allowlist must be non-empty, sorted, unique, and no
larger than 64 entries. Duplicate rules fail closed. `--port-policy` requires
`--forwarding-table`; policy evaluation never contacts a switch.

## Validate

```bash
python -m unittest discover \
  -s projects/network-defense/arp-consistency/tests -v
```

## Interpretation and limits

A mapping change is a review signal, not proof of spoofing or compromise. Planned
failover, device replacement, address reuse, and virtualization can produce the same
observation. A reported port move means only that two saved records name different
ports for the same interface and MAC. The saved DHCP and forwarding files are
unauthenticated supporting evidence. This exercise does not validate packet provenance,
live DHCP state, the completeness of a switch table, interface authorization, switch
topology, or whether an observation was collected correctly. Keep real network
identifiers and infrastructure exports private and out of Git.

## Compare two saved reviews

From the repository root on POSIX, with Python 3.11 or newer:

```bash
python -S projects/network-defense/arp-consistency/demo_comparison.py
```

Expect `arp_comparison_exercise_passed`, one added transition, one changed transition
and four rejected negative cases. The changed finding has the same transition
identity but a different original line reference. All data is bundled original
synthetic metadata, and retained files are temporary. Prepared with assistant support.

For retained local inputs, choose a new output inside private trusted storage:

```bash
python -S projects/network-defense/arp-consistency/compare_reviews.py \
  projects/network-defense/arp-consistency/examples/arp-observations.jsonl \
  projects/network-defense/arp-consistency/examples/arp-observations-later.jsonl \
  --scope synthetic --window-seconds 300 --forwarding-max-age-seconds 300 \
  --output /tmp/arp-comparison.json
```

The command replays both original observation sets under the current reviewer and
prints `arp_comparison_retained`, counts and the exact `report_sha256`. Keep that
digest independently. Both sides can also supply `--before-leases`/`--after-leases`,
`--before-forwarding`/`--after-forwarding` and
`--before-port-policy`/`--after-port-policy`. A policy requires forwarding evidence
on its own side. Each input is an explicitly supplied regular file of at most 4 MiB.
The existing 10,000-row and 16 KiB-row contracts still apply. Empty observations
are valid and mean no observations were supplied.

Replay the complete retained result with the same original inputs and requirements:

```bash
python -S projects/network-defense/arp-consistency/compare_reviews.py \
  projects/network-defense/arp-consistency/examples/arp-observations.jsonl \
  projects/network-defense/arp-consistency/examples/arp-observations-later.jsonl \
  --scope synthetic --window-seconds 300 --forwarding-max-age-seconds 300 \
  --verify-report /tmp/arp-comparison.json \
  --expected-report-sha256 TRUSTED_REPORT_SHA256
```

Replace the placeholder with the independently retained lowercase 64-character digest.
Expect `arp_comparison_reproduced` and `original_inputs_replayed: true`. Verification
compares every retained field, including input digests, parameters, counts, identities
and complete findings. Recalculating a pin after editing a finding cannot replace
reproduction from the originals. Changed original bytes fail even when findings match.
Wrong pin syntax fails before file access; a mismatched report pin fails before source
access. Source and report symlinks, directories and FIFOs are rejected without waiting.

| Comparison status | Meaning |
| --- | --- |
| `added` | Transition key appears only in the after review |
| `not_observed` | Transition key appears only in the before review |
| `changed` | Same transition key, different finding context or source references |
| `unchanged` | Same transition key and complete finding |

A key covers interface, normalized IPv4, both MAC claims and both UTC timestamps.
Repeated mappings at different times stay distinct. Ambiguous repeated transitions
at identical timestamps reject instead of being paired arbitrarily. Event IDs are
domain-separated hashes of those claims, not collector or device identities.
Changing lease, forwarding or policy context can change a finding without changing
the observation transition. Both complete findings and their side-specific line
references remain in the private report; each source is bound by exact byte digest.

Reports are bounded to 32 MiB. `--output` publishes a fresh mode-0600 file exclusively;
existing outputs are preserved. Generation without `--output` prints the full report,
which includes network identifiers. Retention and verification summaries contain
only counts/digests. Invalid input exits 2 with a fixed diagnostic and no success JSON.
Keep real originals, reports and pins private and outside Git. This is not an atomic
filesystem snapshot or power-loss durability guarantee.

These are comparisons of supplied evidence, not proof of collection completeness,
permission, source truth, an attack or accepted remediation. Old inputs can still
reproduce under an old pin. No authenticated freshness, historical model dispatch,
live collection or response action is added. Next: independently define expected
capture coverage before interpreting an absent transition as an operational change.
