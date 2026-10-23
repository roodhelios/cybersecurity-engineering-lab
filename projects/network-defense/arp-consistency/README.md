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

Next, add a small fixture-driven report diff so reviewers can compare two saved runs
without losing the source-line references.
