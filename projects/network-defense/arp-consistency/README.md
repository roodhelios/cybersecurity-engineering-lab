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

Each non-empty input line must contain exactly `timestamp`, `interface`, `ip`, and
`mac`. Timestamps need an explicit UTC offset, IPv4 addresses must be canonical, and
MAC addresses use six colon-separated octets. The command rejects duplicate JSON
fields, records above 16 KiB, more than 10,000 records, and time moving backward for
one interface and IP. Set a review window from 1 to 3,600 seconds with
`--window-seconds`.

## Validate

```bash
python -m unittest discover \
  -s projects/network-defense/arp-consistency/tests -v
```

## Interpretation and limits

A mapping change is a review signal, not proof of spoofing or compromise. Planned
failover, device replacement, address reuse, and virtualization can produce the same
observation. This exercise does not validate packet provenance, DHCP state, switch
tables, interface authorization, or whether an observation was collected correctly.
Keep real network identifiers private and out of Git.

Next, retain a bounded DHCP lease fixture beside the ARP observations so a reviewer
can distinguish an expected reassignment from an unexplained mapping change.
