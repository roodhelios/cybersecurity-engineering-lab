# Offline TCP reset review

Review repeated reset-state claims in a saved Zeek JSON `conn.log`. This is a
standard-library Python exercise. It reads one local file and never captures,
generates, transmits or replays traffic. It does not run Zeek or require packets.

## Run the synthetic example

From the repository root, Python 3.11+ on POSIX:

```bash
python projects/network-defense/tcp-reset-review/tcp_reset_review.py \
  projects/network-defense/tcp-reset-review/examples/connections.jsonl --scope synthetic
```

Expect six records and one `repeated_recorded_tcp_resets` finding for responder
`198.51.100.20:443`, state `RSTR`, count three, with evidence lines 1, 3 and 5.
The first and last records span exactly 60 seconds, which is included. The fixture
is original synthetic metadata, not a capture or evidence of a real incident.

Retain a private report with a fresh destination in a trusted private directory:

```bash
python projects/network-defense/tcp-reset-review/tcp_reset_review.py \
  projects/network-defense/tcp-reset-review/examples/connections.jsonl \
  --scope synthetic --min-resets 3 --window-seconds 60 --output /tmp/tcp-reset-review.json
```

The report is 0600, completed before exclusive publication and never overwrites
an existing path. Retention mode prints no report to stdout. Validation failures
return exit 2 with generic stderr and do not publish a report. Publication errors
can leave a completed destination; inspect privately before retrying. This is not
a power-loss durability guarantee. Without `--output`, stdout contains the report,
including responder addresses, ports and connection UIDs. Keep real logs and reports
private and outside Git. Use `owned` or `authorized` only for inputs you may review;
the scope label records your claim, not proof of permission.

## Input contract

One UTF-8 JSON object per line. Required Zeek field names:

| Field | Accepted subset |
| --- | --- |
| `ts` | Nonnegative numeric epoch seconds through 253402300799, at most six fractional digits |
| `uid` | Unique 1 to 64 character alphanumeric/underscore/hyphen ID, starting alphanumeric |
| `proto` | `tcp`, `udp` or `icmp` |
| `id.orig_h`, `id.resp_h` | Same-family IPv4 or IPv6 literals, no zone identifiers |
| `id.orig_p`, `id.resp_p` | Integers 0 to 65535, not booleans or strings |
| `conn_state` | One of the 13 documented Zeek connection-state labels supported by this version |

Additional metadata is ignored after JSON parsing, not copied to the report.
All rows, including non-TCP rows, must satisfy the common contract. Non-TCP rows
are counted separately. Blank rows, invalid UTF-8, duplicate JSON keys, non-finite
JSON constants, malformed fields and duplicate UIDs reject the entire batch.
Review one sensor export at a time; repeated UIDs are not silently deduplicated.
This is not a TSV, PCAP, arbitrary JSON array or multi-sensor importer.

Limits: 8 MiB input, 64 KiB per row and 10,000 rows. The POSIX reader rejects final
symlinks, directories and FIFOs. It reads one bounded in-memory byte snapshot, not
an atomic filesystem snapshot or protection from a malicious concurrent writer.
The timestamp subset uses exact integer microseconds after decimal parsing.

## Review rule and interpretation

The state meanings follow [Zeek's connection-log contract](https://docs.zeek.org/en/lts/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info).

| State | Recorded reset side | Context retained by this tool |
| --- | --- | --- |
| `RSTO` | Originator | Established |
| `RSTR` | Responder | No establishment claim added |
| `RSTOS0` | Originator | No responder SYN-ACK seen |
| `RSTRH` | Responder | No originator SYN seen |

`REJ` means a rejected attempt and is counted separately. It does not contribute
to these reset-state groups, even if its history includes a reset flag. The tool
does not interpret `history` or inspect sequence/acknowledgment numbers.

Group by normalized **responder address, responder port and exact reset state**.
This is a service-oriented triage grouping, not the identity of a reset sender.
Within each group, sort by timestamp then UID and select the highest-count sliding
window whose first/last timestamps differ by at most `--window-seconds`. Ties retain
the earliest discovered window. Only one best window per group is emitted, and
only if it reaches `--min-resets`. Defaults are three and 60 seconds. Bounds are
2 to 10,000 records and 1 to 86,400 seconds. Windows are not epoch-aligned buckets.
The output and total evidence references are bounded by the input row count.

Each evidence item contains the original 1-based line, UID and SHA-256 of that
line's bytes excluding its LF or CRLF terminator. The report also binds every input
byte with `input_sha256`, including line endings. References help a reviewer inspect
the retained source. They do not authenticate collection or establish historical
signing time. The report is unsigned, and no retained-report verifier is provided yet.

Counts are not traffic-normalized rates, a calibrated anomaly score or an ATT&CK
classification. No spoofing, injection or malicious sender is inferred. Legitimate
application closes, service failures, middleboxes, packet loss and asymmetric sensor
visibility can produce reset observations. Review neighboring logs and application
context privately before drawing a conclusion. This does not mitigate an attack.

## Validate locally

```bash
python -m unittest discover -s projects/network-defense/tcp-reset-review/tests -v
```

Tests use synthetic metadata and temporary native POSIX files. They include the
inclusive microsecond boundary, strongest/tied windows, original-line references,
state and service isolation, malformed batches, bounded readers and a fresh-process
CLI. No live service, packet capture, attack tool or firewall change is involved.

Next: reproduce a retained report against its original input and parameters before
using it as a review handoff. Live packet evidence and sensor validation remain separate.
