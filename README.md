# Cybersecurity Engineering Lab

Python tools for turning security telemetry, authorization decisions, and analysis
notes into evidence another engineer can reproduce and review.

This repository reimplements and extends prior coursework and lab work. Examples use
synthetic data and run locally. It does not deploy cloud resources or run malware.

## Choose a working project

| Project | What you can run | Guide |
| --- | --- | --- |
| Detection engineering | Normalize Suricata and Zeek events, correlate connections, attach conservative ATT&CK candidates | [Event normalizer](projects/detection-engineering/event-normalizer/README.md) |
| Zero Trust | Verify signed requests, reject replay, evaluate policy fixtures, inspect hash-linked audit records | [Aegis threat model](projects/zero-trust/aegis-threat-model/README.md) |
| Cloud security | Review offline IAM and CloudFormation policies, triage synthetic CloudTrail events, validate cost plans | [AWS security tools](projects/cloud-security/aws-cost-plan/README.md) |
| Malware analysis | Validate inert behavior reports and run a pinned YARA training exercise | [Analysis exercises](projects/malware_analysis/README.md) |

## Try it in two minutes

Use Python 3.11 or newer. From the repository root, normalize the included mixed
Suricata and Zeek fixture with the standard library:

```bash
PYTHONPATH=projects/detection-engineering/event-normalizer/src python -m event_normalizer \
  projects/detection-engineering/event-normalizer/tests/fixtures/mixed_events.jsonl
```

The command writes two JSON Lines records. The first has `source: suricata`,
`protocol: TCP`, and `dest_port: 443`. The second has `source: zeek`,
`protocol: udp`, and `dest_port: 53`. Each retains its original record in `raw`.

Correlate a synthetic batch into an investigation report:

```bash
PYTHONPATH=projects/detection-engineering/event-normalizer/src python -m event_normalizer.correlation_cli \
  projects/detection-engineering/event-normalizer/tests/fixtures/repeated_attempts.jsonl
```

Expect four events and one medium-confidence T1046 candidate. This is a local
connection-pattern review, not proof of scanning or compromise. The command bounds
batch size and emits no success report when any input line is invalid.
Add `--include-evidence` for report version 2 with the supporting input line
numbers and canonical event digests. Retain the original file to review those lines;
digests do not authenticate the source.

Review a saved version 2 report against its retained input with
`python -m event_normalizer.evidence_verify INPUT.jsonl REPORT.json` and the same
`PYTHONPATH` above. The verifier recomputes findings and all references, not just
digests. See the project guide for the complete save-and-verify example.

Have a saved tab-separated Zeek `conn.log` instead of JSON? The
[text-log import guide](projects/detection-engineering/event-normalizer/README.md#import-a-zeek-text-connection-log)
shows how to convert its declared connection fields into the same local pipeline.

Validate a synthetic behavior report without installing or running a sample:

```bash
python projects/malware_analysis/report_validator.py \
  projects/malware_analysis/examples/synthetic-behavior-report-v2.json
```

Already have a local CloudTrail `Records` JSON or gzip export? The
[native-file import guide](projects/cloud-security/aws-cost-plan/README.md#import-a-local-cloudtrail-records-file)
converts it to private JSON Lines for triage and response planning without contacting AWS.

Review changes between two inert malware-analysis reports without running a sample:

```bash
python -m projects.malware_analysis.report_diff \
  projects/malware_analysis/examples/synthetic-behavior-report-v1.json \
  projects/malware_analysis/examples/synthetic-behavior-report-v2.json
```

The included reports claim the same sample and observations. Expect no observation
changes and `attack_mappings.status: not_comparable`: version 1 did not record that
collection. For two version 2 reports, the tool also identifies mappings that need
review because their linked observations changed. See the
[comparison contract](projects/malware_analysis/README.md#compare-analysis-revisions).

## Validate a project

```bash
python -m unittest discover -s projects/detection-engineering/event-normalizer/tests -v
python -m unittest discover -s projects/malware_analysis/tests -v
```

The Aegis Ed25519 exercises require `cryptography`, declared in their project package.
Native policy mode is now validated against OPA 1.21.2; see the
[reproduction guide](projects/zero-trust/aegis-threat-model/docs/OPA_VALIDATION.md).
Real OPA conformance and YARA execution require
their respective binaries. A skipped integration test does not establish tool execution.
Each project guide documents its setup, interfaces, and limitations.

## What is still unfinished

The [offline account-response runbook](projects/cloud-security/aws-cost-plan/docs/account-response.md)
walks through the supplied CloudTrail findings, timeline review, proposed containment,
and recovery handoff. Its commands make no AWS API calls; live response remains outside
the validated lab scope.
The runbook also includes a runnable handoff exporter with an input digest and
line-linked timeline. Its output keeps containment and recovery explicitly unverified.

The [ordered roadmap](docs/ROADMAP.md) records local OPA conformance and tracks live validation of
response procedures, and additional isolated network labs. OSINT and network-defense
tracks are planned extensions, not completed tools here. Fixture detections and
analyst confidence fields do not prove compromise or attribution.

Use only owned, synthetic, or explicitly authorized data. Keep credentials and live
malware out of Git. Submit a PR with a reproducible example and relevant validation.
See [AGENTS.md](AGENTS.md) and [repository strategy](docs/decisions/0001-repository-strategy.md).
Implementation has been extended with assistant support.
