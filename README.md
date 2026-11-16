# Cybersecurity Engineering Lab

Python tools for turning saved security telemetry, authorization decisions and
analysis notes into evidence another engineer can reproduce and review.

The project reimplements and extends prior coursework with assistant support.
Examples use synthetic local data. Nothing here deploys cloud resources, scans
hosts, sends packets or runs malware.

## Start with a complete offline exercise

From the repository root, use Python 3.11 or newer on POSIX:

```bash
python -m lab list
python -m lab run cloudtrail-archive
```

No account, package installation or AWS connection is needed for this exercise.
It retains a synthetic CloudTrail case, its ordered plain/gzip originals and an
allowlisted model-source snapshot, removes the separate originals, then restores
and reproduces the evidence. Selected output fields:

```json
{
  "status": "cloudtrail_archive_exercise_passed",
  "originals_removed": true,
  "exact_bytes_restored": true,
  "restored_code_files": 0,
  "negative_cases_rejected": 3
}
```

All generated files are temporary. Archived code is never restored or executed.
This proves local byte and model consistency, not source truth, containment or
recovery of an AWS account. The [archive guide](projects/cloud-security/aws-cost-plan/docs/cloudtrail-archive.md)
shows retained-file commands, publication bounds and trust requirements.

## Choose a project

| Area | Working local behavior | Guide |
| --- | --- | --- |
| Detection engineering | Normalize Suricata/Zeek events, correlate connections and retain original-line evidence | [Event pipeline](projects/detection-engineering/event-normalizer/README.md) |
| Zero Trust | Verify signed requests and replay bounds, evaluate OPA policy fixtures and audit integrity | [Aegis authorization core](projects/zero-trust/aegis-threat-model/README.md) |
| Cloud security | Review supplied IAM/CloudFormation/Terraform plans and reproduce saved CloudTrail cases | [AWS security tools](projects/cloud-security/aws-cost-plan/README.md) |
| Asset intelligence | Compare scoped saved DNS observations, review mismatches and verify enrolled-key task claims | [DNS workflow](projects/asset-intelligence/dns-review/README.md) |
| Network defense | Reconcile saved ARP changes and Linux neighbor snapshots with supporting evidence | [ARP consistency](projects/network-defense/arp-consistency/README.md) |
| TCP reset triage | Group saved Zeek reset-state claims with original-line references | [TCP reset review](projects/network-defense/tcp-reset-review/README.md) |
| Safe malware analysis | Validate and compare inert behavior notes; optionally run a YARA text-fixture exercise | [Analysis exercises](projects/malware_analysis/README.md) |

The [detailed workflow reference](docs/local-workflows.md) preserves the existing
commands, expected results and retained-evidence links. Each project guide explains
its input contract, tests and limits. Existing script/module commands still work.

## Try another bundled exercise

```bash
python -m lab list --format json
python -m lab run arp-compare
python -m lab run malware-notes
python -m lab run zeek-review
python -m lab run dns-sources
```

The catalog contains 13 fixed exercises. The first five use only the standard
library. `arp-compare` returns `arp_comparison_exercise_passed` and reproduces both
saved synthetic input sets. `malware-notes` returns `report_type: behavior-note-coverage`
with two claimed observations and one unlinked observation. It opens no sample.
Neither result establishes malicious activity.

`zeek-review` reports four imported events, one correlation candidate and original
text lines 8 to 11 from a synthetic gzip connection log. It reproduces the complete
review against the exact original bytes without retaining an intermediate JSONL
file. See the [original-log review guide](projects/detection-engineering/event-normalizer/README.md#review-an-original-text-log-in-one-workflow)
for private retained commands and evidence limits.

`dns-sources` groups aligned saved DNS address claims, preserves conflicting sets
and missing observations, and flags byte-identical inputs. It does not count copies
as independent corroboration. It also reproduces the complete report under separate
original-byte pins and rejects a changed original. See the
[source-review and recipient guide](projects/asset-intelligence/dns-review/SOURCE_REVIEW.md).

The eight DNS signature exercises require the listed optional PyNaCl dependency:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python -m lab run dns-recipient
```

Expect `authorized_handoff_exercise_passed`. These exercises use temporary local
keys, fixed fixture instants and synthetic logs. They authenticate enrolled key
claims, not human identity, source truth, accepted ownership or remediation.
Listing/help never imports a project or installs dependencies. `run` accepts only
catalog names, with no external input paths, output paths or forwarded arguments.
It uses the active Python interpreter and the checkout root, and propagates the
exercise's exit status. It is a convenience launcher, not a sandbox or installer.
The catalog is a starting subset, not every project command.

## Status and validation

The [ordered roadmap](docs/ROADMAP.md) tracks completed behavior and unfinished
milestones. Live sensor validation, general cross-source asset identity, trusted
key/policy distribution and accepted asset ownership remain unfinished. An absent
observation is not proof that an asset was deleted or a finding resolved.

```bash
python -m unittest discover -s tests -v
python -m unittest discover -s projects/detection-engineering/event-normalizer/tests -v
```

Root tests exercise catalog dispatch and real bundled workflows. Optional signing
coverage needs PyNaCl. Project suites have their own prerequisites; native OPA and
YARA validation require their respective binaries. Skips do not establish execution.
Use only owned, synthetic or explicitly authorized data. Keep credentials, private
logs and live malware outside Git. See [contribution instructions](AGENTS.md) and
[repository strategy](docs/decisions/0001-repository-strategy.md).
