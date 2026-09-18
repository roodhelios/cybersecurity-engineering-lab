# Cybersecurity Engineering Lab

A living portfolio of small, testable security-engineering systems built from prior coursework, labs, and portfolio experience.

This repository is an ongoing reimplementation and extension of work across Zero Trust authorization, detection engineering, cloud security, network defense, OSINT, and malware analysis. Each pull request should add evidence that can be reviewed: working code, tests, threat models, architecture decisions, reproducible lab notes, or measured results.

## Current deliverable

### Security Event Normalizer

The first module converts Suricata EVE and Zeek JSON records into one typed event format. It provides a small foundation for later correlation, enrichment, risk scoring, and alert triage work.

```bash
cd projects/detection-engineering/event-normalizer
python -m unittest discover -s tests -v
```

### Aegis Authorization Threat Catalog

The Zero Trust track now starts with a machine-readable threat catalog for signed tool
requests, replay protection, policy decisions, step-up binding, and audit evidence. The
Python validator rejects unresolved references and contradictory scope before later
controls are treated as implemented.

```bash
cd projects/zero-trust/aegis-threat-model
PYTHONPATH=src python -m aegis_threat_model.cli model/threats.json
python -m unittest discover -s tests -v
```

## Project tracks

| Track | Starting point | Planned extensions |
| --- | --- | --- |
| Detection engineering | Zeek, Suricata, Wazuh, Splunk, and network-security labs | Event normalization, correlation rules, alert tests, and triage metrics |
| Aegis Zero Trust | FastAPI, OPA, Ed25519 requests, replay protection, and adaptive risk | Policy tests, signed-request verification, audit integrity, and abuse cases |
| Digital footprint and OSINT | Asset discovery, vulnerability tooling, and risk prioritization | Safe fixture-based discovery, deduplication, scoring, and remediation workflows |
| AWS security baseline | IAM, MFA, budgets, logging, and defensive cloud controls | Infrastructure-as-code checks, least privilege, cost guardrails, and incident runbooks |
| Network defense | TCP/IP, iptables, IDS/IPS, packet analysis, and attack/defense labs | Reproducible local labs, detection content, PCAP fixtures, and validation scripts |
| Malware analysis | Static and dynamic analysis with capa, IDA, Procmon, ProcDOT, and FakeNet-NG | Safe metadata parsers, YARA exercises, behavior mapping, and report templates |

## Engineering rules

- Work only against owned, local, fixture-based, or explicitly authorized targets.
- Never commit credentials, private data, live malware, or unverified claims.
- Prefer one reviewable improvement over a fixed commit count.
- Include a test or reproducible validation step with behavioral changes.
- Record assumptions, limitations, and measured evidence honestly.
- Open pull requests for review; do not automatically merge them.

See [the roadmap](docs/ROADMAP.md) for the ordered backlog and [AGENTS.md](AGENTS.md) for the daily-development guardrails.

## Status

Active development. Interfaces and project structure may change while the first milestones are completed.
