# Roadmap

The backlog is ordered to produce complete, reviewable systems instead of many disconnected demos. A milestone is complete only when its behavior, tests, documentation, and limitations agree.

## Milestone 1: Detection event pipeline

- [x] Define a normalized event model.
- [x] Parse representative Suricata EVE alert records.
- [x] Parse representative Zeek JSON connection records.
- [x] Validate timestamps and network ports.
- [x] Add a JSON Lines command-line interface.
- [x] Add deterministic fixture files and golden-output tests.
- [x] Map selected events to MITRE ATT&CK techniques without overstating confidence.
- [x] Add correlation for repeated connection attempts in a bounded time window.
- [x] Measure throughput and document the test environment.

## Milestone 2: Aegis authorization core

- [x] Write a scoped threat model for tool-using AI agents.
- [x] Implement signed request verification with timestamp and nonce validation.
- [ ] Create OPA policies for least-privilege tool access. A Rego draft and Python
  fixture oracle exist, but Rego-native OPA tests are still required.
- [ ] Add replay, privilege-escalation, malformed-signature, and clock-skew tests.
- [ ] Produce an append-only audit record format and integrity checks.

## Milestone 3: AWS security baseline

- [ ] Document a zero-surprise cost model and teardown procedure.
- [ ] Define IAM and MFA guardrails as testable policy.
- [ ] Add local static checks for unsafe infrastructure-as-code examples.
- [ ] Add CloudTrail-oriented incident queries using synthetic events.
- [ ] Create an account-compromise response runbook.

## Milestone 4: Safe asset intelligence

- [ ] Define fixture-based asset and finding schemas.
- [ ] Normalize and deduplicate discoveries from multiple mock sources.
- [ ] Build explainable risk scoring with boundary tests.
- [ ] Create remediation prioritization and ownership workflows.
- [ ] Document explicit authorization and scope controls.

## Milestone 5: Network and malware analysis knowledge base

- [ ] Turn selected network labs into reproducible, isolated exercises.
- [ ] Add defensive detections and expected evidence for each exercise.
- [ ] Create an inert malware behavior-report schema.
- [ ] Add safe YARA exercises using non-malicious fixtures.
- [ ] Map observed behavior to ATT&CK with confidence and evidence fields.

## Definition of done for every pull request

- The change solves one stated problem.
- Relevant tests or validation commands pass.
- Documentation describes how to reproduce the result.
- Security boundaries and limitations are explicit.
- The pull request recommends one concrete next step.
