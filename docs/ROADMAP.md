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
- [x] Create OPA policies for least-privilege tool access. Native OPA 1.21.2 agrees
  with all eight reviewed fixtures and passes the combined signature/policy regression
  suite. See the recorded binary and policy digests in the Aegis validation guide.
  This establishes local conformance, not a deployed OPA service or exhaustive proof.
- [x] Add replay, privilege-escalation, malformed-signature, and clock-skew tests.
- [x] Produce an append-only audit record format and integrity checks.

## Milestone 3: AWS security baseline

- [x] Document a zero-surprise cost model and teardown procedure.
- [x] Define an offline IAM identity policy review for broad Allow permissions and
  explicit MFA conditions on IAM and role-assumption actions. This is not a live IAM
  simulation and does not verify MFA enrollment.
- [x] Review embedded IAM policies in a bounded CloudFormation JSON subset. YAML,
  intrinsic-function evaluation, trust policies, and effective permissions remain out
  of scope.
- [x] Review planned IAM policies in a bounded Terraform plan JSON subset. The local
  parser covers two managed AWS IAM policy resource types and nested modules. It does
  not parse Terraform configuration, trust policies, attachments, or effective access.
- [x] Add bounded CloudTrail-oriented triage rules using synthetic JSON Lines events.
  Current rules are triage signals, not proof of account compromise.
- [x] Create an offline account-compromise triage and response-planning runbook.
  Local fixture commands are validated; live containment and recovery remain untested.

## Milestone 4: Safe asset intelligence

- [ ] Define fixture-based asset and finding schemas. The first bounded DNS observation
  contract and exact hostname-scope policy now work with synthetic fixtures. The first reviewed address-mismatch finding and review-team contract now work.
  Broader finding and accepted-ownership contracts remain unfinished.
- [ ] Normalize and deduplicate discoveries from multiple mock sources. Saved DNS
  snapshots now normalize hostnames and IP addresses, reject ambiguous duplicate rows,
  and compare address sets with source row references. Saved Zeek DNS JSON can supply snapshots for one explicit address family, with
  latest transaction selection and omission reasons. A single saved-log workflow now
  retains both imports and the policy review before private publication. General cross-source asset
  identity and deduplication remain unfinished.
  Retained workflow reports can now reproduce every field from separately supplied
  source logs, scope, policy and optional review inputs under the current implementation.
  A separate recipient requirements file can now require the expected address family
  and selected review layers before reproduction succeeds. This does not authenticate
  collection choices, requirements approval or implement historical model replay.
- [x] Build a bounded explainable risk model for reviewed DNS mismatches, with
  explicit impact, exposure and authorization inputs, observation binding and clipping/
  band boundary tests. This is lab triage, not calibrated general asset risk.
- [ ] Create remediation prioritization and ownership workflows. Explicit routed-team
  response claims now bind an exact DNS finding revision and preserve pending status.
  Optional local review queues now prioritize explicit risk bands and preserve
  unassessed work, response claims and review suggestions. Authenticated acceptance,
  reassignment and remediation remain unfinished.
- [ ] Document explicit authorization and scope controls.

## Milestone 5: Network and malware analysis knowledge base

- [x] Turn the first network lab into a reproducible, isolated exercise. The offline
  ARP consistency review uses saved synthetic metadata and never captures or sends
  traffic. Additional network labs remain planned.
- [x] Add a defensive signal and expected evidence for the first exercise. Findings
  link the prior and current observation lines and explicitly avoid claiming spoofing.
  Optional DHCP-aware reconciliation distinguishes an expected reassignment from an
  unexplained change and rejects ambiguous lease coverage. A bounded saved forwarding
  table can also confirm that the current MAC appeared on a named port near the
  observation without treating the export as authenticated. Two recent forwarding
  snapshots now distinguish a saved port move, a stable port, and insufficient history.
  A reviewed local expected-port policy distinguishes an allowed current port, an
  unexpected port, a missing rule, and missing recent forwarding evidence.
  Saved Linux IPv4 neighbor JSON can now be imported with explicit capture times
  into the same offline review, with unresolved rows counted separately.
  Optional import receipts bind source bytes, claimed capture times, and source row
  references to generated observations, with reproduction before publication.
- [x] Create an inert malware behavior-report schema and bounded Python validator.
- [x] Add a bounded YARA exercise using a non-malicious text fixture. The wrapper
  requires an installed YARA CLI and does not claim that a literal match proves
  malicious behavior.
- [x] Map observed behavior to ATT&CK with confidence and evidence fields. Version 2
  keeps mappings linked to report observations and preserves version 1 compatibility.
  A bounded coverage review now reports phase/category counts and unlinked observation
  IDs without raw evidence text. Version-1 mapping coverage stays unknown, not zero.

## Definition of done for every pull request

- The change solves one stated problem.
- Relevant tests or validation commands pass.
- Documentation describes how to reproduce the result.
- Security boundaries and limitations are explicit.
- The pull request recommends one concrete next step.
