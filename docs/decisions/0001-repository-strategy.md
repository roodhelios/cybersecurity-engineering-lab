# ADR 0001: Use a milestone-driven security engineering monorepo

- Status: Accepted
- Date: 2026-09-12

## Context

The portfolio spans related work in detection, Zero Trust, cloud security, network defense, asset intelligence, and malware analysis. Publishing each small exercise independently would make shared standards difficult to see and could encourage shallow activity.

## Decision

Use one public monorepo with self-contained projects under `projects/`. Develop through milestone-oriented pull requests governed by a shared roadmap and repository-level security rules.

Each project must provide its own setup, validation command, limitations, and safe-use boundaries. Common libraries may be introduced only after at least two projects need the same behavior.

## Consequences

- Reviewers can see consistent engineering practices across security domains.
- Daily work can continue the highest-priority incomplete milestone.
- Projects remain independently runnable, although some configuration is duplicated.
- Repository history should reflect coherent deliverables rather than an arbitrary number of commits.
