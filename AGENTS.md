# Daily Development Instructions

These instructions apply to automated and interactive work in this repository.

## Objective

Build a credible cybersecurity engineering portfolio by extending prior areas of study with small, working, defensible improvements. Optimize for learning value and review quality, not contribution counts.

## Daily workflow

1. Read the repository roadmap, open pull requests, recent commits, and the closest project README.
2. Continue an in-progress milestone before starting unrelated work.
3. Select one bounded change that can be implemented and validated in a single run.
4. Use a branch named `daily/YYYY-MM-DD-short-topic`; never commit directly to `main`.
5. Add or update tests for behavioral changes and run the narrowest relevant test suite.
6. Update documentation when interfaces, assumptions, commands, or limitations change.
7. Open one pull request explaining the problem, implementation, validation, risks, and a suggested next step.
8. Never merge the pull request. Leave it for Aryan to inspect and merge.

## Quality bar

- Do not create empty folders, filler files, fake activity, backdated commits, or arbitrary formatting churn.
- Do not split one logical change into artificial commits. Use one to five coherent commits only when the history benefits.
- Do not claim performance, security, accuracy, or coverage results that were not produced during validation.
- Keep examples deterministic and runnable without paid services whenever possible.
- Prefer standard-library implementations initially; add dependencies only when they materially improve the solution.
- Preserve backward compatibility unless the pull request clearly documents and tests an intentional break.

## Security boundaries

- Use synthetic fixtures or explicitly authorized lab data.
- Never scan, exploit, authenticate to, or disrupt third-party systems.
- Do not include secrets, tokens, personal information, proprietary artifacts, or live malicious payloads.
- Malware-related work must use inert metadata, hashes, reports, or safe simulations rather than executable samples.
- Cloud changes should default to no-cost or minimal-cost local validation and must document any possible charges.

## Validation commands

Run the command documented in the project README. For the current event-normalizer project:

```bash
cd projects/detection-engineering/event-normalizer
python -m unittest discover -s tests -v
```
