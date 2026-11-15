"""Discover and run a fixed set of bundled offline exercises from the repository root."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DNS = 'projects/asset-intelligence/dns-review/'
AUTH = DNS+'requirements-auth.txt'

# Command arguments are repository constants. No user input becomes a path or command.
EXERCISES = (
    ('cloudtrail-archive', ('projects/cloud-security/aws-cost-plan/demo_cloudtrail_archive.py',),
     'standard-library', 'Restore and reproduce a synthetic CloudTrail case and exact originals'),
    ('arp-compare', ('projects/network-defense/arp-consistency/demo_comparison.py',),
     'standard-library', 'Compare and reproduce saved synthetic ARP observation changes'),
    ('malware-notes', ('-m', 'projects.malware_analysis.report_summary',
                       'projects/malware_analysis/examples/synthetic-behavior-report-v2.json'),
     'standard-library', 'Summarize inert analysis notes without opening a sample'),
    ('zeek-review', ('projects/detection-engineering/event-normalizer/demo_zeek_review.py',),
     'standard-library', 'Reproduce original gzip Zeek text findings and source-line references'),
    ('dns-recipient', (DNS+'demo_authorized_handoff.py',), AUTH,
     'Check recipient-signed requirements using temporary keys'),
    ('dns-reviewers', (DNS+'demo_reviewer_handoff.py',), AUTH,
     'Check finding-scoped risk and team review signatures'),
    ('dns-responsibility', (DNS+'demo_responsibility.py',), AUTH,
     'Accept one exact review task with an enrolled key'),
    ('dns-journal', (DNS+'demo_assignment_journal.py',), AUTH,
     'Serialize verified review acceptances in temporary SQLite'),
    ('dns-release', (DNS+'demo_assignment_lifecycle.py',), AUTH,
     'Release a task and verify a fresh successor'),
    ('dns-checkpoint', (DNS+'demo_journal_checkpoint.py',), AUTH,
     'Detect version-1 journal rollback relative to a retained checkpoint'),
    ('dns-lifecycle-checkpoint', (DNS+'demo_lifecycle_checkpoint.py',), AUTH,
     'Check version-2 acceptance and release state together'),
    ('dns-enrollment', (DNS+'demo_journal_enrollment.py',), AUTH,
     'Check version-3 journal identity and enrolled history'),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list', help='list exercises without importing or running them', allow_abbrev=False)
    listing.add_argument('--format', choices=('text', 'json'), default='text')
    run = commands.add_parser('run', help='run one bundled synthetic exercise; no external input paths', allow_abbrev=False)
    run.add_argument('exercise', choices=[item[0] for item in EXERCISES])
    args = parser.parse_args(argv)
    if args.command == 'list':
        rows = [dict(name=name, dependencies=dependencies, description=description)
                for name, _, dependencies, description in EXERCISES]
        if args.format == 'json':
            print(json.dumps(dict(schema_version=1, exercises=rows), sort_keys=True))
        else:
            print('Bundled synthetic exercises. Python 3.11+ on POSIX. No network calls.')
            for row in rows:
                print(f"{row['name']}: {row['description']} [{row['dependencies']}]")
            print('Run: python -m lab run NAME. Detailed commands and limits: docs/local-workflows.md')
        return 0
    _, command, _, _ = next(item for item in EXERCISES if item[0] == args.exercise)
    try:
        return subprocess.run([sys.executable, *command], cwd=ROOT, check=False).returncode
    except OSError:
        print('error: exercise could not start; check the Python environment and checkout', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
