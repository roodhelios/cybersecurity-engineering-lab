"""Reproduce a retained DNS workflow from separately supplied local inputs."""

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from dns_review import _unique, read_input
from zeek_dns_workflow import review_logs

MAX_REPORT_BYTES = 16 * 1024 * 1024
LAYERS = {"risk_review", "ownership_review", "review_queue"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def read_report(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError("expected a bounded regular workflow report")
        return handle.read(MAX_REPORT_BYTES+1)


def read_requirements(data):
    """Validate a requirement contract independently of any workflow report."""
    if len(data) > 1024 * 1024:
        raise ValueError("requirements exceed 1 MiB")
    requirements = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
    if not isinstance(requirements, dict) or type(requirements.get("schema_version")) is not int:
        raise ValueError("unsupported handoff requirements")
    version = requirements["schema_version"]
    fields = {"schema_version", "record_type", "required_layers"}
    if version == 2:
        fields.add("finding_coverage")
    if version not in (1, 2) or set(requirements) != fields or requirements["record_type"] not in ("A", "AAAA"):
        raise ValueError("unsupported handoff requirements")
    layers = requirements["required_layers"]
    if (not isinstance(layers, list) or len(layers) > 3 or
            any(not isinstance(layer, str) or layer not in LAYERS for layer in layers) or
            len(set(layers)) != len(layers)):
        raise ValueError("required layers must be unique supported layer names")
    if version == 2:
        coverage = requirements["finding_coverage"]
        if (not isinstance(coverage, dict) or set(coverage) != {"risk_assessed", "team_responded"} or
                any(type(value) is not bool for value in coverage.values())):
            raise ValueError("expected explicit boolean finding coverage requirements")
        for name, layer in (("risk_assessed", "risk_review"), ("team_responded", "ownership_review")):
            if coverage[name] and layer not in layers:
                raise ValueError("finding coverage requires its review layer")
    return requirements


def check_requirements(data, report):
    """Apply recipient-supplied requirements, never requirements from the report."""
    requirements = read_requirements(data)
    layers = requirements["required_layers"]
    if report.get("record_type") != requirements["record_type"] or any(layer not in report for layer in layers):
        raise ValueError("workflow does not satisfy the recipient's handoff requirements")
    if requirements["schema_version"] == 2:
        coverage = requirements["finding_coverage"]
        if coverage["risk_assessed"] and any(
                item["assessment_status"] != "scored" for item in report["risk_review"]["findings"]):
            raise ValueError("recipient requires risk assessment for every finding")
        if coverage["team_responded"] and any(
                item["ownership_response"]["status"] not in {"accepted_claim", "declined_claim"}
                for item in report["ownership_review"]["findings"]):
            raise ValueError("recipient requires an explicit team response for every finding")
    return hashlib.sha256(data).hexdigest()


def verify_workflow(report_data, previous, current, scope, policy, *,
                    assessment_data=None, ownership_data=None, requirements_data=None):
    """Recompute every receipt, snapshot, finding and optional review layer."""
    if len(report_data) > MAX_REPORT_BYTES:
        raise ValueError("workflow report exceeds 16 MiB")
    report = json.loads(report_data.decode("utf-8"), object_pairs_hook=_unique)
    if not isinstance(report, dict) or report.get("report_type") != "zeek-dns-policy-workflow":
        raise ValueError("expected a saved DNS workflow")
    if (("risk_review" in report) != (assessment_data is not None) or
            ("ownership_review" in report) != (ownership_data is not None)):
        raise ValueError("supply exactly the optional review inputs retained in the report")
    rebuilt = review_logs(previous, current, scope, policy,
        previous_observed_at=report["snapshots"]["previous"]["observed_at"],
        current_observed_at=report["snapshots"]["current"]["observed_at"],
        record_type=report["record_type"], assessment_data=assessment_data,
        ownership_data=ownership_data, include_queue="review_queue" in report)
    # Canonical bytes distinguish booleans/floats from integer counts and reject NaN.
    if _canonical(report) != _canonical(rebuilt):
        raise ValueError("saved DNS workflow did not reproduce")
    requirement_digest = check_requirements(requirements_data, rebuilt) if requirements_data is not None else None
    result = {"schema_version": 1, "status": "workflow_reproduced",
            "finding_count": rebuilt["review"]["finding_count"], "record_type": rebuilt["record_type"],
            "report_sha256": hashlib.sha256(report_data).hexdigest(),
            "risk_review_checked": "risk_review" in rebuilt,
            "ownership_review_checked": "ownership_review" in rebuilt,
            "queue_checked": "review_queue" in rebuilt,
            "interpretation": "All retained workflow fields reproduce from separately supplied inputs "
                "under the current implementation. Recorded times, address family, optional layer selection "
                "and source/policy/reviewer claims remain supplied, not authenticated. This does not "
                "establish historical code, complete discovery, accepted ownership or remediation."}
    if requirement_digest is not None:
        result["requirements_checked"] = True
        result["requirements_sha256"] = requirement_digest
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--assessment", type=Path)
    parser.add_argument("--ownership-responses", type=Path)
    parser.add_argument("--requirements", type=Path, help="independently trusted recipient requirements JSON")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("bounded private input handling requires POSIX")
        result = verify_workflow(read_report(args.report), read_input(args.previous),
            read_input(args.current), read_input(args.scope), read_input(args.policy),
            assessment_data=read_input(args.assessment) if args.assessment else None,
            ownership_data=read_input(args.ownership_responses) if args.ownership_responses else None,
            requirements_data=read_input(args.requirements) if args.requirements else None)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print("error: DNS workflow did not reproduce; check retained report and original input files",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
