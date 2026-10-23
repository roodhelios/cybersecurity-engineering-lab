"""Review supplied DNS observations against explicitly reviewed address/team rules."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

from dns_review import _fields, _hostname, _load, _scope, _version, compare, publish, read_input


def review(previous, current, scope_data, policy_data):
    comparison = compare(previous, current, scope_data)
    _, allowed = _scope(scope_data)
    policy = _load(policy_data)
    _fields(policy, {"schema_version", "rules"})
    _version(policy["schema_version"])
    if not isinstance(policy["rules"], list) or len(policy["rules"]) > 1000:
        raise ValueError("at most 1000 review rules are supported")
    rules = {}
    for index, rule in enumerate(policy["rules"], 1):
        _fields(rule, {"hostname", "review_team", "expected_addresses"})
        host = _hostname(rule["hostname"])
        if host not in allowed or host in rules:
            raise ValueError("duplicate or out-of-scope rule")
        team = rule["review_team"]
        if not isinstance(team, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", team):
            raise ValueError("review_team must be a bounded team identifier")
        values = rule["expected_addresses"]
        if not isinstance(values, list) or not 1 <= len(values) <= 32:
            raise ValueError("expected 1 to 32 literal addresses")
        if any(not isinstance(value, str) or "%" in value for value in values):
            raise ValueError("expected unscoped IP literals")
        addresses = [str(ipaddress.ip_address(value)) for value in values]
        if len(addresses) != len(set(addresses)):
            raise ValueError("duplicate normalized expected address")
        rules[host] = (set(addresses), team, index)
    records = {row["hostname"]: row for row in comparison["records"]}
    reviews, findings = [], []
    for host in sorted(records.keys() | rules.keys()):
        observation = records.get(host)
        rule = rules.get(host)
        observed = observation is not None and observation["current_record"] is not None
        current_addresses = set(observation["current_addresses"]) if observed else set()
        expected, team, index = rule if rule else (set(), None, None)
        if not rule:
            status = "no_review_rule"
        elif not observed:
            status = "not_observed_current"
        else:
            status = "matches_reviewed_addresses" if current_addresses == expected else "address_policy_mismatch"
        result = {
            "hostname": host, "status": status, "review_team": team, "policy_rule": index,
            "current_record": observation["current_record"] if observation else None,
            "unexpected_addresses": sorted(current_addresses - expected) if rule and observed else [],
            "expected_not_observed": sorted(expected - current_addresses) if rule and observed else [],
        }
        reviews.append(result)
        if status == "address_policy_mismatch":
            findings.append(dict(result, finding_type="reviewed_dns_address_mismatch",
                evidence_limit="Mismatch against a supplied policy, not proof of compromise or accepted ownership."))
    return {
        "schema_version": 1, "report_type": "scoped-dns-policy-review",
        "comparison": comparison,
        "policy_sha256": hashlib.sha256(policy_data).hexdigest(),
        "review_count": len(reviews), "finding_count": len(findings),
        "reviews": reviews, "findings": findings,
        "interpretation": (
            "Rules and review teams are caller-supplied review policy, not verified asset ownership. "
            "Missing observations and absent rules remain unassessed. No severity, risk score, "
            "live DNS result, remediation action, or team acceptance is inferred."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("private local input requires POSIX")
        result = review(read_input(args.previous), read_input(args.current),
                        read_input(args.scope), read_input(args.policy))
        rendered = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            publish(args.output, rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: DNS policy review did not complete; check local inputs and reviewed scope", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
