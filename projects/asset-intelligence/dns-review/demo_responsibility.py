"""Exercise explicit DNS review responsibility with temporary native signatures."""

import base64
import hashlib
import json
import sys
import tempfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from demo_reviewer_handoff import fixture as reviewed_fixture
from dns_ownership_review import finding_digest
from dns_responsibility import accept_responsibility, create_acceptance, main as accept_main
from dns_review import publish


def fixture():
    from nacl.signing import SigningKey
    report, inputs, options, keys = reviewed_fixture()
    del keys
    key = SigningKey.generate()
    document = json.loads(report); finding = document["review"]["findings"][0]
    digest = finding_digest(document["review"], finding)
    authority = {"schema_version": 1, "authority_type": "dns-review-responsibility-authorities",
        "audience": "synthetic-recipient", "maximum_validity_seconds": 3600,
        "keys": [{"key_id": "acceptance-lab", "status": "active",
                  "public_key_b64": base64.b64encode(key.verify_key.encode()).decode("ascii"),
                  "grants": [{"finding_sha256": digest, "team": finding["review_team"]}]}]}
    authority_data = json.dumps(authority).encode()
    acceptance = create_acceptance(report, authority_data=authority_data, signing_key=key, key_id="acceptance-lab",
        finding_sha256=digest, team=finding["review_team"], accepted_at="2026-10-28T12:00:00Z",
        expires_at="2026-10-28T13:00:00Z")
    return report, inputs, dict(options, acceptance=acceptance, acceptance_policy=authority_data,
        expected_acceptance_policy_sha256=hashlib.sha256(authority_data).hexdigest()), key


def exercise():
    report, inputs, options, key = fixture(); del key
    with patch("socket.socket", side_effect=AssertionError("network forbidden")):
        receipt = accept_responsibility(report, *inputs, **options)
        wrong = json.loads(options["acceptance"]); wrong["action"] = "approve-remediation"
        missing = json.loads(options["attestations"]); missing["attestations"].pop()
        for change in ({"acceptance": json.dumps(wrong).encode()},
                       {"expected_acceptance_policy_sha256": "0"*64},
                       {"attestations": json.dumps(missing).encode()}):
            try: accept_responsibility(report, *inputs, **dict(options, **change))
            except ValueError: pass
            else: raise ValueError("invalid responsibility acceptance passed")
    with tempfile.TemporaryDirectory(prefix="dns-responsibility-") as name:
        root = Path(name)
        data = dict(report=report, previous=inputs[0], current=inputs[1], scope=inputs[2], policy=inputs[3],
                    requirements=options["requirements"], approval=options["approval"],
                    authority_policy=options["authority_policy"], reviewer_policy=options["reviewer_policy"],
                    attestations=options["attestations"], assessment=options["assessment_data"],
                    ownership_responses=options["ownership_data"], acceptance=options["acceptance"],
                    acceptance_policy=options["acceptance_policy"])
        paths = {key: root/(key+".json") for key in data}
        for key, value in data.items(): publish(paths[key], value.decode())
        args = [str(paths[key]) for key in ("report", "previous", "current")]
        for key in data:
            if key not in ("report", "previous", "current"): args += ["--"+key.replace("_", "-"), str(paths[key])]
        output = root/"receipt.json"
        args += ["--output", str(output), "--at", "2026-10-28T12:00:00Z",
                 "--expected-reviewer-policy-sha256", options["expected_reviewer_policy_sha256"],
                 "--expected-acceptance-policy-sha256", options["expected_acceptance_policy_sha256"]]
        with redirect_stdout(StringIO()):
            if accept_main(args) != 0: raise ValueError("file workflow failed")
        retained = json.loads(output.read_bytes())
        if retained["finding_sha256"] != receipt["finding_sha256"] or retained["status"] != "accepted_review_responsibility":
            raise ValueError("retained receipt differs")
        if any(path.read_bytes() != data[key] for key, path in paths.items()): raise ValueError("input changed")
    return {"status": "dns_responsibility_exercise_passed", "accepted_findings": 1,
            "negative_cases_rejected": 3, "inputs_unchanged": True, "native_ed25519": True,
            "interpretation": "Temporary enrolled-key acceptance of one review task. "
            "No asset ownership, assignment registry, human identity or remediation is established."}


def main():
    try: result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, UnicodeError):
        print("error: local DNS responsibility exercise failed; check PyNaCl and fixtures", file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
