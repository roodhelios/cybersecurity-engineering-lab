"""Exercise aligned synthetic source claims without network or retained files."""

import json
import hashlib
from pathlib import Path

from dns_sources_review import review_sources
from dns_sources_verify import verify_sources


def main():
    examples = Path(__file__).with_name("examples")
    first = (examples / "after.json").read_bytes()
    second = (examples / "alternate-view.json").read_bytes()
    scope = (examples / "scope.json").read_bytes()
    result = review_sources([first, second, first], scope)
    expected = {"agreement": 1, "disagreement": 1, "single_observation": 1, "not_observed": 1}
    if result["status_counts"] != expected or result["identical_input_groups"] != [[1, 3]]:
        raise ValueError("synthetic source grouping did not reproduce")
    rendered = json.dumps(result, sort_keys=True).encode()
    pins = dict(expected_report_sha256=hashlib.sha256(rendered).hexdigest(),
                expected_input_sha256=[hashlib.sha256(data).hexdigest() for data in (first, second, first)],
                expected_scope_sha256=hashlib.sha256(scope).hexdigest())
    reproduced = verify_sources(rendered, [first, second, first], scope, **pins)
    try:
        verify_sources(rendered, [first + b"\n", second, first], scope, **pins)
    except ValueError:
        pass
    else:
        raise ValueError("changed original bytes were accepted")
    print(json.dumps({"status": "dns_source_review_exercise_passed",
        "status_counts": result["status_counts"], "supplied_input_count": 3,
        "distinct_input_byte_count": 2, "identical_input_groups": [[1, 3]],
        "recipient_status": reproduced["status"], "changed_original": "rejected",
        "interpretation": "Synthetic claims only. Agreement is not independent corroboration or truth; "
            "disagreement and missing observations are not security findings."}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
