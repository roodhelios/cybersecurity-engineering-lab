"""Exercise original gzip Zeek text evidence without an intermediate retained JSONL file."""

import gzip
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'src'))
from event_normalizer.zeek_review import build_review, verify_review


def exercise():
    text = (ROOT/'tests/fixtures/repeated_attempts.log').read_bytes()
    original = gzip.compress(text, mtime=0)
    with patch('socket.socket', side_effect=AssertionError('network forbidden')):
        report = build_review(original, scope='synthetic')
        data = json.dumps(report, sort_keys=True).encode()
        pin = hashlib.sha256(data).hexdigest()
        received = verify_review(original, data, scope='synthetic', expected_report_sha256=pin)
        lines = [r['original_line_number'] for r in report['correlation']['findings'][0]['evidence']]
        if lines != [8, 9, 10, 11]: raise ValueError('original line references differed')
        changed = json.loads(data); changed['correlation']['findings'][0]['evidence'][0]['original_line_number'] = 1
        changed = json.dumps(changed).encode()
        rejected = 0
        for source, saved, expected, scope in ((gzip.compress(text, mtime=1), data, pin, 'synthetic'),
                (original, changed, hashlib.sha256(changed).hexdigest(), 'synthetic'),
                (original, data, pin, 'owned')):
            try: verify_review(source, saved, scope=scope, expected_report_sha256=expected)
            except ValueError: rejected += 1
            else: raise ValueError('invalid reproduction accepted')
    return {'status': 'zeek_review_exercise_passed', 'compression': received['compression'],
            'events_read': received['events_read'], 'finding_count': received['finding_count'],
            'evidence_references': received['evidence_references'], 'original_lines': lines,
            'negative_cases_rejected': rejected, 'interpretation': 'Synthetic saved metadata only. '
            'No Zeek process, network, source authentication or confirmed compromise.'}


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError, EOFError):
        print('error: original Zeek review exercise failed', file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
