"""Reproduce a synthetic retained case after removing its separate original files."""

import gzip
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'src'))

from aws_cost_plan.cloudtrail_archive import _publish, _sha, build_archive, verify_archive, restore_archive
from aws_cost_plan.cloudtrail_case import build_case
from aws_cost_plan.cloudtrail_case_verify import verify_case


def exercise():
    with tempfile.TemporaryDirectory(prefix='cloudtrail-archive-exercise-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            work = Path(directory)
            originals = [(ROOT/'examples/cloudtrail-collection-a.json').read_bytes(),
                         gzip.compress((ROOT/'examples/cloudtrail-collection-b.json').read_bytes(), mtime=0)]
            settings = dict(account_id='111122223333', case_id='synthetic-retention', scope_note='synthetic',
                            threshold=3, window_seconds=300)
            case_data = json.dumps(build_case(originals, **settings), sort_keys=True, indent=2).encode()
            paths = [work/'case.json', work/'source-a.json', work/'source-b.json.gz']
            for path, data in zip(paths, (case_data, *originals)): path.write_bytes(data)
            payload = build_archive(paths[0].read_bytes(), (p.read_bytes() for p in paths[1:]),
                                    expected_case_sha256=_sha(case_data), **settings)
            archive = work/'retained-case.zip'
            _publish(archive, payload)
            pin = _sha(payload)
            for path in paths: path.unlink()
            checked = verify_archive(archive.read_bytes(), expected_archive_sha256=pin, **settings)
            restored = work/'restored'
            restoration = restore_archive(archive.read_bytes(), restored, expected_archive_sha256=pin, **settings)
            restored_originals = [(restored/f'source-{index:02d}.bin').read_bytes() for index in (1, 2)]
            if (restored/'case.json').read_bytes() != case_data or restored_originals != originals:
                raise ValueError('restoration changed original bytes')
            replayed = verify_case((restored/'case.json').read_bytes(), restored_originals, **settings)
            if replayed['case_sha256'] != checked['case_sha256']:
                raise ValueError('restored case failed independent reproduction')
            rejected = 0
            for candidate, expected_pin, requirements in (
                    (payload, '0'*64, settings),
                    (payload+b'changed', pin, settings),
                    (payload, pin, dict(settings, threshold=4))):
                try: verify_archive(candidate, expected_archive_sha256=expected_pin, **requirements)
                except ValueError: rejected += 1
                else: raise ValueError('invalid retained archive accepted')
            if any(p.exists() for p in paths) or archive.read_bytes() != payload:
                raise ValueError('exercise changed retained inputs')
    return dict(status='cloudtrail_archive_exercise_passed', originals_removed=True,
        input_count=checked['input_count'], unique_event_count=checked['unique_event_count'],
        duplicate_copy_count=checked['duplicate_copy_count'], negative_cases_rejected=rejected,
        archive_unchanged=True, archived_code_executed=False, containment='not_performed', recovery='not_verified',
        exact_bytes_restored=restoration['exact_bytes_restored'], restored_file_count=restoration['restored_file_count'],
        restored_code_files=restoration['restored_code_files'], restored_case_reproduced=True)


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: CloudTrail archive exercise failed; inspect private temporary storage and trusted source', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
