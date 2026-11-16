"""Root navigation delegates only to reviewed, bundled offline commands."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lab.__main__ import EXERCISES, ROOT, main


class LabEntryPointTests(unittest.TestCase):
    def test_listing_is_read_only_and_has_dependencies_without_running_exercises(self):
        with patch('lab.__main__.subprocess.run', side_effect=AssertionError('must not execute')):
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(main(['list', '--format', 'json']), 0)
            rows = json.loads(output.getvalue())['exercises']
            self.assertEqual(len(rows), 13)
            self.assertEqual(len({row['name'] for row in rows}), 13)
            self.assertEqual(sum(row['dependencies'] == 'standard-library' for row in rows), 5)
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(main(['list']), 0)
            self.assertIn('requirements-auth.txt', output.getvalue())

    def test_unlisted_commands_paths_and_extra_arguments_never_run(self):
        with patch('lab.__main__.subprocess.run', side_effect=AssertionError('must not execute')):
            for arguments in (['run', '../../other.py'], ['run', 'cloudtrail-archive', '--output', '/tmp/no'],
                              ['run', 'os.system'], ['list', '--form', 'json']):
                with self.subTest(arguments=arguments), redirect_stderr(StringIO()), self.assertRaises(SystemExit) as result:
                    main(arguments)
                self.assertEqual(result.exception.code, 2)

    def test_delegation_preserves_exit_status_and_uses_fixed_root(self):
        for name, command, _, _ in EXERCISES:
            with self.subTest(name=name), patch('lab.__main__.subprocess.run') as runner:
                runner.return_value.returncode = 7
                self.assertEqual(main(['run', name]), 7)
                runner.assert_called_once_with([sys.executable, *command], cwd=ROOT, check=False)
        with patch('lab.__main__.subprocess.run', side_effect=OSError), redirect_stderr(StringIO()) as errors:
            self.assertEqual(main(['run', 'arp-compare']), 2)
        self.assertNotIn(str(ROOT), errors.getvalue())

    def test_actual_standard_library_commands_run_from_another_working_directory(self):
        expected = {'cloudtrail-archive': 'cloudtrail_archive_exercise_passed',
                    'arp-compare': 'arp_comparison_exercise_passed', 'malware-notes': None,
                    'zeek-review': 'zeek_review_exercise_passed',
                    'dns-sources': 'dns_source_review_exercise_passed'}
        with tempfile.TemporaryDirectory() as directory:
            for name, status in expected.items():
                with self.subTest(name=name):
                    result = subprocess.run([sys.executable, '-S', str(ROOT/'lab/__main__.py'), 'run', name],
                        cwd=directory, capture_output=True, text=True, timeout=30)
                    self.assertEqual((result.returncode, result.stderr), (0, ''))
                    payload = json.loads(result.stdout)
                    if status: self.assertEqual(payload['status'], status)
                    else: self.assertEqual(payload['report_type'], 'behavior-note-coverage')
            self.assertEqual(list(Path(directory).iterdir()), [])

    @unittest.skipUnless(importlib.util.find_spec('nacl'), 'optional native signing dependency unavailable')
    def test_actual_signing_exercises_use_the_same_interpreter(self):
        for name, _, dependencies, _ in EXERCISES:
            if dependencies == 'standard-library': continue
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, '-m', 'lab', 'run', name], cwd=ROOT,
                    capture_output=True, text=True, timeout=30)
                self.assertEqual((result.returncode, result.stderr), (0, ''))
                self.assertIn('exercise_passed', json.loads(result.stdout)['status'])


if __name__ == '__main__': unittest.main()
