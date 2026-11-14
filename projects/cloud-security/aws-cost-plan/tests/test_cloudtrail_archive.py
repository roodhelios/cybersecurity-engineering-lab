"""Native stored archives retain exact originals and never run archived model code."""

from contextlib import redirect_stderr, redirect_stdout
import gzip
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from aws_cost_plan import cloudtrail_archive as archive
from aws_cost_plan.cloudtrail_case import build_case


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.inputs = [(ROOT/'examples/cloudtrail-collection-a.json').read_bytes(),
                       gzip.compress((ROOT/'examples/cloudtrail-collection-b.json').read_bytes(), mtime=0)]
        self.settings = dict(account_id='111122223333', case_id='archive-case', scope_note='synthetic',
                             threshold=3, window_seconds=300)
        self.case = json.dumps(build_case(self.inputs, **self.settings), indent=2).encode()
        self.case_pin = archive._sha(self.case)
        self.data = archive.build_archive(self.case, self.inputs, expected_case_sha256=self.case_pin, **self.settings)

    def verify(self, data=None, **changes):
        data = self.data if data is None else data
        return archive.verify_archive(data, expected_archive_sha256=archive._sha(data),
                                      **dict(self.settings, **changes))

    def rewrite(self, name, data, *, update_digest=True):
        members = archive._members(self.data)
        members[name] = data
        if update_digest and name != 'manifest.json':
            manifest = json.loads(members['manifest.json'])
            manifest['files'][name] = dict(size=len(data), sha256=archive._sha(data))
            members['manifest.json'] = (archive._canonical(manifest)+'\n').encode('ascii')
        return archive._encode(members)

    def test_reproduction_retains_exact_gzip_case_and_model_with_minimized_output(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.verify()
        self.assertEqual(result['status'], 'cloudtrail_archive_reproduced')
        self.assertEqual((result['unique_event_count'], result['duplicate_copy_count']), (4, 1))
        self.assertTrue(result['model_source_matched'])
        self.assertFalse(result['archived_code_executed'])
        members = archive._members(self.data)
        self.assertEqual(members['case.json'], self.case)
        self.assertEqual(members['inputs/02.bin'], self.inputs[1])
        for value in ('111122223333', 'archive-case', 'fixture-analyst', '192.0.2.'):
            self.assertNotIn(value, json.dumps(result))
        self.assertEqual((result['containment'], result['recovery']), ('not_performed', 'not_verified'))

    def test_same_bytes_and_settings_have_deterministic_archive(self):
        again = archive.build_archive(self.case, self.inputs, expected_case_sha256=self.case_pin, **self.settings)
        self.assertEqual(self.data, again)

    def test_independent_pins_reject_before_sources_or_zip_parsing(self):
        with patch.object(archive, '_members', side_effect=AssertionError('must not parse')):
            with self.assertRaises(ValueError):
                archive.verify_archive(self.data, expected_archive_sha256='0'*64, **self.settings)
        def unavailable():
            raise AssertionError('must not read sources')
            yield
        with self.assertRaises(ValueError):
            archive.build_archive(self.case, unavailable(), expected_case_sha256='0'*64, **self.settings)

    def test_archive_does_not_choose_recipient_settings(self):
        for change in ({'threshold': 4}, {'window_seconds': 60}, {'case_id': 'different'},
                       {'scope_note': 'other'}, {'account_id': '999988887777'}, {'threshold': True}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.verify(**change)

    def test_changed_case_cannot_pass_by_updating_container_digests(self):
        case = json.loads(self.case); case['handoff']['finding_count'] = 0
        with self.assertRaises(ValueError): self.verify(self.rewrite('case.json', json.dumps(case).encode()))

    def test_changed_original_bytes_order_and_omissions_reject(self):
        for originals in (self.inputs[::-1], self.inputs[:1], self.inputs + [self.inputs[0]],
                          [self.inputs[0], gzip.compress(gzip.decompress(self.inputs[1]), mtime=1)]):
            with self.subTest(count=len(originals)), self.assertRaises(ValueError):
                archive.build_archive(self.case, originals, expected_case_sha256=self.case_pin, **self.settings)
        changed = self.rewrite('inputs/01.bin', self.inputs[0]+b'\n')
        with self.assertRaises(ValueError): self.verify(changed)

    def test_changed_archived_model_is_never_executed_or_silently_replayed(self):
        changed = self.rewrite('model/cloudtrail_triage.py', b'raise AssertionError("archived code executed")\n')
        with self.assertRaisesRegex(ValueError, 'different trusted model'):
            self.verify(changed)
        model = archive._model()
        model['model/cloudtrail_triage.py'] += b'\n# different trusted checkout\n'
        with patch.object(archive, '_model', return_value=model):
            with self.assertRaisesRegex(ValueError, 'different trusted model'): self.verify()

    def test_corruption_manifest_numeric_types_and_extra_paths_reject(self):
        with self.assertRaises(ValueError): self.verify(self.rewrite('inputs/01.bin', b'changed', update_digest=False))
        for mutate in (lambda m: m.update(input_count=True), lambda m: m.update(extra=True),
                       lambda m: m['files']['case.json'].update(size=float(len(self.case)))):
            members = archive._members(self.data)
            manifest = json.loads(members['manifest.json']); mutate(manifest)
            members['manifest.json'] = (archive._canonical(manifest)+'\n').encode('ascii')
            with self.assertRaises(ValueError): self.verify(archive._encode(members))
        for name in ('../outside.txt', '/absolute.txt', 'inputs/33.bin'):
            members = archive._members(self.data); members[name] = b'synthetic unexpected member'
            with self.assertRaises(ValueError): self.verify(archive._encode(members))

    def test_duplicate_compressed_and_symlink_entries_reject(self):
        members = archive._members(self.data)
        for condition in ('duplicate', 'compressed', 'symlink', 'zip64_extra', 'comment'):
            output = io.BytesIO()
            with warnings.catch_warnings(), zipfile.ZipFile(output, 'w') as target:
                warnings.simplefilter('ignore', UserWarning)
                for name, data in members.items():
                    entry = zipfile.ZipInfo(name); entry.create_system = 3
                    entry.external_attr = ((stat.S_IFLNK if condition == 'symlink' else stat.S_IFREG) | 0o600) << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED if condition == 'compressed' else zipfile.ZIP_STORED
                    if condition == 'zip64_extra':
                        entry.extra = struct.pack('<HHQQ', 1, 16, len(data), len(data))
                        entry.extract_version = 45
                    if condition == 'comment': entry.comment = b'unsupported member comment'
                    target.writestr(entry, data)
                if condition == 'duplicate': target.writestr('case.json', self.case)
            with self.subTest(condition=condition), self.assertRaises(ValueError): self.verify(output.getvalue())

    def test_archive_and_directory_bounds_reject_before_zipfile(self):
        with patch.object(archive, 'MAX_ARCHIVE_BYTES', len(self.data)-1):
            with self.assertRaises(ValueError): self.verify()
        changed = bytearray(self.data)
        struct.pack_into('<HH', changed, len(changed)-22+8, 500, 500)
        with patch.object(archive.zipfile, 'ZipFile', side_effect=AssertionError('directory must be rejected first')):
            with self.assertRaises(ValueError): self.verify(bytes(changed))
        with patch.object(archive, 'MAX_BYTES', 1):
            with self.assertRaises(ValueError): self.verify()
        with patch.object(archive, 'MAX_MODEL_BYTES', 1):
            with self.assertRaises(ValueError): self.verify()

    def test_forged_member_sizes_reject_before_any_member_read(self):
        data = bytearray(self.data)
        central_offset = struct.unpack_from('<L', data, len(data)-6)[0]
        self.assertEqual(data[central_offset:central_offset+4], b'PK\x01\x02')
        # Metadata only. No large buffer is created or read by this regression.
        struct.pack_into('<LL', data, central_offset+20, 0xfffffff0, 0xfffffff0)
        with patch.object(archive.zipfile.ZipFile, 'read', side_effect=AssertionError('oversized read')):
            with self.assertRaises(ValueError): self.verify(bytes(data))

    def test_cli_after_removing_originals_and_exclusive_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case, first, second, saved = [root/name for name in ('case.json', 'a.bin', 'b.bin', 'case.zip')]
            for path, data in zip((case, first, second), (self.case, *self.inputs)): path.write_bytes(data)
            common = ['--account-id', self.settings['account_id'], '--case-id', self.settings['case_id'],
                      '--scope-note', self.settings['scope_note'], '--threshold', '3', '--window-seconds', '300']
            args = ['create', str(case), str(first), str(second), '--expected-case-sha256', self.case_pin,
                    '--output', str(saved), *common]
            output = io.StringIO()
            with redirect_stdout(output): self.assertEqual(archive.main(args), 0)
            pin = json.loads(output.getvalue())['archive_sha256']
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            before = saved.read_bytes()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(archive.main(args), 2)
            self.assertEqual(saved.read_bytes(), before)
            for path in (case, first, second): path.unlink()
            process = subprocess.run([sys.executable, '-S', '-m', 'aws_cost_plan.cloudtrail_archive',
                'verify', str(saved), '--expected-archive-sha256', pin, *common], cwd=ROOT,
                env=dict(os.environ, PYTHONPATH=str(ROOT/'src')), capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)['status'], 'cloudtrail_archive_reproduced')
            self.assertEqual(saved.read_bytes(), before)
            self.assertFalse(any((root/name).exists() for name in ('case.json', 'a.bin', 'b.bin')))

    def test_restore_exact_bytes_private_modes_and_independent_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'restored'
            before = self.data
            with patch('socket.socket', side_effect=AssertionError('network forbidden')):
                result = archive.restore_archive(self.data, destination,
                    expected_archive_sha256=archive._sha(self.data), **self.settings)
            self.assertEqual(result['status'], 'cloudtrail_archive_restored')
            self.assertEqual(result['restored_file_count'], 3)
            self.assertEqual(result['restored_code_files'], 0)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            expected = {'case.json': self.case, 'source-01.bin': self.inputs[0], 'source-02.bin': self.inputs[1]}
            self.assertEqual(set(p.name for p in destination.iterdir()), set(expected))
            for name, data in expected.items():
                self.assertEqual((destination/name).read_bytes(), data)
                self.assertEqual((destination/name).stat().st_mode & 0o777, 0o600)
            reproduced = archive.verify_case((destination/'case.json').read_bytes(),
                [(destination/f'source-{index:02d}.bin').read_bytes() for index in (1, 2)], **self.settings)
            self.assertEqual(reproduced['unique_event_count'], 4)
            self.assertEqual(self.data, before)
            for value in ('111122223333', 'archive-case', str(destination), 'fixture-analyst', '192.0.2.'):
                self.assertNotIn(value, json.dumps(result))

    def test_restore_rejects_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'absent'
            for data, pin, settings in (
                    (self.data, '0'*64, self.settings),
                    (self.data, archive._sha(self.data), dict(self.settings, threshold=4)),
                    (self.rewrite('case.json', b'{}'), None, self.settings),
                    (self.rewrite('model/model.py', b'raise AssertionError("must not execute")'), None, self.settings)):
                with self.subTest(pin=pin), self.assertRaises(ValueError):
                    archive.restore_archive(data, destination, expected_archive_sha256=pin or archive._sha(data),
                                            **settings)
                self.assertFalse(destination.exists())

    def test_restore_preserves_every_existing_destination_type(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root/'existing'; existing.mkdir(); (existing/'keep').write_bytes(b'preserve')
            file = root/'file'; file.write_bytes(b'preserve')
            empty = root/'empty'; empty.mkdir()
            link = root/'link'; link.symlink_to(existing, target_is_directory=True)
            dangling = root/'dangling'; dangling.symlink_to(root/'missing')
            for destination in (existing, file, empty, link, dangling):
                with self.subTest(destination=destination.name), self.assertRaises(FileExistsError):
                    archive.restore_archive(self.data, destination,
                        expected_archive_sha256=archive._sha(self.data), **self.settings)
            self.assertEqual((existing/'keep').read_bytes(), b'preserve')
            self.assertEqual(file.read_bytes(), b'preserve')
            self.assertEqual(list(empty.iterdir()), [])
            self.assertTrue(link.is_symlink())
            self.assertTrue(dangling.is_symlink())

    def test_restore_requires_private_real_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root/'public'; public.mkdir(mode=0o755); public.chmod(0o755)
            linked = root/'linked'; linked.symlink_to(root, target_is_directory=True)
            for parent in (public, linked):
                with self.subTest(parent=parent.name), self.assertRaises(ValueError):
                    archive.restore_archive(self.data, parent/'absent',
                        expected_archive_sha256=archive._sha(self.data), **self.settings)
                self.assertFalse((parent/'absent').exists())

    def test_restore_cleans_partial_set_after_write_and_readback_failure(self):
        publish = archive._publish
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for failure in ('second_write', 'readback'):
                destination = root/failure
                def failing(path, data):
                    publish(path, data)
                    if failure == 'second_write' and path.name == 'source-01.bin':
                        raise OSError('private failure after publication')
                    if failure == 'readback' and path.name == 'source-02.bin':
                        path.write_bytes(b'changed')
                with patch.object(archive, '_publish', side_effect=failing):
                    with self.assertRaises((OSError, ValueError)):
                        archive.restore_archive(self.data, destination,
                            expected_archive_sha256=archive._sha(self.data), **self.settings)
                self.assertFalse(destination.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_restore_reads_one_archive_and_cli_errors_are_minimized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root/'case.zip', root/'restored'
            source.write_bytes(self.data)
            args = ['restore', str(source), '--expected-archive-sha256', archive._sha(self.data),
                    '--output-directory', str(destination), '--account-id', '111122223333',
                    '--case-id', 'archive-case', '--scope-note', 'synthetic', '--threshold', '3',
                    '--window-seconds', '300']
            reader = archive._read_archive
            output = io.StringIO()
            with patch.object(archive, '_read_archive', wraps=reader) as captured, redirect_stdout(output):
                self.assertEqual(archive.main(args), 0)
                captured.assert_called_once_with(source)
            self.assertEqual(json.loads(output.getvalue())['restored_file_count'], 3)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(archive.main(args), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(root), err.getvalue())
            self.assertEqual(source.read_bytes(), self.data)

    def test_failures_leave_no_output_and_fixed_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case, original, destination = root/'case.json', root/'source.json', root/'archive.zip'
            case.write_bytes(self.case); original.write_bytes(self.inputs[0])
            args = ['create', str(case), str(original), '--expected-case-sha256', self.case_pin,
                    '--output', str(destination), '--account-id', '111122223333', '--case-id', 'archive-case',
                    '--scope-note', 'synthetic', '--threshold', '3', '--window-seconds', '300']
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err): self.assertEqual(archive.main(args), 2)
            self.assertFalse(destination.exists())
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(root), err.getvalue())
            with patch.object(archive.os, 'fsync', side_effect=OSError('private failure')):
                with self.assertRaises(OSError): archive._publish(destination, self.data)
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.glob('.cloudtrail-archive-*')), [])


if __name__ == '__main__':
    unittest.main()
