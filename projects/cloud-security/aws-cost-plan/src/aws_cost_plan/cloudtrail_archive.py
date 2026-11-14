"""Retain a reproduced CloudTrail case, original inputs and matching model as data."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import zipfile
import zlib

from .cloudtrail_case import MAX_CASE_BYTES, MAX_FILES
from .cloudtrail_case_verify import _canonical, _read_case, verify_case
from .cloudtrail_handoff import MAX_BYTES, _read
from .cloudtrail_import import _constant, _object

MODEL_FILES = ('__init__.py', 'model.py', 'cloudtrail_case.py', 'cloudtrail_case_verify.py',
               'cloudtrail_handoff.py', 'cloudtrail_import.py', 'cloudtrail_triage.py',
               'cloudtrail_correlation.py')
MAX_MODEL_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MAX_ARCHIVE_BYTES = 96 * 1024 * 1024
MAX_MEMBERS = MAX_FILES + len(MODEL_FILES) + 2


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _pin(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('expected independent lowercase SHA-256 pin')


def _model():
    files = {f'model/{name}': _read(Path(__file__).parent/name) for name in MODEL_FILES}
    if sum(map(len, files.values())) > MAX_MODEL_BYTES:
        raise ValueError('model snapshot exceeds 1 MiB')
    return files


def _inputs(inputs):
    captured, total = [], 0
    for data in inputs:
        if type(data) is not bytes or len(captured) >= MAX_FILES:
            raise ValueError('expected 1 to 32 original byte inputs')
        total += len(data)
        if total > MAX_BYTES:
            raise ValueError('combined original inputs exceed 16 MiB')
        captured.append(data)
    if not captured:
        raise ValueError('at least one original input is required')
    return captured


def _encode(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, data in sorted(members.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(entry, data)
    data = output.getvalue()
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError('archive exceeds 96 MiB')
    return data


def build_archive(case_data, inputs, *, expected_case_sha256, **requirements):
    """Capture and reproduce all dependencies before assembling a private container."""
    _pin(expected_case_sha256)
    if type(case_data) is not bytes or _sha(case_data) != expected_case_sha256:
        raise ValueError('case differs from independently selected pin')
    originals = _inputs(inputs)
    verify_case(case_data, originals, **requirements)
    members = dict(_model(), **{'case.json': case_data})
    members.update({f'inputs/{index:02d}.bin': data for index, data in enumerate(originals, 1)})
    manifest = dict(schema_version=1, archive_type='offline-cloudtrail-case-archive',
        requirements=requirements, input_count=len(originals),
        files={name: dict(size=len(data), sha256=_sha(data)) for name, data in members.items()})
    encoded = (_canonical(manifest)+'\n').encode('ascii')
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ValueError('manifest exceeds 128 KiB')
    return _encode(dict(members, **{'manifest.json': encoded}))


def _members(data):
    # Bound the classic central directory before ZipFile allocates member objects.
    # This format has no ZIP64, comments, multi-disk layout or trailing data.
    if len(data) < 22:
        raise ValueError('truncated archive')
    signature, disk, central_disk, disk_count, count, size, offset, comment = struct.unpack('<4s4H2LH', data[-22:])
    if (signature != b'PK\x05\x06' or disk or central_disk or disk_count != count or
            not 1 <= count <= MAX_MEMBERS or size > MAX_MEMBERS * 1024 or
            offset + size != len(data) - 22 or comment or data[-42:-38] == b'PK\x06\x07'):
        raise ValueError('unsupported or oversized archive directory')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) != count or len({e.filename for e in entries}) != count:
            raise ValueError('duplicate or inconsistent archive entries')
        members = {}
        total = 0
        for entry in entries:
            name = entry.filename
            limit = (MAX_CASE_BYTES if name == 'case.json' else MAX_MANIFEST_BYTES if name == 'manifest.json'
                     else MAX_MODEL_BYTES if name.startswith('model/') else MAX_BYTES)
            total += entry.file_size
            if (entry.orig_filename != name or entry.extra or entry.comment or entry.extract_version > 20 or
                    entry.compress_type != zipfile.ZIP_STORED or
                    entry.flag_bits & 1 or stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFREG or
                    not 0 <= entry.file_size <= limit or entry.compress_size != entry.file_size or
                    total > MAX_CASE_BYTES + MAX_BYTES + MAX_MODEL_BYTES + MAX_MANIFEST_BYTES):
                raise ValueError('unsupported archive member')
            # Read only bounded named bytes. Never extract, import or execute entries.
            members[name] = archive.read(entry)
        return members


def _inspect_archive(data, *, expected_archive_sha256, **requirements):
    """Reproduce under independent settings and the current trusted checkout only."""
    _pin(expected_archive_sha256)
    if type(data) is not bytes or len(data) > MAX_ARCHIVE_BYTES or _sha(data) != expected_archive_sha256:
        raise ValueError('archive differs from independently retained pin')
    members = _members(data)
    raw = members.get('manifest.json', b'')
    manifest = json.loads(raw.decode('ascii'), object_pairs_hook=_object, parse_constant=_constant)
    if (not isinstance(manifest, dict) or set(manifest) !=
            {'schema_version', 'archive_type', 'requirements', 'input_count', 'files'} or
            type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or
            manifest['archive_type'] != 'offline-cloudtrail-case-archive' or
            type(manifest['input_count']) is not int or not 1 <= manifest['input_count'] <= MAX_FILES or
            (_canonical(manifest)+'\n').encode('ascii') != raw or
            _canonical(manifest['requirements']) != _canonical(requirements)):
        raise ValueError('unsupported archive or different recipient requirements')
    names = [f'inputs/{index:02d}.bin' for index in range(1, manifest['input_count'] + 1)]
    model = _model()
    expected = {'case.json', 'manifest.json', *names, *model}
    if set(members) != expected or not isinstance(manifest['files'], dict) or set(manifest['files']) != expected - {'manifest.json'}:
        raise ValueError('unexpected or missing archive members')
    for name, record in manifest['files'].items():
        if (not isinstance(record, dict) or set(record) != {'size', 'sha256'} or
                type(record['size']) is not int or record['size'] != len(members[name]) or
                record['sha256'] != _sha(members[name])):
            raise ValueError('member differs from manifest')
    if any(members[name] != content for name, content in model.items()):
        raise ValueError('archive requires a different trusted model checkout')
    originals = _inputs(members[name] for name in names)
    result = verify_case(members['case.json'], originals, **requirements)
    return (dict(result, status='cloudtrail_archive_reproduced', archive_sha256=expected_archive_sha256,
                 model_source_matched=True, archived_code_executed=False), members)


def verify_archive(data, *, expected_archive_sha256, **requirements):
    """Reproduce without restoring files or executing archived code."""
    result, _ = _inspect_archive(data, expected_archive_sha256=expected_archive_sha256, **requirements)
    return result


def restore_archive(data, destination, *, expected_archive_sha256, **requirements):
    """Reproduce before creating an exclusive private directory of exact evidence bytes.

    Requires a cooperative caller and trusted private parent/ancestors. The file set
    is not atomically published; only a successful return declares it complete.
    """
    if os.name != 'posix':
        raise ValueError('private restore requires POSIX')
    result, members = _inspect_archive(data, expected_archive_sha256=expected_archive_sha256, **requirements)
    destination = Path(destination)
    parent = destination.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or
            stat.S_IMODE(parent.st_mode) & 0o077):
        raise ValueError('restore parent must be an owned private real directory')
    # Fixed flat output names, never ZIP paths. Archived source stays in the archive.
    outputs = {'case.json': members['case.json']}
    outputs.update({f'source-{index:02d}.bin': members[f'inputs/{index:02d}.bin']
                    for index in range(1, result['input_count'] + 1)})
    destination.mkdir(mode=0o700)
    attempted = []
    try:
        for name, content in outputs.items():
            path = destination/name
            attempted.append(path)
            _publish(path, content)
        # Check the actual written bytes before declaring the set complete.
        if any(path.read_bytes() != outputs[path.name] for path in attempted):
            raise ValueError('restored file differs from verified bytes')
    except BaseException:
        # Only remove this invocation's fresh names under the cooperative-parent contract.
        # Process kill or power loss cannot run cleanup; never reuse a partial target.
        for path in attempted:
            path.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return dict(result, status='cloudtrail_archive_restored', restored_file_count=len(outputs),
                exact_bytes_restored=True, restored_code_files=0)


def _read_archive(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE_BYTES:
            raise ValueError('expected bounded regular archive file')
        data = source.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError('archive exceeds 96 MiB')
    return data


def _publish(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.cloudtrail-archive-', delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('case', type=Path)
    create.add_argument('inputs', nargs='+', type=Path)
    create.add_argument('--expected-case-sha256', required=True)
    create.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('archive', type=Path)
    verify.add_argument('--expected-archive-sha256', required=True)
    restore = commands.add_parser('restore')
    restore.add_argument('archive', type=Path)
    restore.add_argument('--expected-archive-sha256', required=True)
    restore.add_argument('--output-directory', type=Path, required=True)
    for command in (create, verify, restore):
        command.add_argument('--account-id', required=True)
        command.add_argument('--case-id', required=True)
        command.add_argument('--scope-note', required=True)
        command.add_argument('--threshold', type=int, required=True)
        command.add_argument('--window-seconds', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix':
            raise ValueError('private archive commands require POSIX')
        requirements = {name: getattr(args, name) for name in
                        ('account_id', 'case_id', 'scope_note', 'threshold', 'window_seconds')}
        if args.command == 'create':
            data = build_archive(_read_case(args.case), (_read(p) for p in args.inputs),
                                 expected_case_sha256=args.expected_case_sha256, **requirements)
            result = verify_archive(data, expected_archive_sha256=_sha(data), **requirements)
            _publish(args.output, data)
            result['status'] = 'cloudtrail_archive_created'
        elif args.command == 'verify':
            result = verify_archive(_read_archive(args.archive),
                                    expected_archive_sha256=args.expected_archive_sha256, **requirements)
        else:
            result = restore_archive(_read_archive(args.archive), args.output_directory,
                                     expected_archive_sha256=args.expected_archive_sha256, **requirements)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, EOFError, zlib.error,
            RecursionError, OverflowError, zipfile.BadZipFile, zipfile.LargeZipFile):
        print('error: CloudTrail archive failed; check private originals, pins, recipient settings and matching checkout',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
