"""Create local source claims and verify a complete bundle before publication."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import source_auth as auth
from asset_review import _canonical, _publish, _read
from source_review import _parse, _pin

CLAIM_LIMIT = 4096


def _seed(path):
    """Read a private raw Ed25519 seed through one owned regular descriptor."""
    if os.name != 'posix':
        raise ValueError('private seed loading requires POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or
                info.st_nlink != 1 or info.st_size != 32):
            raise ValueError('owned private raw seed required')
        data = handle.read(33)
    if len(data) != 32:
        raise ValueError('exact raw seed required')
    return data


def _context(args):
    requirements = _read(args.requirements, auth.MAX_REQUIREMENTS_BYTES)
    authority = _read(args.authority, auth.AUTHORITY_LIMIT)
    # Reject incorrect independent context pins before loading a private key.
    _pin(requirements, args.expected_requirements_sha256)
    _pin(authority, args.expected_authority_sha256)
    options = dict(expected_requirements_sha256=args.expected_requirements_sha256,
        expected_authority_sha256=args.expected_authority_sha256,
        scope=args.scope, namespace=args.namespace, at=args.at)
    return requirements, authority, options


def _claim(args):
    requirements, authority, options = _context(args)
    original = _read(args.source)
    SigningKey, _, _ = auth._crypto()
    claim = auth.create_claim(original, requirements, authority, **options,
        source_id=args.source_id, signing_key=SigningKey(_seed(args.seed_file)),
        issued_at=args.issued_at, expires_at=args.expires_at)
    data = _canonical(claim) + b'\n'
    if len(data) > CLAIM_LIMIT:
        raise ValueError('claim exceeds bound')
    _publish(args.output, data)
    return {'status': 'source_claim_created', 'claim_sha256': hashlib.sha256(data).hexdigest(),
            'source_truth_verified': False}


def _bundle(args):
    if not 2 <= len(args.sources) == len(args.claims) <= 8:
        raise ValueError('two to eight ordered originals and one claim per source required')
    requirements, authority, options = _context(args)
    originals = [_read(path) for path in args.sources]
    claims = [_parse(_read(path, CLAIM_LIMIT)) for path in args.claims]
    data = _canonical({'schema_version': 1, 'claims': claims}) + b'\n'
    if len(data) > auth.BUNDLE_LIMIT:
        raise ValueError('bundle exceeds bound')
    pin = hashlib.sha256(data).hexdigest()
    # No output exists until every signature and constrained source reproduces.
    auth.review_authenticated(originals, requirements, authority, data,
        expected_bundle_sha256=pin, **options)
    _publish(args.output, data)
    return {'status': 'source_claim_bundle_created', 'bundle_sha256': pin,
            'claim_count': len(claims), 'collector_key_claims_verified': True,
            'source_truth_verified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    claim = commands.add_parser('claim', allow_abbrev=False)
    claim.add_argument('source', type=Path)
    claim.add_argument('--source-id', required=True)
    claim.add_argument('--seed-file', required=True, type=Path)
    claim.add_argument('--issued-at', required=True)
    claim.add_argument('--expires-at', required=True)
    bundle = commands.add_parser('bundle', allow_abbrev=False)
    bundle.add_argument('sources', nargs='+', type=Path)
    bundle.add_argument('--claims', nargs='+', type=Path, required=True)
    for selected in (claim, bundle):
        for name in ('requirements', 'authority'):
            selected.add_argument('--' + name, type=Path, required=True)
            selected.add_argument('--expected-' + name + '-sha256', required=True)
        selected.add_argument('--scope', choices=('synthetic', 'owned', 'authorized'), required=True)
        selected.add_argument('--namespace', required=True)
        selected.add_argument('--at', required=True)
        selected.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = _claim(args) if args.command == 'claim' else _bundle(args)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: source claim preparation failed; check private inputs, independent pins, enrollment, time and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
