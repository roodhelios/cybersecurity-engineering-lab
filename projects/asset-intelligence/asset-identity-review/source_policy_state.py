"""Select signed source policy revisions against a pinned local recipient head."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

import source_auth as auth
from asset_review import _canonical, _exact, _label, _publish, _read
from source_claims import _seed
from source_review import _instant, _parse, _pin

PURPOSE = 'lab-asset-source-policy-update-v1'
DOMAIN = PURPOSE.encode('ascii') + b'\x00'
UPDATE_LIMIT = 8192
STATE_LIMIT = 128 * 1024
ISSUER_FIELDS = ('schema_version', 'scope', 'namespace', 'audience', 'key_id',
                 'public_key_b64', 'status', 'not_before', 'not_after', 'maximum_validity_seconds')
UPDATE_FIELDS = ('schema_version', 'purpose', 'scope', 'namespace', 'audience', 'key_id',
                 'issuer_sha256', 'authority_sha256', 'sequence', 'previous_update_sha256',
                 'issued_at', 'expires_at', 'signature_b64')
STATE_FIELDS = ('schema_version', 'scope', 'namespace', 'audience', 'issuer_sha256',
                'authority_sha256', 'update_sha256', 'sequence', 'authority_json',
                'update_json', 'previous_state_sha256', 'accepted_at')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _hash(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('lowercase SHA-256 required')
    return value


def _bounded(data, limit, pin):
    if type(data) is not bytes or not 0 < len(data) <= limit:
        raise ValueError('bounded policy input required')
    _pin(data, pin)
    return _parse(data)


def _issuer(data, pin, scope, namespace, audience):
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('explicit permitted scope required')
    _label(namespace); _label(audience)
    issuer = _bounded(data, auth.AUTHORITY_LIMIT, pin)
    _exact(issuer, ISSUER_FIELDS)
    if (type(issuer['schema_version']) is not int or issuer['schema_version'] != 1 or
            any(issuer[k] != v for k, v in dict(scope=scope, namespace=namespace, audience=audience).items()) or
            issuer['status'] not in ('active', 'revoked') or
            type(issuer['maximum_validity_seconds']) is not int or
            not 1 <= issuer['maximum_validity_seconds'] <= 86400 or
            _instant(issuer['not_before']) >= _instant(issuer['not_after'])):
        raise ValueError('invalid issuer context or limits')
    _label(issuer['key_id']); auth._decode(issuer['public_key_b64'], 32)
    return issuer


def _message(update):
    return DOMAIN + _canonical({k: v for k, v in update.items() if k != 'signature_b64'})


def verify_update(authority_data, issuer_data, update_data, *, expected_authority_sha256,
                  expected_issuer_sha256, expected_update_sha256, scope, namespace, audience, at):
    # Check all independently selected byte pins before parsing any policy input.
    for data, limit, pin in ((issuer_data, auth.AUTHORITY_LIMIT, expected_issuer_sha256),
                            (authority_data, auth.AUTHORITY_LIMIT, expected_authority_sha256),
                            (update_data, UPDATE_LIMIT, expected_update_sha256)):
        if type(data) is not bytes or not 0 < len(data) <= limit:
            raise ValueError('bounded policy input required')
        _pin(data, pin)
    issuer = _issuer(issuer_data, expected_issuer_sha256, scope, namespace, audience)
    auth._authority(authority_data, expected_authority_sha256, scope, namespace)
    update = _bounded(update_data, UPDATE_LIMIT, expected_update_sha256)
    _exact(update, UPDATE_FIELDS)
    if (type(update['schema_version']) is not int or update['schema_version'] != 1 or
            type(update['sequence']) is not int or not 1 <= update['sequence'] <= 1_000_000 or
            any(update[k] != v for k, v in dict(purpose=PURPOSE, scope=scope, namespace=namespace,
                audience=audience, key_id=issuer['key_id'], issuer_sha256=expected_issuer_sha256,
                authority_sha256=expected_authority_sha256).items())):
        raise ValueError('invalid signed update context or sequence')
    if update['sequence'] == 1:
        if update['previous_update_sha256'] is not None:
            raise ValueError('initial update cannot have a predecessor')
    else:
        _hash(update['previous_update_sha256'])
    auth._window(update, issuer, issuer['maximum_validity_seconds'], at)
    _, VerifyKey, BadSignatureError = auth._crypto()
    try:
        VerifyKey(auth._decode(issuer['public_key_b64'], 32)).verify(
            _message(update), auth._decode(update['signature_b64'], 64))
    except BadSignatureError:
        raise ValueError('policy update signature did not verify') from None
    return update


def issue_update(authority_data, issuer_data, *, expected_authority_sha256,
                 expected_issuer_sha256, scope, namespace, audience, signing_key,
                 sequence, previous_update_sha256, issued_at, expires_at, at):
    issuer = _issuer(issuer_data, expected_issuer_sha256, scope, namespace, audience)
    auth._authority(authority_data, expected_authority_sha256, scope, namespace)
    SigningKey, _, _ = auth._crypto()
    if (not isinstance(signing_key, SigningKey) or
            signing_key.verify_key.encode() != auth._decode(issuer['public_key_b64'], 32)):
        raise ValueError('signer differs from enrolled issuer')
    update = dict(schema_version=1, purpose=PURPOSE, scope=scope, namespace=namespace,
        audience=audience, key_id=issuer['key_id'], issuer_sha256=expected_issuer_sha256,
        authority_sha256=expected_authority_sha256, sequence=sequence,
        previous_update_sha256=previous_update_sha256, issued_at=issued_at, expires_at=expires_at)
    update['signature_b64'] = base64.b64encode(signing_key.sign(_message(update)).signature).decode('ascii')
    data = _canonical(update) + b'\n'
    verify_update(authority_data, issuer_data, data, expected_authority_sha256=expected_authority_sha256,
        expected_issuer_sha256=expected_issuer_sha256, expected_update_sha256=digest(data),
        scope=scope, namespace=namespace, audience=audience, at=at)
    return data


def _private(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ValueError('owned singly linked private recipient file required')


@contextmanager
def _lock(path, exclusive):
    if os.name != 'posix':
        raise ValueError('recipient state requires POSIX locking')
    import fcntl
    with os.fdopen(os.open(str(path) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                          os.O_NONBLOCK, 0o600), 'r+b') as handle:
        _private(os.fstat(handle.fileno()))
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield


def _snapshot(path, expected_state_sha256, issuer_data, context, historical=False):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
        info = os.fstat(handle.fileno()); _private(info)
        if info.st_size > STATE_LIMIT:
            raise ValueError('recipient state exceeds bound')
        data = handle.read(STATE_LIMIT + 1)
    state = _bounded(data, STATE_LIMIT, expected_state_sha256)
    _exact(state, STATE_FIELDS)
    if (type(state['schema_version']) is not int or state['schema_version'] != 1 or
            type(state['sequence']) is not int or
            any(state[k] != context[k] for k in ('scope', 'namespace', 'audience')) or
            state['issuer_sha256'] != context['expected_issuer_sha256'] or
            type(state['authority_json']) is not str or type(state['update_json']) is not str):
        raise ValueError('recipient state context differs')
    if state['sequence'] == 1:
        if state['previous_state_sha256'] is not None:
            raise ValueError('invalid initial recipient state')
    else:
        _hash(state['previous_state_sha256'])
    _instant(state['accepted_at'])
    authority, update = state['authority_json'].encode('utf-8'), state['update_json'].encode('utf-8')
    options = dict(context)
    if historical:
        # Verify the old signature at its signed issuance instant only to link a successor.
        options['at'] = _bounded(update, UPDATE_LIMIT, state['update_sha256'])['issued_at']
    verified = verify_update(authority, issuer_data, update,
        expected_authority_sha256=state['authority_sha256'], expected_update_sha256=state['update_sha256'], **options)
    if state['sequence'] != verified['sequence']:
        raise ValueError('recipient sequence differs from signed update')
    return state, authority


def _replacement(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=Path(path).parent, prefix='.policy-', delete=False) as handle:
            temporary = handle.name
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)


def select_policy(path, authority_data, issuer_data, update_data, *, expected_state_sha256=None,
                  expected_authority_sha256, expected_update_sha256, expected_issuer_sha256,
                  scope, namespace, audience, at):
    """Initialize explicitly, or compare and advance one pinned local policy head."""
    context = dict(expected_issuer_sha256=expected_issuer_sha256,
                   scope=scope, namespace=namespace, audience=audience, at=at)
    update = verify_update(authority_data, issuer_data, update_data,
        expected_authority_sha256=expected_authority_sha256,
        expected_update_sha256=expected_update_sha256, **context)
    with _lock(path, True):
        if expected_state_sha256 is None:
            if update['sequence'] != 1 or update['previous_update_sha256'] is not None:
                raise ValueError('explicit initialization requires the first update')
        else:
            old, _ = _snapshot(path, expected_state_sha256, issuer_data, context, historical=True)
            if (update['sequence'] != old['sequence'] + 1 or
                    update['previous_update_sha256'] != old['update_sha256']):
                raise ValueError('update must be the exact selected successor')
        state = dict(schema_version=1, scope=scope, namespace=namespace, audience=audience,
            issuer_sha256=expected_issuer_sha256, authority_sha256=expected_authority_sha256,
            update_sha256=expected_update_sha256, sequence=update['sequence'],
            authority_json=authority_data.decode('utf-8'), update_json=update_data.decode('utf-8'),
            previous_state_sha256=expected_state_sha256, accepted_at=at)
        data = _canonical(state) + b'\n'
        if len(data) > STATE_LIMIT:
            raise ValueError('recipient state exceeds bound')
        if expected_state_sha256 is None:
            _publish(Path(path), data)
        else:
            _replacement(path, data)
        return dict(state_sha256=digest(data), update_sha256=expected_update_sha256,
                    authority_sha256=expected_authority_sha256, sequence=state['sequence'])


def review_selected(path, issuer_data, originals, requirements_data, bundle_data, *,
                    expected_state_sha256, expected_issuer_sha256, expected_requirements_sha256,
                    expected_bundle_sha256, scope, namespace, audience, at):
    context = dict(expected_issuer_sha256=expected_issuer_sha256,
                   scope=scope, namespace=namespace, audience=audience, at=at)
    with _lock(path, False):
        state, authority = _snapshot(path, expected_state_sha256, issuer_data, context)
        report = auth.review_authenticated(originals, requirements_data, authority, bundle_data,
            expected_requirements_sha256=expected_requirements_sha256,
            expected_bundle_sha256=expected_bundle_sha256,
            expected_authority_sha256=state['authority_sha256'], scope=scope, namespace=namespace, at=at)
        return dict(schema_version=1, report_type='selected-source-policy-review',
            policy_selection=dict(state_sha256=expected_state_sha256, update_sha256=state['update_sha256'],
                authority_sha256=state['authority_sha256'], sequence=state['sequence'], audience=audience, verified_at=at),
            selected_policy_revision_authenticated=True, global_latest_verified=False,
            source_truth_verified=False, authenticated_review=report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('issue', 'initialize', 'advance', 'review'):
        command = commands.add_parser(name)
        for option in ('issuer', 'expected-issuer-sha256', 'scope', 'namespace', 'audience', 'at'):
            command.add_argument('--' + option, required=True)
        if name != 'issue':
            command.add_argument('--state', required=True)
        if name in ('advance', 'review'):
            command.add_argument('--expected-state-sha256', required=True)
        if name != 'review':
            for option in ('authority', 'expected-authority-sha256'):
                command.add_argument('--' + option, required=True)
        if name in ('initialize', 'advance'):
            command.add_argument('--update', required=True)
            command.add_argument('--expected-update-sha256', required=True)
        if name == 'issue':
            for option in ('seed-file', 'issued-at', 'expires-at', 'output'):
                command.add_argument('--' + option, required=True)
            command.add_argument('--sequence', type=int, required=True)
            command.add_argument('--previous-update-sha256')
        if name == 'review':
            command.add_argument('sources', nargs='+')
            for option in ('requirements', 'expected-requirements-sha256', 'bundle', 'expected-bundle-sha256', 'output'):
                command.add_argument('--' + option, required=True)
    args = parser.parse_args(argv)
    try:
        issuer = _read(args.issuer, auth.AUTHORITY_LIMIT)
        context = dict(expected_issuer_sha256=args.expected_issuer_sha256,
            scope=args.scope, namespace=args.namespace, audience=args.audience, at=args.at)
        if args.command == 'review':
            if not 2 <= len(args.sources) <= 8:
                raise ValueError('two to eight originals required')
            result = review_selected(args.state, issuer, [_read(p) for p in args.sources],
                _read(args.requirements, auth.MAX_REQUIREMENTS_BYTES), _read(args.bundle, auth.BUNDLE_LIMIT),
                expected_state_sha256=args.expected_state_sha256,
                expected_requirements_sha256=args.expected_requirements_sha256,
                expected_bundle_sha256=args.expected_bundle_sha256, **context)
            data = _canonical(result) + b'\n'
            if len(data) > auth.MAX_REPORT_BYTES: raise ValueError('report exceeds bound')
            _publish(Path(args.output), data)
            result = dict(report_sha256=digest(data), **result['policy_selection'])
        else:
            authority = _read(args.authority, auth.AUTHORITY_LIMIT)
            if args.command == 'issue':
                # Check public pins before loading private key material.
                _issuer(issuer, args.expected_issuer_sha256, args.scope, args.namespace, args.audience)
                auth._authority(authority, args.expected_authority_sha256, args.scope, args.namespace)
                SigningKey, _, _ = auth._crypto()
                data = issue_update(authority, issuer, expected_authority_sha256=args.expected_authority_sha256,
                    signing_key=SigningKey(_seed(args.seed_file)), sequence=args.sequence,
                    previous_update_sha256=args.previous_update_sha256,
                    issued_at=args.issued_at, expires_at=args.expires_at, **context)
                _publish(Path(args.output), data)
                result = dict(update_sha256=digest(data), authority_sha256=args.expected_authority_sha256)
            else:
                result = select_policy(args.state, authority, issuer, _read(args.update, UPDATE_LIMIT),
                    expected_state_sha256=getattr(args, 'expected_state_sha256', None),
                    expected_authority_sha256=args.expected_authority_sha256,
                    expected_update_sha256=args.expected_update_sha256, **context)
        print(json.dumps(dict(status=args.command + '_completed', **result), sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print('source policy operation rejected; check local inputs and independent pins', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
