"""Require separately enrolled source-key claims before constrained host grouping."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

from asset_review import LABEL, MAX_INPUT_BYTES, _canonical, _exact, _label, _publish, _read
from source_review import (
    MAX_REPORT_BYTES, MAX_REQUIREMENTS_BYTES, _check_source, _instant, _parse, _pin,
    _requirements, review_constrained,
)

PURPOSE = 'lab-asset-source-claim-v1'
DOMAIN = PURPOSE.encode('ascii') + b'\x00'
AUTHORITY_LIMIT = 16 * 1024
BUNDLE_LIMIT = 32 * 1024
CLAIM_FIELDS = ('schema_version', 'purpose', 'scope', 'namespace', 'source_id', 'key_id',
                'source_sha256', 'requirements_sha256', 'authority_sha256',
                'issued_at', 'expires_at', 'signature_b64')


def _crypto():
    try:
        from nacl.signing import SigningKey, VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        raise ValueError('optional PyNaCl required for source authentication') from None
    return SigningKey, VerifyKey, BadSignatureError


def _decode(value, size):
    if type(value) is not str or len(value) != 4 * ((size+2)//3):
        raise ValueError('bounded canonical cryptographic encoding required')
    raw = base64.b64decode(value, validate=True)
    if len(raw) != size or base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('invalid cryptographic encoding')
    return raw


def _authority(data, pin, scope, namespace):
    if type(data) is not bytes or not 0 < len(data) <= AUTHORITY_LIMIT:
        raise ValueError('bounded source authority required')
    _pin(data, pin)
    policy = _parse(data)
    _exact(policy, ('schema_version', 'scope', 'namespace', 'maximum_validity_seconds', 'sources'))
    if (type(policy['schema_version']) is not int or policy['schema_version'] != 1 or
            policy['scope'] != scope or policy['namespace'] != namespace or
            type(policy['maximum_validity_seconds']) is not int or
            not 1 <= policy['maximum_validity_seconds'] <= 86400 or
            type(policy['sources']) is not list or not 2 <= len(policy['sources']) <= 8):
        raise ValueError('invalid source authority context or limits')
    sources, ids, public_keys = {}, set(), set()
    for key in policy['sources']:
        _exact(key, ('source_id', 'key_id', 'public_key_b64', 'status', 'not_before', 'not_after'))
        source_id, key_id = _label(key['source_id'], LABEL), _label(key['key_id'], LABEL)
        public = _decode(key['public_key_b64'], 32)
        if (source_id in sources or key_id in ids or public in public_keys or
                key['status'] not in ('active', 'revoked') or
                _instant(key['not_before']) >= _instant(key['not_after'])):
            raise ValueError('duplicate or invalid source enrollment')
        sources[source_id] = key; ids.add(key_id); public_keys.add(public)
    return sources, policy['maximum_validity_seconds']


def _window(claim, key, maximum, at):
    issued, expires, now = (_instant(claim['issued_at']), _instant(claim['expires_at']), _instant(at))
    if (key['status'] != 'active' or not issued <= now < expires or
            not 0 < (expires-issued).total_seconds() <= maximum or
            issued < _instant(key['not_before']) or expires > _instant(key['not_after'])):
        raise ValueError('source claim outside active enrolled window')


def _message(claim):
    return DOMAIN + _canonical({k: v for k, v in claim.items() if k != 'signature_b64'})


def create_claim(original, requirements_data, authority_data, *, expected_requirements_sha256,
                 expected_authority_sha256, scope, namespace, source_id, signing_key,
                 issued_at, expires_at, at):
    _label(namespace)
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('explicit permitted scope required')
    if type(requirements_data) is not bytes or len(requirements_data) > MAX_REQUIREMENTS_BYTES:
        raise ValueError('bounded requirements required')
    _pin(requirements_data, expected_requirements_sha256)
    keys, maximum = _authority(authority_data, expected_authority_sha256, scope, namespace)
    requirements, start, end = _requirements(requirements_data, scope, namespace)
    if set(keys) != {r['source_id'] for r in requirements['sources']} or source_id not in keys:
        raise ValueError('enrollment differs from expected source roster')
    key = keys[source_id]
    SigningKey, _, _ = _crypto()
    if not isinstance(signing_key, SigningKey) or signing_key.verify_key.encode() != _decode(key['public_key_b64'], 32):
        raise ValueError('signer differs from enrolled source key')
    rule = next(r for r in requirements['sources'] if r['source_id'] == source_id)
    if type(original) is not bytes or len(original) > MAX_INPUT_BYTES:
        raise ValueError('bounded original required')
    _pin(original, rule['expected_original_sha256'])
    captured = _check_source(original, rule, scope, namespace, start, end)
    claim = {'schema_version': 1, 'purpose': PURPOSE, 'scope': scope, 'namespace': namespace,
        'source_id': source_id, 'key_id': key['key_id'], 'source_sha256': rule['expected_original_sha256'],
        'requirements_sha256': expected_requirements_sha256, 'authority_sha256': expected_authority_sha256,
        'issued_at': issued_at, 'expires_at': expires_at}
    _window(claim, key, maximum, at)
    if captured > _instant(issued_at):
        raise ValueError('source capture claim is later than issuance')
    claim['signature_b64'] = base64.b64encode(signing_key.sign(_message(claim)).signature).decode('ascii')
    return claim


def review_authenticated(originals, requirements_data, authority_data, bundle_data, *,
                         expected_requirements_sha256, expected_authority_sha256,
                         expected_bundle_sha256, scope, namespace, at):
    _label(namespace)
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('explicit permitted scope required')
    for data, limit, pin in ((requirements_data, MAX_REQUIREMENTS_BYTES, expected_requirements_sha256),
                            (authority_data, AUTHORITY_LIMIT, expected_authority_sha256),
                            (bundle_data, BUNDLE_LIMIT, expected_bundle_sha256)):
        if type(data) is not bytes or len(data) > limit: raise ValueError('bounded review input required')
        _pin(data, pin)
    keys, maximum = _authority(authority_data, expected_authority_sha256, scope, namespace)
    requirements, _, _ = _requirements(requirements_data, scope, namespace)
    rules = requirements['sources']
    if set(keys) != {r['source_id'] for r in rules} or not 2 <= len(originals) == len(rules) <= 8:
        raise ValueError('complete enrolled source roster required')
    bundle = _parse(bundle_data); _exact(bundle, ('schema_version', 'claims'))
    if type(bundle['schema_version']) is not int or bundle['schema_version'] != 1 or type(bundle['claims']) is not list or len(bundle['claims']) != len(rules):
        raise ValueError('complete source claim bundle required')
    claims = {}
    for claim in bundle['claims']:
        _exact(claim, CLAIM_FIELDS)
        source_id = _label(claim['source_id'], LABEL)
        if source_id in claims or source_id not in keys:
            raise ValueError('duplicate or unexpected source claim')
        claims[source_id] = claim
    _, VerifyKey, BadSignatureError = _crypto()
    # Verify every signature, context and original pin before parsing any original or grouping.
    for data, rule in zip(originals, rules):
        claim = claims[rule['source_id']]; key = keys[rule['source_id']]
        if (type(claim['schema_version']) is not int or claim['schema_version'] != 1 or
                any(claim[name] != value for name, value in {'purpose': PURPOSE, 'scope': scope,
                    'namespace': namespace, 'key_id': key['key_id'],
                    'requirements_sha256': expected_requirements_sha256,
                    'authority_sha256': expected_authority_sha256,
                    'source_sha256': rule['expected_original_sha256']}.items())):
            raise ValueError('source claim context differs')
        _window(claim, key, maximum, at)
        try:
            VerifyKey(_decode(key['public_key_b64'], 32)).verify(_message(claim), _decode(claim['signature_b64'], 64))
        except BadSignatureError:
            raise ValueError('source signature did not verify') from None
        if type(data) is not bytes or len(data) > MAX_INPUT_BYTES: raise ValueError('bounded original required')
        _pin(data, rule['expected_original_sha256'])
    for data, rule in zip(originals, rules):
        if _instant(_parse(data)['captured_at']) > _instant(claims[rule['source_id']]['issued_at']):
            raise ValueError('capture claim is later than source issuance')
    constrained = review_constrained(originals, requirements_data,
        expected_requirements_sha256=expected_requirements_sha256, scope=scope, namespace=namespace)
    result = {'schema_version': 1, 'report_type': 'authenticated-source-identity-review',
        'authority_sha256': expected_authority_sha256, 'bundle_sha256': expected_bundle_sha256,
        'collector_key_claims_verified': True, 'source_truth_verified': False,
        'collector_independence_verified': False, 'verified_at': at,
        'source_claims': bundle['claims'], 'constrained_review': constrained,
        'interpretation': 'Each expected source key signed its exact bytes and selected requirements/authority. '
            'Distinct keys are not independent physical collectors or truthful capture times. Grants, '
            'conflicts and grouping retain existing semantics. No accepted identity/ownership, latest '
            'policy distribution, anti-rollback selection or one-time execution is established.'}
    if len(_canonical(result)) > MAX_REPORT_BYTES:
        raise ValueError('authenticated review exceeds bound')
    return result


def exercise():
    SigningKey, _, _ = _crypto(); root = Path(__file__).resolve().parent / 'examples'
    originals = [(root/name).read_bytes() for name in ('cloud.json', 'endpoint.json')]
    requirements = (root/'source-requirements.json').read_bytes(); rules = _parse(requirements)['sources']
    signers = [SigningKey.generate() for _ in rules]
    authority = {'schema_version':1,'scope':'synthetic','namespace':'synthetic-assets',
        'maximum_validity_seconds':3600,'sources':[
            {'source_id':r['source_id'],'key_id':'collector-'+str(i),'public_key_b64':base64.b64encode(k.verify_key.encode()).decode(),
             'status':'active','not_before':'2026-11-17T00:00:00Z','not_after':'2026-11-18T00:00:00Z'}
            for i,(r,k) in enumerate(zip(rules,signers))]}
    authority_data = _canonical(authority)
    options = dict(expected_requirements_sha256=hashlib.sha256(requirements).hexdigest(),
        expected_authority_sha256=hashlib.sha256(authority_data).hexdigest(), scope='synthetic',
        namespace='synthetic-assets', at='2026-11-17T00:02:00Z')
    claims = [create_claim(data,requirements,authority_data,**options,source_id=r['source_id'],signing_key=k,
        issued_at='2026-11-17T00:01:00Z',expires_at='2026-11-17T00:31:00Z')
        for data,r,k in zip(originals,rules,signers)]
    bundle = _canonical({'schema_version':1,'claims':claims}); options['expected_bundle_sha256']=hashlib.sha256(bundle).hexdigest()
    result = review_authenticated(originals,requirements,authority_data,bundle,**options)
    return {'status':'authenticated_source_identity_exercise_passed','collector_key_claims_verified':True,
        'source_truth_verified':False,**{key:result['constrained_review']['review'][key]
            for key in ('record_count','group_count','unresolved_component_count')}}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    commands=parser.add_subparsers(dest='command',required=True); commands.add_parser('demo')
    review=commands.add_parser('review',allow_abbrev=False);review.add_argument('sources',nargs='+',type=Path)
    for name in ('requirements','authority','bundle'):
        review.add_argument('--'+name,type=Path,required=True);review.add_argument('--expected-'+name+'-sha256',required=True)
    review.add_argument('--scope',choices=('synthetic','owned','authorized'),required=True)
    for name in ('namespace','at'):review.add_argument('--'+name,required=True)
    review.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='demo':result=exercise()
        else:
            if not 2 <= len(args.sources) <= 8: raise ValueError('two to eight sources required')
            report=review_authenticated([_read(p) for p in args.sources],_read(args.requirements),_read(args.authority),_read(args.bundle),
                expected_requirements_sha256=args.expected_requirements_sha256,expected_authority_sha256=args.expected_authority_sha256,
                expected_bundle_sha256=args.expected_bundle_sha256,scope=args.scope,namespace=args.namespace,at=args.at)
            data=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
            if len(data)>MAX_REPORT_BYTES:raise ValueError('authenticated review exceeds bound')
            _publish(args.output,data)
            result={'status':'authenticated_source_identity_review_created','collector_key_claims_verified':True,
                'source_truth_verified':False,'report_sha256':hashlib.sha256(data).hexdigest(),
                **{key:report['constrained_review']['review'][key] for key in ('record_count','group_count','unresolved_component_count')}}
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):
        print('error: authenticated identity review failed; check private sources, independent pins, enrollment, time and new output',file=sys.stderr)
        return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
