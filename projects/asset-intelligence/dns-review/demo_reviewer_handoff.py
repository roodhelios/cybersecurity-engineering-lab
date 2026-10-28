"""Run a complete local DNS handoff with ephemeral recipient, risk and team keys."""

import base64
import hashlib
import json
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from dns_authorized_handoff import create_approval
from dns_ownership_review import finding_digest
from dns_review import publish
from dns_reviewer_handoff import create_attestation, verify_reviewed_handoff, main as verify_main
from zeek_dns_workflow import review_logs


def fixture():
    from nacl.signing import SigningKey
    root = Path(__file__).resolve().parent/'examples'
    inputs = [(root/name).read_bytes() for name in
              ('zeek-dns-before.jsonl', 'zeek-dns.jsonl', 'scope.json', 'review-policy.json')]
    requirements = (root/'handoff-requirements-complete.json').read_bytes()
    assessment = (root/'risk-assessments.json').read_bytes()
    ownership = (root/'ownership-responses.json').read_bytes()
    keys = {role: SigningKey.generate() for role in ('recipient', 'risk', 'team-response')}
    recipient = {'schema_version': 1, 'authority_type': 'dns-recipient-authorities',
        'audience': 'synthetic-recipient', 'maximum_validity_seconds': 86400,
        'keys': [{'key_id': 'recipient-lab', 'status': 'active',
                  'public_key_b64': base64.b64encode(keys['recipient'].verify_key.encode()).decode('ascii')}]}
    recipient_data = json.dumps(recipient).encode()
    approval = create_approval(requirements, *inputs[2:], recipient_data, signing_key=keys['recipient'],
        key_id='recipient-lab', issued_at='2026-10-28T00:00:00Z', expires_at='2026-10-29T00:00:00Z')
    report = review_logs(*inputs, previous_observed_at='2026-10-23T00:00:00Z',
        current_observed_at='2026-10-24T00:00:00Z', record_type='A', include_queue=True,
        assessment_data=assessment, ownership_data=ownership)
    digest = finding_digest(report['review'], report['review']['findings'][0])
    records = {'risk': json.loads(assessment)['assessments'][0],
               'team-response': json.loads(ownership)['responses'][0]}
    reviewers = {'schema_version': 1, 'authority_type': 'dns-reviewer-authorities',
                 'audience': 'synthetic-recipient', 'maximum_validity_seconds': 86400, 'keys': []}
    for role in records:
        reviewers['keys'].append({'key_id': role+'-lab', 'status': 'active',
            'public_key_b64': base64.b64encode(keys[role].verify_key.encode()).decode('ascii'),
            'grants': [{'finding_sha256': digest, 'role': role,
                        'team': None if role == 'risk' else records[role]['team']}]})
    reviewer_data = json.dumps(reviewers).encode()
    attestations = [create_attestation(record, finding_sha256=digest, role=role,
        team=None if role == 'risk' else record['team'], authority_data=reviewer_data,
        signing_key=keys[role], key_id=role+'-lab', issued_at='2026-10-28T00:00:00Z',
        expires_at='2026-10-29T00:00:00Z') for role, record in records.items()]
    options = dict(requirements=requirements, approval=approval, authority_policy=recipient_data,
        reviewer_policy=reviewer_data, expected_reviewer_policy_sha256=hashlib.sha256(reviewer_data).hexdigest(),
        attestations=json.dumps({'schema_version': 1, 'attestations': attestations}).encode(),
        now=datetime(2026, 10, 28, 12, tzinfo=timezone.utc), assessment_data=assessment, ownership_data=ownership)
    return json.dumps(report).encode(), inputs, options, keys


def exercise():
    report, inputs, options, keys = fixture()
    del keys
    result = verify_reviewed_handoff(report, *inputs, **options)
    missing = json.loads(options['attestations']); missing['attestations'].pop()
    forged = json.loads(options['attestations']); forged['attestations'][0]['review_record_sha256'] = '0'*64
    reviewer = json.loads(options['reviewer_policy']); reviewer['keys'][0]['status'] = 'revoked'
    revoked = json.dumps(reviewer).encode()
    for change in ({'attestations': json.dumps(missing).encode()}, {'attestations': json.dumps(forged).encode()},
        {'reviewer_policy': revoked, 'expected_reviewer_policy_sha256': hashlib.sha256(revoked).hexdigest()},
        {'expected_reviewer_policy_sha256': '0'*64}):
        try:
            verify_reviewed_handoff(report, *inputs, **dict(options, **change))
        except ValueError:
            pass
        else:
            raise ValueError('invalid reviewer handoff accepted')
    with tempfile.TemporaryDirectory(prefix='dns-reviewer-handoff-') as name:
        work = Path(name)
        data = dict(report=report, previous=inputs[0], current=inputs[1], scope=inputs[2], policy=inputs[3],
            requirements=options['requirements'], approval=options['approval'], authority=options['authority_policy'],
            reviewers=options['reviewer_policy'], attestations=options['attestations'],
            assessment=options['assessment_data'], ownership=options['ownership_data'])
        paths = {key: work/(key+'.json') for key in data}
        for key, content in data.items():
            publish(paths[key], content.decode())
        args = [str(paths[key]) for key in ('report', 'previous', 'current')]
        for flag, key in (('scope','scope'), ('policy','policy'), ('requirements','requirements'),
            ('approval','approval'), ('authority-policy','authority'), ('reviewer-policy','reviewers'),
            ('attestations','attestations'), ('assessment','assessment'), ('ownership-responses','ownership')):
            args.extend(['--'+flag, str(paths[key])])
        args.extend(['--expected-reviewer-policy-sha256', options['expected_reviewer_policy_sha256'],
                     '--at', '2026-10-28T12:00:00Z'])
        output = StringIO()
        with redirect_stdout(output):
            if verify_main(args) != 0:
                raise ValueError('file-based reviewer verification failed')
        if json.loads(output.getvalue())['reviewer_authority']['attestation_count'] != 2:
            raise ValueError('CLI lost reviewer coverage')
        if any(path.read_bytes() != data[key] for key, path in paths.items()):
            raise ValueError('input evidence changed')
    return {'schema_version': 1, 'status': 'reviewer_handoff_exercise_passed',
            'finding_count': result['finding_count'], 'attestation_count': 2,
            'negative_cases_rejected': 4, 'inputs_unchanged': True, 'native_ed25519': True}


def main():
    try:
        result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('error: local reviewer handoff exercise failed; check optional PyNaCl and bundled fixtures', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
