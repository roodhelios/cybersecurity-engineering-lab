"""Exercise recipient-signed requirements with ephemeral keys and synthetic DNS inputs."""

import base64
import json
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from dns_authorized_handoff import create_approval, verify_authorized_workflow, main as verify_main
from dns_review import publish
from zeek_dns_workflow import review_logs


def exercise():
    try:
        from nacl.signing import SigningKey
    except ImportError:
        raise ValueError('install the optional PyNaCl dependency') from None
    root = Path(__file__).resolve().parent
    inputs = [(root/'examples'/name).read_bytes() for name in
              ('zeek-dns-before.jsonl', 'zeek-dns.jsonl', 'scope.json', 'review-policy.json')]
    requirements = (root/'examples/handoff-requirements-complete.json').read_bytes()
    reviews = {'assessment_data': (root/'examples/risk-assessments.json').read_bytes(),
               'ownership_data': (root/'examples/ownership-responses.json').read_bytes()}
    key = SigningKey.generate()
    authority = {'schema_version': 1, 'authority_type': 'dns-recipient-authorities',
        'audience': 'synthetic-recipient', 'maximum_validity_seconds': 86400,
        'keys': [{'key_id': 'recipient-lab', 'status': 'active',
                  'public_key_b64': base64.b64encode(bytes(key.verify_key)).decode()}]}
    authority_data = json.dumps(authority).encode()
    approval = create_approval(requirements, *inputs[2:], authority_data, signing_key=key,
        key_id='recipient-lab', issued_at='2026-10-27T00:00:00Z', expires_at='2026-10-28T00:00:00Z')
    report = json.dumps(review_logs(*inputs, previous_observed_at='2026-10-23T00:00:00Z',
        current_observed_at='2026-10-24T00:00:00Z', record_type='A', include_queue=True, **reviews)).encode()
    now = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
    options = dict(requirements=requirements, approval=approval, authority_policy=authority_data, now=now, **reviews)
    result = verify_authorized_workflow(report, *inputs, **options)
    revoked = json.loads(authority_data); revoked['keys'][0]['status'] = 'revoked'
    forged = json.loads(report); forged['review']['finding_count'] = 0
    for supplied_report, changes in ((report, {'requirements': requirements+b'\n'}),
        (report, {'authority_policy': json.dumps(revoked).encode()}),
        (report, {'now': datetime(2026, 10, 28, tzinfo=timezone.utc)}), (json.dumps(forged).encode(), {})):
        try:
            verify_authorized_workflow(supplied_report, *inputs, **dict(options, **changes))
        except ValueError:
            pass
        else:
            raise ValueError('invalid handoff was accepted')
    with tempfile.TemporaryDirectory(prefix='dns-authorized-handoff-') as name:
        work = Path(name)
        data = dict(report=report, previous=inputs[0], current=inputs[1], scope=inputs[2], policy=inputs[3],
            requirements=requirements, approval=approval, authority=authority_data,
            assessment=reviews['assessment_data'], ownership=reviews['ownership_data'])
        paths = {name: work/(name+'.json') for name in data}
        for name, content in data.items():
            publish(paths[name], content.decode())
        saved = {path: path.read_bytes() for path in paths.values()}
        args = [str(paths[name]) for name in ('report', 'previous', 'current')]
        for flag, name in (('scope','scope'), ('policy','policy'), ('requirements','requirements'),
            ('approval','approval'), ('authority-policy','authority'), ('assessment','assessment'), ('ownership-responses','ownership')):
            args.extend(['--'+flag, str(paths[name])])
        args.extend(['--at', '2026-10-27T12:00:00Z'])
        output = StringIO()
        with redirect_stdout(output):
            if verify_main(args) != 0:
                raise ValueError('file-based verification failed')
        if json.loads(output.getvalue())['finding_count'] != 1 or any(p.read_bytes() != b for p, b in saved.items()):
            raise ValueError('CLI verification changed or lost evidence')
    return {'schema_version': 1, 'status': 'authorized_handoff_exercise_passed',
            'finding_count': result['finding_count'], 'negative_cases_rejected': 4,
            'native_ed25519': True, 'inputs_unchanged': True, 'verification_time_source': 'explicit_fixture'}


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('error: local authorized handoff exercise failed; check optional PyNaCl and bundled fixtures', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
