"""Run the local claim, bundle, review and receipt CLIs with temporary keys."""

import base64
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile

import source_auth as auth
import source_claims
from asset_review import _canonical


def run(command, args):
    output = StringIO()
    with redirect_stdout(output):
        if command(args) != 0:
            raise ValueError('temporary claim workflow failed')
    return json.loads(output.getvalue())


def prepare(root):
    """Write only synthetic enrollment and fresh ephemeral seeds, never real keys."""
    SigningKey, _, _ = auth._crypto()
    examples = Path(__file__).resolve().parent / 'examples'
    for name in ('cloud.json', 'endpoint.json', 'source-requirements.json'):
        (root / name).write_bytes((examples / name).read_bytes())
    requirements = json.loads((root / 'source-requirements.json').read_bytes())
    entries = []
    for i, rule in enumerate(requirements['sources']):
        key = SigningKey.generate()
        path = root / ('seed-' + str(i))
        path.touch(mode=0o600)
        path.write_bytes(key.encode())
        entries.append({'source_id': rule['source_id'], 'key_id': 'collector-' + str(i),
            'public_key_b64': base64.b64encode(key.verify_key.encode()).decode('ascii'),
            'status': 'active', 'not_before': '2026-11-17T00:00:00Z',
            'not_after': '2026-11-18T00:00:00Z'})
    authority = {'schema_version': 1, 'scope': 'synthetic', 'namespace': 'synthetic-assets',
                 'maximum_validity_seconds': 3600, 'sources': entries}
    (root / 'authority.json').write_bytes(_canonical(authority))
    common = ['--requirements', str(root / 'source-requirements.json'),
        '--expected-requirements-sha256', hashlib.sha256((root / 'source-requirements.json').read_bytes()).hexdigest(),
        '--authority', str(root / 'authority.json'), '--expected-authority-sha256',
        hashlib.sha256((root / 'authority.json').read_bytes()).hexdigest(),
        '--scope', 'synthetic', '--namespace', 'synthetic-assets', '--at', '2026-11-17T00:02:00Z']
    return requirements, common


def exercise():
    with tempfile.TemporaryDirectory(prefix='lab-source-claims-') as directory:
        root = Path(directory)
        requirements, common = prepare(root)
        originals = [str(root / name) for name in ('cloud.json', 'endpoint.json')]
        claims = [str(root / ('claim-' + str(i) + '.json')) for i in range(2)]
        for i, rule in enumerate(requirements['sources']):
            run(source_claims.main, ['claim', originals[i], '--source-id', rule['source_id'],
                '--seed-file', str(root / ('seed-' + str(i))),
                '--issued-at', '2026-11-17T00:01:00Z', '--expires-at', '2026-11-17T00:31:00Z',
                '--output', claims[i], *common])
        bundle = root / 'bundle.json'
        result = run(source_claims.main, ['bundle', *originals, '--claims', *claims,
            '--output', str(bundle), *common])
        report = root / 'report.json'
        context = [*common, '--bundle', str(bundle), '--expected-bundle-sha256', result['bundle_sha256']]
        created = run(auth.main, ['review', *originals, '--output', str(report), *context])
        received = run(auth.main, ['verify', str(report), *originals,
            '--expected-report-sha256', created['report_sha256'], *context])
        return {'status': 'source_claim_cli_exercise_passed', 'claim_count': result['claim_count'],
            'received_report_reproduced': received['status'] == 'authenticated_source_identity_report_reproduced',
            'group_count': received['group_count'], 'unresolved_component_count': received['unresolved_component_count'],
            'source_truth_verified': False, 'temporary_keys_only': True}


if __name__ == '__main__':
    print(json.dumps(exercise(), sort_keys=True))
