"""Exercise local policy selection with fresh temporary issuer and source keys."""

import base64
import json
from pathlib import Path
import tempfile

import demo_source_claims as claims_demo
import source_auth as auth
import source_claims
import source_policy_state as policy
from asset_review import _canonical


def prepare(root):
    requirements, common = claims_demo.prepare(root)
    SigningKey, _, _ = auth._crypto()
    key = SigningKey.generate()
    seed = root / 'issuer-seed'; seed.touch(mode=0o600); seed.write_bytes(key.encode())
    issuer = dict(schema_version=1, scope='synthetic', namespace='synthetic-assets',
        audience='local-reviewer', key_id='policy-issuer',
        public_key_b64=base64.b64encode(key.verify_key.encode()).decode('ascii'),
        status='active', not_before='2026-11-17T00:00:00Z', not_after='2026-11-18T00:00:00Z',
        maximum_validity_seconds=3600)
    (root / 'issuer.json').write_bytes(_canonical(issuer))
    context = dict(scope='synthetic', namespace='synthetic-assets', audience='local-reviewer',
        at='2026-11-17T00:02:00Z', expected_issuer_sha256=policy.digest(_canonical(issuer)))
    return key, common, context


def exercise():
    with tempfile.TemporaryDirectory(prefix='lab-policy-state-') as directory:
        root = Path(directory)
        _, source_context, context = prepare(root)
        originals = [str(root / name) for name in ('cloud.json', 'endpoint.json')]
        requirements = json.loads((root / 'source-requirements.json').read_bytes())
        claims = [str(root / ('claim-' + str(i))) for i in range(2)]
        for i, rule in enumerate(requirements['sources']):
            claims_demo.run(source_claims.main, ['claim', originals[i], '--source-id', rule['source_id'],
                '--seed-file', str(root / ('seed-' + str(i))), '--issued-at', '2026-11-17T00:01:00Z',
                '--expires-at', '2026-11-17T00:31:00Z', '--output', claims[i], *source_context])
        bundle = root / 'bundle.json'
        bundled = claims_demo.run(source_claims.main, ['bundle', *originals, '--claims', *claims,
            '--output', str(bundle), *source_context])
        common = ['--issuer', str(root / 'issuer.json')]
        for k, v in context.items(): common += ['--' + k.replace('_', '-'), v]
        authority = root / 'authority.json'
        selected = None
        for sequence in (1, 2):
            if sequence == 2:
                revoked = json.loads(authority.read_bytes()); revoked['sources'][0]['status'] = 'revoked'
                authority.write_bytes(_canonical(revoked))
            authority_args = ['--authority', str(authority), '--expected-authority-sha256', policy.digest(authority.read_bytes())]
            update = root / ('update-' + str(sequence))
            issue = ['issue', '--seed-file', str(root / 'issuer-seed'), '--sequence', str(sequence),
                '--issued-at', '2026-11-17T00:01:00Z', '--expires-at', '2026-11-17T00:31:00Z',
                '--output', str(update), *authority_args, *common]
            if selected: issue += ['--previous-update-sha256', selected['update_sha256']]
            issued = claims_demo.run(policy.main, issue)
            selection = ['initialize' if sequence == 1 else 'advance', '--state', str(root / 'state.json'),
                '--update', str(update), '--expected-update-sha256', issued['update_sha256'], *authority_args, *common]
            if selected: selection += ['--expected-state-sha256', selected['state_sha256']]
            selected = claims_demo.run(policy.main, selection)
            if sequence == 1:
                report_path = root / 'report.json'
                claims_demo.run(policy.main, ['review', *originals, '--state', str(root / 'state.json'),
                    '--expected-state-sha256', selected['state_sha256'], '--requirements', str(root / 'source-requirements.json'),
                    '--expected-requirements-sha256', policy.digest((root / 'source-requirements.json').read_bytes()),
                    '--bundle', str(bundle), '--expected-bundle-sha256', bundled['bundle_sha256'],
                    '--output', str(report_path), *common])
                initial_report = json.loads(report_path.read_bytes())
        try:
            policy.review_selected(root / 'state.json', (root / 'issuer.json').read_bytes(),
                [Path(p).read_bytes() for p in originals], (root / 'source-requirements.json').read_bytes(), bundle.read_bytes(),
                expected_state_sha256=selected['state_sha256'], expected_requirements_sha256=policy.digest((root / 'source-requirements.json').read_bytes()),
                expected_bundle_sha256=bundled['bundle_sha256'], **context)
        except ValueError:
            revoked_bundle_rejected = True
        else:
            raise AssertionError('old bundle accepted after selected policy change')
        nested = initial_report['authenticated_review']['constrained_review']['review']
        return dict(status='source_policy_state_exercise_passed', selected_sequence=selected['sequence'],
            group_count=nested['group_count'], unresolved_component_count=nested['unresolved_component_count'],
            old_bundle_rejected=revoked_bundle_rejected, global_latest_verified=False,
            source_truth_verified=False, temporary_keys_only=True)


if __name__ == '__main__':
    print(json.dumps(exercise(), sort_keys=True))
