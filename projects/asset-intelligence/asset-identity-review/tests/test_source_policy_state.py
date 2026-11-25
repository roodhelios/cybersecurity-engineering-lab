import base64
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import demo_source_policy_state as demo
import source_policy_state as policy
from asset_review import _canonical


class PolicyStateTests(unittest.TestCase):
    def setUp(self):
        try:
            import nacl.signing
        except ImportError:
            self.skipTest('optional PyNaCl required')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key, _, self.context = demo.prepare(self.root)
        self.authority = (self.root / 'authority.json').read_bytes()
        self.issuer = (self.root / 'issuer.json').read_bytes()
        self.path = self.root / 'state.json'
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)

    def issue(self, sequence=1, previous=None, **extra):
        options = dict(expected_authority_sha256=policy.digest(self.authority), **self.context,
            signing_key=self.key, sequence=sequence, previous_update_sha256=previous,
            issued_at='2026-11-17T00:01:00Z', expires_at='2026-11-17T00:31:00Z')
        options.update(extra)
        return policy.issue_update(self.authority, self.issuer, **options)

    def select(self, update, state=None, **extra):
        options = dict(expected_authority_sha256=policy.digest(self.authority), **self.context,
            expected_update_sha256=policy.digest(update), expected_state_sha256=state)
        options.update(extra)
        return policy.select_policy(self.path, self.authority, self.issuer, update, **options)

    def verify(self, update, **extra):
        options = dict(expected_authority_sha256=policy.digest(self.authority), **self.context,
            expected_update_sha256=policy.digest(update)); options.update(extra)
        return policy.verify_update(self.authority, self.issuer, update, **options)

    def signed_mutation(self, update, **changes):
        value = json.loads(update); value.update(changes)
        value['signature_b64'] = base64.b64encode(self.key.sign(policy._message(value)).signature).decode('ascii')
        return _canonical(value)

    def test_native_cli_end_to_end_preserves_conflict_and_rejects_old_bundle(self):
        result = demo.exercise()
        self.assertEqual(result['selected_sequence'], 2)
        self.assertEqual(result['group_count'], 6)
        self.assertEqual(result['unresolved_component_count'], 1)
        self.assertTrue(result['old_bundle_rejected'])
        self.assertFalse(result['global_latest_verified'])

    def test_signed_context_purpose_types_bounds_and_windows(self):
        update = self.issue()
        for changes in (dict(audience='other-reviewer'), dict(purpose='lab-asset-source-claim-v1'),
                        dict(sequence=True), dict(sequence=0), dict(sequence=1_000_001),
                        dict(previous_update_sha256='0'*64), dict(issuer_sha256='0'*64),
                        dict(authority_sha256='0'*64), dict(key_id='other-issuer'),
                        dict(expires_at='2026-11-17T02:00:00Z')):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(self.signed_mutation(update, **changes))
        for at in ('2026-11-17T00:00:59Z', '2026-11-17T00:31:00Z'):
            with self.assertRaises(ValueError): self.verify(update, at=at)
        value = json.loads(update); value['signature_b64'] = base64.b64encode(b'\0'*64).decode()
        with self.assertRaises(ValueError): self.verify(_canonical(value))

    def test_pins_wrong_issuer_malformed_json_and_revoked_issuer(self):
        update = self.issue()
        for option in ('expected_update_sha256', 'expected_authority_sha256', 'expected_issuer_sha256'):
            with self.assertRaises(ValueError): self.verify(update, **{option: '0'*64})
        with self.assertRaises(ValueError): self.verify(b'{"a":1,"a":2}')
        SigningKey, _, _ = policy.auth._crypto()
        with self.assertRaises(ValueError): self.issue(signing_key=SigningKey.generate())
        for changes in (dict(status='revoked'), dict(maximum_validity_seconds=True), dict(extra='field')):
            value = json.loads(self.issuer); value.update(changes)
            self.issuer = _canonical(value); self.context['expected_issuer_sha256'] = policy.digest(self.issuer)
            with self.assertRaises(ValueError): self.issue()
            value.pop('extra', None); value['status'] = 'active'; value['maximum_validity_seconds'] = 3600
            self.issuer = _canonical(value); self.context['expected_issuer_sha256'] = policy.digest(self.issuer)

    def test_exact_successor_only_and_state_rollback_against_retained_pin(self):
        first = self.issue(); head = self.select(first); original = self.path.read_bytes()
        for update in (first, self.issue(3, policy.digest(first)), self.issue(2, '0'*64)):
            with self.assertRaises(ValueError): self.select(update, head['state_sha256'])
            self.assertEqual(self.path.read_bytes(), original)
        second = self.issue(2, policy.digest(first))
        advanced = self.select(second, head['state_sha256'])
        state = json.loads(self.path.read_bytes())
        self.assertEqual(state['previous_state_sha256'], head['state_sha256'])
        self.path.write_bytes(original)
        with self.assertRaises(ValueError):
            policy._snapshot(self.path, advanced['state_sha256'], self.issuer, self.context)

    def test_expired_head_rejects_review_but_allows_current_signed_successor(self):
        first = self.issue(); head = self.select(first)
        later = dict(self.context, at='2026-11-17T00:32:00Z')
        with self.assertRaises(ValueError): policy._snapshot(self.path, head['state_sha256'], self.issuer, later)
        second = self.issue(2, policy.digest(first), issued_at='2026-11-17T00:32:00Z',
            expires_at='2026-11-17T01:00:00Z', at=later['at'])
        self.assertEqual(self.select(second, head['state_sha256'], at=later['at'])['sequence'], 2)

    def test_repinned_state_cannot_forge_signed_sequence_or_embedded_update(self):
        first = self.issue(); self.select(first); original = self.path.read_bytes()
        for change in (dict(sequence=2, previous_state_sha256='0'*64),
                       dict(authority_sha256='0'*64), dict(audience='other-reviewer')):
            value = json.loads(original); value.update(change)
            data = _canonical(value); self.path.write_bytes(data)
            with self.assertRaises(ValueError):
                policy._snapshot(self.path, policy.digest(data), self.issuer, self.context)
        value = json.loads(original); update = json.loads(value['update_json'])
        update['sequence'] = 2; update['previous_update_sha256'] = '0'*64
        forged = _canonical(update)
        value.update(sequence=2, previous_state_sha256='0'*64,
                     update_json=forged.decode(), update_sha256=policy.digest(forged))
        data = _canonical(value); self.path.write_bytes(data)
        with self.assertRaises(ValueError):
            policy._snapshot(self.path, policy.digest(data), self.issuer, self.context)

    def test_repinning_issuer_cannot_replace_the_retained_root(self):
        first = self.issue(); head = self.select(first); original = self.path.read_bytes()
        value = json.loads(self.issuer); value['key_id'] = 'different-issuer'
        self.issuer = _canonical(value); self.context['expected_issuer_sha256'] = policy.digest(self.issuer)
        replacement = self.issue(2, policy.digest(first))
        with self.assertRaises(ValueError): self.select(replacement, head['state_sha256'])
        self.assertEqual(self.path.read_bytes(), original)

    def test_existing_initialization_invalid_successor_and_replace_failure_preserve_state(self):
        first = self.issue(); head = self.select(first); original = self.path.read_bytes()
        with self.assertRaises(FileExistsError): self.select(first)
        second = self.issue(2, policy.digest(first))
        with patch.object(policy.os, 'replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError): self.select(second, head['state_sha256'])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.root.glob('.policy-*')), [])
        with self.assertRaises(ValueError): self.select(second, '0'*64)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(Path(str(self.path)+'.lock').stat().st_mode), 0o600)

    def test_unsafe_state_and_lock_entries_reject_without_touching_target(self):
        first = self.issue(); head = self.select(first)
        second = self.issue(2, policy.digest(first)); original = self.path.read_bytes()
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): self.select(second, head['state_sha256'])
        self.path.chmod(0o600)
        real = self.root / 'real'; self.path.rename(real); self.path.symlink_to(real)
        with self.assertRaises(OSError): self.select(second, head['state_sha256'])
        self.assertEqual(real.read_bytes(), original)
        self.path.unlink(); real.rename(self.path)
        lock = Path(str(self.path)+'.lock'); lock.unlink(); lock.symlink_to(real)
        with self.assertRaises(OSError): self.select(second, head['state_sha256'])
        self.assertEqual(self.path.read_bytes(), original)

    def test_two_native_processes_with_same_pin_have_one_winner(self):
        first = self.issue(); head = self.select(first)
        second = self.issue(2, policy.digest(first)); (self.root / 'update.json').write_bytes(second)
        common = ['advance', '--state', str(self.path), '--expected-state-sha256', head['state_sha256'],
            '--issuer', str(self.root / 'issuer.json'), '--authority', str(self.root / 'authority.json'),
            '--expected-authority-sha256', policy.digest(self.authority), '--update', str(self.root / 'update.json'),
            '--expected-update-sha256', policy.digest(second)]
        for k, v in self.context.items(): common += ['--'+k.replace('_', '-'), v]
        processes = [subprocess.Popen([sys.executable, str(ROOT / 'source_policy_state.py'), *common],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        self.addCleanup(lambda: [p.kill() for p in processes if p.poll() is None])
        results = [p.communicate(timeout=20) for p in processes]
        self.assertEqual(sorted(p.returncode for p in processes), [0, 2])
        self.assertEqual(sum('advance_completed' in out for out, _ in results), 1)
        self.assertEqual(json.loads(self.path.read_bytes())['sequence'], 2)

    def test_issue_cli_wrong_pin_rejects_before_private_seed_access(self):
        args = ['issue', '--issuer', str(self.root / 'issuer.json'), '--authority', str(self.root / 'authority.json'),
            '--expected-authority-sha256', '0'*64, '--seed-file', str(self.root / 'issuer-seed'),
            '--sequence', '1', '--issued-at', '2026-11-17T00:01:00Z', '--expires-at', '2026-11-17T00:31:00Z',
            '--output', str(self.root / 'output')]
        for k, v in self.context.items(): args += ['--'+k.replace('_','-'), v]
        with patch.object(policy, '_seed', side_effect=AssertionError('private seed must remain unread')):
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(policy.main(args), 2)
        self.assertFalse((self.root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
