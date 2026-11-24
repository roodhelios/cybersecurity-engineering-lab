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
import demo_source_claims as demo
import source_claims as claims


class SourceClaimCliTests(unittest.TestCase):
    def setUp(self):
        try:
            import nacl.signing
        except ImportError:
            self.skipTest('optional PyNaCl required')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.requirements, self.common = demo.prepare(self.root)
        self.sources = [str(self.root / name) for name in ('cloud.json', 'endpoint.json')]
        self.outputs = [str(self.root / ('claim-' + str(i) + '.json')) for i in range(2)]
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)

    def call(self, args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = claims.main(args)
        return code, out.getvalue(), err.getvalue()

    def claim_args(self, i=0):
        return ['claim', self.sources[i], '--source-id', self.requirements['sources'][i]['source_id'],
            '--seed-file', str(self.root / ('seed-' + str(i))),
            '--issued-at', '2026-11-17T00:01:00Z', '--expires-at', '2026-11-17T00:31:00Z',
            '--output', self.outputs[i], *self.common]

    def signed(self):
        for i in range(2):
            self.assertEqual(self.call(self.claim_args(i))[0], 0)

    def bundle_args(self):
        return ['bundle', *self.sources, '--claims', *self.outputs,
                '--output', str(self.root / 'bundle.json'), *self.common]

    def test_complete_native_cli_workflow_keeps_conflict_and_private_outputs(self):
        originals = [Path(p).read_bytes() for p in self.sources]
        result = demo.exercise()
        self.assertTrue(result['received_report_reproduced'])
        self.assertEqual(result['unresolved_component_count'], 1)
        self.assertFalse(result['source_truth_verified'])
        self.signed()
        code, out, err = self.call(self.bundle_args())
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out)['claim_count'], 2)
        for p in [*self.outputs, str(self.root / 'bundle.json')]:
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual([Path(p).read_bytes() for p in self.sources], originals)

    def test_wrong_pins_reject_before_seed_access(self):
        args = self.claim_args()
        args[args.index('--expected-authority-sha256') + 1] = '0' * 64
        with patch.object(claims, '_seed', side_effect=AssertionError('seed must remain unread')):
            self.assertEqual(self.call(args)[0], 2)
        self.assertFalse(Path(self.outputs[0]).exists())

    def test_seed_mode_symlink_hardlink_size_and_wrong_key_reject(self):
        seed = self.root / 'seed-0'; original = seed.read_bytes()
        for mode in (0o644, 0o640, 0o700):
            seed.chmod(mode)
            self.assertEqual(self.call(self.claim_args())[0], 2)
        seed.chmod(0o600)
        hardlink = self.root / 'hardlink'; os.link(seed, hardlink)
        self.assertEqual(self.call(self.claim_args())[0], 2); hardlink.unlink()
        for data in (b'', original + b'x', b'x' * 32):
            seed.write_bytes(data)
            self.assertEqual(self.call(self.claim_args())[0], 2)
        seed.write_bytes(original)
        seed.rename(self.root / 'real-seed'); seed.symlink_to(self.root / 'real-seed')
        self.assertEqual(self.call(self.claim_args())[0], 2)
        self.assertFalse(Path(self.outputs[0]).exists())

    def test_expired_claim_and_substituted_source_reject_without_output(self):
        args = self.claim_args(); args[args.index('--at') + 1] = '2026-11-17T00:31:00Z'
        self.assertEqual(self.call(args)[0], 2)
        source = Path(self.sources[0]); source.write_bytes(source.read_bytes() + b' ')
        self.assertEqual(self.call(self.claim_args())[0], 2)
        self.assertFalse(Path(self.outputs[0]).exists())

    def test_bundle_rejects_bad_signature_duplicate_missing_and_reordered_sources(self):
        self.signed()
        claim = Path(self.outputs[1]); original = claim.read_bytes()
        value = json.loads(original); value['signature_b64'] = 'A' * 86 + '=='
        claim.write_text(json.dumps(value))
        for args in (self.bundle_args(),
                ['bundle', *self.sources, '--claims', self.outputs[0], self.outputs[0],
                 '--output', str(self.root / 'bundle.json'), *self.common]):
            self.assertEqual(self.call(args)[0], 2)
        claim.write_bytes(original)
        args = self.bundle_args(); args[1:3] = list(reversed(self.sources))
        self.assertEqual(self.call(args)[0], 2)
        args = self.bundle_args(); args.remove(self.outputs[1])
        self.assertEqual(self.call(args)[0], 2)
        self.assertFalse((self.root / 'bundle.json').exists())

    def test_existing_outputs_and_failed_publish_preserve_inputs(self):
        output = Path(self.outputs[0]); output.write_bytes(b'existing')
        code, out, err = self.call(self.claim_args())
        self.assertEqual((code, out), (2, ''))
        self.assertEqual(output.read_bytes(), b'existing')
        self.assertNotIn(str(self.root), err)
        output.unlink()
        with patch.object(claims, '_publish', side_effect=OSError('private detail')):
            self.assertEqual(self.call(self.claim_args())[0], 2)
        self.assertEqual(len(list(self.root.glob('.asset-review-*'))), 0)

    def test_standalone_process_demo_prints_only_minimized_summary(self):
        process = subprocess.run([sys.executable, str(ROOT / 'demo_source_claims.py')],
            capture_output=True, text=True, timeout=30, check=True)
        result = json.loads(process.stdout)
        self.assertEqual(result['status'], 'source_claim_cli_exercise_passed')
        self.assertEqual(process.stderr, '')
        self.assertNotIn('signature_b64', process.stdout)
        self.assertNotIn('public_key_b64', process.stdout)
