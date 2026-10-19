#!/usr/bin/env python3
"""Exercise the workflow's scan step with synthetic credentials in a real Git repo."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/gitleaks.yml'

def run(*args, cwd, env=None):
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)

class SecretScanTest(unittest.TestCase):
    def test_custom_credentials_block_and_reports_omit_values(self):
        workflow = WORKFLOW.read_text()
        step = workflow.split('      - name: Scan with central credential rules\n', 1)[1]
        block = step.split('        run: |\n', 1)[1].split('      - name: Save paths', 1)[0]
        script = '\n'.join(line[10:] if line.startswith('          ') else line for line in block.splitlines())
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, 'repo'); repo.mkdir()
            scratch = Path(tmp, 'runner'); scratch.mkdir()
            for args in [('init', '-q'), ('config', 'user.name', 'Security Test'), ('config', 'user.email', 'test@example.invalid')]:
                self.assertEqual(run('git', *args, cwd=repo).returncode, 0)
            (repo / 'README.md').write_text('Synthetic secret-scanner test.\n')
            self.commit(repo, 'Clean base')
            base = run('git', 'rev-parse', 'HEAD', cwd=repo).stdout.strip()
            api_key = 'sk_' + 'live_' + 'F' * 43
            (repo / 'fake.txt').write_text('Obviously fake scanner fixture: ' + api_key + '\n')
            self.commit(repo, 'Synthetic API credential')
            baseline = run('gitleaks', 'git', '.', '--log-opts=--all', '--redact=100', '--no-banner', cwd=repo)
            self.assertEqual(baseline.returncode, 0, 'Default rules unexpectedly caught the fixture; baseline must be re-evaluated')
            (repo / 'other-fakes.txt').write_text(
                'refresh_token="' + 'FAKE0000' * 8 + '"\n'
                'client_secret="' + ('FAKE0000' * 6)[:43] + '"\n'
                '{"private_key":"' + '-----BEGIN' + ' PRIVATE KEY-----\\nOBVIOUSLY_FAKE_NOT_A_KEY\\n-----END' + ' PRIVATE KEY-----\\n"}\n')
            self.commit(repo, 'Other synthetic credentials')
            env = os.environ | {'RUNNER_TEMP': str(scratch), 'GITHUB_STEP_SUMMARY': str(scratch/'summary'),
                                'GITHUB_OUTPUT': str(scratch/'output'), 'FULL_HISTORY': 'true', 'BASE_SHA': base, 'HEAD_SHA': ''}
            result = run('bash', '-c', script, cwd=repo, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('result=10', (scratch/'output').read_text())
            report = json.loads((scratch/'gitleaks-findings.json').read_text())
            rules = {x['rule_id'] for x in report}
            self.assertTrue({'60x-api-key', '60x-oauth-refresh-token', '60x-oauth-client-secret', 'gcp-service-account-private-key'} <= rules, sorted(rules))
            self.assertTrue(all(set(x) == {'path','rule_id'} for x in report))
            self.assertNotIn(api_key, json.dumps(report))
            self.assertFalse((scratch/'gitleaks-redacted.json').exists())
            (repo / 'fake.txt').unlink(); (repo / 'other-fakes.txt').unlink()
            self.commit(repo, 'Remove synthetic fixtures')
            clean_base = run('git', 'rev-parse', 'HEAD', cwd=repo).stdout.strip()
            (repo / 'README.md').write_text('A clean follow-up change.\n')
            self.commit(repo, 'Clean follow-up')
            head = run('git', 'rev-parse', 'HEAD', cwd=repo).stdout.strip()
            env.update(FULL_HISTORY='false', BASE_SHA=clean_base, HEAD_SHA=head)
            (scratch/'output').write_text('')
            clean = run('bash', '-c', script, cwd=repo, env=env)
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
            self.assertIn('result=0', (scratch/'output').read_text())
            self.assertEqual(json.loads((scratch/'gitleaks-findings.json').read_text()), [])
            print('Baseline: default rules miss the fake API key. Custom rules: all four block. Clean PR range: passes despite historical fixtures.')

    def commit(self, repo, message):
        self.assertEqual(run('git', 'add', '.', cwd=repo).returncode, 0)
        self.assertEqual(run('git', 'commit', '-qm', message, cwd=repo).returncode, 0)

if __name__ == '__main__':
    unittest.main()
