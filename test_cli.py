"""Subprocess regressions for the shared Q-SHIELD command-line interface."""
import copy
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import main as cli_main, run_pipeline
from scan_results import post_process_scan_result, render_markdown

ROOT = Path(__file__).resolve().parent


class TestCLI(unittest.TestCase):
    def run_cli(self, *args, entry='cli_demo.py', cwd=ROOT):
        return subprocess.run([sys.executable, str(ROOT / entry), *args], cwd=cwd,
                              capture_output=True, text=True, encoding='utf-8', timeout=20)

    def test_launcher_and_main_help(self):
        for entry in ('cli_demo.py', 'main.py'):
            res = self.run_cli('--help', entry=entry)
            self.assertEqual(res.returncode, 0, res.stderr)
            for option in ('--repo', '--host', '--json', '--output', '--no-color'):
                self.assertIn(option, res.stdout)

    def test_json_stdout_is_machine_readable(self):
        res = self.run_cli('--repo', 'sample_vulnerable_app', '--json')
        self.assertEqual(res.returncode, 0, res.stderr)
        report = json.loads(res.stdout)
        self.assertGreater(report['risk_assessment']['summary']['total_assessments'], 0)
        self.assertIn('readiness_score', report['risk_assessment']['summary'])
        self.assertNotIn('\x1b', res.stdout)

    def test_json_stdout_plus_markdown_output(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'audit report.md'
            res = self.run_cli('--repo', 'sample_vulnerable_app', '--json', '-', '-o', str(target))
            self.assertEqual(res.returncode, 0, res.stderr)
            json.loads(res.stdout)
            md = target.read_text(encoding='utf-8')
            self.assertTrue(md.startswith('# Q-SHIELD'))
            self.assertIn('## Assessment details', md)
            self.assertNotIn('\x1b', md)
            self.assertIn('Report written', res.stderr)

    def test_json_file_and_text_export(self):
        with tempfile.TemporaryDirectory() as folder:
            report, text = Path(folder) / 'scan.json', Path(folder) / 'scan.txt'
            res = self.run_cli('--repo', 'sample_vulnerable_app', '--json', str(report), '-o', str(text))
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, '')
            self.assertGreater(json.loads(report.read_text(encoding='utf-8'))['inventory']['total_items'], 0)
            self.assertIn('Q-SHIELD', text.read_text(encoding='utf-8'))
            self.assertNotIn('\x1b', text.read_text(encoding='utf-8'))

    def test_repository_with_spaces_and_other_working_directory(self):
        with tempfile.TemporaryDirectory(prefix='qshield cli ') as folder:
            source = Path(folder) / 'crypto source.py'
            source.write_text('import hashlib\ndigest = hashlib.md5(b"test").hexdigest()\n', encoding='utf-8')
            res = self.run_cli('--repo', str(source), '--json', cwd=folder)
            self.assertEqual(res.returncode, 0, res.stderr)
            report = json.loads(res.stdout)
            self.assertTrue(any(a['algorithm'] == 'MD5' for a in report['risk_assessment']['assessments']))

    def test_failures_return_one_with_json_diagnostics(self):
        res = self.run_cli('--repo', 'directory-that-does-not-exist', '--json')
        self.assertEqual(res.returncode, 1)
        self.assertNotIn('Traceback', res.stderr)
        report = json.loads(res.stdout)
        self.assertTrue(report['metadata']['errors'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_partial_tls_scan_reports_failure_without_losing_observations(self):
        observed = {'scan_status': 'partial', 'target': {'host': 'example.com', 'port': 443},
                    'connection': {'tls_version': 'TLSv1.3'},
                    'cipher_suite': {'name': 'TLS_AES_128_GCM_SHA256', 'encryption': 'aes-128-gcm', 'secret_bits': 128},
                    'errors': [{'stage': 'certificate', 'error': 'Unable to parse certificate'}]}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch('main.scan_tls', return_value=observed), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli_main(['--host', 'example.com', '--json'])
        self.assertEqual(code, 1)
        report = json.loads(stdout.getvalue())
        self.assertTrue(report['inventory']['findings'])
        self.assertIn('certificate', report['metadata']['errors'][0]['error'])

    def test_invalid_cli_values_return_two(self):
        cases = [('--port', '0'), ('--port', '70000'), ('--timeout', 'nan'),
                 ('--timeout', 'inf'), ('--timeout', '-1'), ('--scenario', 'unknown')]
        for option, value in cases:
            with self.subTest(option=option, value=value):
                res = self.run_cli('--repo', 'sample_vulnerable_app', option, value)
                self.assertEqual(res.returncode, 2)
                self.assertNotIn('Traceback', res.stderr)

    def test_missing_rules_do_not_silently_succeed(self):
        res = self.run_cli('--repo', 'sample_vulnerable_app', '--rules', 'missing-rules.json', '--json')
        self.assertEqual(res.returncode, 1)
        self.assertTrue(any(e['module'] == 'rules' for e in json.loads(res.stdout)['metadata']['errors']))

    def test_unwritable_output_is_handled(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'missing' / 'report.json'
            res = self.run_cli('--repo', 'sample_vulnerable_app', '--json', str(target))
            self.assertEqual(res.returncode, 1)
            self.assertIn('Unable to write report', res.stderr)
            self.assertNotIn('Traceback', res.stderr)

    def test_filters_do_not_discard_full_json_inventory(self):
        res = self.run_cli('--repo', 'sample_vulnerable_app', '--track', 'conventional', '--json')
        self.assertEqual(res.returncode, 0, res.stderr)
        tracks = {a['track'] for a in json.loads(res.stdout)['risk_assessment']['assessments']}
        self.assertEqual(tracks, {'quantum', 'conventional'})
        text = self.run_cli('--repo', 'sample_vulnerable_app', '--track', 'conventional', '--no-color')
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertNotIn('=== TRACK A:', text.stdout)
        self.assertIn('=== TRACK B:', text.stdout)
        self.assertNotIn('\x1b', text.stdout)

    def test_historical_report_is_valid_reference_data(self):
        report = json.loads((ROOT / 'docs/examples/cli_test_report.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(set(report), {'metadata', 'modules', 'inventory', 'risk_assessment'})
        self.assertEqual(len(report['risk_assessment']['assessments']), report['risk_assessment']['summary']['total_assessments'])
        self.assertTrue(render_markdown(report).startswith('# Q-SHIELD'))

    def test_cli_normalization_is_shared_and_idempotent(self):
        import dashboard
        self.assertIs(dashboard.post_process_scan_result, post_process_scan_result)
        report = run_pipeline(repo_path=str(ROOT / 'sample_vulnerable_app'))
        self.assertEqual(post_process_scan_result(copy.deepcopy(report)), report)

    def test_pipeline_normalizes_observed_pqc_and_deprecated_protocols(self):
        observed = {'scan_status': 'ok', 'target': {'host': 'example.com', 'port': 443},
                    'connection': {'tls_version': 'TLSv1.3'},
                    'key_exchange': {'method': 'ECDHE', 'group': 'X25519MLKEM768',
                                     'post_quantum_or_hybrid_group': True},
                    'supported_protocols': {'TLSv1.0': True}}
        with patch('main.scan_tls', return_value=observed):
            report = run_pipeline(host='example.com')
        by_rule = {a['rule_id']: a for a in report['risk_assessment']['assessments']}
        self.assertEqual(by_rule['PQC_HYBRID_KEM_DEPLOYED']['severity'], 'info')
        self.assertEqual(by_rule['DEPRECATED_TLS_PROTOCOL']['track'], 'conventional')
        self.assertEqual(sum(report['risk_assessment']['summary']['confidence'].values()), len(by_rule))

    def test_conflicting_exports_and_missing_targets_return_two(self):
        self.assertEqual(self.run_cli('--json').returncode, 2)
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'report.json')
            res = self.run_cli('--repo', 'sample_vulnerable_app', '--json', path, '--output', path)
            self.assertEqual(res.returncode, 2)


if __name__ == '__main__':
    unittest.main()
