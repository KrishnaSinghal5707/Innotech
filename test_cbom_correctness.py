"""Regression coverage for report correctness defects found in final verification."""
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import dashboard
from cbom import export_cbom, validate_cbom_schema

ROOT = Path(__file__).resolve().parent


class TestCBOMCorrectness(unittest.TestCase):
    def finding(self, algorithm, bits=None):
        return export_cbom({
            'inventory': {'findings': [{'id': 'test', 'algorithm': algorithm,
                                       'key_bits': bits, 'attributes': {}}]},
        })['components'][0]['cryptoProperties']['algorithmProperties']

    def test_key_length_is_preserved_without_invented_security_strength(self):
        for algorithm, bits in [('RSA-1024', 1024), ('EC P-256', 256),
                                ('3DES', 168), ('AES', 256), ('UnknownCipher', 256)]:
            with self.subTest(algorithm=algorithm):
                props = self.finding(algorithm, bits)
                self.assertEqual(props['parameterSetIdentifier'], str(bits))
                self.assertNotIn('classicalSecurityLevel', props)

    def test_nist_parameter_categories(self):
        for algorithm, category in [('ML-DSA-44', 2), ('ML-DSA-65', 3),
                                    ('ML-DSA-87', 5), ('ML-KEM-512', 1),
                                    ('ML-KEM-768', 3), ('ML-KEM-1024', 5)]:
            with self.subTest(algorithm=algorithm):
                self.assertEqual(self.finding(algorithm)['nistQuantumSecurityLevel'], category)
        self.assertNotIn('nistQuantumSecurityLevel', self.finding('UnknownPQC'))

    def test_invalid_component_fails_formal_schema_validation(self):
        doc = export_cbom({})
        doc['components'] = [{'type': 'NOT-A-COMPONENT-TYPE', 'name': 'bad'}]
        valid, error = validate_cbom_schema(doc)
        self.assertFalse(valid)
        self.assertIn('Schema validation error', error)

    def test_missing_validator_is_not_success(self):
        with patch.dict(sys.modules, {'jsonschema': None}):
            valid, error = validate_cbom_schema(export_cbom({}))
        self.assertFalse(valid)
        self.assertIn('unavailable', error)

    def test_missing_or_bad_explicit_schema_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'schema.json'
            for content in (None, '{', '{"type": "invalid-type"}'):
                with self.subTest(content=content):
                    if content is not None:
                        path.write_text(content, encoding='utf-8')
                    valid, error = validate_cbom_schema(export_cbom({}), path)
                    self.assertFalse(valid)
                    self.assertTrue(error)

    def test_malformed_serial_type_is_validation_failure(self):
        doc = export_cbom({})
        doc['serialNumber'] = None
        self.assertFalse(validate_cbom_schema(doc)[0])

    def cli(self, *args):
        return subprocess.run([sys.executable, 'main.py', '--repo', 'sample_vulnerable_app',
                               *args], cwd=ROOT, capture_output=True, text=True, encoding='utf-8')

    def test_stdout_export_conflict_is_rejected_before_scan(self):
        result = self.cli('--cbom', '-', '--json', '-')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertIn('cannot both write to stdout', result.stderr)

    def test_cbom_stdout_with_json_file_remains_one_document(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'scan.json'
            result = self.cli('--cbom', '-', '--json', str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['bomFormat'], 'CycloneDX')
            self.assertIn('inventory', json.loads(path.read_text()))

    def test_json_stdout_with_cbom_file_remains_one_document(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bom.json'
            result = self.cli('--json', '-', '--cbom', str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('inventory', json.loads(result.stdout))
            self.assertTrue(validate_cbom_schema(json.loads(path.read_text()))[0])

    def test_history_cbom_export_uses_requested_scan_and_missing_id_does_not_fallback(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), dashboard.DashboardRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with dashboard.SCAN_HISTORY_LOCK:
            saved = list(dashboard.SCAN_HISTORY)
            dashboard.SCAN_HISTORY.clear()
        thread.start()
        try:
            older = {'metadata': {'targets': {'repo': 'older-target'}},
                     'inventory': {'findings': []}, 'risk_assessment': {'summary': {}}}
            newer = {'metadata': {'targets': {'repo': 'latest-target'}},
                     'inventory': {'findings': []}, 'risk_assessment': {'summary': {}}}
            scan_id = dashboard.record_scan_history(older)
            dashboard.record_scan_history(newer)
            base = f'http://127.0.0.1:{server.server_port}/api/export?format=cbom&id='
            with urllib.request.urlopen(base + scan_id) as response:
                self.assertEqual(json.load(response)['metadata']['component']['name'], 'older-target')
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(base + 'expired')
            self.assertEqual(error.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            with dashboard.SCAN_HISTORY_LOCK:
                dashboard.SCAN_HISTORY[:] = saved


if __name__ == '__main__':
    unittest.main()
