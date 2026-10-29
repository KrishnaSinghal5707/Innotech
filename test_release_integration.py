"""Regression checks for merging the fixed backend with the visual dashboard."""
import copy
import json
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import dashboard
from adapters import convert_tls_results_to_findings


class TestMergedDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), dashboard.DashboardRequestHandler)
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, payload=None, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={'Content-Type': 'application/json'})
        try:
            response = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers

    def setUp(self):
        with dashboard.SCAN_HISTORY_LOCK:
            dashboard.SCAN_HISTORY.clear()

    def test_malformed_json_types_are_client_errors(self):
        for raw in (b'[]', b'null', b'42', b'"host"', b'\xff', b'{'):
            with self.subTest(raw=raw):
                status, body, _ = self.request('/api/scan', raw=raw)
                self.assertEqual(status, 400)
                self.assertIn('error', json.loads(body))

    def test_invalid_host_shapes_and_ports(self):
        for host in ('https://example.com:nope', 'example.com:0', 'example.com:65536',
                     'example.com:abc', 'https://', ['example.com'], {'host': 'example.com'}):
            with self.subTest(host=host):
                status, _, _ = self.request('/api/scan', {'scan_type': 'tls', 'host': host})
                self.assertEqual(status, 400)

    def test_ipv6_and_explicit_port_parsing(self):
        for text, expected_host, expected_port in (
            ('[::1]:8443', '::1', 8443), ('::1', '::1', None),
            ('https://[2001:db8::1]:8443/test', '2001:db8::1', 8443),
            ('example.com port = 9443', 'example.com', 9443),
        ):
            host, err, port = dashboard.validate_host_input(text)
            self.assertIsNone(err)
            self.assertEqual((host, port), (expected_host, expected_port))

    def test_unknown_mode_and_non_boolean_options(self):
        for extra in ({'scan_type': 'unexpected'}, {'deep': 'false'}, {'port': True}):
            status, _, _ = self.request('/api/scan', {'repo': 'sample_vulnerable_app', **extra})
            self.assertEqual(status, 400)

    def test_code_mode_ignores_unused_host(self):
        status, body, _ = self.request('/api/scan', {
            'scan_type': 'code', 'repo': 'sample_vulnerable_app', 'host': 'https://', 'port': 'unused'
        })
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)['modules']['tls_scanner'])

    def test_tls_mode_ignores_unused_repo(self):
        fake = {'metadata': {'errors': []}, 'inventory': {'findings': [], 'total_items': 0},
                'risk_assessment': {'assessments': [], 'summary': {}}}
        with patch.object(dashboard, 'run_pipeline', return_value=fake) as run:
            status, _, _ = self.request('/api/scan', {
                'scan_type': 'tls', 'host': 'example.com', 'repo': 'missing-directory'
            })
        self.assertEqual(status, 200)
        self.assertIsNone(run.call_args.kwargs['repo_path'])

    def test_visual_assets_and_section_targets(self):
        status, page, _ = self.request('/')
        self.assertEqual(status, 200)
        for text in (b'function QuantumScene', b'function VisualIntelligence', b'function CyberExploration',
                     b'function EvidenceTools', b'data-presets="qshield-react"'):
            self.assertIn(text, page)
        status, css, headers = self.request('/command.css')
        self.assertEqual(status, 200)
        self.assertIn('text/css', headers['Content-Type'])
        self.assertIn(b'prefers-reduced-motion', css)
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')

    def test_exports_do_not_fall_back_from_missing_id(self):
        self.request('/api/demo')
        self.assertEqual(self.request('/api/export?format=json&id=missing')[0], 404)
        self.assertEqual(self.request('/api/export?format=invalid')[0], 400)

    def test_demo_is_explicitly_marked(self):
        status, body, _ = self.request('/api/demo')
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)['metadata']['is_demo'])

    def test_history_ids_are_unique_after_capacity(self):
        def record(_):
            return dashboard.record_scan_history({'metadata': {}, 'risk_assessment': {'summary': {}}})
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(record, range(100)))
        self.assertEqual(len(set(ids)), 100)
        self.assertEqual(len(dashboard.get_scan_history_list()), dashboard.MAX_HISTORY_ENTRIES)

    def test_no_host_based_hybrid_or_protocol_guesses(self):
        for host in ('google.com', 'tls-v1-0.badssl.com'):
            findings = convert_tls_results_to_findings({
                'scan_status': 'ok', 'target': {'host': host, 'port': 443},
                'connection': {'tls_version': 'TLSv1.3'},
                'key_exchange': {'method': 'ECDHE', 'group': None,
                                 'post_quantum_or_hybrid_group': False,
                                 'openssl_probe': {'available': False}},
            })
            self.assertFalse(any(f.attributes.get('is_pqc_hybrid') for f in findings))
            self.assertFalse(any(f.attributes.get('evidence_type') == 'tls_protocol' for f in findings))

    def test_comparison_keeps_findings_when_line_numbers_shift(self):
        baseline = {'metadata': {'targets': {'repo': '/workspace/app'}},
                    'risk_assessment': {'summary': {}, 'assessments': [{
                        'finding_id': 'code-finding-1', 'assessment_id': 'code-finding-1::MD5',
                        'asset': '/workspace/app/auth.py:10', 'algorithm': 'MD5', 'rule_id': 'MD5'}]}}
        current = copy.deepcopy(baseline)
        a = current['risk_assessment']['assessments'][0]
        a.update(finding_id='code-finding-4', assessment_id='code-finding-4::MD5',
                 asset='/workspace/app/auth.py:25')
        result = dashboard.compare_scans(baseline, current)
        self.assertEqual(len(result['persistent_findings']), 1)
        self.assertFalse(result['resolved_findings'])
        self.assertFalse(result['new_findings'])

    def test_failed_scan_comparison_is_inconclusive(self):
        baseline = {'metadata': {}, 'risk_assessment': {'summary': {'severity': {'critical': 2}}}}
        failed = {'metadata': {'errors': [{'module': 'tls_scanner', 'error': 'unreachable'}]},
                  'risk_assessment': {'summary': {}}}
        self.assertEqual(dashboard.compare_scans(baseline, failed)['status'], 'inconclusive')


if __name__ == '__main__':
    unittest.main()
