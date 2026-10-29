"""Independent regression expectations for the 23 scanner audit findings."""
import copy
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import dashboard
import tls_scanner
from adapters import convert_tls_results_to_findings
from code_scanner import CodeScanner, scan_code
from main import run_pipeline
from risk_engine import DEFAULT_RULES_JSON, Finding, FindingError, RiskEngine, RuleSet, normalize_algorithm
from scan_results import post_process_scan_result

ROOT = Path(__file__).resolve().parent


class AuditScannerRegression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def scan(self, code, suffix='.py', **options):
        path = self.root / ('fixture'+suffix)
        path.write_text(code, encoding='utf-8')
        return run_pipeline(repo_path=str(path), **options)

    def assess_tls(self, **changes):
        telemetry = {'scan_status': 'ok', 'target': {'host': 'audit.test', 'port': 443}}
        telemetry.update(changes)
        with patch('main.scan_tls', return_value=telemetry):
            return run_pipeline(host='audit.test')

    def test_known_unsafe_primitives_never_score_100(self):
        for code in ('hashlib.md5(b"x")', 'hashlib.sha1(b"x")', 'hashlib.sha256(password)', 'modes.ECB()'):
            with self.subTest(code=code):
                report = self.scan(code)
                self.assertTrue(report['risk_assessment']['assessments'])
                self.assertNotEqual(report['risk_assessment']['summary']['readiness_score'], 100)

    def test_rsa_width_and_generic_purpose(self):
        for width in (1024, 4096):
            report = self.scan('from cryptography.hazmat.primitives.asymmetric import rsa\nk=rsa.generate_private_key(\n public_exponent=65537,\n key_size='+str(width)+')')
            item = next(f for f in report['inventory']['findings'] if f['algorithm'].startswith('RSA'))
            self.assertEqual(item['key_bits'], width)
            self.assertEqual(item['usage'], 'asymmetric_key')
            self.assertEqual(any(a['rule_id']=='WEAK_RSA_KEY_LENGTH' for a in report['risk_assessment']['assessments']), width==1024)

    def test_aes_width_resolution_and_unknowns(self):
        for count, expected in ((16,128),(32,256)):
            report=self.scan('key=b"x"*'+str(count)+'\nx=AESGCM(key)')
            self.assertEqual(report['inventory']['findings'][0]['key_bits'],expected)
            if expected==256:
                self.assertEqual(report['risk_assessment']['assessments'][0]['severity'],'info')
        report=self.scan('def encrypt(key):\n return AESGCM(key)')
        self.assertIsNone(report['inventory']['findings'][0]['key_bits'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_curves_and_ffdh_remain_distinct(self):
        ec=self.scan('ec.generate_private_key(ec.SECP384R1())')
        self.assertEqual(ec['inventory']['findings'][0]['algorithm'],'EC P-384')
        dh=self.scan('dh.generate_parameters(generator=2,key_size=2048)')
        self.assertEqual(dh['inventory']['findings'][0]['algorithm'],'Diffie-Hellman-2048')

    def test_import_bindings_and_multiline_calls(self):
        for code,suffix in [('import hashlib as h\nh.md5(b"x")','.py'),
                            ('from hashlib import md5\nmd5(b"x")','.py'),
                            ('const {createHash: h}=require("crypto");h(\n"md5"\n);','.js'),
                            ('import {createHash as h} from "node:crypto";h("md5");','.ts')]:
            with self.subTest(code=code):
                report=self.scan(code,suffix)
                self.assertIn('MD5_USAGE',[a['rule_id'] for a in report['risk_assessment']['assessments']])

    def test_strings_and_comment_delimiters(self):
        for code,suffix in [('example="hashlib.md5(password)"','.py'),
                            ('const example="crypto.createHash(\'md5\')";','.js')]:
            self.assertFalse(self.scan(code,suffix)['risk_assessment']['assessments'])
        for code,suffix in [('x="#"; hashlib.md5(b"x")','.py'),
                            ('const url="https://audit.test";crypto.createHash("md5");','.js'),
                            ('/* prefix */crypto.createHash("md5");/* suffix */','.js')]:
            self.assertTrue(self.scan(code,suffix,ignore_comments=True)['risk_assessment']['assessments'])

    def test_inactive_comments_remain_inactive_and_digest_is_correct(self):
        report=self.scan('# hashlib.md5(password)')
        self.assertFalse(report['risk_assessment']['assessments'])
        self.assertTrue(all(f['algorithm']=='MD5' for f in report['inventory']['findings']))

    def test_standard_cipher_and_dsa_apis(self):
        cases=[('crypto.createCipheriv("aes-128-ecb",key,null)','.js','ECB_MODE_USAGE'),
               ('dsa.generate_private_key(key_size=2048)','.py','DSA_SIGNATURE'),
               ('Cipher(algorithms.AES(b"x"*16),modes.CBC(iv))','.py','AES128_QUANTUM_REDUCTION')]
        for code,suffix,rule in cases:
            self.assertIn(rule,[a['rule_id'] for a in self.scan(code,suffix)['risk_assessment']['assessments']])

    def test_primitive_families_and_safe_info_severity(self):
        for algo in ('DSA-2048','Ed448','ML-KEM-768','ML-DSA-65','ChaCha20-Poly1305','PBKDF2-HMAC'):
            self.assertNotEqual(normalize_algorithm(algo).family,'unknown')
        engine=RiskEngine(RuleSet.load_from_file(ROOT/'rules.json'))
        finding=Finding(id='aes',algorithm='AES-256-GCM',key_bits=256,usage='symmetric_encryption')
        self.assertEqual(engine.assess([finding]).to_dict()['assessments'][0]['severity'],'info')

    def test_embedded_rules_and_file_rules_match(self):
        self.assertEqual(json.loads(DEFAULT_RULES_JSON),json.loads((ROOT/'rules.json').read_text()))

    def test_key_parameters_are_not_extracted_from_strings_or_shadowed_globals(self):
        report=self.scan('key=b"x"*32\ndef encrypt(key):\n return AESGCM(key)')
        self.assertIsNone(report['inventory']['findings'][0]['key_bits'])
        report=self.scan('rsa.generate_private_key(key_size=size,backend="key_size=4096")')
        self.assertIsNone(report['inventory']['findings'][0]['key_bits'])

    def test_redaction_across_raw_inventory_and_history(self):
        marker='SYNTHETIC_REGRESSION_SENTINEL'
        report=self.scan('KEY="-----BEGIN PRIVATE KEY-----'+marker+'-----END PRIVATE KEY-----"')
        self.assertNotIn(marker,json.dumps(report))
        self.assertIn('EXPOSED_PRIVATE_KEY',[a['rule_id'] for a in report['risk_assessment']['assessments']])
        self.assertNotEqual(report['risk_assessment']['summary']['readiness_score'],100)
        with dashboard.SCAN_HISTORY_LOCK:
            original=copy.deepcopy(dashboard.SCAN_HISTORY)
            try:
                key=dashboard.record_scan_history(report)
                self.assertNotIn(marker,json.dumps(dashboard.get_scan_by_id(key)))
            finally:
                dashboard.SCAN_HISTORY[:]=original

    def test_tls_certificate_failures_and_signature_hash(self):
        report=self.assess_tls(certificate_validation={'trusted':False,'error':'hostname mismatch'},
            certificate={'public_key':{'algorithm':'RSA','key_size_bits':2048},'expired':True,
                         'subject':{},'signature':{'algorithm':'sha1WithRSAEncryption'}})
        rules={a['rule_id'] for a in report['risk_assessment']['assessments']}
        self.assertTrue({'CERTIFICATE_UNTRUSTED','CERTIFICATE_EXPIRED','SHA1_USAGE'} <= rules)
        unknown=self.assess_tls(certificate={'public_key':{},'subject':{}})
        self.assertIsNone(unknown['risk_assessment']['summary']['readiness_score'])
        self.assertNotIn('RSA-2048',json.dumps(unknown))

    def test_all_accepted_ciphers_are_assessed(self):
        report=self.assess_tls(supported_tls12_ciphers=[{'name':'RC4-SHA','bits':128}])
        self.assertIn('RC4_CIPHER',[a['rule_id'] for a in report['risk_assessment']['assessments']])

    def test_cipher_authentication_name_is_not_a_public_key(self):
        report=self.assess_tls(supported_tls12_ciphers=[{'name':'ECDHE-RSA-ARIA128-GCM-SHA256','bits':128}])
        self.assertNotIn('WEAK_RSA_KEY_LENGTH',[a['rule_id'] for a in report['risk_assessment']['assessments']])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])

    def test_tls_unknown_and_static_rsa(self):
        unknown=self.assess_tls(key_exchange={'method':'ECDHE/DHE (ephemeral, group negotiated)','group':None})
        self.assertIsNone(unknown['risk_assessment']['summary']['readiness_score'])
        rsa=self.assess_tls(key_exchange={'method':'RSA (static key transport)','forward_secrecy':False})
        self.assertIn('RSA_KEY_ENCAPSULATION',[a['rule_id'] for a in rsa['risk_assessment']['assessments']])
        self.assertNotIn('Ephemeral Session',json.dumps(rsa))

    def test_exact_pqc_identities_and_experimental_groups(self):
        for group,identity in [('X25519MLKEM768','X25519 + ML-KEM-768'),('SecP256r1MLKEM768','P-256 + ML-KEM-768'),('MLKEM768','ML-KEM-768')]:
            report=self.assess_tls(key_exchange={'method':'ECDHE','group':group,'post_quantum_or_hybrid_group':True})
            a=report['risk_assessment']['assessments'][0]
            self.assertIn(identity,a['title'])
            self.assertNotIn('CNSA',json.dumps(a))
            if group=='MLKEM768': self.assertNotIn('X25519',json.dumps(a))
        for group in ('X25519Kyber768Draft00','X25519Frodo640'):
            report=self.assess_tls(key_exchange={'group':group,'post_quantum_or_hybrid_group':True})
            self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
            self.assertNotIn('PQC_HYBRID_KEM_DEPLOYED',json.dumps(report))

    def test_pqc_on_one_asset_does_not_mask_another(self):
        with patch('main.scan_tls',return_value={'scan_status':'ok','target':{'host':'audit.test'},
            'key_exchange':{'group':'X25519MLKEM768','post_quantum_or_hybrid_group':True}}):
            path=self.root/'classical.py';path.write_text('ec.ECDH()')
            report=run_pipeline(host='audit.test',repo_path=str(path))
        self.assertLess(report['risk_assessment']['summary']['readiness_score'],100)

    def test_detector_confidence_is_a_ceiling(self):
        engine=RiskEngine(RuleSet.load_from_file(ROOT/'rules.json'))
        finding=Finding(id='inferred',algorithm='ECDH',usage='key_exchange',evidence_source='network',attributes={'confidence':'MEDIUM'})
        self.assertNotEqual(engine.assess([finding]).to_dict()['assessments'][0]['confidence'],'high')

    def test_empty_parse_failed_and_skipped_coverage(self):
        clean=self.scan('print("hello")')
        self.assertEqual(clean['risk_assessment']['summary']['readiness_posture'],'unassessed')
        bad=self.scan('def invalid(')
        self.assertTrue(bad['metadata']['errors'])
        self.assertEqual(bad['modules']['code_scanner']['summary']['scanned_files'],0)
        path=self.root/'oversize.py';path.write_text('x'*(10*1024*1024+1))
        skipped=run_pipeline(repo_path=str(path))
        self.assertTrue(skipped['metadata']['errors'])
        self.assertEqual(skipped['modules']['code_scanner']['summary']['scanned_files'],0)

    def test_protocol_timeouts_are_unknown(self):
        with patch('tls_scanner._connect',side_effect=TimeoutError('inconclusive')):
            values=tls_scanner.probe_protocol_versions('audit.test',443,.01)
        self.assertTrue(all(v is None for v in values.values()))

    def test_invalid_finding_sizes(self):
        for bits in (-1,0,True,128.5,'128'):
            with self.assertRaises(FindingError):
                Finding.from_dict({'id':'x','algorithm':'AES','key_bits':bits})

    def test_scanner_instance_is_independent_per_target(self):
        a=self.root/'a.py';b=self.root/'b.py'
        a.write_text('hashlib.md5(b"x")');b.write_text('print("safe")')
        scanner=CodeScanner()
        self.assertTrue(scanner.scan_path(a))
        self.assertFalse(scanner.scan_path(b))
        self.assertEqual(scanner.scanned_files_count,1)

    def test_real_hybrid_agreement_and_tamper_rejection(self):
        from sample_remediated_app.crypto_service import hybrid_demo_exchange
        sender,receiver=hybrid_demo_exchange()
        self.assertEqual(sender,receiver)
        self.assertEqual(len(sender),48)
        with self.assertRaisesRegex(ValueError,'confirmation failed'):
            hybrid_demo_exchange(tamper=True)


class AuditAPIRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),dashboard.DashboardRequestHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def request(self,path,payload=None,headers=None,method=None):
        headers={'Content-Type':'application/json',**(headers or {})}
        req=urllib.request.Request(self.base+path,data=json.dumps(payload).encode() if payload is not None else None,headers=headers,method=method)
        try: response=urllib.request.urlopen(req,timeout=5)
        except urllib.error.HTTPError as e: response=e
        with response: return response.status,dict(response.headers),response.read()

    def test_cross_origin_and_rebinding_are_rejected(self):
        for path in ('/api/history','/api/scan'):
            status,headers,_=self.request(path,headers={'Origin':'https://untrusted.invalid'})
            self.assertEqual(status,403)
            self.assertNotIn('Access-Control-Allow-Origin',headers)
        self.assertEqual(self.request('/api/health',headers={'Host':'rebind.invalid:'+str(self.server.server_port)})[0],403)
        self.assertEqual(self.request('/api/health',headers={'Sec-Fetch-Site':'cross-site'})[0],403)
        self.assertEqual(self.request('/api/scan',headers={'Origin':'https://untrusted.invalid'},method='OPTIONS')[0],403)

    def test_same_origin_remains_usable(self):
        self.assertEqual(self.request('/api/health',headers={'Origin':self.base})[0],200)

    def test_workspace_root_is_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder,'secret.py').write_text('hashlib.md5(b"x")')
            self.assertEqual(self.request('/api/scan',{'scan_type':'code','repo':folder})[0],400)

    def test_nested_malformed_comparison_is_a_client_error(self):
        cases=[{'metadata':None},{'risk_assessment':None},{'risk_assessment':{'summary':[]}},{'inventory':{'findings':[None]}},
               {'inventory':{'findings':[{'id':[]}]}}, {'risk_assessment':{'assessments':[{'finding_id':[]}]}}]
        for report in cases:
            with self.subTest(report=report):
                self.assertEqual(self.request('/api/compare',{'baseline':report,'comparison':{'metadata':{}}})[0],400)

    def test_server_default_binds_loopback(self):
        with patch('dashboard.ThreadingHTTPServer') as server, patch('dashboard.find_free_port',return_value=9999):
            server.return_value.serve_forever.side_effect=KeyboardInterrupt
            dashboard.start_dashboard(open_browser=False)
        self.assertEqual(server.call_args.args[0],('127.0.0.1',9999))


if __name__=='__main__':
    unittest.main()
