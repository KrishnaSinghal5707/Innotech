"""Q-Patch integration and adversarial tests; never contact a live provider."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import ThreadingHTTPServer
import urllib.error
import urllib.request

from ai_provider import AIError, OpenAIProvider, configured_provider
from q_patch import PatchError, propose_patch, _safe_path
from main import run_pipeline
import dashboard


def answer(path='digest.py', before='hashlib.md5(data).hexdigest()', after='hashlib.sha256(data).hexdigest()'):
    return {'status': 'proposal', 'explanation': 'MD5 has broken collision resistance.',
            'remediation': 'Use SHA-256 for this declared integrity use. Review digest consumers.',
            'architectural_changes': [], 'validation_steps': ['Verify digest consumer compatibility.'],
            'edits': [{'path': path, 'before': before, 'after': after}]}


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'digest.py'
        self.source.write_text('import hashlib\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n', encoding='utf-8')
        self.scan = run_pipeline(repo_path=str(self.root))
        self.finding = next(f for f in self.scan['inventory']['findings'] if f['algorithm'] == 'MD5')
        self.provider = Mock()
        self.provider.generate_json.return_value = answer()

    def propose(self, purpose='integrity'):
        return propose_patch(self.scan, self.finding['id'], purpose, self.root, self.provider)

    def test_real_scanner_to_reviewable_diff_without_writes(self):
        original = self.source.read_bytes()
        result = self.propose()
        self.assertTrue(result['proposal_only'])
        self.assertIn('-    return hashlib.md5', result['diff'])
        self.assertIn('+    return hashlib.sha256', result['diff'])
        self.assertEqual(result['source_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(self.source.read_bytes(), original)
        context = self.provider.generate_json.call_args.args[1]
        self.assertEqual(context['finding']['algorithm'], 'MD5')
        self.assertNotIn(str(self.root), json.dumps(context))

    def test_no_trailing_newline_diff_is_well_formed(self):
        self.source.write_text('import hashlib\nhashlib.md5(data).hexdigest()', encoding='utf-8')
        self.scan = run_pipeline(repo_path=str(self.root))
        self.finding = next(f for f in self.scan['inventory']['findings'] if f['algorithm'] == 'MD5')
        result = self.propose()
        self.assertIn('\\ No newline at end of file\n', result['diff'])

    def test_reject_model_paths_and_unmatched_edits(self):
        for replacement in [answer('../outside.py'), answer('/tmp/out.py'),
                            answer('C:/Windows/x.py'), answer('other.py'),
                            answer(before='not actual evidence'), answer(after='hashlib.md5(data).hexdigest()')]:
            with self.subTest(replacement=replacement):
                self.provider.generate_json.return_value = replacement
                with self.assertRaises(AIError): self.propose()

    def test_missing_or_demo_finding_is_rejected(self):
        with self.assertRaises(PatchError):
            propose_patch(self.scan, 'invented', 'integrity', self.root, self.provider)
        self.scan['metadata']['is_demo'] = True
        with self.assertRaises(PatchError): self.propose()
        self.provider.generate_json.assert_not_called()

    def test_unknown_password_and_quantum_never_accept_simple_edits(self):
        for purpose in ('unknown', 'password', 'signature', 'encryption', 'key_exchange'):
            with self.subTest(purpose=purpose):
                with self.assertRaises(AIError): self.propose(purpose)
        self.scan['risk_assessment']['assessments'][0]['track'] = 'quantum'
        with self.assertRaises(AIError): self.propose()

    def test_password_evidence_overrides_incorrect_declared_purpose(self):
        self.finding['attributes']['likely_purpose'] = 'Password hashing'
        with self.assertRaises(AIError): self.propose('integrity')

    def test_architecture_guidance_is_honest(self):
        self.provider.generate_json.return_value = {**answer(), 'status': 'architecture_required', 'edits': [],
            'architectural_changes': ['Version stored hashes and migrate during successful login.']}
        result = self.propose('password')
        self.assertEqual(result['status'], 'architecture_required')
        self.assertEqual(result['diff'], '')

    def test_stale_evidence_never_sent_to_ai(self):
        self.source.write_text('import hashlib\nhashlib.sha256(data)\n')
        result = self.propose()
        self.assertEqual(result['status'], 'insufficient_evidence')
        self.provider.generate_json.assert_not_called()

    def test_source_changing_during_generation_is_rejected(self):
        def change(*args):
            self.source.write_text('changed')
            return answer()
        self.provider.generate_json.side_effect = change
        with self.assertRaises(PatchError): self.propose()

    def test_secrets_withheld_instead_of_exported(self):
        for secret in ('API_KEY = "super-sensitive-value"\n', '-----BEGIN PRIVATE KEY-----\nAAA\n'):
            with self.subTest(secret=secret):
                self.source.write_text('import hashlib\nhashlib.md5(data)\n'+secret)
                result = self.propose()
                self.assertEqual(result['status'], 'insufficient_evidence')
                self.assertNotIn('super-sensitive-value', json.dumps(result))
        self.provider.generate_json.assert_not_called()

    def test_secret_findings_require_rotation_without_provider(self):
        self.finding['attributes']['match_type'] = 'EXPOSED_SECRET'
        result = self.propose()
        self.assertEqual(result['status'], 'architecture_required')
        self.assertIn('rotate', result['remediation'])
        self.provider.generate_json.assert_not_called()

    def test_invalid_or_sensitive_model_output_is_rejected(self):
        for value in ({'explanation':'broken'}, {**answer(), 'edits':[], 'remediation':'api_key = "leaked-value"'}):
            self.provider.generate_json.return_value = value
            with self.assertRaises(AIError): self.propose()

    def test_no_source_receives_guidance_only(self):
        self.finding['evidence_source'] = 'tls_handshake'
        self.provider.generate_json.return_value = {**answer(), 'status':'insufficient_evidence', 'edits':[]}
        result = self.propose()
        self.assertEqual(result['diff'], '')
        context = self.provider.generate_json.call_args.args[1]
        self.assertFalse(context['patch_allowed'])
        self.assertEqual(context['source_context'], '')

    def test_large_binary_outside_and_symlink_sources_are_rejected(self):
        for data in (b'x'*64001, b'\0binary'):
            self.source.write_bytes(data)
            with self.assertRaises(PatchError): self.propose()
        for raw in ('../file.py', 'C:relative.py', '.env', 'digest.py\nmore'):
            with self.subTest(raw=raw), self.assertRaises(PatchError): _safe_path(self.root, raw)
        with patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaises(PatchError): _safe_path(self.root, 'digest.py')
        outside = self.root.parent/'outside.py'
        with self.assertRaises(PatchError): _safe_path(self.root, str(outside))


class ProviderTests(unittest.TestCase):
    def test_missing_and_unsupported_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(AIError): configured_provider()
        with patch.dict(os.environ, {'QSHIELD_AI_PROVIDER':'invalid'}):
            with self.assertRaises(AIError): configured_provider()

    def call(self, response):
        fake = Mock()
        fake.__enter__ = Mock(return_value=fake)
        fake.__exit__ = Mock(return_value=False)
        fake.read.return_value = json.dumps(response).encode()
        opener = Mock(); opener.open.return_value = fake
        return opener

    @patch.dict(os.environ, {'OPENAI_API_KEY':'test-only-key', 'QSHIELD_AI_MODEL':'test-model'})
    def test_real_api_request_shape_and_secret_not_in_body(self):
        opener = self.call({'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'{"answer":"ok"}'}]}]})
        with patch('urllib.request.build_opener',return_value=opener):
            result = OpenAIProvider().generate_json('instructions',{'evidence':'actual'}, {'type':'object'})
        self.assertEqual(result, {'answer':'ok'})
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, 'https://api.openai.com/v1/responses')
        body = json.loads(req.data)
        self.assertFalse(body['store'])
        self.assertNotIn('test-only-key', req.data.decode())
        self.assertNotIn('tools',body)
        self.assertEqual(body['text']['format']['type'],'json_schema')

    @patch.dict(os.environ, {'OPENAI_API_KEY':'test-only-key', 'QSHIELD_AI_MODEL':'test-model'})
    def test_provider_errors_are_sanitized(self):
        opener = Mock(); opener.open.side_effect = urllib.error.URLError('test-only-key secret provider body')
        with patch('urllib.request.build_opener',return_value=opener), self.assertRaises(AIError) as error:
            OpenAIProvider().generate_json('instructions',{}, {})
        self.assertNotIn('test-only-key', str(error.exception))

    @patch.dict(os.environ, {'OPENAI_API_KEY':'test-only-key', 'QSHIELD_AI_MODEL':'test-model'})
    def test_refusal_incomplete_invalid_and_oversized_responses(self):
        for response in ({'status':'incomplete'}, {'status':'completed','output':[{'type':'message','content':[{'type':'refusal'}]}]},
                         {'status':'completed','output':[]}, ['bad']):
            with patch('urllib.request.build_opener',return_value=self.call(response)), self.assertRaises(AIError):
                OpenAIProvider().generate_json('instructions',{}, {})
        opener = self.call({}); opener.open.return_value.read.return_value = b'x'*128001
        with patch('urllib.request.build_opener',return_value=opener), self.assertRaises(AIError):
            OpenAIProvider().generate_json('instructions',{}, {})


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1',0),dashboard.DashboardRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'
        self.scan = run_pipeline(repo_path='tests/fixtures/q_patch')
        self.id = dashboard.record_scan_history(self.scan)
        self.finding = next(f for f in self.scan['inventory']['findings'] if f['algorithm']=='MD5')
        self.payload={'scan_id':self.id,'finding_id':self.finding['id'],'purpose':'integrity','consent':True}

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
        with dashboard.SCAN_HISTORY_LOCK:
            dashboard.SCAN_HISTORY[:] = [r for r in dashboard.SCAN_HISTORY if r['id'] != self.id]

    def request(self, payload, origin=None):
        req = urllib.request.Request(self.base+'/api/q-patch',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json',**({'Origin':origin} if origin else {})})
        try: response=urllib.request.urlopen(req)
        except urllib.error.HTTPError as e: response=e
        with response: return response.status,json.load(response)

    def test_saved_evidence_only_and_consent(self):
        for changes in ({'scan_id':'missing'}, {'finding_id':'invented'}, {'consent':False}, {'path':'outside.py'}):
            with self.subTest(changes=changes):
                status,_=self.request({**self.payload,**changes})
                self.assertIn(status,(400,404))
        self.assertEqual(self.request(self.payload, 'https://evil.example')[0],403)

    def test_configuration_errors_are_public_safe_and_slots_released(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY':'', 'QSHIELD_AI_MODEL':''}):
            status,body=self.request(self.payload)
        self.assertEqual(status,503)
        self.assertIn('Configure',body['error'])
        with patch('dashboard.propose_patch', return_value={'proposal_only':True,'diff':''}):
            self.assertEqual(self.request(self.payload)[0],200)

    def test_real_pipeline_with_mocked_ai_and_no_source_changes(self):
        provider=Mock()
        snippet=self.finding['attributes']['code_snippet']
        relative='digest.py'
        provider.generate_json.return_value=answer(relative,snippet,snippet.replace('md5','sha256'))
        path=Path(self.finding['location'].rpartition(':')[0]);original=path.read_bytes()
        with patch('q_patch.configured_provider',return_value=provider):
            status,body=self.request(self.payload)
        self.assertEqual(status,200,body)
        self.assertIn('--- a/digest.py',body['diff'])
        self.assertEqual(path.read_bytes(),original)


if __name__=='__main__': unittest.main()
