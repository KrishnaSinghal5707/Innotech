"""Website access to static IaC scans, including history and exports."""
import json
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from unittest.mock import patch
import dashboard


class TestIaCDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),dashboard.DashboardRequestHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def request(self,path,payload=None):
        request=urllib.request.Request(self.base+path,data=json.dumps(payload).encode() if payload is not None else None,headers={'Content-Type':'application/json'})
        try: response=urllib.request.urlopen(request,timeout=10)
        except urllib.error.HTTPError as error: response=error
        with response: return response.status,response.read()

    def test_real_iac_sample_history_and_exports(self):
        with patch('main.scan_tls',side_effect=AssertionError('IaC must not scan the network')):
            status,body=self.request('/api/scan',{'scan_type':'iac','repo':'docs/examples/iac_sample','host':'https://','port':'unused','quantum_only':True,'deep':True})
        self.assertEqual(status,200)
        report=json.loads(body)
        self.assertEqual(report['metadata']['flow_type'],'iac')
        self.assertIsNone(report['modules']['tls_scanner'])
        self.assertTrue(report['risk_assessment']['assessments'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
        self.assertEqual(report['modules']['iac_scanner']['coverage_status'],'partial')
        self.assertIn('unknown',[o['status'] for o in report['modules']['iac_scanner']['observations']])
        scan_id=report['metadata']['scan_id']
        status,body=self.request('/api/history/'+scan_id)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['metadata']['flow_type'],'iac')
        status,body=self.request('/api/export?format=markdown&id='+scan_id)
        self.assertEqual(status,200)
        self.assertIn(b'Static IaC coverage',body)
        self.assertIn(b'&lt;unresolved&gt;',body)

    def test_iac_requires_valid_workspace_repository(self):
        for repo in (None,'missing-config-directory','C:/Windows'):
            self.assertEqual(self.request('/api/scan',{'scan_type':'iac','repo':repo,'host':'example.com'})[0],400)

    def test_iac_options_are_forced_to_supported_scope(self):
        fake={'metadata':{'errors':[]},'inventory':{'findings':[]},'risk_assessment':{'assessments':[],'summary':{}}}
        with patch('dashboard.run_pipeline',return_value=fake) as run:
            status,_=self.request('/api/scan',{'scan_type':'iac','repo':'docs/examples/iac_sample','deep':True,'ignore_comments':True,'quantum_only':True})
        self.assertEqual(status,200)
        self.assertTrue(run.call_args.kwargs['iac'])
        self.assertIsNone(run.call_args.kwargs['host'])
        self.assertFalse(run.call_args.kwargs['deep_tls'])
        self.assertFalse(run.call_args.kwargs['ignore_comments'])
        self.assertFalse(run.call_args.kwargs['quantum_only'])

    def test_web_controls_and_evidence_panel_are_served(self):
        status,body=self.request('/')
        self.assertEqual(status,200)
        for label in (b'function IaCEvidence',b'Scan IaC & Docker',b'Try IaC example',b'IaC &amp; Docker Evidence',b'Unknown settings'):
            self.assertIn(label,body)


if __name__=='__main__':
    unittest.main()
