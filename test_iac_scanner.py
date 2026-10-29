"""Fixture and adversarial tests for the explicitly supported static IaC subset."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from iac_scanner import MAX_BYTES, IaCScanner, _link, scan_iac, convert_iac_results_to_findings
from iac_policies import RULES, ELB_LEGACY, ELB_MODERN, CF_LEGACY, CF_MODERN
from main import run_pipeline, main
from scan_results import render_markdown

FIXTURES = Path(__file__).parent / 'tests' / 'fixtures' / 'iac'


class TestIaCFixtures(unittest.TestCase):
    def test_positive_docker(self):
        data=scan_iac(FIXTURES/'Dockerfile.positive')
        self.assertEqual(len(data['findings']),2)
        self.assertEqual({f['attributes']['iac_rule_id'] for f in data['findings']},{'IAC_DOCKER_TLS_VERIFY_DISABLED'})
        self.assertEqual(data['coverage_status'],'complete')
        self.assertNotIn('SYNTHETIC_NEVER_EMIT',json.dumps(data))

    def test_negative_docker_and_image_not_a_pqc_judgment(self):
        data=scan_iac(FIXTURES/'Dockerfile.negative')
        self.assertFalse(data['findings'])
        images=[o for o in data['observations'] if o['field']=='FROM']
        self.assertEqual([x['observed_value'] for x in images],['docker.io/library/node:22','build'])
        self.assertTrue(all('unverified' in x['note'] for x in images))

    def test_dynamic_docker(self):
        data=scan_iac(FIXTURES/'Dockerfile.unknown')
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'partial')
        self.assertNotIn('${',json.dumps(data))

    def test_positive_ingress_all_supported_annotations(self):
        data=scan_iac(FIXTURES/'ingress-positive.yaml')
        self.assertEqual({f['attributes']['iac_rule_id'] for f in data['findings']},
                         {'IAC_INGRESS_LEGACY_TLS','IAC_INGRESS_WEAK_CIPHER','IAC_INGRESS_VERIFY_DISABLED'})
        self.assertEqual(len(data['findings']),6)
        self.assertEqual(data['coverage_status'],'complete')

    def test_negative_ingress(self):
        data=scan_iac(FIXTURES/'ingress-negative.yaml')
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'complete')

    def test_unknown_ingress_secrets_and_cipher_exclusions(self):
        data=scan_iac(FIXTURES/'ingress-unknown.yaml')
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'partial')
        for marker in ('SYNTHETIC_SECRET_MUST_NOT_LEAK','{{','${'):
            self.assertNotIn(marker,json.dumps(data))

    def test_positive_terraform(self):
        data=scan_iac(FIXTURES/'policies-positive.tf')
        self.assertEqual(len(data['findings']),3,data)
        self.assertEqual({f['attributes']['rule_id'] for f in data['findings']},{'IAC_AWS_LEGACY_TLS_POLICY'})
        self.assertEqual(data['coverage_status'],'complete')

    def test_negative_terraform(self):
        data=scan_iac(FIXTURES/'policies-negative.tf')
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'complete')
        self.assertNotIn('post_quantum_or_hybrid_group',json.dumps(data))

    def test_dynamic_missing_and_unknown_terraform(self):
        data=scan_iac(FIXTURES/'policies-unknown.tf')
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'partial')
        self.assertEqual(len(data['observations']),3)
        for marker in ('SYNTHETIC_TERRAFORM_SECRET','SYNTHETIC_UNKNOWN_POLICY','var.policy'):
            self.assertNotIn(marker,json.dumps(data))

    def test_normalized_model_has_evidence_and_engine_rule(self):
        data=scan_iac(FIXTURES/'Dockerfile.positive')
        finding=convert_iac_results_to_findings(data)[0]
        self.assertEqual(finding.evidence_source,'static')
        for field in ('file_path','line_number','rule_id','observed_value','rationale','confidence','remediation'):
            self.assertTrue(finding.attributes[field])
        report=run_pipeline(repo_path=str(FIXTURES/'Dockerfile.positive'),iac=True)
        self.assertEqual(len(report['risk_assessment']['assessments']),2)
        self.assertTrue(all(a['track']=='conventional' for a in report['risk_assessment']['assessments']))
        self.assertTrue(all('runtime' in a['rationale'] for a in report['risk_assessment']['assessments']))
        self.assertIsNone(report['modules']['tls_scanner'])
        self.assertIsNone(report['modules']['code_scanner'])

    def test_opt_in_default_is_unchanged(self):
        report=run_pipeline(repo_path=str(Path(__file__).parent/'sample_vulnerable_app'))
        self.assertNotIn('iac_scanner',report['modules'])


class TestIaCAdversarial(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def scan(self,name,content):
        path=self.root/name
        path.write_text(content,encoding='utf-8')
        return scan_iac(path)

    def test_every_catalog_policy_has_positive_or_negative_expectation(self):
        for policy in ELB_LEGACY | ELB_MODERN:
            data=self.scan('main.tf',f'resource "aws_lb_listener" "x" {{ protocol="TLS"\n ssl_policy="{policy}" }}')
            self.assertEqual(bool(data['findings']),policy in ELB_LEGACY,policy)
            self.assertEqual(data['coverage_status'],'complete',policy)
        for policy in CF_LEGACY | CF_MODERN:
            method='vip' if policy=='SSLv3' else 'sni-only'
            data=self.scan('main.tf',f'resource "aws_cloudfront_distribution" "x" {{ viewer_certificate {{ cloudfront_default_certificate=false\n ssl_support_method="{method}"\n minimum_protocol_version="{policy}" }} }}')
            self.assertEqual(bool(data['findings']),policy in CF_LEGACY,policy)
            self.assertEqual(data['coverage_status'],'complete',policy)

    def test_malformed_yaml_hcl_and_docker_errors_do_not_echo_source(self):
        for name,content in [('bad.yaml','kind: Ingress\ndata: [SYNTHETIC_PRIVATE_MARKER'),
                             ('bad.tf','resource "aws_lb_listener" "x" { token="SYNTHETIC_PRIVATE_MARKER"'),
                             ('Dockerfile','FROM node:22\nENV NODE_TLS_REJECT_UNAUTHORIZED="SYNTHETIC_PRIVATE_MARKER')]:
            data=self.scan(name,content)
            self.assertEqual(data['coverage_status'],'partial')
            self.assertNotIn('SYNTHETIC_PRIVATE_MARKER',json.dumps(data))

    def test_yaml_duplicate_keys_aliases_custom_tags_and_nesting(self):
        for content in ['kind: Ingress\nkind: Secret', 'a: &a [*a]', '['*60+'0'+']'*60]:
            self.assertEqual(self.scan('bad.yaml',content)['coverage_status'],'partial')
        data=self.scan('custom.yaml','apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n annotations:\n  nginx.ingress.kubernetes.io/proxy-ssl-protocols: !Ref "TLSv1"')
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'partial')

    def test_no_state_or_tfvars_reads(self):
        for name in ('terraform.tfstate','terraform.tfstate.backup','secrets.tfvars'):
            path=self.root/name;path.write_text('SYNTHETIC_STATE_SECRET')
            with patch('iac_scanner.os.open',side_effect=AssertionError('must not read')):
                data=scan_iac(path)
            self.assertNotIn('SYNTHETIC_STATE_SECRET',json.dumps(data))
            self.assertEqual(data['summary']['excluded_files'],1)
        with patch('main.scan_code',side_effect=AssertionError('state must not enter source scanner')):
            report=run_pipeline(repo_path=str(path),iac=True)
        self.assertIsNone(report['modules']['code_scanner'])

    def test_oversize_and_unreadable_inputs(self):
        data=self.scan('big.tf',' '*(MAX_BYTES+1))
        self.assertEqual(data['diagnostics'][0]['code'],'large_input')
        path=self.root/'unreadable.tf';path.write_text('')
        with patch('iac_scanner.os.open',side_effect=PermissionError('SYNTHETIC_ERROR_SECRET')):
            data=scan_iac(path)
        self.assertEqual(data['coverage_status'],'partial')
        self.assertNotIn('SYNTHETIC_ERROR_SECRET',json.dumps(data))

    def test_traversal_and_symlinks_never_followed(self):
        path=self.root/'Dockerfile';path.write_text('FROM node:22')
        data=scan_iac(self.root/'..'/self.root.name/'Dockerfile')
        self.assertEqual(data['diagnostics'][0]['code'],'invalid_target')
        with patch('iac_scanner._link',return_value=True), patch('iac_scanner.os.open',side_effect=AssertionError('must not follow')):
            data=scan_iac(path)
        self.assertEqual(data['diagnostics'][0]['code'],'symlink')
        with patch('iac_scanner._link',side_effect=lambda candidate: candidate==self.root), patch('iac_scanner.os.open',side_effect=AssertionError('must not follow ancestor')):
            data=scan_iac(path)
        self.assertEqual(data['diagnostics'][0]['code'],'symlink')
        with patch.object(Path,'is_symlink',return_value=False), patch.object(Path,'is_junction',return_value=True,create=True):
            self.assertTrue(_link(path))

    def test_actual_symlink_is_excluded(self):
        outside=self.root/'outside';outside.mkdir()
        (outside/'Dockerfile').write_text('FROM node:22\nENV GIT_SSL_NO_VERIFY=true')
        scope=self.root/'scope';scope.mkdir()
        try:
            os.symlink(outside,scope/'linked',target_is_directory=True)
        except OSError:
            self.skipTest('Host does not permit creating symlinks; mocked no-follow regression still runs')
        data=scan_iac(scope)
        self.assertFalse(data['findings'])
        self.assertEqual(data['coverage_status'],'partial')

    def test_missing_fields_and_ignored_default_certificate(self):
        data=self.scan('ingress.yaml','apiVersion: networking.k8s.io/v1\nkind: Ingress')
        self.assertFalse(data['findings']);self.assertEqual(data['coverage_status'],'partial')
        data=self.scan('main.tf','resource "aws_cloudfront_distribution" "x" { viewer_certificate { cloudfront_default_certificate=true\n minimum_protocol_version="SSLv3" } }')
        self.assertFalse(data['findings'])
        self.assertEqual(data['observations'][0]['status'],'not_applicable')

    def test_http_listener_and_inapplicable_proxy_verification(self):
        data=self.scan('main.tf','resource "aws_lb_listener" "x" { protocol="HTTP"\n ssl_policy="ELBSecurityPolicy-2016-08" }')
        self.assertFalse(data['findings'])
        data=self.scan('ingress.yaml','apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n annotations:\n  nginx.ingress.kubernetes.io/backend-protocol: "HTTP"\n  nginx.ingress.kubernetes.io/proxy-ssl-verify: "off"')
        self.assertFalse(data['findings'])

    def test_cloudfront_uncertain_or_invalid_certificate_context_is_unknown(self):
        for selection in ('','cloudfront_default_certificate=var.default_certificate\n','cloudfront_default_certificate=false\n'):
            policy='SSLv3' if selection.endswith('false\n') else 'TLSv1'
            data=self.scan('main.tf',f'resource "aws_cloudfront_distribution" "x" {{ viewer_certificate {{ {selection} ssl_support_method="sni-only"\n minimum_protocol_version="{policy}" }} }}')
            self.assertFalse(data['findings'])
            self.assertEqual(data['coverage_status'],'partial')

    def test_hcl_expression_not_mistaken_for_quoted_policy(self):
        data=self.scan('main.tf','resource "aws_lb_listener" "x" { protocol="HTTPS"\n ssl_policy=var.flag ? "ELBSecurityPolicy-2016-08" : "ELBSecurityPolicy-TLS-1-2-2017-01" }')
        self.assertFalse(data['findings']);self.assertEqual(data['coverage_status'],'partial')
        nested=self.scan('main.tf','unsupported_block { resource "aws_lb_listener" "fake" { protocol="HTTPS"\n ssl_policy="ELBSecurityPolicy-2016-08" } }')
        self.assertFalse(nested['findings'])

    def test_known_weak_tokens_are_preserved_alongside_unknowns(self):
        data=self.scan('ingress.yaml','apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n annotations:\n  nginx.ingress.kubernetes.io/proxy-ssl-protocols: "TLSv1 TLSv1.4"\n  nginx.ingress.kubernetes.io/ssl-ciphers: "RC4-SHA:SYNTHETIC_PRIVATE_TOKEN"')
        self.assertEqual(len(data['findings']),2)
        self.assertEqual(data['coverage_status'],'partial')
        self.assertNotIn('SYNTHETIC_PRIVATE_TOKEN',json.dumps(data))

    def test_directory_enumeration_failures_are_diagnostics(self):
        def fail_walk(target,**options):
            options['onerror'](PermissionError('SYNTHETIC_PRIVATE_ERROR'))
            return iter(())
        with patch('iac_scanner.os.walk',side_effect=fail_walk):
            data=scan_iac(self.root)
        self.assertEqual(data['coverage_status'],'partial')
        self.assertNotIn('SYNTHETIC_PRIVATE_ERROR',json.dumps(data))

    def test_docker_digest_tab_and_legacy_env_format(self):
        data=self.scan('Dockerfile','FROM\tnode@sha256:'+'a'*64+'\nENV GIT_SSL_NO_VERIFY true')
        self.assertEqual(len(data['findings']),1)
        self.assertEqual(data['coverage_status'],'complete')

    def test_docker_unsupported_heredoc_does_not_scan_body(self):
        data=self.scan('Dockerfile','FROM node:22\nRUN <<EOF\nENV GIT_SSL_NO_VERIFY=true\nEOF')
        self.assertFalse(data['findings']);self.assertEqual(data['coverage_status'],'partial')

    def test_cli_reports_partial_with_issue_and_unknown(self):
        path=self.root/'Dockerfile'
        path.write_text('FROM ${IMAGE}\nENV GIT_SSL_NO_VERIFY=true')
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=main(['--repo',str(path),'--iac','--json'])
        self.assertEqual(code,1)
        report=json.loads(stdout.getvalue())
        self.assertTrue(report['risk_assessment']['assessments'])
        self.assertIsNone(report['risk_assessment']['summary']['readiness_score'])
        self.assertEqual(report['modules']['iac_scanner']['coverage_status'],'partial')
        self.assertIn('&lt;unresolved&gt;',render_markdown(report))
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--repo',str(path),'--iac','--no-color']),1)

    def test_cli_iac_requires_repository(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as raised:
            main(['--iac','--host','example.com'])
        self.assertEqual(raised.exception.code,2)

    def test_parser_dependencies_missing_produce_partial(self):
        with patch.dict('sys.modules',{'yaml':None}):
            data=self.scan('input.yaml','kind: Ingress')
        self.assertEqual(data['diagnostics'][0]['code'],'dependency')
        with patch.dict('sys.modules',{'hcl2':None}):
            data=self.scan('input.tf','')
        self.assertEqual(data['diagnostics'][0]['code'],'dependency')

    def test_reuse_and_candidate_limit(self):
        first=self.root/'Dockerfile.one';first.write_text('FROM node:22\nENV GIT_SSL_NO_VERIFY=true')
        second=self.root/'Dockerfile.two';second.write_text('FROM node:22')
        scanner=IaCScanner()
        old=scanner.scan(first)
        self.assertTrue(old['findings'])
        self.assertFalse(scanner.scan(second)['findings'])
        self.assertTrue(old['findings'])
        with patch('iac_scanner.MAX_FILES',1):
            data=scan_iac(self.root)
        self.assertEqual(data['summary']['attempted_files'],1)
        self.assertEqual(data['coverage_status'],'partial')

    def test_shell_commands_and_terraform_functions_are_not_executed(self):
        with patch('subprocess.run',side_effect=AssertionError('must not execute')):
            data=self.scan('Dockerfile','FROM node:22\nRUN curl --insecure https://example.invalid')
            self.assertFalse(data['findings'])
            data=self.scan('main.tf','resource "aws_lb_listener" "x" { protocol="HTTPS"\n ssl_policy=file("SYNTHETIC_PRIVATE_PATH") }')
        self.assertEqual(data['coverage_status'],'partial')
        self.assertNotIn('SYNTHETIC_PRIVATE_PATH',json.dumps(data))


if __name__=='__main__':
    unittest.main()
