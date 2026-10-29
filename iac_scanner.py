"""Bounded static Dockerfile, ingress-nginx Ingress and Terraform TLS evidence.

Never evaluates templates, shells, Terraform, includes, or user-defined code.
Only allowlisted configuration values are emitted; source snippets and parser
exception messages are intentionally excluded to avoid disclosing secrets.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

from risk_engine import Finding
from iac_policies import (CATALOG_VERSION, CF_LEGACY, CF_MODERN, CF_SOURCE, ELB_LEGACY,
                          ELB_MODERN, ELB_SOURCE, INGRESS_SOURCE, RULES)

MAX_BYTES = 256 * 1024
MAX_FILES = 1000
IGNORE_DIRS = {'.git', '.venv', 'venv', 'node_modules', '.terraform', '__pycache__'}
PREFIX = 'nginx.ingress.kubernetes.io/'
WEAK_PROTOCOLS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'}
KNOWN_PROTOCOLS = WEAK_PROTOCOLS | {'TLSv1.2', 'TLSv1.3'}
WEAK_CIPHERS = {'RC4', 'RC4-SHA', 'RC4-MD5', 'DES-CBC-SHA', 'DES-CBC3-SHA',
                'NULL', 'eNULL', 'aNULL', 'EXP', 'EXPORT'}
# Only these modern cipher names are recognized as not matching our weak rule.
MODERN_CIPHERS = {'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
                  'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384',
                  'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-CHACHA20-POLY1305'}
IMAGE = re.compile(r'(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*'
                   r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?'
                   r'(?:@sha256:[0-9a-f]{64})?\Z')


def is_iac_file(path):
    name = Path(path).name.lower()
    return (name == 'dockerfile' or name.startswith('dockerfile.') or name.endswith('.dockerfile')
            or Path(name).suffix in ('.yaml', '.yml', '.tf'))


def _link(path):
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


class IaCScanner:
    def __init__(self):
        self._reset()

    def _reset(self):
        self.result = {'module': 'iac_scanner', 'schema_version': '1.0',
                       'catalog_reviewed_at': CATALOG_VERSION, 'static_only': True,
                       'findings': [], 'observations': [],
                       'diagnostics': [], 'coverage_status': 'complete',
                       'summary': {'attempted_files': 0, 'scanned_files': 0, 'excluded_files': 0, 'total_findings': 0}}

    def diagnostic(self, file, code, line=None, partial=True):
        self.result['diagnostics'].append({'file': file, 'line': line, 'code': code,
            'message': {
                'unknown_value': 'Missing, dynamic, templated or unrecognized setting; no vulnerability inferred.',
                'malformed': 'Malformed or unsupported syntax; source and parser details withheld.',
                'unsupported': 'Configuration outside the documented static subset was not evaluated.',
                'excluded_state': 'Terraform state/variable input is excluded without reading its contents.',
                'symlink': 'Symbolic link or junction excluded without following it.',
                'unreadable': 'File could not be read safely; source and exception details withheld.',
                'large_input': 'File exceeds the 256 KiB input limit.',
                'limit': 'File count or parser structural limit reached.',
                'dependency': 'Required safe parser unavailable; install requirements.txt.',
                'invalid_target': 'Target is absent, unsupported, or contains parent traversal.',
            }[code], 'partial': partial})
        if partial:
            self.result['coverage_status'] = 'partial'

    def observe(self, file, line, field, status, value=None, rule=None, source=None):
        # value is supplied only from a known enum/token catalog, never raw snippets.
        self.result['observations'].append({'file': file, 'line': line, 'field': field,
            'status': status, 'observed_value': value if value is not None else '<unresolved>',
            'rule_id': rule, 'evidence_source': 'static_iac', 'source': source,
            'note': 'Static declaration only; effective deployment and PQC capability are unverified.'})
        if status == 'unknown':
            self.diagnostic(file, 'unknown_value', line)

    def issue(self, file, line, rule_id, field, value, source):
        title, action = RULES[rule_id]
        identity = hashlib.sha256(f'{file}:{line}:{field}:{rule_id}:{value}'.encode()).hexdigest()[:20]
        self.result['findings'].append(dict(id='iac-'+identity, asset=file,
            algorithm='Static IaC TLS configuration', usage='tls_configuration',
            location=f'{file}:{line}' if line else file, evidence_source='static',
            exposure='internal', criticality='high', attributes={
                'iac_rule_id': rule_id, 'rule_id': rule_id, 'file_path': file, 'line_number': line,
                'field': field, 'observed_value': value, 'rationale': title+'. This is configured intent, not observed runtime posture.',
                'remediation': action, 'confidence': 'HIGH', 'evidence_type': 'static_iac',
                'match_type': 'STATIC_CONFIGURATION', 'source': source,
            }))
        self.observe(file, line, field, 'issue', value, rule_id, source)

    def protocols(self, value, file, line, field):
        if not isinstance(value, str) or len(value) > 512:
            self.observe(file, line, field, 'unknown'); return
        tokens = value.split()
        if not tokens or any(marker in value for marker in ('${','{{','%{')):
            self.observe(file, line, field, 'unknown'); return
        for token in sorted(set(tokens) & WEAK_PROTOCOLS):
            self.issue(file, line, 'IAC_INGRESS_LEGACY_TLS', field, token, INGRESS_SOURCE)
        if not set(tokens) <= KNOWN_PROTOCOLS:
            self.observe(file, line, field, 'unknown')
        elif not set(tokens) & WEAK_PROTOCOLS:
            self.observe(file, line, field, 'no_match', ' '.join(tokens), source=INGRESS_SOURCE)

    def ciphers(self, value, file, line, field):
        if not isinstance(value, str) or len(value) > 2048:
            self.observe(file, line, field, 'unknown'); return
        # OpenSSL exclusions/operators require evaluation of the complete expression.
        # Do not interpret !RC4 as enabling RC4, or HIGH as a known complete list.
        tokens = value.split(':')
        if not tokens or any(not t or t[0] in '!+-@' for t in tokens) or any(marker in value for marker in ('${','{{','%{')):
            self.observe(file, line, field, 'unknown'); return
        known = WEAK_CIPHERS | MODERN_CIPHERS
        for token in sorted(set(tokens) & WEAK_CIPHERS):
            self.issue(file, line, 'IAC_INGRESS_WEAK_CIPHER', field, token, INGRESS_SOURCE)
        if not set(tokens) <= known:
            self.observe(file, line, field, 'unknown')
        elif not set(tokens) & WEAK_CIPHERS:
            self.observe(file, line, field, 'no_match', ':'.join(tokens), source=INGRESS_SOURCE)

    def docker(self, text, file):
        source = 'https://docs.docker.com/reference/dockerfile/'
        stages = set()
        logical, start, pending = '', 1, False
        found_base = False
        for number, raw in enumerate(text.splitlines(), 1):
            if raw.lstrip().startswith('#'):
                if re.match(r'#\s*escape\s*=\s*`', raw, re.I):
                    self.diagnostic(file, 'unsupported', number); return
                continue
            if not logical:
                start = number
            logical += raw.strip()
            if logical.endswith('\\'):
                logical = logical[:-1]+' '; pending = True; continue
            pending = False
            if not logical:
                continue
            words = re.split(r'\s+', logical, maxsplit=1)
            instruction, rest = words[0], words[1] if len(words)>1 else ''
            instruction = instruction.upper()
            logical = ''
            if '<<' in rest:
                self.diagnostic(file, 'unsupported', start); return
            if instruction not in {'FROM','ENV','ARG','RUN','COPY','ADD','WORKDIR','USER','EXPOSE',
                                   'LABEL','CMD','ENTRYPOINT','SHELL','HEALTHCHECK','VOLUME','STOPSIGNAL','ONBUILD','MAINTAINER'}:
                self.diagnostic(file, 'malformed', start); continue
            if instruction not in ('FROM', 'ENV'):
                continue
            try:
                parts = shlex.split(rest, posix=True)
            except ValueError:
                self.diagnostic(file, 'malformed', start); continue
            if instruction == 'FROM':
                if parts and parts[0].startswith('--platform='):
                    parts = parts[1:]
                if len(parts) not in (1,3) or (len(parts)==3 and parts[1].upper()!='AS'):
                    self.diagnostic(file, 'malformed', start); continue
                image = parts[0]; found_base = True
                if image in stages or image == 'scratch':
                    self.observe(file, start, 'FROM', 'observed', image, source=source)
                elif IMAGE.fullmatch(image):
                    self.observe(file, start, 'FROM', 'observed', image, source=source)
                else:
                    self.observe(file, start, 'FROM', 'unknown')
                if len(parts)==3 and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*',parts[2]):
                    stages.add(parts[2])
            else:
                pairs = []
                if parts and '=' in parts[0]:
                    for part in parts:
                        key, sep, value = part.partition('=')
                        if not sep:
                            self.diagnostic(file, 'malformed', start)
                        else:
                            pairs.append((key,value))
                elif len(parts)>=2:
                    pairs = [(parts[0], ' '.join(parts[1:]))]
                else:
                    self.diagnostic(file, 'malformed', start)
                for key,value in pairs:
                    if key not in ('NODE_TLS_REJECT_UNAUTHORIZED', 'GIT_SSL_NO_VERIFY'):
                        continue
                    disabled = value == '0' if key.startswith('NODE') else value.lower() in ('true','yes','on','1')
                    enabled = value == '1' if key.startswith('NODE') else value.lower() in ('false','no','off','0')
                    if disabled:
                        self.issue(file,start,'IAC_DOCKER_TLS_VERIFY_DISABLED',key,value.lower(),
                            'https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue' if key.startswith('NODE') else 'https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslVerify')
                    elif enabled:
                        self.observe(file,start,key,'no_match',value.lower())
                    else:
                        self.observe(file,start,key,'unknown')
        if pending or not found_base:
            self.diagnostic(file, 'malformed', start)

    def yaml(self, text, file):
        try:
            import yaml
        except ImportError:
            self.diagnostic(file, 'dependency'); return False
        try:
            # Preflight bounds also prevent alias cycles/expansion and deep recursion.
            depth = 0
            for count,event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader)):
                if count > 10000 or isinstance(event, yaml.AliasEvent):
                    self.diagnostic(file, 'limit'); return False
                if isinstance(event, (yaml.MappingStartEvent,yaml.SequenceStartEvent)): depth += 1
                elif isinstance(event, (yaml.MappingEndEvent,yaml.SequenceEndEvent)): depth -= 1
                if depth > 48:
                    self.diagnostic(file, 'limit'); return False
            docs = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
            def mapping(node):
                if not isinstance(node,yaml.MappingNode): return {}
                result = {}
                for k,v in node.value:
                    if not isinstance(k,yaml.ScalarNode) or k.tag!='tag:yaml.org,2002:str' or k.value in result:
                        raise ValueError('invalid mapping')
                    result[k.value]=v
                return result
            def scalar(node):
                return node.value if isinstance(node,yaml.ScalarNode) and node.tag=='tag:yaml.org,2002:str' else None
            for doc in docs:
                root = mapping(doc)
                kind = scalar(root.get('kind'))
                if kind == 'Secret':
                    continue  # Never walk, construct or emit Secret data.
                if kind != 'Ingress':
                    continue
                if scalar(root.get('apiVersion')) not in ('networking.k8s.io/v1','networking.k8s.io/v1beta1'):
                    self.diagnostic(file,'unsupported',doc.start_mark.line+1); continue
                annotations = mapping(mapping(root.get('metadata')).get('annotations'))
                def setting(key):
                    node = annotations.get(PREFIX+key)
                    return scalar(node), node.start_mark.line+1 if node else doc.start_mark.line+1
                protocols,line = setting('proxy-ssl-protocols')
                self.protocols(protocols,file,line,PREFIX+'proxy-ssl-protocols')
                for key in ('ssl-ciphers','proxy-ssl-ciphers'):
                    value,line = setting(key)
                    self.ciphers(value,file,line,PREFIX+key)
                value,line = setting('proxy-ssl-verify')
                backend,_ = setting('backend-protocol')
                if value == 'off' and backend in ('HTTPS','GRPCS'):
                    self.issue(file,line,'IAC_INGRESS_VERIFY_DISABLED',PREFIX+'proxy-ssl-verify','off',INGRESS_SOURCE)
                elif value == 'on':
                    self.observe(file,line,PREFIX+'proxy-ssl-verify','no_match','on',source=INGRESS_SOURCE)
                else:
                    self.observe(file,line,PREFIX+'proxy-ssl-verify','unknown')
        except (yaml.YAMLError, ValueError, RecursionError):
            self.diagnostic(file,'malformed'); return False
        return True

    def terraform(self, text, file):
        text = text.replace('\r\n','\n').replace('\r','\n')
        try:
            import hcl2
        except ImportError:
            self.diagnostic(file,'dependency'); return False
        try:
            # hcl2's public loads() similarly appends EOF newline for its grammar.
            tree = hcl2.parses(text+'\n')
            # Transformer performs additional validation (e.g. duplicate attributes).
            hcl2.transform(tree)
            nodes = list(tree.iter_subtrees())
            if len(nodes)>10000:
                self.diagnostic(file,'limit'); return False
            def literal(node):
                if node is None: return None
                raw = text[node.meta.start_pos:node.meta.end_pos].strip()
                if '${' in raw or '%{' in raw: return None
                try:
                    value=json.loads(raw)
                    return value if isinstance(value,(str,bool)) else None
                except (ValueError,TypeError): return None
            def body(block):
                return next(c for c in block.children if getattr(c,'data',None)=='body')
            def attributes(container):
                return {str(c.children[0].children[0]):c.children[-1] for c in container.children if getattr(c,'data',None)=='attribute'}
            top_level = next(c for c in tree.children if getattr(c,'data',None)=='body')
            for block in top_level.children:
                if str(getattr(block,'data',None))!='block' or str(block.children[0].children[0])!='resource': continue
                labels=[c for c in block.children if getattr(c,'data',None)=='string']
                if len(labels)!=2: continue
                # Resource type is an exact syntax label, not an evaluated expression.
                resource_type=text[labels[0].meta.start_pos:labels[0].meta.end_pos].strip('"')
                contents=body(block); attrs=attributes(contents)
                if resource_type in ('aws_lb_listener','aws_alb_listener'):
                    protocol=literal(attrs.get('protocol'))
                    if protocol in ('HTTP','TCP','UDP','TCP_UDP'):
                        continue
                    if protocol not in ('HTTPS','TLS'):
                        self.observe(file,block.meta.line,'protocol','unknown'); continue
                    node=attrs.get('ssl_policy')
                    self.aws_policy(literal(node),file,node.meta.line if node else block.meta.line,'ssl_policy','elb')
                elif resource_type=='aws_cloudfront_distribution':
                    viewers=[c for c in contents.children if getattr(c,'data',None)=='block' and str(c.children[0].children[0])=='viewer_certificate']
                    if not viewers:
                        self.observe(file,block.meta.line,'viewer_certificate.minimum_protocol_version','unknown')
                    for viewer in viewers:
                        fields=attributes(body(viewer)); node=fields.get('minimum_protocol_version')
                        if literal(fields.get('cloudfront_default_certificate')) is True:
                            self.observe(file,viewer.meta.line,'minimum_protocol_version','not_applicable','CloudFront default certificate'); continue
                        default = fields.get('cloudfront_default_certificate')
                        if ((default is not None and literal(default) is not False) or
                            (default is None and not {'acm_certificate_arn','iam_certificate_id'} & fields.keys())):
                            self.observe(file,viewer.meta.line,'certificate_selection','unknown'); continue
                        method = literal(fields.get('ssl_support_method'))
                        if method not in ('sni-only','vip'):
                            self.observe(file,viewer.meta.line,'ssl_support_method','unknown'); continue
                        if method=='sni-only' and literal(node)=='SSLv3':
                            self.observe(file,node.meta.line,'minimum_protocol_version','unknown'); continue
                        self.aws_policy(literal(node),file,node.meta.line if node else viewer.meta.line,'minimum_protocol_version','cloudfront')
        except Exception:
            # Parser exceptions often contain source text and possibly secrets.
            self.diagnostic(file,'malformed'); return False
        return True

    def aws_policy(self,value,file,line,field,service):
        legacy,modern,source=(ELB_LEGACY,ELB_MODERN,ELB_SOURCE) if service=='elb' else (CF_LEGACY,CF_MODERN,CF_SOURCE)
        if isinstance(value,str) and value in legacy:
            self.issue(file,line,'IAC_AWS_LEGACY_TLS_POLICY',field,value,source)
        elif isinstance(value,str) and value in modern:
            self.observe(file,line,field,'no_match',value,source=source)
        else:
            self.observe(file,line,field,'unknown')

    def scan(self, target):
        self._reset()
        target=Path(target)
        if '..' in target.parts or not target.exists():
            self.diagnostic('<target>','invalid_target'); return self.result
        if any(_link(parent) for parent in (target, *target.parents)):
            self.diagnostic('<target>','symlink'); return self.result
        root=target.resolve() if target.is_dir() else target.resolve().parent
        def candidates():
            if target.is_file(): yield target; return
            for folder,dirs,files in os.walk(target,followlinks=False,
                                            onerror=lambda error: self.diagnostic('<directory>','unreadable')):
                for name in list(dirs):
                    child=Path(folder)/name
                    if name in IGNORE_DIRS:
                        dirs.remove(name)
                    elif _link(child):
                        dirs.remove(name); self.diagnostic(str(child.relative_to(target)),'symlink')
                for name in sorted(files): yield Path(folder)/name
        count=0
        for path in candidates():
            file=path.relative_to(target).as_posix() if target.is_dir() else path.name
            if '.tfstate' in path.name.lower() or path.suffix.lower()=='.tfvars':
                self.result['summary']['excluded_files']+=1
                self.diagnostic(file,'excluded_state',partial=False); continue
            if not is_iac_file(path): continue
            count+=1
            if count>MAX_FILES:
                self.diagnostic('<scope>','limit'); break
            self.result['summary']['attempted_files']+=1
            try:
                if _link(path) or not path.resolve().is_relative_to(root):
                    self.diagnostic(file,'symlink'); continue
                before=path.stat(follow_symlinks=False)
                if not stat.S_ISREG(before.st_mode):
                    self.diagnostic(file,'unreadable'); continue
                if before.st_size>MAX_BYTES:
                    self.diagnostic(file,'large_input'); continue
                descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
                with os.fdopen(descriptor,'rb') as handle:
                    opened=os.fstat(handle.fileno())
                    if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
                        self.diagnostic(file,'unreadable'); continue
                    data=handle.read(MAX_BYTES+1)
                if len(data)>MAX_BYTES:
                    self.diagnostic(file,'large_input'); continue
                text=data.decode('utf-8-sig')
                suffix=path.suffix.lower()
                analyzed=(self.yaml(text,file) if suffix in ('.yaml','.yml') else
                          self.terraform(text,file) if suffix=='.tf' else self.docker(text,file))
                if analyzed is not False:
                    self.result['summary']['scanned_files']+=1
            except (OSError,UnicodeError):
                self.diagnostic(file,'unreadable')
        if self.result['summary']['attempted_files']==0 and target.is_file() and not self.result['summary']['excluded_files']:
            self.diagnostic(target.name,'invalid_target')
        self.result['summary']['total_findings']=len(self.result['findings'])
        return self.result


def scan_iac(path):
    return IaCScanner().scan(path)


def convert_iac_results_to_findings(result):
    """Adapter boundary: the scanner already emits the existing normalized model."""
    return [Finding.from_dict(f) for f in result.get('findings',[])]
