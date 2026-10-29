"""Structural source evidence for Python and lexical call evidence for JS/TS.

Python uses ast and tokenize. JS uses token spans and balanced call arguments;
it deliberately reports lexical evidence, not an AST or runtime guarantee.
Only bounded literal evaluation is used; repository code is never executed.
"""
import ast
import io
import re
import tokenize


def _literal(node, bindings, depth=0):
    if depth > 8:
        return None
    if isinstance(node, ast.Name):
        return _literal(bindings.get(node.id), bindings, depth + 1)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        a, b = _literal(node.left, bindings, depth+1), _literal(node.right, bindings, depth+1)
        if isinstance(a, (str, bytes)) and type(b) is int and 0 <= b <= 4096:
            return a * b
    if isinstance(node, ast.Call):
        name = ast.unparse(node.func)
        if name in ('os.urandom', 'secrets.token_bytes') and node.args:
            size = _literal(node.args[0], bindings, depth+1)
            if type(size) is int and 0 <= size <= 4096:
                return b'\0' * size
    return None


def _parameters(text, key=None):
    params = {}
    m = re.search(r'\b(?:key_size|modulusLength)\s*[=:]\s*(\d+)\b', text)
    if m:
        params['key_bits'] = int(m.group(1))
    curve = re.search(r'(?:SECP|secp|prime|P-)(256|384|521)(?:R1|r1|v1)?', text)
    if curve:
        params['curve'] = f'P-{curve.group(1)}'
    if isinstance(key, bytes):
        params['key_bits'] = len(key) * 8
    cipher = re.search(r'\baes[-_](128|192|256)[-_](gcm|cbc|ecb|ctr|ccm)\b', text, re.I)
    if cipher:
        params.update(key_bits=int(cipher.group(1)), mode=cipher.group(2).upper())
    return params


def _extra_call(name, text):
    """Return explicit identities not covered by the legacy pattern catalog."""
    low = name.lower()
    if low.endswith('dsa.generate_private_key') and not low.endswith('ecdsa.generate_private_key'):
        return 'DSA', 'Digital Signature Scheme', 'CRITICAL_VULNERABLE'
    if low.endswith('dh.generate_parameters') or low.endswith('diffie_hellman.generate_parameters'):
        return 'Diffie-Hellman', 'Key Agreement', 'CRITICAL_VULNERABLE'
    if low.endswith('algorithms.aes') or name == 'AES.new':
        return 'AES', 'Symmetric Encryption', 'MODERATE_IMPACT'
    if low.endswith(('algorithms.tripledes', 'des3.new')):
        return '3DES', 'Symmetric Encryption', 'MODERATE_IMPACT'
    if low.endswith(('algorithms.arc4', 'arc4.new')):
        return 'RC4', 'Symmetric Encryption', 'NOT_APPLICABLE'
    if low.endswith('des.new'):
        return 'DES', 'Symmetric Encryption', 'MODERATE_IMPACT'
    if low.endswith('modes.cbc'):
        return 'Block cipher CBC', 'Block Cipher Mode', 'NOT_APPLICABLE'
    if low.endswith('createcipheriv') or low.endswith('createdecipheriv'):
        m = re.search(r"\(\s*['\"]([^'\"]+)", text)
        return (m.group(1) if m else 'Unknown-Cipher'), 'Symmetric Encryption', 'MODERATE_IMPACT'
    if re.search(r'mlkem(?:512|768|1024)(?:privatekey)?\.generate$', low):
        bits = re.search(r'(512|768|1024)', low).group(1)
        return 'ML-KEM-'+bits, 'Key Agreement', 'QUANTUM_RESISTANT'
    if low.endswith(('ed448privatekey.generate', 'ed448.ed448privatekey.generate')):
        return 'Ed448', 'Digital Signature', 'CRITICAL_VULNERABLE'
    if name.endswith('ChaCha20Poly1305'):
        return 'ChaCha20-Poly1305', 'Authenticated Symmetric Encryption', 'QUANTUM_RESISTANT'
    return None


def _emit_call(name, text, line, column, snippet, rules, params, evidence):
    results = []
    for rule in rules:
        if rule['match_type'].value in ('IMPORT_STATEMENT', 'EXPOSED_SECRET'):
            continue
        match = re.search(rule['pattern'], text, re.I)
        # A nested call is visited separately; don't duplicate it at its parent.
        if match and match.start() <= len(name):
            item = dict(rule=rule, line=line, column=column, snippet=snippet,
                        parameters=params, evidence=evidence)
            results.append(item)
    extra = _extra_call(name, text)
    if extra and not results:
        results.append(dict(identity=extra, line=line, column=column, snippet=snippet,
                            parameters=params, evidence=evidence))
    return results


def python_events(content, rules):
    events, diagnostics = [], []
    try:
        tree = ast.parse(content)
    except SyntaxError as err:
        return [], [f'Python parse error at line {err.lineno}; file not analyzed structurally.']
    aliases, bindings = {}, {}
    # Conflicting assignments are never resolved to an arbitrary last value.
    assignments = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                aliases[alias.asname or alias.name] = (node.module or '')+'.'+alias.name
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
    bindings = {k: v[0] for k, v in assignments.items() if len(v) == 1}
    # Do not resolve a caller-controlled parameter using a same-named global.
    shadowed = {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}
    bindings = {k:v for k,v in bindings.items() if k not in shadowed}

    def canonical(node):
        name = ast.unparse(node)
        first, *rest = name.split('.')
        full = '.'.join([aliases.get(first, first), *rest])
        for prefix in ('hashlib.', 'rsa.', 'ec.', 'dsa.', 'dh.', 'x25519.', 'ed25519.', 'ed448.', 'mlkem.', 'padding.', 'modes.', 'algorithms.', 'bcrypt.', 'argon2.'):
            start = full.rfind(prefix)
            if start >= 0:
                return full[start:]
        if '.RSA.' in full:
            return full[full.index('RSA.'):]
        for cipher in ('AES', 'DES3', 'DES', 'ARC4'):
            if '.'+cipher+'.' in full:
                return full[full.index(cipher+'.'):]
        if full.startswith('cryptography.'):
            parts = full.split('.')
            return '.'.join(parts[-2:]) if parts[-1] == 'generate' else parts[-1]
        return full

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            text = ast.unparse(node)
            for rule in rules:
                if rule['match_type'].value == 'IMPORT_STATEMENT' and re.search(rule['pattern'], text, re.I):
                    events.append(dict(rule=rule, line=node.lineno, column=node.col_offset+1,
                                       snippet=text, parameters={}, evidence='python_ast'))
        if isinstance(node, ast.Call):
            name = canonical(node.func)
            text = name + '(' + ', '.join([ast.unparse(a) for a in node.args] + [f'{k.arg}={ast.unparse(k.value)}' for k in node.keywords]) + ')'
            original = ast.get_source_segment(content, node) or text
            key = None
            if name in ('AESGCM', 'algorithms.AES', 'AES.new', 'ChaCha20Poly1305') and node.args:
                key = _literal(node.args[0], bindings)
            params = {'key_bits': len(key)*8} if isinstance(key, bytes) else {}
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    curve = re.fullmatch(r'ec\.SECP(256|384|521)R1',canonical(child.func),re.I)
                    if curve:
                        params['curve'] = 'P-'+curve.group(1)
                elif isinstance(child, ast.Attribute) and child.attr in ('MODE_ECB','MODE_CBC','MODE_GCM','MODE_CTR'):
                    params['mode'] = child.attr[5:]
            if name.endswith('RSA.generate') and node.args:
                bits = _literal(node.args[0], bindings)
                if type(bits) is int:
                    params['key_bits'] = bits
            # Keyword values may refer to bounded literals too.
            for kw in node.keywords:
                if kw.arg == 'key_size':
                    bits = _literal(kw.value, bindings)
                    if type(bits) is int:
                        params['key_bits'] = bits
            events.extend(_emit_call(name, text, node.lineno, node.col_offset+1,
                                     original, rules, params, 'python_ast'))
        # A PEM in an actual literal is exposed even inside a docstring.
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search(r'-----BEGIN [^-]*PRIVATE KEY-----', node.value):
            events.append(dict(secret=True, line=node.lineno, column=node.col_offset+1,
                               snippet='[REDACTED PRIVATE KEY MATERIAL]', parameters={}, evidence='python_ast'))
    # Comments remain optional inventory references, never active assessments.
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type == tokenize.COMMENT:
                events.extend(_comment_events(token.string, token.start[0], rules))
    except tokenize.TokenError:
        diagnostics.append('Incomplete token stream; comment inventory may be partial.')
    return events, diagnostics


def _comment_events(text, line, rules):
    events = []
    for rule in rules:
        if rule['match_type'].value != 'EXPOSED_SECRET' and re.search(rule['pattern'], text, re.I):
            events.append(dict(rule=rule, line=line, column=1, snippet=text,
                               parameters={}, comment=True, evidence='comment'))
    return events


# Strings/comments are tokens, so their delimiters never hide neighboring calls.
_JS_TOKEN = re.compile(r'(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)|(?P<id>[A-Za-z_$][\w$]*)|(?P<number>\d+)|(?P<punct>[^\s])')

def javascript_events(content, rules):
    tokens = list(_JS_TOKEN.finditer(content))
    events, aliases, diagnostics = [], {}, []
    for t in tokens:
        if t.lastgroup == 'comment':
            events.extend(_comment_events(t.group(), content.count('\n',0,t.start())+1, rules))
        elif t.lastgroup == 'string' and re.search(r'-----BEGIN [^-]*PRIVATE KEY-----', t.group()):
            events.append(dict(secret=True, line=content.count('\n',0,t.start())+1,column=1,
                               snippet='[REDACTED PRIVATE KEY MATERIAL]', parameters={}, evidence='javascript_lexical'))
        if t.lastgroup == 'string' and t.group().startswith('`') and '${' in t.group():
            diagnostics.append('Template interpolation is not analyzed; review embedded expressions.')
    active = [t for t in tokens if t.lastgroup != 'comment']
    # Only genuine import declarations and require calls are considered bindings.
    for i,t in enumerate(active):
        if t.group() not in ('import','require') or t.lastgroup != 'id':
            continue
        end = i
        while end < len(active) and end-i < 60 and active[end].group() != ';':
            end += 1
        span = content[t.start():active[min(end,len(active)-1)].end()]
        for rule in rules:
            if rule['match_type'].value=='IMPORT_STATEMENT' and re.search(rule['pattern'],span,re.I):
                events.append(dict(rule=rule,line=content.count('\n',0,t.start())+1,column=1,snippet=span,parameters={},evidence='javascript_lexical'))
        if any(x.lastgroup=='string' and x.group().strip('"\'') in ('crypto','node:crypto') for x in active[i:min(end+1,len(active))]):
            # import {createHash as hash} ... / const {createHash: hash}=require(...)
            before = content[max(0,t.start()-250):t.start()] if t.group()=='require' else span
            m = re.search(r'\{([^{}]+)\}', before)
            if m:
                for item in m.group(1).split(','):
                    pair = re.split(r'\s+as\s+|\s*:\s*',item.strip())
                    if pair and re.fullmatch(r'\w+',pair[0]):
                        aliases[pair[-1]]='crypto.'+pair[0]
            else:
                m = (re.search(r'(\w+)\s*=\s*$',before) if t.group()=='require'
                     else re.search(r'import\s+(?:\*\s+as\s+)?(\w+)\s+from',span))
                if m:
                    aliases[m.group(1)]='crypto'

    for i,t in enumerate(active):
        if t.lastgroup!='id' or (i and active[i-1].group()=='.'):
            continue
        j=i+1
        while j+1 < len(active) and active[j].group()=='.' and active[j+1].lastgroup=='id':
            j+=2
        if j>=len(active) or active[j].group()!='(':
            continue
        level=0; end=None
        for k in range(j,len(active)):
            if active[k].lastgroup=='string': continue
            if active[k].group()=='(': level+=1
            if active[k].group()==')':
                level-=1
                if level==0: end=k;break
        if end is None:
            diagnostics.append('Unbalanced call arguments; file coverage is partial.')
            continue
        parts=[x.group() for x in active[i:j]]
        name=''.join(parts)
        root,*tail=name.split('.')
        name='.'.join([aliases.get(root,root),*tail])
        # Ignore quoted examples: only the callee token can start this call.
        argtext=' '.join(x.group() for x in active[j:end+1])
        text=name+argtext
        original=content[t.start():active[end].end()]
        events.extend(_emit_call(name,text,content.count('\n',0,t.start())+1,
                                 t.start()-content.rfind('\n',0,t.start()),original,
                                 rules,_parameters(text),'javascript_lexical'))
    return events, sorted(set(diagnostics))
