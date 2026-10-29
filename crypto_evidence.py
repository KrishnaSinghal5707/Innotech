"""Shared exact identities and output redaction; no security inferred from names."""
import re

MLKEM_GROUPS = {
    'X25519MLKEM768': ('X25519 + ML-KEM-768', True),
    'SecP256r1MLKEM768': ('P-256 + ML-KEM-768', True),
    'SecP384r1MLKEM1024': ('P-384 + ML-KEM-1024', True),
    'MLKEM512': ('ML-KEM-512', False),
    'MLKEM768': ('ML-KEM-768', False),
    'MLKEM1024': ('ML-KEM-1024', False),
}

def mlkem_group(group):
    return MLKEM_GROUPS.get(group)

def redact_evidence(value):
    """Redact recursively, including raw scanner modules, exports and history.

    Entire exposed-secret snippets are removed, including partial PEM headers.
    PEM blocks embedded in other strings are scrubbed defensively as well.
    """
    if isinstance(value, dict):
        secret = value.get('match_type') == 'EXPOSED_SECRET'
        return {k: ('[REDACTED PRIVATE KEY MATERIAL]' if secret and k == 'code_snippet'
                    else redact_evidence(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_evidence(v) for v in value]
    if isinstance(value, str):
        return re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)',
                      '[REDACTED PRIVATE KEY MATERIAL]', value)
    return value
