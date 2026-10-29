#!/usr/bin/env python3
"""
adapters.py - Normalization Adapters for Q-SHIELD Orchestrator.

Converts raw scanner outputs from:
  1. tls_scanner (Member 1) - Network TLS & X.509 Certificate telemetry
  2. code_scanner (Member 2) - Source code cryptographic AST & pattern findings
into standardized `Finding` objects consumed by risk_engine (Member 3).
"""

from __future__ import annotations

import re
from crypto_evidence import mlkem_group, redact_evidence
from typing import Any, Dict, List, Optional, Tuple

try:
    from risk_engine import Finding
except ImportError:
    from .risk_engine import Finding


def convert_tls_results_to_findings(tls_data: Dict[str, Any]) -> List[Finding]:
    """
    Transforms TLS scan results into a list of normalized risk_engine Finding objects.
    Extracts findings for:
      - X.509 Certificate Public Key (RSA, ECDSA, Ed25519)
      - Key Exchange Mechanism & Group (ECDH, DH, or PQC Hybrid)
      - Bulk Symmetric Cipher (AES-128, AES-256, 3DES, RC4)
      - Deprecated Protocols (TLS 1.0, TLS 1.1)
    """
    findings: List[Finding] = []
    if not isinstance(tls_data, dict):
        return findings

    target = tls_data.get("target") or {}
    host = target.get("host") or target.get("input") or "unknown-host"
    port = target.get("port") or 443
    asset_id = f"{host}:{port}"

    # If scan failed completely, do not synthesize cryptographic findings
    if tls_data.get("scan_status") == "failed":
        return findings

    # 1. Certificate Public Key Finding
    cert = tls_data.get("certificate")
    if cert and isinstance(cert, dict):
        pk = cert.get("public_key") or {}
        algo_raw = pk.get("algorithm") or ""
        key_bits = pk.get("key_size_bits")
        curve = pk.get("curve")

        # Normalize algorithm name for risk_engine matching
        algo_name = _normalize_tls_pk_algo(algo_raw, key_bits, curve)
        if algo_name:
            # Estimate trust lifetime from certificate validity
            days_left = cert.get("days_until_expiry")
            trust_years = max(0.0, round(days_left / 365.25, 2)) if days_left is not None else None

            findings.append(Finding(
                id=f"tls-cert-pk-{host}",
                asset=asset_id,
                algorithm=algo_name,
                usage="signature",
                key_bits=key_bits,
                trust_lifetime_years=trust_years,
                migration_years=3.0,
                exposure="internet",
                criticality="high",
                evidence_source="certificate",
                location=f"TLS Certificate Subject: {cert.get('subject', {}).get('common_name') or host}",
                attributes={
                    "evidence_type": "x509_certificate",
                    "subject": cert.get("subject", {}),
                    "issuer": cert.get("issuer", {}),
                    "validity": {
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                        "days_until_expiry": days_left,
                    },
                    "signature_algorithm": cert.get("signature", {}).get("algorithm"),
                    "serial_number": cert.get("serial_number"),
                    "fingerprint_sha256": cert.get("fingerprints", {}).get("sha256"),
                    "likely_purpose": "TLS Server Authentication & Public Key Certificate",
                    "confidence": "HIGH",
                    "match_type": "X509_CERTIFICATE",
                }
            ))

    # 2. Key Exchange Finding
    kx = tls_data.get("key_exchange")
    if kx and isinstance(kx, dict):
        group = kx.get("group")
        identity = mlkem_group(group)
        is_pqc = bool(identity)
        method = kx.get("method") or ""

        kx_algo = _normalize_tls_kx_algo(group, method, is_pqc)
        if kx_algo:
            findings.append(Finding(
                id=f"tls-kx-{host}",
                asset=asset_id,
                algorithm=kx_algo,
                usage="key_exchange",
                data_lifetime_years=10.0,  # Long-lived encrypted sessions subject to HNDL
                migration_years=3.0,
                exposure="internet",
                criticality="critical" if not is_pqc else "medium",
                evidence_source="network",
                location=f"TLS Handshake Key Exchange (Group: {group or 'inferred'})",
                attributes={
                    "evidence_type": "tls_key_exchange",
                    "group": group,
                    "method": method,
                    "forward_secrecy": kx.get("forward_secrecy"),
                    "is_pqc_hybrid": is_pqc,
                    "pqc_identity": identity[0] if identity else None,
                    "openssl_probe": kx.get("openssl_probe", {}),
                    "likely_purpose": identity[0] if identity else ("Static RSA key transport; no forward secrecy" if "RSA" in kx_algo else "Session key agreement; inspect group evidence"),
                    "confidence": "HIGH" if group else "MEDIUM",
                    "match_type": "TLS_HANDSHAKE_PROBE" if group else "TLS_HANDSHAKE_INFERENCE",
                }
            ))

    # 3. Bulk Symmetric Cipher Suite Finding
    cipher = tls_data.get("cipher_suite")
    if cipher and isinstance(cipher, dict):
        cipher_name = cipher.get("name") or ""
        enc = cipher.get("encryption") or ""
        secret_bits = cipher.get("secret_bits")

        sym_algo = _normalize_tls_cipher_algo(cipher_name, enc, secret_bits)
        if sym_algo:
            findings.append(Finding(
                id=f"tls-cipher-{host}",
                asset=asset_id,
                algorithm=sym_algo,
                usage="symmetric_encryption",
                key_bits=secret_bits,
                data_lifetime_years=10.0,
                migration_years=2.0,
                exposure="internet",
                criticality="high",
                evidence_source="network",
                location=f"TLS Negotiated Cipher: {cipher_name}",
                attributes={
                    "evidence_type": "tls_cipher_suite",
                    "cipher_suite_name": cipher_name,
                    "protocol": cipher.get("protocol"),
                    "mac_or_aead": cipher.get("mac_or_aead"),
                    "secret_bits": secret_bits,
                    "likely_purpose": "Transport Layer Symmetric Data Encryption",
                    "confidence": "HIGH",
                    "match_type": "TLS_NEGOTIATED_CIPHER",
                }
            ))

    # 4. Deprecated Protocol Findings (TLS 1.0 / 1.1)
    protocols = dict(tls_data.get("supported_protocols") or {})
    negotiated_protocol = (tls_data.get("connection") or {}).get("tls_version")
    if negotiated_protocol in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        protocols["TLSv1.0" if negotiated_protocol == "TLSv1" else negotiated_protocol] = True
    for proto, supported in protocols.items():
        if supported and proto in ("TLSv1.0", "TLSv1.1"):
            findings.append(Finding(
                id=f"tls-proto-{proto.lower()}-{host}",
                asset=asset_id,
                algorithm=f"Deprecated-{proto}",
                usage="protocol_negotiation",
                exposure="internet",
                criticality="high",
                evidence_source="network",
                location=f"Server accepts obsolete protocol {proto}",
                attributes={
                    "evidence_type": "tls_protocol",
                    "protocol": proto,
                    "likely_purpose": "Transport Protocol Negotiation",
                    "confidence": "HIGH",
                    "match_type": "PROTOCOL_SUPPORT_CHECK",
                    "recommendation": f"Disable {proto} immediately. Minimum compliant version is TLS 1.2; TLS 1.3 strongly recommended.",
                }
            ))

    # Certificate trust/validity and signature evidence must reach assessment.
    def issue(name, title):
        findings.append(Finding(id=f'tls-{name}-{host}', asset=asset_id,
            algorithm=title, usage='certificate_validation', evidence_source='certificate',
            exposure='internet', criticality='high',
            attributes={'issue': name, 'confidence': 'HIGH', 'evidence_type': 'certificate_validation'}))

    validation = tls_data.get('certificate_validation') or {}
    if validation.get('trusted') is False:
        issue('certificate_untrusted', 'Certificate chain or hostname validation failed')
    if validation.get('trusted') is None and validation.get('error'):
        issue('certificate_validation_unknown', 'Certificate validation inconclusive')
    if isinstance(cert, dict):
        if cert.get('expired') or (cert.get('days_until_expiry') is not None and cert['days_until_expiry'] < 0):
            issue('certificate_expired', 'Expired TLS certificate')
        if cert.get('not_yet_valid'):
            issue('certificate_not_yet_valid', 'TLS certificate not yet valid')
        signature = str((cert.get('signature') or {}).get('algorithm') or '').lower()
        digest = 'MD5' if 'md5' in signature else 'SHA-1' if ('sha1' in signature or 'sha-1' in signature) else None
        if digest:
            findings.append(Finding(id=f'tls-cert-digest-{host}', asset=asset_id,
                algorithm=digest, usage='certificate_signature_hash', evidence_source='certificate',
                exposure='internet', criticality='high', attributes={'confidence': 'HIGH'}))

    for index, suite in enumerate(tls_data.get('supported_tls12_ciphers') or []):
        name = suite.get('name', '')
        algorithm = _normalize_tls_cipher_algo(name, '', suite.get('bits'))
        if algorithm:
            findings.append(Finding(id=f'tls-accepted-cipher-{index}-{host}', asset=asset_id,
                algorithm=algorithm, usage='symmetric_encryption', key_bits=suite.get('bits'),
                exposure='internet', criticality='high', evidence_source='network',
                attributes={'evidence_type': 'tls_accepted_cipher', 'cipher_suite_name': name,
                            'confidence': 'HIGH', 'match_type': 'TLS_CIPHER_ENUMERATION'}))
    return findings


def convert_code_results_to_findings(code_data: Dict[str, Any]) -> List[Finding]:
    """
    Transforms code scanner findings into a list of normalized risk_engine Finding objects.
    Maps file paths, code snippets, confidence levels, and algorithms.
    """
    findings: List[Finding] = []
    if not isinstance(code_data, dict):
        return findings

    seen_dedup = set()
    raw_findings = code_data.get("findings", [])
    for idx, f in enumerate(raw_findings, start=1):
        if not isinstance(f, dict):
            continue

        raw_algo = f.get("detected_algorithm", "")
        purpose = f.get("likely_purpose", "")
        file_path = f.get("file_path", "")
        line_no = f.get("line_number", 0)
        is_comment = f.get("is_comment", False)
        match_type = f.get("match_type", "")
        conf_str = f.get("confidence", "MEDIUM")
        code_snippet = f.get("code_snippet", "")

        # Map to standard algorithm and usage
        algo_name, usage, key_bits = _normalize_code_finding_algo(raw_algo, purpose, code_snippet, f.get("parameters"))

        # Asset identifier with file and line location
        asset_id = f"{file_path}:{line_no}" if file_path else f"code-finding-{idx}"

        # Deduplicate identical findings on the exact same asset location
        dedup_key = (asset_id, algo_name, usage)
        if dedup_key in seen_dedup:
            continue
        seen_dedup.add(dedup_key)

        safe_snippet = redact_evidence({'match_type': match_type, 'code_snippet': code_snippet})['code_snippet']

        # Determine criticality based on context
        criticality = "medium"
        if match_type == "EXPOSED_SECRET":
            criticality = "critical"
        elif "password" in purpose.lower() or "password" in usage.lower():
            criticality = "critical"
        elif f.get("quantum_risk") == "CRITICAL_VULNERABLE" and not is_comment:
            criticality = "high"
        elif is_comment:
            criticality = "low"

        # Evidence source mapping
        evidence_src = "static" if not is_comment else "heuristic"

        findings.append(Finding(
            id=f"code-finding-{idx}",
            asset=asset_id,
            algorithm=algo_name,
            usage=usage,
            key_bits=key_bits,
            data_lifetime_years=10.0 if usage in ("key_exchange", "symmetric_encryption") else None,
            trust_lifetime_years=5.0 if usage == "signature" else None,
            migration_years=3.0,
            exposure="internal",
            criticality=criticality,
            evidence_source=evidence_src,
            location=f"{file_path}:{line_no}",
            attributes={
                "evidence_type": f.get("evidence_type", "static"),
                "issue": "exposed_private_key" if match_type == "EXPOSED_SECRET" else None,
                "raw_algorithm": raw_algo,
                "likely_purpose": purpose,
                "match_type": match_type,
                "confidence": conf_str,
                "code_snippet": safe_snippet,
                "is_comment": is_comment,
                "runtime_note": f.get("runtime_note", ""),
                "migration_advice": f.get("migration_advice"),
                "cwe_id": f.get("cwe_id"),
            }
        ))

    return findings


# ============================================================================
# HELPER NORMALIZERS
# ============================================================================

def _normalize_tls_pk_algo(algo_raw, key_bits, curve):
    low = (algo_raw or '').lower()
    if 'ed25519' in low: return 'Ed25519'
    if 'ed448' in low: return 'Ed448'
    if 'ecdsa' in low or low == 'ec': return 'ECDSA'+(' '+curve if curve else '')
    if 'rsa' in low: return 'RSA'+('-'+str(key_bits) if key_bits else '')
    if 'dsa' in low: return 'DSA'+('-'+str(key_bits) if key_bits else '')
    return algo_raw or 'Unknown certificate key'


def _normalize_tls_kx_algo(group, method, is_pqc):
    identity = mlkem_group(group)
    if identity:
        return group+' (Post-Quantum '+('Hybrid' if identity[1] else 'KEM')+')'
    if group:
        g = group.lower()
        if re.fullmatch(r'ffdhe\d+',g): return 'Diffie-Hellman-'+g[5:]
        if g == 'x25519': return 'ECDH X25519'
        if g in ('secp256r1','p-256','prime256v1'): return 'ECDH P-256'
        if g in ('secp384r1','p-384'): return 'ECDH P-384'
        if g in ('secp521r1','p-521'): return 'ECDH P-521'
        return 'Unknown key exchange ('+group+')'
    m = (method or '').lower()
    if 'rsa' in m: return 'RSA'
    # TLS 1.3 cipher suite telemetry cannot establish classical vs hybrid KX.
    if 'group negotiated' in m or 'tls 1.3' in m or not m: return 'Unknown key exchange'
    if m in ('ecdhe','ecdh (static)'): return 'ECDH'
    if m in ('dhe','dh (static)'): return 'Diffie-Hellman'
    return 'Unknown key exchange'


def _normalize_tls_cipher_algo(cipher_name: str, enc: str, bits: Optional[int]) -> str:
    c = (cipher_name + " " + (enc or "")).lower()
    if "3des" in c or "des-ede" in c or "des-cbc3" in c:
        return "3DES-CBC"
    if re.search(r'\bdes[-_]', c):
        return 'DES-CBC'
    if "rc4" in c:
        return "RC4"
    if "chacha20" in c:
        return "ChaCha20-Poly1305"
    if "aes" in c:
        mode = next((x.upper() for x in ("gcm", "cbc", "ccm", "ecb", "ctr") if x in c), "unknown")
        # Determine bit length strictly based on secret_bits and cipher name, avoiding false matches on 'sha256'
        if bits == 256 or re.search(r"\baes[-_]?256\b", c) or "aes_256" in c or "256-gcm" in c or "256-cbc" in c:
            return f"AES-256-{mode}"
        if bits == 128 or re.search(r"\baes[-_]?128\b", c) or "aes_128" in c or "128-gcm" in c or "128-cbc" in c:
            return f"AES-128-{mode}"
        if bits:
            return f"AES-{bits}-{mode}"
        return f"AES-{mode}"
    # A cipher-suite authentication component (e.g. RSA in an ARIA suite)
    # is not the bulk cipher, and its strength_bits is not an RSA key size.
    return 'Unknown symmetric cipher ('+(enc or cipher_name)+')'


def _normalize_code_finding_algo(raw_algo: str, purpose: str, snippet: str = "", parameters=None) -> Tuple[str, str, Optional[int]]:
    from crypto_source import _parameters
    algo = raw_algo.strip()
    low, context = algo.lower(), purpose.lower()
    params = dict(parameters) if parameters is not None else _parameters(snippet)
    bits = params.get('key_bits')
    if type(bits) is not int or bits <= 0:
        bits = None
    curve = params.get('curve')
    if not curve:
        m = re.search(r'(?:p-|secp)(256|384|521)', algo, re.I)
        curve = 'P-'+m.group(1) if m else None
    if 'private key material' in low:
        return algo, 'secret_exposure', None
    if any(k in low for k in ('argon2', 'bcrypt', 'scrypt', 'pbkdf2')):
        return algo, 'password_storage', None
    if 'password' in context or 'fast hash' in low:
        # Match the actual digest before the generic fast-hash label.
        for pattern, digest in ((r'md5', 'MD5'), (r'sha-?1\b', 'SHA-1'), (r'sha-?256', 'SHA-256')):
            if re.search(pattern, algo+' '+snippet, re.I):
                return digest, 'password_storage', None
        return algo, 'password_storage', None
    for token,digest in (('md5','MD5'),('sha1','SHA-1'),('sha-1','SHA-1')):
        if token in low:
            return digest, 'hash', None
    if low.startswith(('ml-kem','mlkem')):
        return algo, 'key_exchange', None
    if low.startswith(('ml-dsa','slh-dsa')):
        return algo, 'signature', None
    if 'finite field' in low or 'ffdh' in low or low == 'diffie-hellman':
        return ('Diffie-Hellman-'+str(bits) if bits else 'Diffie-Hellman'), 'key_exchange', bits
    if any(k in low for k in ('ecdh','x25519','x448','diffie-hellman shared')) or 'key agreement' in context:
        if 'x25519' in low or 'x25519' in snippet.lower():
            return 'ECDH X25519', 'key_exchange', 256
        return ('ECDH '+curve if curve else 'ECDH'), 'key_exchange', int(curve[2:]) if curve else bits
    if 'rsa' in low:
        m = re.search(r'rsa[- ]?(\d{3,5})\b',low)
        bits = bits or (int(m.group(1)) if m else None)
        usage = ('key_exchange' if any(k in low+' '+context for k in ('oaep','encrypt','encapsulation','transport')) else
                 'asymmetric_key' if 'key pair' in context else 'signature')
        return ('RSA-'+str(bits) if bits else 'RSA'), usage, bits
    for identity in ('Ed25519','Ed448'):
        if identity.lower() in low:
            return identity, 'signature', 256 if identity=='Ed25519' else 448
    if low.startswith('dsa'):
        return ('DSA-'+str(bits) if bits else 'DSA'), 'signature', bits
    if any(k in low for k in ('ecdsa','elliptic','ecc','nist / secp')):
        generic = 'ecdsa' not in low
        name = 'EC' if generic else 'ECDSA'
        return name+(' '+curve if curve else ''), 'asymmetric_key' if generic else 'signature', int(curve[2:]) if curve else bits
    if 'block cipher' in low:
        return algo, 'cipher_mode', None
    if '3des' in low or 'tripledes' in low:
        return '3DES', 'symmetric_encryption', 168
    if 'des' in low:
        return 'DES', 'symmetric_encryption', 56
    if 'rc4' in low or 'arcfour' in low:
        return 'RC4', 'symmetric_encryption', bits
    if 'chacha20' in low:
        return 'ChaCha20-Poly1305', 'symmetric_encryption', 256
    if 'aes' in low:
        m = re.search(r'aes[-_]?(128|192|256)\b', low)
        bits = bits or (int(m.group(1)) if m else None)
        mode = params.get('mode')
        if not mode:
            m = re.search(r'\b(gcm|ecb|cbc|ccm|ctr)\b|MODE_(GCM|ECB|CBC|CCM|CTR)',algo+' '+snippet,re.I)
            mode = next((x for x in m.groups() if x), '').upper() if m else None
        return 'AES'+('-'+str(bits) if bits else '')+('-'+mode if mode else ''), 'symmetric_encryption', bits
    return algo or 'Unknown-Crypto', 'general_crypto', None
