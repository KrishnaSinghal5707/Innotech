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
            trust_years = max(0.5, round(days_left / 365.25, 2)) if days_left else 2.0

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
        is_pqc = kx.get("post_quantum_or_hybrid_group", False)
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
                    "forward_secrecy": kx.get("forward_secrecy", True),
                    "is_pqc_hybrid": is_pqc,
                    "openssl_probe": kx.get("openssl_probe", {}),
                    "likely_purpose": "Post-Quantum Hybrid Key Encapsulation (ML-KEM)" if is_pqc else "Ephemeral Session Key Agreement (Forward Secrecy)",
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
        algo_name, usage, key_bits = _normalize_code_finding_algo(raw_algo, purpose, code_snippet)

        # Asset identifier with file and line location
        asset_id = f"{file_path}:{line_no}" if file_path else f"code-finding-{idx}"

        # Deduplicate identical findings on the exact same asset location
        dedup_key = (asset_id, algo_name, usage)
        if dedup_key in seen_dedup:
            continue
        seen_dedup.add(dedup_key)

        # Prevent accidental secret disclosure in stored attributes
        safe_snippet = code_snippet
        if match_type == "EXPOSED_SECRET":
            safe_snippet = re.sub(
                r"(-----BEGIN[^-]+-----)([\s\S]*?)(-----END[^-]+-----)",
                r"\1\n[REDACTED PRIVATE KEY MATERIAL]\n\3",
                code_snippet
            )

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
                "evidence_type": "source_code_ast",
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

def _normalize_tls_pk_algo(algo_raw: str, key_bits: Optional[int], curve: Optional[str]) -> str:
    raw = (algo_raw or "").lower()
    if "ecdsa" in raw or "ec" in raw:
        if curve:
            return f"ECDSA {curve}"
        return "ECDSA P-256"
    if "ed25519" in raw:
        return "Ed25519"
    if "rsa" in raw:
        bits = key_bits or 2048
        return f"RSA-{bits}"
    if "dsa" in raw:
        return "DSA"
    return algo_raw or "RSA-2048"


def _normalize_tls_kx_algo(group: Optional[str], method: str, is_pqc: bool) -> str:
    if is_pqc:
        return f"{group or 'X25519MLKEM768'} (Post-Quantum Hybrid)"
    if group:
        g = group.lower()
        if "x25519" in g:
            return "ECDH X25519"
        if "secp256r1" in g or "p-256" in g:
            return "ECDH P-256"
        if "secp384r1" in g or "p-384" in g:
            return "ECDH P-384"
        return f"ECDH {group}"
    m = (method or "").lower()
    # Check ecdh before dhe because 'dhe' is a substring of 'ecdhe'
    if "ecdh" in m:
        return "ECDHE"
    if "dhe" in m or "diffie-hellman" in m or "ffdhe" in m:
        return "Diffie-Hellman (FFDHE)"
    return "ECDHE"


def _normalize_tls_cipher_algo(cipher_name: str, enc: str, bits: Optional[int]) -> str:
    c = (cipher_name + " " + (enc or "")).lower()
    if "3des" in c or "des-ede" in c:
        return "3DES-CBC"
    if "rc4" in c:
        return "RC4"
    if "chacha20" in c:
        return "ChaCha20-Poly1305"
    if "aes" in c:
        mode = "GCM" if "gcm" in c else "CBC"
        # Determine bit length strictly based on secret_bits and cipher name, avoiding false matches on 'sha256'
        if bits == 256 or re.search(r"\baes[-_]?256\b", c) or "aes_256" in c or "256-gcm" in c or "256-cbc" in c:
            return f"AES-256-{mode}"
        if bits == 128 or re.search(r"\baes[-_]?128\b", c) or "aes_128" in c or "128-gcm" in c or "128-cbc" in c:
            return f"AES-128-{mode}"
        if bits:
            return f"AES-{bits}-{mode}"
        return f"AES-128-{mode}"
    return enc or cipher_name


def _normalize_code_finding_algo(raw_algo: str, purpose: str, snippet: str = "") -> Tuple[str, str, Optional[int]]:
    algo = raw_algo.strip()
    a_lower = algo.lower()
    p_lower = purpose.lower()
    s_lower = snippet.lower()

    # Password hashing check
    if any(k in a_lower for k in ("argon2", "bcrypt", "scrypt", "pbkdf2")):
        return algo, "password_storage", None

    if "password" in p_lower or "fast hash" in a_lower:
        if "sha256" in a_lower or "sha-256" in a_lower or "sha256" in s_lower or "sha-256" in s_lower or "fast hash" in a_lower:
            return "SHA-256", "password_storage", None
        if "md5" in a_lower or "md5" in s_lower:
            return "MD5", "password_storage", None
        if "sha1" in a_lower or "sha-1" in a_lower or "sha1" in s_lower:
            return "SHA-1", "password_storage", None
        return algo, "password_storage", None

    # MD5 / SHA1
    if "md5" in a_lower:
        return "MD5", "hash", None
    if "sha1" in a_lower or "sha-1" in a_lower:
        return "SHA-1", "hash", None

    # Diffie-Hellman / ECDH / Key Agreement (Checked before generic ECC so 'elliptic' does not misclassify ECDH)
    if any(k in a_lower for k in ("diffie-hellman", "dh", "ecdh", "x25519", "key exchange", "key agreement")) or \
       any(k in p_lower for k in ("key agreement", "key exchange", "key establishment", "ecdh")) or \
       any(k in s_lower for k in ("ecdh", "exchange(", ".exchange", "shared_secret")):
        if "x25519" in a_lower or "x25519" in s_lower:
            return "ECDH X25519", "key_exchange", 256
        if "384" in a_lower or "384" in s_lower:
            return "ECDH P-384", "key_exchange", 384
        if "521" in a_lower or "521" in s_lower:
            return "ECDH P-521", "key_exchange", 521
        return "ECDH P-256", "key_exchange", 256

    # RSA: Distinguish Digital Signature from Key Encapsulation / OAEP Encryption
    if "rsa" in a_lower:
        bits_match = re.search(r"(\d{3,4})", a_lower)
        bits = int(bits_match.group(1)) if bits_match else 2048
        if any(k in p_lower for k in ("encrypt", "encapsulation", "oaep", "transport", "kem")) or \
           any(k in a_lower for k in ("oaep", "encrypt", "encapsulation")) or \
           any(k in s_lower for k in ("oaep", "encrypt")):
            usage = "key_exchange"
        else:
            usage = "signature"
        return f"RSA-{bits}", usage, bits

    # ECC / ECDSA / Ed25519
    if "ed25519" in a_lower:
        return "Ed25519", "signature", 256
    if "ecdsa" in a_lower or "elliptic" in a_lower or "ecc" in a_lower:
        return "ECDSA P-256", "signature", 256

    # Symmetric Ciphers
    if "des" in a_lower:
        return "DES", "symmetric_encryption", 64
    if "rc4" in a_lower:
        return "RC4", "symmetric_encryption", 128
    if "aes" in a_lower:
        mode = "ecb" if "ecb" in a_lower or "ecb" in p_lower else "gcm"
        if "256" in a_lower or "256" in s_lower or "32" in s_lower:
            return f"AES-256-{mode.upper()}", "symmetric_encryption", 256
        if "128" in a_lower or "128" in s_lower or "16" in s_lower:
            return f"AES-128-{mode.upper()}", "symmetric_encryption", 128
        return f"AES-256-{mode.upper()}", "symmetric_encryption", 256

    # Default fallback
    return algo or "Unknown-Crypto", "general_crypto", None
