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
                }
            ))

    # 4. Deprecated Protocol Findings (TLS 1.0 / 1.1)
    protocols = tls_data.get("supported_protocols") or {}
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
                "code_snippet": f.get("code_snippet", ""),
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
    if "dhe" in method.lower():
        return "Diffie-Hellman"
    if "ecdh" in method.lower():
        return "ECDH P-256"
    return "ECDH"


def _normalize_tls_cipher_algo(cipher_name: str, enc: str, bits: Optional[int]) -> str:
    c = (cipher_name + " " + enc).lower()
    if "3des" in c or "des-ede" in c:
        return "3DES-CBC"
    if "rc4" in c:
        return "RC4"
    if "aes" in c:
        if "256" in c or (bits == 256):
            return "AES-256-GCM" if "gcm" in c else "AES-256-CBC"
        return "AES-128-GCM" if "gcm" in c else "AES-128-CBC"
    if "chacha20" in c:
        return "ChaCha20-Poly1305"
    return enc or cipher_name


def _normalize_code_finding_algo(raw_algo: str, purpose: str, snippet: str = "") -> Tuple[str, str, Optional[int]]:
    algo = raw_algo.strip()
    a_lower = algo.lower()
    p_lower = purpose.lower()
    s_lower = snippet.lower()

    # Password hashing check
    if "password" in p_lower or "argon2" in a_lower or "bcrypt" in a_lower or "scrypt" in a_lower or "fast hash" in a_lower:
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

    # RSA
    if "rsa" in a_lower:
        bits_match = re.search(r"(\d{3,4})", a_lower)
        bits = int(bits_match.group(1)) if bits_match else 2048
        usage = "signature" if "signature" in p_lower or "sign" in p_lower else "signature"
        return f"RSA-{bits}", usage, bits

    # ECC / ECDSA / Ed25519
    if "ed25519" in a_lower:
        return "Ed25519", "signature", 256
    if "ecdsa" in a_lower or "elliptic" in a_lower or "ecc" in a_lower:
        return "ECDSA P-256", "signature", 256

    # Diffie-Hellman / ECDH
    if "diffie-hellman" in a_lower or "dh" in a_lower or "key agreement" in p_lower:
        if "ecdh" in a_lower or "curve" in a_lower:
            return "ECDH P-256", "key_exchange", 256
        return "Diffie-Hellman", "key_exchange", 2048

    # Symmetric Ciphers
    if "des" in a_lower:
        return "DES", "symmetric_encryption", 64
    if "rc4" in a_lower:
        return "RC4", "symmetric_encryption", 128
    if "aes" in a_lower:
        mode = "ecb" if "ecb" in a_lower or "ecb" in p_lower else "gcm"
        if "256" in a_lower:
            return f"AES-256-{mode.upper()}", "symmetric_encryption", 256
        return f"AES-128-{mode.upper()}", "symmetric_encryption", 128

    # Default fallback
    return algo or "Unknown-Crypto", "general_crypto", None
