#!/usr/bin/env python3
"""
Q-SHIELD Source-Code Cryptography Scanner
=========================================
A specialized security scanner for local repositories that detects:
- Password-hashing APIs (bcrypt, argon2, pbkdf2, scrypt, weak md5/sha1/sha256)
- Cryptographic libraries (PyCA cryptography, PyCryptodome, Node crypto, SubtleCrypto, etc.)
- Asymmetric Public-Key Cryptography (RSA, ECC, Ed25519, DSA)
- Digital Signatures (RSA-PSS, ECDSA, Ed25519)
- Key-Exchange / Agreement Functions (Diffie-Hellman, ECDH, X25519)
- Potentially Exposed Private Keys & High-Risk Secrets

Features:
- Multi-language support: Python (.py), JavaScript/TypeScript (.js, .jsx, .ts, .tsx, .mjs, .cjs)
- Distinguishes active code calls, imports, string literals, and commented-out code
- Assigns confidence ratings (HIGH, MEDIUM, LOW) with transparent rationale
- Quantum vulnerability risk assessment (Shor's / Grover's algorithm exposure)
- Migration guidance for Quantum-Safe Cryptography (NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA)
- JSON and formatted CLI terminal reporting
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class MatchType(str, Enum):
    CONFIRMED_CALL = "CONFIRMED_CALL"       # Direct function invocation / instantiation
    IMPORT_STATEMENT = "IMPORT_STATEMENT"   # Library import / require
    KEY_DECLARATION = "KEY_DECLARATION"     # Key or algorithm parameter configuration
    EXPOSED_SECRET = "EXPOSED_SECRET"       # Hardcoded PEM private key or high-entropy secret
    STRING_REFERENCE = "STRING_REFERENCE"   # Algorithm name in string literal or config
    COMMENT_ONLY = "COMMENT_ONLY"           # Detected inside single-line or multi-line comment


class QuantumRisk(str, Enum):
    CRITICAL_VULNERABLE = "CRITICAL_VULNERABLE"  # Broken by Shor's algorithm (RSA, ECC, DH, DSA)
    MODERATE_IMPACT = "MODERATE_IMPACT"          # Weakened by Grover's algorithm (AES-128, etc.)
    QUANTUM_RESISTANT = "QUANTUM_RESISTANT"      # Hash functions (SHA-256/384/512), AES-256, or PQC
    NOT_APPLICABLE = "NOT_APPLICABLE"            # General library import or utility


@dataclass
class Finding:
    file_path: str
    line_number: int
    column_start: int
    detected_algorithm: str
    likely_purpose: str
    confidence: Confidence
    match_type: MatchType
    quantum_risk: QuantumRisk
    code_snippet: str
    is_comment: bool
    runtime_note: str
    migration_advice: Optional[str] = None
    cwe_id: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    evidence_type: str = "static"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_start": self.column_start,
            "detected_algorithm": self.detected_algorithm,
            "likely_purpose": self.likely_purpose,
            "confidence": self.confidence.value,
            "match_type": self.match_type.value,
            "quantum_risk": self.quantum_risk.value,
            "code_snippet": self.code_snippet.strip(),
            "is_comment": self.is_comment,
            "runtime_note": self.runtime_note,
            "migration_advice": self.migration_advice,
            "cwe_id": self.cwe_id,
            "parameters": self.parameters,
            "evidence_type": self.evidence_type,
        }


# ============================================================================
# DETECTION RULES & SIGNATURE DEFINITIONS
# ============================================================================

PATTERNS_PYTHON = [
    # 1. Exposed Private Keys (Critical)
    {
        "id": "PY_EXPOSED_PEM_PRIVATE_KEY",
        "pattern": r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP)?\s*PRIVATE\s+KEY-----",
        "algorithm": "Exposed Private Key Material",
        "purpose": "Hardcoded Private Key / Secret Exposure",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.EXPOSED_SECRET,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-798",
        "advice": "CRITICAL: Immediately revoke and rotate this key. Never commit private key files into source control. Use AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.",
    },
    # 2. Password Hashing APIs
    {
        "id": "PY_BCRYPT_HASH",
        "pattern": r"\bbcrypt\.(?:hashpw|gensalt|kdf)\b",
        "algorithm": "bcrypt",
        "purpose": "Password Hashing / Key Derivation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Secure classical password hash. For next-gen systems, consider Argon2id (RFC 9106) for optimal GPU/ASIC resistance.",
    },
    {
        "id": "PY_ARGON2_HASH",
        "pattern": r"\bargon2\.(?:PasswordHasher|low_level|hash_password)\b",
        "algorithm": "Argon2id",
        "purpose": "Password Hashing",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Argon2id is the current industry gold standard password hash (Password Hashing Competition winner).",
    },
    {
        "id": "PY_PBKDF2_HASH",
        "pattern": r"\bhashlib\.pbkdf2_hmac\s*\(",
        "algorithm": "PBKDF2-HMAC",
        "purpose": "Password-Based Key Derivation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Ensure iteration count >= 600,000 for PBKDF2-HMAC-SHA256 (OWASP recommendation).",
    },
    {
        "id": "PY_WEAK_PASSWORD_HASH",
        "pattern": r"\bhashlib\.(?:sha256|sha1|md5)\s*\(\s*(?:password|pwd|pass|secret)\b",
        "algorithm": "Unsalted Fast Hash for Password",
        "purpose": "Weak Password Storage",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "VULNERABILITY: Raw cryptographic hashes (SHA-256, MD5, SHA-1) lack a work factor. Replace immediately with Argon2id or bcrypt.",
    },
    # 3. RSA Operations
    {
        "id": "PY_RSA_KEYGEN",
        "pattern": r"\brsa\.generate_private_key\s*\(",
        "algorithm": "RSA (Rivest-Shamir-Adleman)",
        "purpose": "Asymmetric Key Pair Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "QUANTUM ALERT: RSA integer factorization is completely breakable in polynomial time by Shor's algorithm. Plan migration to ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) for signatures.",
    },
    {
        "id": "PY_PYCRYPTODOME_RSA_GEN",
        "pattern": r"\bRSA\.generate\s*\(",
        "algorithm": "RSA (PyCryptodome)",
        "purpose": "Asymmetric Key Pair Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Vulnerable to Shor's algorithm. Transition to Post-Quantum Cryptography standards.",
    },
    {
        "id": "PY_RSA_PSS_SIGN",
        "pattern": r"\bpadding\.PSS\s*\(",
        "algorithm": "RSA-PSS",
        "purpose": "Digital Signature Scheme",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-327",
        "advice": "RSA-PSS is quantum-vulnerable. Transition digital signature workflows to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
    },
    {
        "id": "PY_RSA_OAEP_ENCRYPT",
        "pattern": r"\bpadding\.OAEP\s*\(",
        "algorithm": "RSA-OAEP",
        "purpose": "Asymmetric Key Encapsulation / Encryption",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-327",
        "advice": "Replace RSA-OAEP key encapsulation with ML-KEM-768 / ML-KEM-1024 (FIPS 203).",
    },
    # 4. ECC Operations & Curves
    {
        "id": "PY_ECC_KEYGEN",
        "pattern": r"\bec\.generate_private_key\s*\(",
        "algorithm": "Elliptic Curve Cryptography (ECC)",
        "purpose": "Asymmetric Key Pair Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "QUANTUM ALERT: Elliptic curve discrete logarithms are breakable by Shor's algorithm. Plan migration to ML-KEM or ML-DSA.",
    },
    {
        "id": "PY_ECC_ECDSA_SIGN",
        "pattern": r"\bec\.ECDSA\s*\(",
        "algorithm": "ECDSA",
        "purpose": "Digital Signature Scheme",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-327",
        "advice": "ECDSA will be broken by quantum computers running Shor's algorithm. Target migration to ML-DSA-65 (FIPS 204).",
    },
    {
        "id": "PY_ECC_CURVE_SECP",
        "pattern": r"\bec\.(?:SECP256R1|SECP384R1|SECP521R1|SECP256K1)\s*\(",
        "algorithm": "NIST / SECP Elliptic Curve",
        "purpose": "Elliptic Curve Parameter Selection",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.KEY_DECLARATION,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Standard elliptic curves provide 128-256 bit classical security but 0 bits quantum security against Shor's algorithm.",
    },
    {
        "id": "PY_ED25519_KEYGEN",
        "pattern": r"\bed25519\.Ed25519PrivateKey\.generate\s*\(",
        "algorithm": "Ed25519",
        "purpose": "Modern Digital Signature Scheme",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Ed25519 is classically robust and side-channel resistant, but vulnerable to quantum Shor's algorithm.",
    },
    # 5. Key Exchange Functions
    {
        "id": "PY_ECDH_EXCHANGE",
        "pattern": r"\b(?:exchange\s*\(\s*ec\.ECDH\s*\(\)|ec\.ECDH\s*\(\))",
        "algorithm": "ECDH (Elliptic Curve Diffie-Hellman)",
        "purpose": "Key Agreement / Key Exchange",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "QUANTUM ALERT: Vulnerable to Harvest Now, Decrypt Later (HNDL) attacks. Migrate key establishment to ML-KEM (FIPS 203) or hybrid X25519+ML-KEM-768.",
    },
    {
        "id": "PY_X25519_EXCHANGE",
        "pattern": r"\b(?:x25519\.X25519PrivateKey|X25519PrivateKey\.generate)\b",
        "algorithm": "X25519",
        "purpose": "Diffie-Hellman Key Agreement (Curve25519)",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Migrate toward hybrid post-quantum key exchange (e.g. X25519Kyber768Draft00 as deployed in TLS 1.3 / OpenSSH).",
    },
    {
        "id": "PY_CLASSIC_DH",
        "pattern": r"\bdiffie_hellman\.generate_parameters\s*\(",
        "algorithm": "Finite Field Diffie-Hellman (FFDH)",
        "purpose": "Key Agreement / Key Exchange",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Classical DH is obsolete and vulnerable to both Logjam and quantum Shor's algorithm. Replace with ML-KEM.",
    },
    # 6. Symmetric Ciphers & Modes
    {
        "id": "PY_AES_GCM",
        "pattern": r"\bAESGCM\s*\(",
        "algorithm": "AES-GCM",
        "purpose": "Authenticated Symmetric Encryption (AEAD)",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": None,
        "advice": "AES-256-GCM is quantum-resistant against Grover's algorithm (retains 128-bit quantum security). Ensure 96-bit nonces are NEVER reused.",
    },
    {
        "id": "PY_AES_ECB",
        "pattern": r"\bmodes\.ECB\s*\(",
        "algorithm": "AES-ECB Mode",
        "purpose": "Insecure Block Cipher Mode",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-327",
        "advice": "VULNERABILITY: ECB mode preserves plaintext block patterns. Replace with AES-GCM or ChaCha20-Poly1305.",
    },
    # 7. Broken Hash Algorithms
    {
        "id": "PY_BROKEN_MD5",
        "pattern": r"\bhashlib\.md5\s*\(",
        "algorithm": "MD5",
        "purpose": "Cryptographic Hashing (Broken)",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-328",
        "advice": "MD5 is collision-broken since 2004. Use SHA-256, SHA-384, or SHA-3 for integrity.",
    },
    {
        "id": "PY_BROKEN_SHA1",
        "pattern": r"\bhashlib\.sha1\s*\(",
        "algorithm": "SHA-1",
        "purpose": "Cryptographic Hashing (Broken)",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-328",
        "advice": "SHA-1 has practical collision attacks (SHAttered, 2017). Migrate to SHA-256 or SHA-3.",
    },
    # 8. Library Imports
    {
        "id": "PY_IMPORT_CRYPTOGRAPHY",
        "pattern": r"^\s*(?:from\s+cryptography\b|import\s+cryptography\b)",
        "algorithm": "PyCA Cryptography",
        "purpose": "Cryptographic Library Import",
        "confidence": Confidence.MEDIUM,
        "match_type": MatchType.IMPORT_STATEMENT,
        "quantum_risk": QuantumRisk.NOT_APPLICABLE,
        "cwe": None,
        "advice": "PyCA Cryptography is the recommended standard Python crypto library. Check specific algorithm uses.",
    },
    {
        "id": "PY_IMPORT_PYCRYPTODOME",
        "pattern": r"^\s*(?:from\s+Crypto\b|import\s+Crypto\b)",
        "algorithm": "PyCryptodome / PyCrypto",
        "purpose": "Cryptographic Library Import",
        "confidence": Confidence.MEDIUM,
        "match_type": MatchType.IMPORT_STATEMENT,
        "quantum_risk": QuantumRisk.NOT_APPLICABLE,
        "cwe": None,
        "advice": "Ensure PyCryptodome is kept updated and unauthenticated legacy ciphers (DES, RC4) are avoided.",
    },
    {
        "id": "PY_IMPORT_HASHLIB",
        "pattern": r"^\s*import\s+hashlib\b",
        "algorithm": "Python hashlib",
        "purpose": "Standard Hash Library Import",
        "confidence": Confidence.MEDIUM,
        "match_type": MatchType.IMPORT_STATEMENT,
        "quantum_risk": QuantumRisk.NOT_APPLICABLE,
        "cwe": None,
        "advice": "General hashing module. Verify specific digest algorithm.",
    },
]

PATTERNS_JS_TS = [
    # 1. Exposed Private Keys (Critical)
    {
        "id": "JS_EXPOSED_PEM_PRIVATE_KEY",
        "pattern": r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP)?\s*PRIVATE\s+KEY-----",
        "algorithm": "Exposed Private Key Material",
        "purpose": "Hardcoded Private Key / Secret Exposure",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.EXPOSED_SECRET,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-798",
        "advice": "CRITICAL: Immediately revoke and rotate this key. Store secrets in environment variables or cloud secret managers.",
    },
    # 2. Password Hashing APIs
    {
        "id": "JS_BCRYPT_HASH",
        "pattern": r"\b(?:bcrypt|bcryptjs)\.(?:hash|hashSync|compare|genSalt)\b",
        "algorithm": "bcrypt",
        "purpose": "Password Hashing",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Recommended classical password hash. Ensure salt rounds >= 12.",
    },
    {
        "id": "JS_ARGON2_HASH",
        "pattern": r"\bargon2\.(?:hash|verify)\s*\(",
        "algorithm": "Argon2id",
        "purpose": "Password Hashing",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Argon2id is the state-of-the-art password hashing standard.",
    },
    {
        "id": "JS_CRYPTO_PBKDF2",
        "pattern": r"\bcrypto\.(?:pbkdf2|pbkdf2Sync)\s*\(",
        "algorithm": "PBKDF2",
        "purpose": "Password-Based Key Derivation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Use PBKDF2 with SHA-512 or SHA-256 and at least 600,000 iterations.",
    },
    {
        "id": "JS_CRYPTO_SCRYPT",
        "pattern": r"\bcrypto\.(?:scrypt|scryptSync)\s*\(",
        "algorithm": "scrypt",
        "purpose": "Memory-Hard Password Hashing",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-916",
        "advice": "Memory-hard function resilient against FPGA/ASIC password cracking.",
    },
    # 3. RSA Key Generation & Encryption
    {
        "id": "JS_RSA_KEYGEN",
        "pattern": r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]",
        "algorithm": "RSA (Rivest-Shamir-Adleman)",
        "purpose": "Asymmetric Key Pair Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "QUANTUM ALERT: RSA keys will be broken by Shor's algorithm on CRQCs. Plan migration to ML-KEM (FIPS 203) / ML-DSA (FIPS 204).",
    },
    {
        "id": "JS_SUBTLE_RSA_GEN",
        "pattern": r"\bname:\s*['\"]RSA-(?:OAEP|PSS|PKCS1-v1_5)['\"]",
        "algorithm": "WebCrypto RSA",
        "purpose": "Browser Asymmetric Key Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "WebCrypto RSA is vulnerable to quantum attacks. Watch for W3C WebCrypto PQC algorithm adoption.",
    },
    {
        "id": "JS_RSA_PUBLIC_ENCRYPT",
        "pattern": r"\bcrypto\.(?:publicEncrypt|privateDecrypt)\s*\(",
        "algorithm": "RSA Public Key Encryption",
        "purpose": "Asymmetric Encryption / Decryption",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Ensure RSA_PKCS1_OAEP_PADDING is used classically; plan migration to ML-KEM-768.",
    },
    # 4. ECC Key Generation, ECDSA & Curves
    {
        "id": "JS_EC_KEYGEN",
        "pattern": r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]",
        "algorithm": "Elliptic Curve (EC)",
        "purpose": "Asymmetric Key Pair Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "QUANTUM ALERT: Elliptic curve cryptography is breakable by Shor's algorithm.",
    },
    {
        "id": "JS_ED25519_KEYGEN",
        "pattern": r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]ed25519['\"]",
        "algorithm": "Ed25519",
        "purpose": "Modern Digital Signature Key Pair",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Classically optimal, but quantum-vulnerable. Transition to ML-DSA or SLH-DSA.",
    },
    {
        "id": "JS_SUBTLE_ECDSA_GEN",
        "pattern": r"\bname:\s*['\"]ECDSA['\"]",
        "algorithm": "WebCrypto ECDSA",
        "purpose": "Elliptic Curve Digital Signature Generation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "ECDSA signatures are quantum-vulnerable. Target migration to ML-DSA (FIPS 204).",
    },
    # 5. Key Exchange (Diffie-Hellman / ECDH)
    {
        "id": "JS_CRYPTO_ECDH",
        "pattern": r"\bcrypto\.createECDH\s*\(",
        "algorithm": "ECDH (Elliptic Curve Diffie-Hellman)",
        "purpose": "Key Agreement / Key Exchange",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "QUANTUM ALERT: Subject to Harvest Now, Decrypt Later (HNDL). Plan hybrid X25519+ML-KEM key exchange.",
    },
    {
        "id": "JS_CRYPTO_CLASSIC_DH",
        "pattern": r"\bcrypto\.createDiffieHellman\s*\(",
        "algorithm": "Finite Field Diffie-Hellman",
        "purpose": "Key Agreement / Key Exchange",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Classical DH is obsolete and quantum-broken. Migrate to ML-KEM.",
    },
    {
        "id": "JS_ECDH_COMPUTE_SECRET",
        "pattern": r"\.computeSecret\s*\(",
        "algorithm": "Diffie-Hellman Shared Secret Computation",
        "purpose": "Shared Secret Derivation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Ensure raw shared secret is processed with a KDF (e.g. HKDF). Plan post-quantum transition.",
    },
    # 6. Digital Signatures
    {
        "id": "JS_CRYPTO_SIGN",
        "pattern": r"\bcrypto\.createSign\s*\(",
        "algorithm": "Digital Signature (Node.js crypto.createSign)",
        "purpose": "Message Authentication & Non-Repudiation",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-327",
        "advice": "Underlying asymmetric algorithm (RSA/ECDSA) is quantum-vulnerable.",
    },
    {
        "id": "JS_JWT_SIGN_ASYMMETRIC",
        "pattern": r"\bjwt\.sign\s*\([^)]*algorithm:\s*['\"](?:RS256|RS384|RS512|ES256|ES384|ES512|PS256)['\"]",
        "algorithm": "Asymmetric JWT Signature (RSA/ECDSA)",
        "purpose": "Token Authentication / Digital Signature",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.CRITICAL_VULNERABLE,
        "cwe": "CWE-326",
        "advice": "Asymmetric JWT algorithms depend on RSA or ECDSA. Short token lifetimes mitigate HNDL, but signature spoofing is possible under CRQC.",
    },
    # 7. Broken / Deprecated Algorithms
    {
        "id": "JS_BROKEN_MD5",
        "pattern": r"\bcrypto\.createHash\s*\(\s*['\"]md5['\"]",
        "algorithm": "MD5",
        "purpose": "Cryptographic Hashing (Broken)",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-328",
        "advice": "MD5 is collision-broken. Replace with SHA-256.",
    },
    {
        "id": "JS_BROKEN_SHA1",
        "pattern": r"\bcrypto\.createHash\s*\(\s*['\"]sha1['\"]",
        "algorithm": "SHA-1",
        "purpose": "Cryptographic Hashing (Broken)",
        "confidence": Confidence.HIGH,
        "match_type": MatchType.CONFIRMED_CALL,
        "quantum_risk": QuantumRisk.QUANTUM_RESISTANT,
        "cwe": "CWE-328",
        "advice": "SHA-1 has practical collision exploits. Migrate to SHA-256.",
    },
    # 8. Library Imports & Requires
    {
        "id": "JS_IMPORT_CRYPTO",
        "pattern": r"(?:import\s+(?:\*|crypto|\{[^}]*\})\s+from\s+['\"](?:node:)?crypto['\"]|require\s*\(\s*['\"](?:node:)?crypto['\"]\s*\))",
        "algorithm": "Node.js Native crypto",
        "purpose": "Cryptographic Library Import",
        "confidence": Confidence.MEDIUM,
        "match_type": MatchType.IMPORT_STATEMENT,
        "quantum_risk": QuantumRisk.NOT_APPLICABLE,
        "cwe": None,
        "advice": "Standard Node.js cryptographic module.",
    },
    {
        "id": "JS_IMPORT_BCRYPT",
        "pattern": r"(?:import\s+.*from\s+['\"]bcrypt(?:js)?['\"]|require\s*\(\s*['\"]bcrypt(?:js)?['\"]\s*\))",
        "algorithm": "bcrypt Library",
        "purpose": "Password Hashing Library Import",
        "confidence": Confidence.MEDIUM,
        "match_type": MatchType.IMPORT_STATEMENT,
        "quantum_risk": QuantumRisk.NOT_APPLICABLE,
        "cwe": None,
        "advice": "Password hashing dependency.",
    },
    {
        "id": "JS_IMPORT_TWEETNACL",
        "pattern": r"(?:import\s+.*from\s+['\"]tweetnacl['\"]|require\s*\(\s*['\"]tweetnacl['\"]\s*\))",
        "algorithm": "TweetNaCl",
        "purpose": "Modern Cryptographic Library Import (Ed25519/Curve25519)",
        "confidence": Confidence.MEDIUM,
        "match_type": MatchType.IMPORT_STATEMENT,
        "quantum_risk": QuantumRisk.NOT_APPLICABLE,
        "cwe": None,
        "advice": "TweetNaCl uses Curve25519 / Ed25519. Classical security is high; quantum migration will require PQC.",
    },
]


# ============================================================================
# SCANNER ENGINE CORE
# ============================================================================

class CodeScanner:
    """
    Scans directories and files for cryptographic API calls, libraries,
    asymmetric keys, digital signatures, key exchanges, and hardcoded secrets.
    """

    SUPPORTED_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mjs": "javascript",
        ".cjs": "javascript",
    }

    IGNORE_DIRS = {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".pytest_cache",
        ".idea",
        ".vscode",
    }

    def __init__(self, ignore_comments: bool = False, quantum_only: bool = False):
        self.ignore_comments = ignore_comments
        self.quantum_only = quantum_only
        self.findings: List[Finding] = []
        self.scanned_files_count = 0
        self.scanned_lines_count = 0
        self.diagnostics = []
        self.attempted_files_count = 0

    def scan_path(self, target_path: str | Path) -> List[Finding]:
        """Scan a file or recursively scan a directory."""
        self.findings = []
        self.scanned_files_count = self.scanned_lines_count = self.attempted_files_count = 0
        self.diagnostics = []
        path = Path(target_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        if path.is_file():
            self._scan_file(path)
        elif path.is_dir():
            for root, dirs, files in os.walk(path):
                # Filter out excluded directories
                dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
                for file_name in files:
                    ext = Path(file_name).suffix.lower()
                    if ext in self.SUPPORTED_EXTENSIONS:
                        self._scan_file(Path(root) / file_name)

        return self.findings

    def _scan_file(self, file_path: Path) -> None:
        """Scan an individual Python or JavaScript/TypeScript file."""
        self.attempted_files_count += 1
        try:
            # Bound resource use: skip files larger than 10MB
            if file_path.stat().st_size > 10 * 1024 * 1024:
                self.diagnostics.append({"file": str(file_path), "error": "Skipped file larger than 10 MiB"})
                return
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            self.diagnostics.append({"file": str(file_path), "error": f"Unable to read file: {type(e).__name__}"})
            return

        lines = content.splitlines()
        self.scanned_lines_count += len(lines)
        ext = file_path.suffix.lower()
        lang = self.SUPPORTED_EXTENSIONS.get(ext, "unknown")
        if lang == 'unknown':
            self.diagnostics.append({"file": str(file_path), "error": "Unsupported source extension"})
            return
        self.scanned_files_count += 1

        if lang == "python":
            self._scan_python_file(file_path, content, lines)
        elif lang in ("javascript", "typescript"):
            self._scan_jsts_file(file_path, content, lines)

    def _structural_scan(self, file_path, content, language):
        from crypto_source import python_events, javascript_events
        rules = PATTERNS_PYTHON if language == 'python' else PATTERNS_JS_TS
        events, diagnostics = (python_events(content, rules) if language == 'python'
                               else javascript_events(content, rules))
        self.diagnostics.extend({'file': str(file_path), 'error': error} for error in diagnostics)
        if any(error.startswith('Python parse error') for error in diagnostics):
            self.scanned_files_count -= 1
        for event in events:
            comment = event.get('comment', False)
            if comment and self.ignore_comments:
                continue
            if event.get('secret'):
                rule = next(r for r in rules if r['match_type'] == MatchType.EXPOSED_SECRET)
            else:
                rule = event.get('rule')
            if rule:
                algorithm, purpose, risk = rule['algorithm'], rule['purpose'], rule['quantum_risk']
                match_type = rule['match_type']
            else:
                algorithm, purpose, risk_name = event['identity']
                risk = QuantumRisk(risk_name)
                match_type = MatchType.CONFIRMED_CALL
            # Mode selection alone identifies a mode, not a cipher or key width.
            if algorithm == 'AES-ECB Mode':
                algorithm = 'Block cipher ECB'
            params = event.get('parameters', {})
            advice = rule.get('advice') if rule else None
            if algorithm in ('AES-GCM', 'AES'):
                bits = params.get('key_bits')
                risk = QuantumRisk.MODERATE_IMPACT if bits != 256 else QuantumRisk.QUANTUM_RESISTANT
                advice = ('AES-128 has a reduced quantum security margin; plan AES-256 for long-lived confidentiality.' if bits == 128 else
                          'Verify the actual AES key width and mode; missing parameters do not establish quantum resistance.' if bits is None else
                          'Review the observed AES key width and authenticated mode; avoid nonce reuse.')
            if comment:
                match_type = MatchType.COMMENT_ONLY
            from crypto_evidence import redact_evidence
            finding = Finding(
                file_path=str(file_path), line_number=event['line'], column_start=event['column'],
                detected_algorithm=algorithm, likely_purpose=purpose,
                confidence=Confidence.LOW if comment else (rule['confidence'] if rule else Confidence.HIGH),
                match_type=match_type, quantum_risk=risk, code_snippet=redact_evidence(event['snippet']),
                is_comment=comment,
                runtime_note=('Inactive comment reference.' if comment else
                              'Static syntax evidence; execution and runtime parameters require verification.'),
                migration_advice=advice,
                cwe_id=rule.get('cwe') if rule else None,
                parameters=params, evidence_type=event['evidence'])
            if self.quantum_only and risk not in (QuantumRisk.CRITICAL_VULNERABLE, QuantumRisk.MODERATE_IMPACT):
                continue
            self.findings.append(finding)

    def _scan_python_file(self, file_path, content, lines):
        self._structural_scan(file_path, content, 'python')

    def _scan_jsts_file(self, file_path, content, lines):
        self._structural_scan(file_path, content, 'javascript')


# ============================================================================
# REPORTING & CLI INTERFACE
# ============================================================================

class ScannerReporter:
    """Formats scanner findings into terminal text or JSON."""

    @staticmethod
    def print_terminal_report(scanner: CodeScanner, target_path: str) -> None:
        total_findings = len(scanner.findings)
        quantum_count = sum(
            1 for f in scanner.findings if f.quantum_risk == QuantumRisk.CRITICAL_VULNERABLE
        )
        secrets_count = sum(
            1 for f in scanner.findings if f.match_type == MatchType.EXPOSED_SECRET
        )
        comments_count = sum(1 for f in scanner.findings if f.is_comment)
        active_calls_count = sum(
            1 for f in scanner.findings if f.match_type == MatchType.CONFIRMED_CALL
        )

        header = "=" * 80
        print(f"\n{header}")
        print("  Q-SHIELD: SOURCE-CODE CRYPTOGRAPHY & QUANTUM MIGRATION SCANNER")
        print(f"{header}")
        print(f" Target Directory : {target_path}")
        print(f" Files Scanned    : {scanner.scanned_files_count}")
        print(f" Lines Scanned    : {scanner.scanned_lines_count:,}")
        print(f" Total Detections : {total_findings}")
        print(f"   |-- Quantum-Vulnerable (Shor's Algorithm) : {quantum_count}")
        print(f"   |-- Confirmed Active Cryptographic Calls  : {active_calls_count}")
        print(f"   |-- Hardcoded Key / Secret Exposures      : {secrets_count}")
        print(f"   \\-- Commented / Inactive Code Matches     : {comments_count}")
        print(f"{header}\n")

        if not scanner.findings:
            print(" No cryptographic APIs or vulnerabilities detected in scanned files.")
            print(f"{header}\n")
            return

        for idx, f in enumerate(scanner.findings, start=1):
            rel_path = f.file_path
            try:
                rel_path = os.path.relpath(f.file_path, os.getcwd())
            except ValueError:
                pass

            # Badge formatting
            q_badge = "[QUANTUM-VULNERABLE]" if f.quantum_risk == QuantumRisk.CRITICAL_VULNERABLE else (
                "[QUANTUM-RESISTANT]" if f.quantum_risk == QuantumRisk.QUANTUM_RESISTANT else "[CONVENTIONAL]"
            )
            conf_badge = f"[{f.confidence.value} CONFIDENCE]"
            comment_badge = " [COMMENTED/DEAD CODE]" if f.is_comment else ""

            print(f"[{idx}] {rel_path}:{f.line_number}:{f.column_start} {q_badge} {conf_badge}{comment_badge}")
            print(f"    Algorithm : {f.detected_algorithm}")
            print(f"    Purpose   : {f.likely_purpose}")
            print(f"    Match Type: {f.match_type.value}")
            print(f"    Snippet   : {f.code_snippet}")
            print(f"    Status    : {f.runtime_note}")
            if f.cwe_id:
                print(f"    CWE       : {f.cwe_id}")
            if f.migration_advice:
                print(f"    Migration : {f.migration_advice}")
            print("-" * 80)

        print("\n" + "=" * 80)
        print(" SCAN SUMMARY & RUNTIME DISTINCTION NOTE:")
        print(" - STATIC CONFIRMED CALL: Code explicitly invokes a cryptographic API.")
        print(" - STATIC MATCH ONLY: Library imported or declared, but not yet called on this line.")
        print(" - COMMENTED ONLY: Found in comments/docstrings; does not execute at runtime.")
        print(" - Quantum-Vulnerable findings (RSA/ECC/DH) must be migrated to NIST FIPS 203/204.")
        print("=" * 80 + "\n")

    @staticmethod
    def generate_json_report(scanner: CodeScanner, target_path: str) -> str:
        report_data = {
            "scanner": "Q-SHIELD Source-Code Cryptography Scanner",
            "version": "1.0.0",
            "target_path": str(target_path),
            "summary": {
                "scanned_files": scanner.scanned_files_count,
                "scanned_lines": scanner.scanned_lines_count,
                "total_findings": len(scanner.findings),
                "quantum_vulnerable_count": sum(
                    1 for f in scanner.findings if f.quantum_risk == QuantumRisk.CRITICAL_VULNERABLE
                ),
                "exposed_secrets_count": sum(
                    1 for f in scanner.findings if f.match_type == MatchType.EXPOSED_SECRET
                ),
                "commented_matches_count": sum(1 for f in scanner.findings if f.is_comment),
                "active_calls_count": sum(
                    1 for f in scanner.findings if f.match_type == MatchType.CONFIRMED_CALL
                ),
            },
            "findings": [f.to_dict() for f in scanner.findings],
        }
        return json.dumps(report_data, indent=2)


def scan_code(
    path: str | Path,
    ignore_comments: bool = False,
    quantum_only: bool = False
) -> Dict[str, Any]:
    """
    Programmatic entrypoint for risk_engine.py and main orchestrator.
    Scans a file or directory and returns a structured dictionary.
    
    Usage:
        from code_scanner import scan_code
        result = scan_code("./my_project")
    """
    scanner = CodeScanner(ignore_comments=ignore_comments, quantum_only=quantum_only)
    findings = scanner.scan_path(path)
    return {
        "target_path": str(path),
        "diagnostics": scanner.diagnostics,
        "coverage_status": "partial" if scanner.diagnostics else "complete",
        "summary": {
            "attempted_files": scanner.attempted_files_count,
            "scanned_files": scanner.scanned_files_count,
            "scanned_lines": scanner.scanned_lines_count,
            "total_findings": len(findings),
            "quantum_vulnerable_count": sum(
                1 for f in findings if f.quantum_risk == QuantumRisk.CRITICAL_VULNERABLE
            ),
            "exposed_secrets_count": sum(
                1 for f in findings if f.match_type == MatchType.EXPOSED_SECRET
            ),
            "commented_matches_count": sum(1 for f in findings if f.is_comment),
            "active_calls_count": sum(
                1 for f in findings if f.match_type == MatchType.CONFIRMED_CALL
            ),
        },
        "findings": [f.to_dict() for f in findings],
    }


# ============================================================================
# MAIN CLI ENTRYPOINT
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Q-SHIELD: Source-Code Cryptography & Quantum-Safe Migration Scanner"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository root path or individual file to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as structured JSON instead of human-readable text",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="File path to save the scan report (JSON or TXT)",
    )
    parser.add_argument(
        "--ignore-comments",
        action="store_true",
        help="Exclude matches located inside code comments and docstrings",
    )
    parser.add_argument(
        "--quantum-only",
        action="store_true",
        help="Only display findings that represent quantum-vulnerable cryptography (RSA, ECC, DH)",
    )
    parser.add_argument(
        "--fail-on-vulnerable",
        action="store_true",
        help="Exit with code 1 if quantum-vulnerable cryptography or exposed keys are detected (useful for CI/CD)",
    )

    args = parser.parse_args()

    scanner = CodeScanner(
        ignore_comments=args.ignore_comments,
        quantum_only=args.quantum_only,
    )

    try:
        scanner.scan_path(args.path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # Render output
    if args.json:
        report_json = ScannerReporter.generate_json_report(scanner, args.path)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(report_json)
            print(f"JSON scan report saved to {args.output}")
        else:
            print(report_json)
    else:
        ScannerReporter.print_terminal_report(scanner, args.path)
        if args.output:
            # Save plain text report to file
            import io
            from contextlib import redirect_stdout
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                ScannerReporter.print_terminal_report(scanner, args.path)
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(buffer.getvalue())
            print(f"Scan report saved to {args.output}")

    if args.fail_on_vulnerable:
        has_critical = any(
            f.quantum_risk == QuantumRisk.CRITICAL_VULNERABLE or f.match_type == MatchType.EXPOSED_SECRET
            for f in scanner.findings
        )
        if has_critical:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
