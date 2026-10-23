#!/usr/bin/env python3
"""
risk_engine.py - Cryptographic Risk Assessment & Migration Recommendation Engine.

Converts cryptographic inventory findings into defensible risk assessments,
strictly separating Quantum risks (governed by Shor's/Grover's algorithms,
Harvest-Now-Decrypt-Later, and Mosca's Theorem) from Conventional security weaknesses
(such as fast hashing for passwords, deprecated ciphers, and insecure modes).

Assigns mathematically grounded severity, evidence-backed confidence, priority scores,
and actionable migration recommendations with technical reasons.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

ENGINE_VERSION = "2.0.0"

# ============================================================================
# EMBEDDED DEFAULT RULES & FINDINGS
# ============================================================================

DEFAULT_RULES_JSON = """{
  "schema_version": 1,
  "ruleset_version": "2.0.0",
  "planning": {
    "scenario": "central",
    "crqc_years": {
      "conservative": 10,
      "central": 15,
      "relaxed": 25
    },
    "migration_years_default": 5,
    "unknown_lifetime_floor": "medium",
    "timeframe_by_severity": {
      "critical": "immediate",
      "high": "near_term",
      "medium": "planned",
      "low": "roadmap",
      "info": "monitor"
    }
  },
  "confidence": {
    "evidence_base": {
      "config": 3.0,
      "certificate": 3.0,
      "manual": 3.0,
      "network": 2.8,
      "static": 2.5,
      "binary": 2.0,
      "heuristic": 1.2,
      "unknown": 1.5
    },
    "thresholds": {
      "high": 2.5,
      "medium": 1.5
    }
  },
  "rules": [
    {
      "id": "RSA_SIGNATURE",
      "track": "quantum",
      "title": "RSA Digital Signature Vulnerable to Shor's Algorithm",
      "match": {
        "family": "rsa",
        "usage": "signature"
      },
      "severity_model": "signature_lifetime",
      "rationale": "Shor's algorithm computes integer prime factors in polynomial time on a Cryptanalytically Relevant Quantum Computer (CRQC), breaking the mathematical assumption underlying RSA signature authenticity.",
      "quantum_relevance": "Directly vulnerable to polynomial-time forgery via Shor's algorithm once a CRQC is realized.",
      "recommendation": {
        "action": "Initiate quantum migration planning to transition public-key digital signatures to NIST-standardized Post-Quantum Cryptography (PQC) signature algorithms.",
        "reason": "RSA signatures cannot withstand quantum cryptanalysis. Systems must migrate before long-lived certificates, trust anchors, or signed binaries outlive the CRQC horizon.",
        "alternatives": ["ML-DSA (FIPS 204 / Dilithium)", "SLH-DSA (FIPS 205 / SPHINCS+)", "LMS/XMSS (RFC 8554 / RFC 8391 for firmware/boot)"]
      }
    },
    {
      "id": "ECDSA_SIGNATURE",
      "track": "quantum",
      "title": "ECDSA Signature Vulnerable to Shor's Algorithm",
      "match": {
        "family": "ec_dsa",
        "usage": "signature"
      },
      "severity_model": "signature_lifetime",
      "rationale": "Shor's algorithm solves elliptic-curve discrete logarithms in polynomial time, completely compromising ECDSA private keys and enabling signature forgery.",
      "quantum_relevance": "Directly vulnerable via Shor's algorithm. All standard curves (NIST P-256, P-384, secp256k1) are broken.",
      "recommendation": {
        "action": "Transition to post-quantum signature schemes (NIST FIPS 204 ML-DSA or FIPS 205 SLH-DSA) or hybrid classical-quantum signatures.",
        "reason": "ECDSA provides zero security against quantum adversaries capable of running Shor's algorithm.",
        "alternatives": ["ML-DSA-44 / ML-DSA-65 (FIPS 204)", "SLH-DSA-SHA2-128s (FIPS 205)"]
      }
    },
    {
      "id": "ED25519_SIGNATURE",
      "track": "quantum",
      "title": "Ed25519 Signature Vulnerable to Shor's Algorithm",
      "match": {
        "family": "ed25519",
        "usage": "signature"
      },
      "severity_model": "signature_lifetime",
      "rationale": "Ed25519 (EdDSA over Curve25519) relies on the discrete logarithm problem over elliptic curves, which is solvable in polynomial time by Shor's algorithm.",
      "quantum_relevance": "Directly vulnerable to private key recovery and signature forgery via Shor's algorithm.",
      "recommendation": {
        "action": "Plan migration to stateful hash-based signatures for firmware or lattice-based ML-DSA for interactive protocols.",
        "reason": "Elliptic curve cryptography provides no defense against Shor's algorithm regardless of implementation robustness.",
        "alternatives": ["ML-DSA-65", "SLH-DSA"]
      }
    },
    {
      "id": "ECDH_KEY_EXCHANGE",
      "track": "quantum",
      "title": "ECDH Key Establishment Vulnerable to Harvest-Now-Decrypt-Later (HNDL)",
      "match": {
        "family": "ec_dh",
        "usage": "key_exchange"
      },
      "severity_model": "hndl",
      "rationale": "Elliptic Curve Diffie-Hellman (ECDH) is vulnerable to Shor's algorithm. Adversaries can record encrypted ciphertext today and decrypt it retrospectively when a CRQC becomes operational (Harvest-Now-Decrypt-Later).",
      "quantum_relevance": "Subject to immediate Harvest-Now-Decrypt-Later (HNDL) risk for any data whose confidentiality lifetime exceeds the CRQC horizon.",
      "recommendation": {
        "action": "Deploy hybrid post-quantum key encapsulation mechanisms (KEM) combining classical ECDH with ML-KEM (Kyber) or pure ML-KEM.",
        "reason": "Traffic captured today can be stored by adversaries and decrypted later. Long-lived confidential data requires immediate hybrid or post-quantum key encapsulation.",
        "alternatives": ["X25519MLKEM768 (hybrid)", "ML-KEM-768 (FIPS 203 / Kyber)", "ML-KEM-1024"]
      }
    },
    {
      "id": "DH_KEY_EXCHANGE",
      "track": "quantum",
      "title": "Finite-Field Diffie-Hellman Key Exchange Vulnerable to HNDL",
      "match": {
        "family": "dh",
        "usage": "key_exchange"
      },
      "severity_model": "hndl",
      "rationale": "Finite-field Diffie-Hellman (FFDHE) relies on the discrete logarithm problem in multiplicative groups of integers modulo a prime, which Shor's algorithm solves efficiently.",
      "quantum_relevance": "Vulnerable to retrospective decryption under Harvest-Now-Decrypt-Later threat models.",
      "recommendation": {
        "action": "Replace finite-field Diffie-Hellman with hybrid KEMs (e.g., X25519 + ML-KEM-768) or pure ML-KEM-768.",
        "reason": "Classical key exchange offers zero confidentiality protection against future quantum decryption of recorded traffic.",
        "alternatives": ["ML-KEM-768 (FIPS 203)", "X25519MLKEM768"]
      }
    },
    {
      "id": "AES128_QUANTUM_REDUCTION",
      "track": "quantum",
      "title": "AES-128 Effective Security Halved by Grover's Algorithm",
      "match": {
        "family": "aes",
        "key_bits": 128
      },
      "severity_model": "symmetric_quantum",
      "rationale": "Grover's search algorithm provides a quadratic speedup for brute-force key search, reducing the effective security of AES-128 from 128 bits to approximately 64 bits.",
      "quantum_relevance": "Grover's algorithm provides a square-root speedup (O(sqrt(N))), making 128-bit symmetric keys borderline for ultra-high-assurance or classified workloads.",
      "recommendation": {
        "action": "Upgrade symmetric encryption from AES-128 to AES-256 for long-term confidentiality.",
        "reason": "AES-256 maintains a comfortable 128-bit quantum security margin against Grover's algorithm, satisfying post-quantum security requirements (e.g., NSA CNSA 2.0).",
        "alternatives": ["AES-256-GCM", "ChaCha20-Poly1305 (256-bit)"]
      }
    },
    {
      "id": "AES256_QUANTUM_SAFE",
      "track": "quantum",
      "title": "AES-256 Symmetric Cipher is Quantum-Resistant",
      "match": {
        "family": "aes",
        "key_bits": 256
      },
      "severity_model": "static",
      "severity": "info",
      "rationale": "AES-256 provides 256 bits of classical security and 128 bits of post-quantum security against Grover's algorithm, which exceeds all foreseeable quantum computational brute-force bounds.",
      "quantum_relevance": "Quantum-resistant. Grover's algorithm reduces 256 bits to 128 bits of security, which is computationally infeasible to break.",
      "recommendation": {
        "action": "Retain AES-256 as the symmetric encryption standard; ensure it is deployed in AEAD modes (such as GCM).",
        "reason": "AES-256 meets NIST and NSA CNSA 2.0 requirements for post-quantum symmetric confidentiality.",
        "alternatives": []
      }
    },
    {
      "id": "SHA256_PASSWORD_STORAGE",
      "track": "conventional",
      "title": "Fast Hash Function (SHA-256) Inappropriately Used for Password Storage",
      "match": {
        "family": "sha2",
        "usage": "password_storage"
      },
      "severity_model": "static",
      "severity": "critical",
      "rationale": "SHA-256 is an unkeyed general-purpose cryptographic hash function engineered for rapid computation. It lacks memory-hardness and work factor controls, enabling adversaries to execute billions of guesses per second on consumer GPUs.",
      "quantum_relevance": "Conventional security vulnerability, NOT a quantum risk. Grover's algorithm is irrelevant; classical offline cracking tools (hashcat, John the Ripper) break unsalted or fast hashes effortlessly today.",
      "recommendation": {
        "action": "Replace SHA-256 password storage immediately with a standardized, memory-hard password-hashing function such as Argon2id, bcrypt, or scrypt.",
        "reason": "Password storage requires computational and memory hardness to defend against offline GPU/ASIC brute-force dictionary attacks. Post-quantum algorithms do not solve this problem.",
        "alternatives": ["Argon2id (RFC 9106, recommended)", "bcrypt (cost factor >= 12)", "scrypt"]
      }
    },
    {
      "id": "MD5_USAGE",
      "track": "conventional",
      "title": "Cryptographically Broken Hash Function MD5 in Active Use",
      "match": {
        "family": "md5"
      },
      "severity_model": "static",
      "severity": "critical",
      "rationale": "MD5 suffers from catastrophic collision vulnerabilities, allowing practical chosen-prefix collision attacks in seconds on commodity hardware.",
      "quantum_relevance": "Classical cryptanalytic failure, not a quantum issue. MD5 was broken classically in 2004.",
      "recommendation": {
        "action": "Migrate from MD5 to SHA-256, SHA-384, or SHA-3 for integrity checks and signatures.",
        "reason": "MD5 provides zero collision resistance. Attackers can forge valid certificates, signatures, or checksums.",
        "alternatives": ["SHA-256", "SHA-384", "SHA-3-256", "BLAKE3"]
      }
    },
    {
      "id": "SHA1_USAGE",
      "track": "conventional",
      "title": "Deprecated and Collision-Vulnerable Hash Function SHA-1 in Use",
      "match": {
        "family": "sha1"
      },
      "severity_model": "static",
      "severity": "high",
      "rationale": "SHA-1 has practical collision vulnerabilities (SHAttered, Shambles attacks) and has been formally deprecated by NIST (NIST SP 800-131A) and major web browsers.",
      "quantum_relevance": "Classical collision vulnerability. This is a conventional hygiene issue, not a post-quantum migration issue.",
      "recommendation": {
        "action": "Replace SHA-1 with modern hash algorithms such as SHA-256 or SHA-3.",
        "reason": "SHA-1 collisions allow attackers to produce colliding documents or certificates with identical signatures.",
        "alternatives": ["SHA-256", "SHA-384", "SHA-512"]
      }
    },
    {
      "id": "DES_OR_3DES_CIPHER",
      "track": "conventional",
      "title": "Legacy 64-Bit Block Cipher (DES / 3DES) in Use",
      "match": {
        "family": "des"
      },
      "severity_model": "static",
      "severity": "critical",
      "rationale": "DES and Triple-DES use an obsolete 64-bit block size, rendering them vulnerable to birthday collision attacks (Sweet32) in TLS and bulk encryption, alongside small key size limitations.",
      "quantum_relevance": "Classical block cipher vulnerability. Deprecated by NIST SP 800-131A Rev 2 since 2023.",
      "recommendation": {
        "action": "Decommission DES/3DES immediately and migrate to AES-256-GCM or ChaCha20-Poly1305.",
        "reason": "64-bit block ciphers leak plaintext after approximately 32 GB of data under the same key (Sweet32 attack).",
        "alternatives": ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]
      }
    },
    {
      "id": "RC4_CIPHER",
      "track": "conventional",
      "title": "Insecure Stream Cipher RC4 in Use",
      "match": {
        "family": "rc4"
      },
      "severity_model": "static",
      "severity": "critical",
      "rationale": "RC4 has multiple severe statistical biases in its keystream output (RC4 NOMORE attack), allowing practical plaintext recovery in TLS sessions.",
      "quantum_relevance": "Classical keystream bias vulnerability. Formally prohibited in TLS by RFC 7465.",
      "recommendation": {
        "action": "Disable RC4 across all cipher suites and migrate to modern authenticated ciphers.",
        "reason": "RC4 is completely insecure against passive classical eavesdroppers.",
        "alternatives": ["AES-256-GCM", "ChaCha20-Poly1305"]
      }
    },
    {
      "id": "ECB_MODE_USAGE",
      "track": "conventional",
      "title": "Insecure Electronic Codebook (ECB) Cipher Mode",
      "match": {
        "mode": "ecb"
      },
      "severity_model": "static",
      "severity": "high",
      "rationale": "Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical ciphertext blocks, preserving structural patterns and failing semantic security.",
      "quantum_relevance": "Mode of operation architectural failure, not a quantum issue.",
      "recommendation": {
        "action": "Switch from ECB mode to an Authenticated Encryption with Associated Data (AEAD) mode such as GCM or CCM.",
        "reason": "ECB mode leaks data confidentiality through structural pattern visibility and provides no message integrity.",
        "alternatives": ["GCM (Galois/Counter Mode)", "CCM", "ChaCha20-Poly1305"]
      }
    },
    {
      "id": "WEAK_RSA_KEY_LENGTH",
      "track": "conventional",
      "title": "Sub-2048 Bit RSA Key Vulnerable to Classical Factoring",
      "match": {
        "family": "rsa",
        "max_key_bits": 2047
      },
      "severity_model": "static",
      "severity": "critical",
      "rationale": "RSA keys smaller than 2048 bits (e.g., 512, 1024 bits) can be factored using classical General Number Field Sieve (GNFS) algorithms on academic or cloud compute resources.",
      "quantum_relevance": "Vulnerable to classical computers today, irrespective of future quantum advancements.",
      "recommendation": {
        "action": "Immediately revoke and replace sub-2048 bit RSA keys with at least RSA-2048/3072 or transition directly to PQC signatures.",
        "reason": "RSA-1024 was deprecated by NIST in 2013 and offers insufficient resistance against classical factoring clusters.",
        "alternatives": ["RSA-3072", "ML-DSA-65", "ECDSA P-256 (interim)"]
      }
    }
  ]
}"""

DEFAULT_FINDINGS_JSON = """{
  "findings": [
    {
      "id": "find-001",
      "asset": "api-gateway.corp.com",
      "algorithm": "RSA-2048",
      "usage": "signature",
      "trust_lifetime_years": 12.0,
      "migration_years": 4.0,
      "exposure": "internet",
      "criticality": "high",
      "evidence_source": "certificate"
    },
    {
      "id": "find-002",
      "asset": "customer-vpn-gateway",
      "algorithm": "ECDH P-256",
      "usage": "key_exchange",
      "data_lifetime_years": 15.0,
      "migration_years": 3.0,
      "exposure": "internet",
      "criticality": "critical",
      "evidence_source": "config"
    },
    {
      "id": "find-003",
      "asset": "identity-user-db",
      "algorithm": "SHA-256",
      "usage": "password_storage",
      "exposure": "internal",
      "criticality": "critical",
      "evidence_source": "static"
    },
    {
      "id": "find-004",
      "asset": "archival-storage-volume",
      "algorithm": "AES-128-CBC",
      "usage": "symmetric_encryption",
      "data_lifetime_years": 30.0,
      "exposure": "internal",
      "criticality": "high",
      "evidence_source": "config"
    },
    {
      "id": "find-005",
      "asset": "legacy-payment-terminal",
      "algorithm": "3DES-ECB",
      "usage": "symmetric_encryption",
      "exposure": "partner",
      "criticality": "critical",
      "evidence_source": "binary"
    }
  ]
}"""

# ============================================================================
# ENUMS & EXCEPTIONS
# ============================================================================

class RiskEngineError(Exception):
    """Base exception for Risk Engine errors."""


class FindingError(RiskEngineError):
    """Raised for malformed findings input."""


class RuleError(RiskEngineError):
    """Raised when rule configuration is malformed."""


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            names = [s.name.lower() for s in cls]
            raise RuleError(f"unknown severity {value!r}; expected one of {names}")

    def shift(self, delta: int, floor: Optional["Severity"] = None, ceiling: Optional["Severity"] = None) -> "Severity":
        lo = Severity.INFO if floor is None else floor
        hi = Severity.CRITICAL if ceiling is None else ceiling
        new_val = max(int(lo), min(int(hi), int(self) + delta))
        return Severity(new_val)


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: Any) -> "Confidence":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise RuleError(f"unknown confidence {value!r}; expected low|medium|high")


class Track(str, Enum):
    QUANTUM = "quantum"
    CONVENTIONAL = "conventional"
    INVENTORY = "inventory"


# ============================================================================
# DATA MODELS
# ============================================================================

EXPOSURE_ALIASES = {
    "internet": "internet", "public": "internet", "external": "internet",
    "partner": "partner", "dmz": "partner", "extranet": "partner",
    "internal": "internal", "intranet": "internal", "corp": "internal",
    "isolated": "isolated", "airgap": "isolated", "offline": "isolated",
}

CRITICALITY_VALUES = {"low", "medium", "high", "critical"}

_FINDING_KEYS = {
    "id", "asset", "algorithm", "usage", "key_bits", "data_lifetime_years",
    "trust_lifetime_years", "migration_years", "exposure", "criticality",
    "replaceable", "evidence_source", "location", "attributes", "context", "evidence"
}


def _as_years(name: str, value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise FindingError(f"{name} must be a number of years, got {value!r}")
    if v < 0:
        raise FindingError(f"{name} must be >= 0, got {value!r}")
    return v


def _as_bool(name: str, value: Any) -> Optional[bool]:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "1"):
        return True
    if isinstance(value, str) and value.strip().lower() in ("false", "no", "0"):
        return False
    raise FindingError(f"{name} must be a boolean, got {value!r}")


@dataclass
class Finding:
    id: str
    algorithm: str
    asset: str = "unknown"
    usage: Optional[str] = None
    key_bits: Optional[int] = None
    data_lifetime_years: Optional[float] = None
    trust_lifetime_years: Optional[float] = None
    migration_years: Optional[float] = None
    exposure: Optional[str] = None
    criticality: Optional[str] = None
    replaceable: Optional[bool] = None
    evidence_source: Optional[str] = None
    location: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Finding":
        if not isinstance(raw, dict):
            raise FindingError(f"Finding must be an object, got {type(raw).__name__}")
        d = dict(raw)
        attrs = dict(d.pop("attributes", None) or {})
        ctx = d.pop("context", None) or {}
        ev = d.pop("evidence", None) or {}
        if "source" in ev:
            ev = {**ev, "evidence_source": ev.pop("source")}
        merged = {**ctx, **ev, **d}
        for k in list(merged):
            if k not in _FINDING_KEYS:
                attrs[k] = merged.pop(k)

        fid = merged.get("id")
        algo = merged.get("algorithm")
        if not fid or not isinstance(fid, (str, int)):
            raise FindingError(f"Finding is missing a valid 'id': {raw!r}")
        if not algo or not isinstance(algo, str):
            raise FindingError(f"Finding {fid!r} is missing 'algorithm'")

        key_bits = merged.get("key_bits")
        if key_bits is not None:
            try:
                key_bits = int(key_bits)
            except (TypeError, ValueError):
                raise FindingError(f"Finding {fid!r}: key_bits must be an integer, got {key_bits!r}")

        exposure = merged.get("exposure")
        if exposure is not None:
            exposure = EXPOSURE_ALIASES.get(str(exposure).strip().lower(), str(exposure).strip().lower())

        crit = merged.get("criticality")
        if crit is not None:
            crit = str(crit).strip().lower()
            if crit not in CRITICALITY_VALUES:
                crit = "medium"

        src = merged.get("evidence_source")
        if src is not None:
            src = str(src).strip().lower()

        usage = merged.get("usage")
        if usage is not None:
            usage = str(usage).strip().lower()

        return cls(
            id=str(fid),
            algorithm=str(algo).strip(),
            asset=str(merged.get("asset") or "unknown"),
            usage=usage,
            key_bits=key_bits,
            data_lifetime_years=_as_years("data_lifetime_years", merged.get("data_lifetime_years")),
            trust_lifetime_years=_as_years("trust_lifetime_years", merged.get("trust_lifetime_years")),
            migration_years=_as_years("migration_years", merged.get("migration_years")),
            exposure=exposure,
            criticality=crit,
            replaceable=_as_bool("replaceable", merged.get("replaceable")),
            evidence_source=src,
            location=merged.get("location"),
            attributes=attrs,
        )


# ============================================================================
# ALGORITHM NORMALIZATION
# ============================================================================

@dataclass
class Normalized:
    family: str = "unknown"
    key_bits: Optional[int] = None
    curve: Optional[str] = None
    hash: Optional[str] = None
    mode: Optional[str] = None
    usage_hint: Optional[str] = None
    notes: List[str] = field(default_factory=list)


def normalize_algorithm(raw: str) -> Normalized:
    t = re.sub(r"[\s_]+", "-", str(raw).strip().lower())
    n = Normalized()
    if not t:
        return n

    # Modes detection
    for mode in ("gcm", "cbc", "ecb", "ctr", "cfb", "ofb", "ccm"):
        if f"-{mode}" in t or f"/{mode}" in t or t.endswith(f"-{mode}") or t.startswith(f"{mode}-"):
            n.mode = mode
            break
    if not n.mode and "-ecb" in t or "ecb" in t:
        n.mode = "ecb"

    # RSA
    if "rsa" in t:
        n.family = "rsa"
        n.usage_hint = "signature"
        bits_match = re.search(r"(\d{3,4})", t)
        if bits_match:
            n.key_bits = int(bits_match.group(1))
        return n

    # ECDSA & Ed25519
    if "ed25519" in t:
        n.family = "ed25519"
        n.curve = "curve25519"
        n.key_bits = 256
        n.usage_hint = "signature"
        return n

    if "ecdsa" in t:
        n.family = "ec_dsa"
        n.usage_hint = "signature"
        if "p-256" in t or "p256" in t or "secp256r1" in t or "prime256v1" in t:
            n.curve = "p-256"
            n.key_bits = 256
        elif "p-384" in t or "p384" in t or "secp384r1" in t:
            n.curve = "p-384"
            n.key_bits = 384
        elif "p-521" in t or "p521" in t or "secp521r1" in t:
            n.curve = "p-521"
            n.key_bits = 521
        elif "secp256k1" in t or "256k1" in t:
            n.curve = "secp256k1"
            n.key_bits = 256
        return n

    # ECDH & DH
    if "ecdh" in t or "x25519" in t:
        n.family = "ec_dh"
        n.usage_hint = "key_exchange"
        if "x25519" in t:
            n.curve = "x25519"
            n.key_bits = 256
        elif "p-256" in t or "p256" in t or "secp256r1" in t:
            n.curve = "p-256"
            n.key_bits = 256
        elif "p-384" in t or "p384" in t:
            n.curve = "p-384"
            n.key_bits = 384
        return n

    if re.search(r"\b(dh|diffie-hellman|ffdhe)\b", t):
        n.family = "dh"
        n.usage_hint = "key_exchange"
        bits_match = re.search(r"(\d{3,4})", t)
        if bits_match:
            n.key_bits = int(bits_match.group(1))
        return n

    # Hash functions: SHA-256, SHA-512, SHA-1, MD5
    if "sha-256" in t or "sha256" in t:
        n.family = "sha2"
        n.hash = "sha256"
        n.key_bits = 256
        return n

    if "sha-512" in t or "sha512" in t or "sha-384" in t or "sha384" in t:
        n.family = "sha2"
        n.hash = "sha512" if "512" in t else "sha384"
        return n

    if "sha-1" in t or "sha1" in t:
        n.family = "sha1"
        n.hash = "sha1"
        return n

    if "md5" in t:
        n.family = "md5"
        n.hash = "md5"
        return n

    # Symmetric: AES, 3DES, DES, RC4
    if "3des" in t or "tripledes" in t or "des-ede" in t or "desede" in t:
        n.family = "des"
        n.key_bits = 168
        n.usage_hint = "symmetric_encryption"
        return n

    if re.search(r"\bdes\b", t):
        n.family = "des"
        n.key_bits = 56
        n.usage_hint = "symmetric_encryption"
        return n

    if "rc4" in t or "arcfour" in t:
        n.family = "rc4"
        n.usage_hint = "symmetric_encryption"
        return n

    if "aes" in t:
        n.family = "aes"
        n.usage_hint = "symmetric_encryption"
        if "128" in t:
            n.key_bits = 128
        elif "192" in t:
            n.key_bits = 192
        elif "256" in t:
            n.key_bits = 256
        return n

    # Argon2 / Bcrypt / Scrypt
    if "argon2" in t:
        n.family = "argon2"
        n.usage_hint = "password_storage"
        return n

    if "bcrypt" in t:
        n.family = "bcrypt"
        n.usage_hint = "password_storage"
        return n

    return n


@dataclass
class NormalizedFinding:
    finding: Finding
    family: str
    key_bits: Optional[int]
    curve: Optional[str]
    hash: Optional[str]
    mode: Optional[str]
    usage: Optional[str]
    exposure: Optional[str]
    criticality: Optional[str]
    data_lifetime_years: Optional[float]
    trust_lifetime_years: Optional[float]
    migration_years: Optional[float]
    notes: List[str] = field(default_factory=list)


def normalize_finding(f: Finding) -> NormalizedFinding:
    n = normalize_algorithm(f.algorithm)
    usage = f.usage or n.usage_hint

    return NormalizedFinding(
        finding=f,
        family=n.family,
        key_bits=f.key_bits or n.key_bits,
        curve=n.curve,
        hash=n.hash,
        mode=n.mode,
        usage=usage,
        exposure=f.exposure,
        criticality=f.criticality,
        data_lifetime_years=f.data_lifetime_years,
        trust_lifetime_years=f.trust_lifetime_years,
        migration_years=f.migration_years,
        notes=n.notes
    )


# ============================================================================
# RULES & PLANNING
# ============================================================================

@dataclass(frozen=True)
class RecommendationDef:
    action: str
    reason: str
    timeframe: str = "by_severity"
    alternatives: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    track: Track
    title: str
    match: Dict[str, Any]
    severity_model: str
    rationale: str
    recommendation: RecommendationDef
    severity: Optional[Severity] = None
    quantum_relevance: Optional[str] = None


@dataclass
class PlanningConfig:
    scenario: str
    crqc_years: float
    migration_years_default: float
    unknown_lifetime_floor: str
    timeframe_by_severity: Dict[Severity, str]


@dataclass
class ConfidenceConfig:
    evidence_base: Dict[str, float]
    threshold_high: float
    threshold_medium: float


@dataclass
class RuleSet:
    version: str
    rules: List[Rule]
    planning_cfg: Dict[str, Any]
    confidence_cfg: Dict[str, Any]
    sha256: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any], raw_json: str = "") -> "RuleSet":
        rules: List[Rule] = []
        for r in data.get("rules", []):
            rec = r.get("recommendation", {})
            alts = tuple(rec.get("alternatives", []))
            rules.append(Rule(
                id=r["id"],
                track=Track(r["track"]),
                title=r["title"],
                match=r["match"],
                severity_model=r.get("severity_model", "static"),
                severity=Severity.parse(r["severity"]) if "severity" in r else None,
                rationale=r.get("rationale", ""),
                recommendation=RecommendationDef(
                    action=rec.get("action", ""),
                    reason=rec.get("reason", ""),
                    timeframe=rec.get("timeframe", "by_severity"),
                    alternatives=alts
                ),
                quantum_relevance=r.get("quantum_relevance")
            ))

        rs = cls(
            version=data.get("ruleset_version", "1.0.0"),
            rules=rules,
            planning_cfg=data.get("planning", {}),
            confidence_cfg=data.get("confidence", {})
        )
        if raw_json:
            rs.sha256 = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        return rs

    @classmethod
    def load_from_json_string(cls, json_str: str) -> "RuleSet":
        data = json.loads(json_str)
        return cls.from_dict(data, raw_json=json_str)

    @classmethod
    def load_from_file(cls, path: Union[str, Path]) -> "RuleSet":
        text = Path(path).read_text(encoding="utf-8")
        return cls.load_from_json_string(text)

    def build_planning(self, scenario_override: Optional[str] = None) -> PlanningConfig:
        cfg = self.planning_cfg
        scenario = scenario_override or cfg.get("scenario", "central")
        crqc_map = cfg.get("crqc_years", {"conservative": 10, "central": 15, "relaxed": 25})
        crqc_years = float(crqc_map.get(scenario, 15))
        mig_def = float(cfg.get("migration_years_default", 5))
        floor = str(cfg.get("unknown_lifetime_floor", "medium"))
        tf_map = {
            Severity.CRITICAL: "immediate",
            Severity.HIGH: "near_term",
            Severity.MEDIUM: "planned",
            Severity.LOW: "roadmap",
            Severity.INFO: "monitor"
        }
        return PlanningConfig(
            scenario=scenario,
            crqc_years=crqc_years,
            migration_years_default=mig_def,
            unknown_lifetime_floor=floor,
            timeframe_by_severity=tf_map
        )

    def build_confidence_config(self) -> ConfidenceConfig:
        cfg = self.confidence_cfg
        base = {
            "config": 3.0,
            "certificate": 3.0,
            "manual": 3.0,
            "network": 2.8,
            "static": 2.5,
            "binary": 2.0,
            "heuristic": 1.2,
            "unknown": 1.5,
        }
        base.update(cfg.get("evidence_base", {}))
        thresh = cfg.get("thresholds", {})
        return ConfidenceConfig(
            evidence_base=base,
            threshold_high=float(thresh.get("high", 2.5)),
            threshold_medium=float(thresh.get("medium", 1.5))
        )


# ============================================================================
# RULE MATCHING
# ============================================================================

def rule_matches(match: Dict[str, Any], nf: NormalizedFinding) -> bool:
    for key, expected in match.items():
        if key == "max_key_bits":
            actual = nf.key_bits
            if actual is None or actual > expected:
                return False
        elif key == "min_key_bits":
            actual = nf.key_bits
            if actual is None or actual < expected:
                return False
        else:
            actual = getattr(nf, key, None)
            if actual is None and key in nf.finding.attributes:
                actual = nf.finding.attributes[key]
            if actual != expected:
                return False
    return True


# ============================================================================
# EVALUATION & SEVERITY / CONFIDENCE / PRIORITY ENGINES
# ============================================================================

@dataclass
class ThreatAnalysis:
    model: str
    mosca_delta: Optional[float] = None
    data_shelf_life: Optional[float] = None
    migration_window: Optional[float] = None
    crqc_horizon: Optional[float] = None
    details: str = ""


@dataclass
class Assessment:
    assessment_id: str
    finding_id: str
    asset: str
    algorithm: str
    track: Track
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    confidence_score: float
    confidence_rationale: str
    priority: float
    rationale: str
    quantum_relevance: Optional[str]
    threat_analysis: ThreatAnalysis
    recommendation: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "finding_id": self.finding_id,
            "asset": self.asset,
            "algorithm": self.algorithm,
            "track": self.track.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "confidence": self.confidence.name.lower(),
            "confidence_score": round(self.confidence_score, 2),
            "confidence_rationale": self.confidence_rationale,
            "priority": round(self.priority, 1),
            "rationale": self.rationale,
            "quantum_relevance": self.quantum_relevance,
            "threat_analysis": {
                "model": self.threat_analysis.model,
                "mosca_delta": self.threat_analysis.mosca_delta,
                "data_shelf_life": self.threat_analysis.data_shelf_life,
                "migration_window": self.threat_analysis.migration_window,
                "crqc_horizon": self.threat_analysis.crqc_horizon,
                "details": self.threat_analysis.details,
            },
            "recommendation": self.recommendation,
        }


class RiskEngine:
    """Core Cryptographic Risk & Migration Engine."""

    def __init__(self, rules: RuleSet, scenario: Optional[str] = None):
        self.rules = rules
        self.planning = rules.build_planning(scenario)
        self.conf_cfg = rules.build_confidence_config()

    def evaluate_confidence(self, nf: NormalizedFinding) -> Tuple[Confidence, float, str]:
        """Compute defensible confidence based on evidence provenance and completeness."""
        src = (nf.finding.evidence_source or "unknown").lower()
        base = self.conf_cfg.evidence_base.get(src, 1.5)
        adjustments = []

        score = base

        # Check specificity of algorithm info
        if nf.family != "unknown":
            score += 0.2
            adjustments.append("+0.2 known family")
        else:
            score -= 0.4
            adjustments.append("-0.4 unknown family")

        if nf.key_bits is not None or nf.curve is not None:
            score += 0.2
            adjustments.append("+0.2 explicit key/curve")

        if nf.usage:
            score += 0.1
            adjustments.append("+0.1 explicit usage")
        else:
            score -= 0.2
            adjustments.append("-0.2 inferred usage")

        # Cap score between 0.5 and 3.5
        score = max(0.5, min(3.5, score))

        if score >= self.conf_cfg.threshold_high:
            conf = Confidence.HIGH
        elif score >= self.conf_cfg.threshold_medium:
            conf = Confidence.MEDIUM
        else:
            conf = Confidence.LOW

        rat = f"Base {base:.1f} ({src}); adjustments: {', '.join(adjustments)} -> final {score:.2f} ({conf.name})"
        return conf, score, rat

    def evaluate_severity_and_threat(
        self, rule: Rule, nf: NormalizedFinding
    ) -> Tuple[Severity, ThreatAnalysis]:
        """
        Derive defensible severity using mathematical and threat-modeling rules:
        - HNDL: Mosca's Theorem (X + Y > Z)
        - Signature Lifetime: Trust lifetime + migration vs CRQC horizon
        - Symmetric Quantum: Grover key reduction
        - Static / Conventional: Classical vulnerability severity + environmental adjustments
        """
        model = rule.severity_model
        Z = self.planning.crqc_years
        Y = nf.migration_years if nf.migration_years is not None else self.planning.migration_years_default

        if model == "hndl":
            X = nf.data_lifetime_years
            if X is not None:
                mosca_sum = X + Y
                delta = mosca_sum - Z
                if delta >= 5.0:
                    sev = Severity.CRITICAL
                    details = (
                        f"Mosca's Theorem: Data lifetime X ({X}y) + Migration Y ({Y}y) = {mosca_sum}y exceeds "
                        f"CRQC horizon Z ({Z}y) by {delta:.1f}y. Critical HNDL exposure window."
                    )
                elif delta > 0:
                    sev = Severity.HIGH
                    details = (
                        f"Mosca's Theorem: X+Y ({mosca_sum}y) exceeds CRQC horizon Z ({Z}y) by {delta:.1f}y. "
                        f"Adversaries harvesting today will decrypt sensitive data in year {Z}."
                    )
                elif (Z - mosca_sum) <= 3.0:
                    sev = Severity.MEDIUM
                    details = (
                        f"Mosca's Theorem: X+Y ({mosca_sum}y) <= CRQC Z ({Z}y), but tight buffer of {Z - mosca_sum:.1f}y "
                        f"requires active migration roadmap."
                    )
                else:
                    sev = Severity.LOW
                    details = (
                        f"Mosca's Theorem: X+Y ({mosca_sum}y) is within CRQC Z ({Z}y) with comfortable safety margin "
                        f"of {Z - mosca_sum:.1f}y."
                    )
                threat = ThreatAnalysis(
                    model="hndl",
                    mosca_delta=delta,
                    data_shelf_life=X,
                    migration_window=Y,
                    crqc_horizon=Z,
                    details=details
                )
            else:
                sev = Severity.MEDIUM
                details = (
                    f"Data lifetime unspecified. Defaulting to MEDIUM severity floor under central scenario (Z={Z}y). "
                    f"Recommend auditing data retention policies."
                )
                threat = ThreatAnalysis(
                    model="hndl",
                    mosca_delta=None,
                    data_shelf_life=None,
                    migration_window=Y,
                    crqc_horizon=Z,
                    details=details
                )

        elif model == "signature_lifetime":
            T = nf.trust_lifetime_years
            if T is not None:
                total_trust = T + Y
                delta = total_trust - Z
                if T >= Z:
                    sev = Severity.CRITICAL
                    details = (
                        f"Signature trust validity T ({T}y) outlives CRQC horizon Z ({Z}y). "
                        f"Artifacts/certificates will remain active and vulnerable to real-time quantum forgery."
                    )
                elif total_trust > Z:
                    sev = Severity.HIGH
                    details = (
                        f"Trust validity T ({T}y) + Migration Y ({Y}y) = {total_trust}y exceeds CRQC horizon Z ({Z}y). "
                        f"Migration cannot complete before quantum risk materializes."
                    )
                else:
                    sev = Severity.MEDIUM
                    details = (
                        f"Trust validity T ({T}y) + Migration Y ({Y}y) = {total_trust}y is within CRQC Z ({Z}y). "
                        f"Scheduled quantum migration recommended."
                    )
                threat = ThreatAnalysis(
                    model="signature_lifetime",
                    mosca_delta=delta,
                    data_shelf_life=T,
                    migration_window=Y,
                    crqc_horizon=Z,
                    details=details
                )
            else:
                # Without explicit trust lifetime, public internet exposure elevates risk
                if nf.exposure == "internet":
                    sev = Severity.HIGH
                    details = "Internet-exposed public signature anchor without explicit trust lifetime; assigned HIGH."
                else:
                    sev = Severity.MEDIUM
                    details = "Internal signature finding without explicit trust lifetime; assigned MEDIUM."
                threat = ThreatAnalysis(
                    model="signature_lifetime",
                    mosca_delta=None,
                    data_shelf_life=None,
                    migration_window=Y,
                    crqc_horizon=Z,
                    details=details
                )

        elif model == "symmetric_quantum":
            bits = nf.key_bits or 128
            effective_q_bits = bits / 2.0
            if bits <= 128:
                sev = Severity.MEDIUM
                details = (
                    f"Grover's algorithm reduces {bits}-bit symmetric key to {effective_q_bits:.0f}-bit effective quantum security. "
                    f"Insufficient for classified or multi-decade confidentiality."
                )
            else:
                sev = Severity.INFO
                details = f"Key length {bits} bits provides {effective_q_bits:.0f}-bit quantum security under Grover's algorithm (quantum safe)."
            threat = ThreatAnalysis(model="symmetric_quantum", details=details)

        else:
            # Static conventional or baseline rule
            sev = rule.severity or Severity.HIGH
            details = f"Static security rule: {rule.title}."
            threat = ThreatAnalysis(model="static", details=details)

        # Environmental & Exposure adjustments
        # Internet exposure or critical asset escalates lower severities
        if nf.exposure == "internet" and sev == Severity.MEDIUM and rule.track == Track.CONVENTIONAL:
            sev = Severity.HIGH
            threat.details += " [Escalated to HIGH due to direct Internet exposure]."

        return sev, threat

    def calculate_priority(
        self,
        sev: Severity,
        conf_score: float,
        exposure: Optional[str],
        criticality: Optional[str],
        threat: ThreatAnalysis
    ) -> float:
        """
        Defensible Priority Score (0.0 - 100.0) synthesized from:
        - Severity points (up to 50 pts)
        - Exposure points (up to 25 pts)
        - Asset Criticality points (up to 20 pts)
        - Mosca Urgency boost (up to 5 pts)
        - Scaled by Evidence Confidence Multiplier
        """
        sev_points = {
            Severity.CRITICAL: 50.0,
            Severity.HIGH: 35.0,
            Severity.MEDIUM: 20.0,
            Severity.LOW: 10.0,
            Severity.INFO: 0.0,
        }.get(sev, 10.0)

        exp_points = {
            "internet": 25.0,
            "partner": 15.0,
            "internal": 10.0,
            "isolated": 5.0,
        }.get(exposure or "internal", 10.0)

        crit_points = {
            "critical": 20.0,
            "high": 15.0,
            "medium": 10.0,
            "low": 5.0,
        }.get(criticality or "medium", 10.0)

        urgency_boost = 0.0
        if threat.mosca_delta is not None and threat.mosca_delta > 0:
            urgency_boost = min(5.0, threat.mosca_delta)

        raw_score = sev_points + exp_points + crit_points + urgency_boost

        # Confidence weight: low confidence discounts priority slightly to prioritize verified findings
        conf_weight = min(1.0, max(0.5, conf_score / 3.0))
        final_priority = raw_score * conf_weight
        return max(0.0, min(100.0, final_priority))

    def assess_finding(self, finding: Finding) -> List[Assessment]:
        """Convert a single finding into defensible risk assessments."""
        nf = normalize_finding(finding)
        assessments: List[Assessment] = []

        conf, conf_score, conf_rat = self.evaluate_confidence(nf)

        for rule in self.rules.rules:
            if rule_matches(rule.match, nf):
                sev, threat = self.evaluate_severity_and_threat(rule, nf)
                priority = self.calculate_priority(sev, conf_score, nf.exposure, nf.criticality, threat)

                # Determine recommendation timeframe
                tf = rule.recommendation.timeframe
                if tf == "by_severity":
                    tf = self.planning.timeframe_by_severity.get(sev, "planned")

                rec_data = {
                    "action": rule.recommendation.action,
                    "reason": rule.recommendation.reason,
                    "timeframe": tf,
                    "alternatives": list(rule.recommendation.alternatives),
                    "track": rule.track.value
                }

                a = Assessment(
                    assessment_id=f"{finding.id}::{rule.id}",
                    finding_id=finding.id,
                    asset=finding.asset,
                    algorithm=finding.algorithm,
                    track=rule.track,
                    rule_id=rule.id,
                    title=rule.title,
                    severity=sev,
                    confidence=conf,
                    confidence_score=conf_score,
                    confidence_rationale=conf_rat,
                    priority=priority,
                    rationale=rule.rationale,
                    quantum_relevance=rule.quantum_relevance,
                    threat_analysis=threat,
                    recommendation=rec_data
                )
                assessments.append(a)

        return assessments

    def assess(self, findings: Iterable[Union[Finding, Dict[str, Any]]]) -> Report:
        """Process a collection of findings and return a structured Report."""
        parsed: List[Finding] = [
            f if isinstance(f, Finding) else Finding.from_dict(f) for f in findings
        ]

        all_assessments: List[Assessment] = []
        for f in parsed:
            all_assessments.extend(self.assess_finding(f))

        # Sort assessments by priority descending
        all_assessments.sort(key=lambda x: x.priority, reverse=True)
        return Report(assessments=all_assessments, planning=self.planning, ruleset_version=self.rules.version)


# ============================================================================
# REPORT GENERATION & FORMATTING
# ============================================================================

@dataclass
class Report:
    assessments: List[Assessment]
    planning: PlanningConfig
    ruleset_version: str

    def filter(
        self,
        track: Optional[Track] = None,
        min_severity: Optional[Severity] = None
    ) -> "Report":
        filtered = self.assessments
        if track:
            filtered = [a for a in filtered if a.track == track]
        if min_severity is not None:
            filtered = [a for a in filtered if int(a.severity) >= int(min_severity)]
        return Report(assessments=filtered, planning=self.planning, ruleset_version=self.ruleset_version)

    def summary_stats(self) -> Dict[str, Any]:
        sev_counts = {s.name.lower(): 0 for s in Severity}
        track_counts = {t.value: 0 for t in Track}
        conf_counts = {c.name.lower(): 0 for c in Confidence}

        for a in self.assessments:
            sev_counts[a.severity.name.lower()] += 1
            track_counts[a.track.value] += 1
            conf_counts[a.confidence.name.lower()] += 1

        return {
            "total_assessments": len(self.assessments),
            "severity": sev_counts,
            "track": track_counts,
            "confidence": conf_counts,
            "scenario": self.planning.scenario,
            "crqc_horizon_years": self.planning.crqc_years
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "engine_version": ENGINE_VERSION,
                "ruleset_version": self.ruleset_version,
                "planning_scenario": self.planning.scenario,
                "crqc_years": self.planning.crqc_years
            },
            "summary": self.summary_stats(),
            "assessments": [a.to_dict() for a in self.assessments]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        stats = self.summary_stats()
        out: List[str] = [
            "# Cryptographic Risk & Migration Assessment Report",
            "",
            f"**Engine Version:** `{ENGINE_VERSION}` | **Ruleset Version:** `{self.ruleset_version}` | "
            f"**Planning Scenario:** `{self.planning.scenario.title()}` (CRQC Horizon: **{self.planning.crqc_years:.0f} years**)",
            "",
            "## Executive Summary",
            "",
            "| Metric | Count | Category Breakdown |",
            "| :--- | :---: | :--- |",
            f"| **Total Findings Assessed** | **{stats['total_assessments']}** | Quantum: **{stats['track']['quantum']}** | Conventional: **{stats['track']['conventional']}** |",
            f"| **Critical Severity** | **{stats['severity']['critical']}** | Immediate action required |",
            f"| **High Severity** | **{stats['severity']['high']}** | Near-term remediation target |",
            f"| **Medium Severity** | **{stats['severity']['medium']}** | Planned architecture roadmap |",
            f"| **Low / Info Severity** | **{stats['severity']['low'] + stats['severity']['info']}** | Low priority / Quantum-safe baseline |",
            "",
            "> [!IMPORTANT]",
            "> **Separation of Tracks**: Quantum migration rules protect against Shor's and Grover's algorithms (Harvest-Now-Decrypt-Later). "
            "Conventional rules address classical cryptographic flaws (such as fast hashing for passwords, weak keys, or deprecated ciphers). "
            "Conventional security weaknesses are **never** solved by post-quantum cryptographic migration.",
            "",
            "---",
            "",
            "## Detailed Assessments by Priority",
            ""
        ]

        # Group by Track for absolute clarity
        quantum_assessments = [a for a in self.assessments if a.track == Track.QUANTUM]
        conventional_assessments = [a for a in self.assessments if a.track == Track.CONVENTIONAL]

        if quantum_assessments:
            out.append("### Track A: Post-Quantum Cryptography (PQC) Migration")
            out.append("")
            for a in quantum_assessments:
                out.extend(self._format_assessment_md(a))

        if conventional_assessments:
            out.append("### Track B: Conventional Cryptographic & Hygiene Weaknesses")
            out.append("")
            for a in conventional_assessments:
                out.extend(self._format_assessment_md(a))

        return "\n".join(out)

    def _format_assessment_md(self, a: Assessment) -> List[str]:
        lines: List[str] = [
            f"#### [{a.severity.name}] `{a.rule_id}`: {a.title}",
            f"- **Asset:** `{a.asset}` | **Algorithm:** `{a.algorithm}` | **Priority Score:** `{a.priority:.1f}/100`",
            f"- **Threat Rationale:** {a.rationale}",
        ]
        if a.threat_analysis.details:
            lines.append(f"- **Threat & Horizon Model:** {a.threat_analysis.details}")
        if a.quantum_relevance:
            lines.append(f"- **Quantum Relevance:** {a.quantum_relevance}")

        lines.append(
            f"- **Confidence:** `{a.confidence.name}` ({a.confidence_score:.2f}/3.0) — *{a.confidence_rationale}*"
        )

        rec = a.recommendation
        lines.append(f"- **Recommendation (`{rec['timeframe'].upper()}`):** {rec['action']}")
        lines.append(f"  - **Defensible Reason:** {rec['reason']}")
        if rec.get("alternatives"):
            alts_str = ", ".join(f"`{x}`" for x in rec["alternatives"])
            lines.append(f"  - **Standardized Alternatives:** {alts_str}")
        lines.append("")
        return lines


# ============================================================================
# CLI INTERFACE
# ============================================================================

def build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="risk_engine.py",
        description="Cryptographic Risk Assessment and Migration Recommendation Engine."
    )
    p.add_argument(
        "findings",
        nargs="?",
        help="Path to JSON file containing inventory findings. Uses embedded representative findings if omitted."
    )
    p.add_argument(
        "--rules",
        "-r",
        help="Path to external rules JSON file. Uses embedded default rules if omitted."
    )
    p.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Output report format (default: markdown)."
    )
    p.add_argument(
        "--scenario",
        "-s",
        choices=["conservative", "central", "relaxed"],
        default="central",
        help="CRQC timeline scenario (conservative: 10y, central: 15y, relaxed: 25y)."
    )
    p.add_argument(
        "--track",
        "-t",
        choices=["all", "quantum", "conventional"],
        default="all",
        help="Filter assessments by risk track (default: all)."
    )
    p.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity threshold to report."
    )
    p.add_argument(
        "--output",
        "-o",
        help="Save report to specified output file path."
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    # 1. Load RuleSet
    if args.rules:
        try:
            rules = RuleSet.load_from_file(args.rules)
        except Exception as e:
            sys.stderr.write(f"Error loading rules from {args.rules}: {e}\n")
            return 1
    else:
        rules = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)

    # 2. Initialize Engine
    engine = RiskEngine(rules, scenario=args.scenario)

    # 3. Load Findings
    if args.findings:
        try:
            text = Path(args.findings).read_text(encoding="utf-8")
            raw_data = json.loads(text)
            findings_data = raw_data.get("findings", raw_data if isinstance(raw_data, list) else [])
        except Exception as e:
            sys.stderr.write(f"Error reading findings from {args.findings}: {e}\n")
            return 1
    else:
        sys.stderr.write("[*] No findings file provided. Running on embedded representative dataset...\n\n")
        findings_data = json.loads(DEFAULT_FINDINGS_JSON).get("findings", [])

    # 4. Execute Assessment
    report = engine.assess(findings_data)

    # 5. Apply CLI Filters
    track_filter = Track(args.track) if args.track != "all" else None
    min_sev = Severity.parse(args.min_severity) if args.min_severity else None
    filtered_report = report.filter(track=track_filter, min_severity=min_sev)

    # 6. Format Output
    output_text = (
        filtered_report.to_markdown() if args.format == "markdown" else filtered_report.to_json()
    )

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        sys.stderr.write(f"Report saved to {args.output}\n")
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
