# 📋 Q-SHIELD Shared Finding Schema & Contract Specification

This document defines the official, shared contract and schema agreed upon across all five engineering roles for the Q-SHIELD Cryptographic Post-Quantum Migration and Risk Engine.

> **Team Immutability Notice**: Once merged into `integration`, modifications to field names, types, or enumeration values require cross-member agreement and corresponding adapter updates to maintain integration stability.

---

## 🏛️ Pipeline Data Flow Architecture

```
┌────────────────────────┐      ┌─────────────────────────┐
│  Network TLS Scanner   │      │ Static Code AST Scanner │
│   (tls_scanner.py)     │      │    (code_scanner.py)    │
│       Member 1         │      │        Member 1         │
└───────────┬────────────┘      └────────────┬────────────┘
            │ Raw Dict                       │ Raw Dict
            ▼                                ▼
┌─────────────────────────────────────────────────────────┐
│           Adapters & Normalization Engine               │
│                    (adapters.py)                        │
│                 Member 4 & Member 5                     │
└───────────────────────────┬─────────────────────────────┘
                            │ Standardized Finding Objects
                            ▼
┌─────────────────────────────────────────────────────────┐
│         Defensible Risk & PQC Migration Engine          │
│                   (risk_engine.py)                      │
│                       Member 3                          │
└───────────────────────────┬─────────────────────────────┘
                            │ Standardized Assessment & Report
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Presentation & Export Layer                │
│    Terminal CLI / JSON Export / React 18 Dashboard      │
│            (main.py / dashboard.py / web)               │
└─────────────────────────────────────────────────────────┘
```

---

## 1. Scanner Layer Output Schemas

### 1.1 TLS Scanner Raw Schema (`tls_scanner.py`)
Each TLS scan produces a structured dictionary with telemetry facts (zero risk assignment):
```json
{
  "module": "tls_scanner",
  "schema_version": "1.0",
  "scan_status": "ok | partial | failed",
  "target": {
    "host": "api.example.com",
    "port": 443,
    "input": "api.example.com:443"
  },
  "connection": {
    "tls_version": "TLSv1.3",
    "alpn_protocol": "h2",
    "ip_address": "93.184.216.34"
  },
  "cipher_suite": {
    "name": "TLS_AES_256_GCM_SHA384",
    "protocol": "TLSv1.3",
    "secret_bits": 256,
    "encryption": "aes-256-gcm",
    "mac_or_aead": "AEAD"
  },
  "key_exchange": {
    "method": "ECDHE",
    "group": "X25519",
    "forward_secrecy": true,
    "post_quantum_or_hybrid_group": false,
    "note": "Standard classical Curve25519; vulnerable to HNDL."
  },
  "certificate": {
    "subject": {"common_name": "api.example.com"},
    "issuer": {"common_name": "DigiCert Global Root G2"},
    "public_key": {
      "algorithm": "ECDSA",
      "key_size_bits": 256,
      "curve": "secp256r1"
    },
    "signature": {"algorithm": "ecdsa-with-SHA256"},
    "days_until_expiry": 180,
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z"
  },
  "supported_protocols": {
    "TLSv1.0": false,
    "TLSv1.1": false,
    "TLSv1.2": true,
    "TLSv1.3": true
  },
  "errors": []
}
```

### 1.2 Code Scanner Raw Schema (`code_scanner.py`)
Each AST / regex code detection is packaged into a findings array:
```json
{
  "target_path": "sample_vulnerable_app",
  "summary": {
    "scanned_files": 2,
    "scanned_lines": 47,
    "total_findings": 7,
    "quantum_vulnerable_count": 4,
    "active_calls_count": 7,
    "secrets_count": 0,
    "commented_count": 0
  },
  "findings": [
    {
      "file_path": "sample_vulnerable_app/auth.py",
      "line_number": 7,
      "column_start": 12,
      "detected_algorithm": "SHA-256",
      "likely_purpose": "Weak Password Storage",
      "confidence": "HIGH",
      "match_type": "CONFIRMED_CALL",
      "quantum_risk": "QUANTUM_RESISTANT",
      "code_snippet": "return hashlib.sha256(password.encode('utf-8')).hexdigest()",
      "is_comment": false,
      "runtime_note": "STATIC_CONFIRMED_CALL",
      "migration_advice": "Raw fast hashes lack work factor; replace with Argon2id.",
      "cwe_id": "CWE-916"
    }
  ]
}
```

---

## 2. Shared Normalization Contract: `Finding` Dataclass

Both scanners are converted by `adapters.py` into instances of `risk_engine.Finding`. This is the single, canonical input model accepted by the assessment engine:

```python
@dataclass
class Finding:
    id: str                                  # Unique finding identifier
    algorithm: str                           # Normalized algorithm name (e.g., "RSA-2048", "ECDH X25519")
    asset: str = "unknown"                   # Target asset identifier (e.g., "host:port" or "file.py:line")
    usage: Optional[str] = None              # Cryptographic usage (see valid values below)
    key_bits: Optional[int] = None           # Cryptographic key length in bits
    data_lifetime_years: Optional[float] = None   # Confidentiality shelf-life X (for Mosca HNDL)
    trust_lifetime_years: Optional[float] = None  # Certificate/Signature trust validity T
    migration_years: Optional[float] = None       # Estimated migration timeline Y (default: 5.0)
    exposure: Optional[str] = None           # Network exposure ("internet", "partner", "internal", "isolated")
    criticality: Optional[str] = None        # Asset criticality ("critical", "high", "medium", "low")
    replaceable: Optional[bool] = None       # Cryptographic agility / modular replacement flag
    evidence_source: Optional[str] = None    # Provenance source ("certificate", "network", "static", "binary", "config")
    location: Optional[str] = None           # Human-readable code or certificate location
    attributes: Dict[str, Any] = field(default_factory=dict) # Provenance metadata, snippets, and CWE IDs
```

### 2.1 Valid Field Enumerations

| Field | Allowed / Normalized Values | Description |
| :--- | :--- | :--- |
| **`usage`** | `signature`<br>`key_exchange`<br>`symmetric_encryption`<br>`password_storage`<br>`hash`<br>`protocol_negotiation` | The functional operational purpose of the algorithm. Recommending signature schemes for key exchange is strictly prohibited. |
| **`exposure`** | `internet` (public)<br>`partner` (DMZ/extranet)<br>`internal` (corp intranet)<br>`isolated` (airgap/offline) | Directly influences the priority calculation ($0-100$). |
| **`criticality`** | `critical`<br>`high`<br>`medium`<br>`low` | Asset business impact; scales priority scoring. |
| **`evidence_source`** | `certificate` (base 3.0)<br>`manual` (base 3.0)<br>`network` (base 2.8)<br>`static` (base 2.5)<br>`binary` (base 2.0)<br>`heuristic` (base 1.2) | Determines baseline confidence rating. Live TLS network scans outrank heuristic text patterns. |

---

## 3. Risk Engine Output Schema: `Assessment`

Each evaluated finding produces an `Assessment` object with mathematical defensibility:

```json
{
  "assessment_id": "assess-ecdsa-001",
  "finding_id": "tls-cert-pk-google.com",
  "asset": "google.com:443",
  "algorithm": "ECDSA P-256",
  "track": "quantum",
  "rule_id": "ECDSA_SIGNATURE",
  "title": "ECDSA Signature Vulnerable to Shor's Algorithm",
  "severity": "medium",
  "confidence": "high",
  "confidence_score": 3.3,
  "confidence_rationale": "Base 3.0 (certificate); adjustments: +0.2 known family, +0.2 explicit key/curve, +0.1 explicit usage -> final 3.30 (HIGH)",
  "priority": 65.0,
  "rationale": "Shor's algorithm solves elliptic-curve discrete logarithms in polynomial time, completely compromising ECDSA private keys and enabling signature forgery.",
  "quantum_relevance": "Directly vulnerable via Shor's algorithm. All standard curves (NIST P-256, P-384, secp256k1) are broken.",
  "threat_analysis": {
    "model": "signature_lifetime",
    "mosca_delta": null,
    "data_shelf_life": null,
    "migration_window": 3.0,
    "crqc_horizon": 15.0,
    "details": "Trust validity T (0.5y) + Migration Y (3.0y) = 3.5y is within CRQC Z (15.0y). Scheduled quantum migration recommended."
  },
  "recommendation": {
    "action": "Transition to post-quantum signature schemes (NIST FIPS 204 ML-DSA or FIPS 205 SLH-DSA) or hybrid classical-quantum signatures.",
    "reason": "ECDSA provides zero security against quantum adversaries capable of running Shor's algorithm.",
    "timeframe": "planned",
    "alternatives": [
      "ML-DSA-44 / ML-DSA-65 (FIPS 204)",
      "SLH-DSA-SHA2-128s (FIPS 205)"
    ]
  }
}
```

---

## 4. Track Boundary Rules

1. **Track A (Post-Quantum Cryptography)**:
   - Governed by Shor's algorithm (asymmetric keys/signatures/KEMs) and Grover's algorithm (symmetric keys).
   - Mosca's Theorem ($X + Y > Z$) applies to confidential data subject to Harvest-Now-Decrypt-Later.
   - Remediations: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), AES-256.
2. **Track B (Conventional Cryptographic Hygiene)**:
   - Classical vulnerabilities (unsalted fast hashes, collision-broken MD5/SHA-1, 64-bit ciphers, ECB mode).
   - Governed by offline GPU brute-force, birthday attacks, and structural pattern leakage.
   - Remediations: Argon2id (RFC 9106), AES-256-GCM, SHA-256/384.
   - **Cardinal Rule**: PQC NEVER remediates conventional flaws. Migrating an ECB-mode or MD5 flaw to a post-quantum algorithm is cryptographically invalid.
