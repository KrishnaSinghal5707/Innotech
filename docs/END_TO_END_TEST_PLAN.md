# 🧪 Q-SHIELD End-to-End Quality Assurance & Test Plan

This document defines the comprehensive end-to-end test plan for the Q-SHIELD cryptographic discovery and migration suite. It establishes the test cases, verification methodologies, and pass/fail criteria required for release certification.

---

## 🎯 Test Objectives
1. **Source Scanning**: Validate AST parsing, regex detection, comment ignoring, secret redaction, and bounded resource usage.
2. **TLS Scanning**: Verify handshake telemetry, certificate chain inspection, protocol enumeration, and network timeout bounds.
3. **Risk Classification**: Verify strict separation between Track A (Quantum) and Track B (Conventional) risks and Mosca's Theorem mathematics.
4. **Report Generation**: Certify ANSI terminal reports, structured JSON exports, and React 18 REST endpoints.
5. **Fault Tolerance**: Prove non-blocking, graceful recovery across all potential failure modes (DNS, timeout, missing files).
6. **Controlled Migration**: Independently verify risk reduction in the before/after workflow, distinguishing static AST findings from runtime execution.

---

## 📊 Comprehensive Test Matrix

### 1. Static Source-Code Cryptography Scanner (`code_scanner.py`)

| Test ID | Test Description | Input / Condition | Expected Output | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **TC-SRC-01** | Python AST & Call Detection | `sample_vulnerable_app/auth.py` | Detects `hashlib.sha256`, `hashlib.md5`, `hashlib.sha1` as confirmed active calls. | `test_integration.py` |
| **TC-SRC-02** | Asymmetric & Key Exchange APIs | `sample_vulnerable_app/crypto_service.py` | Detects RSA-1024, ECDH P-256 (`server_key.exchange`), 3DES-CBC, AES-ECB. | `test_integration.py` |
| **TC-SRC-03** | Comment Filtering | Commented crypto lines (`# hashlib.md5(...)`) with `--ignore-comments` | Commented calls are omitted or marked `COMMENT_ONLY` with `LOW` confidence. | `code_scanner.py` CLI / Unit |
| **TC-SRC-04** | Accidental Secret Redaction | Hardcoded RSA/EC private keys (`-----BEGIN PRIVATE KEY-----`) | Raw base64 key payload is masked with `[REDACTED PRIVATE KEY MATERIAL]`. | `test_secret_redaction_in_adapter` |
| **TC-SRC-05** | Bounded Resource Exhaustion | File exceeding 10 MB threshold | Scanner skips oversized file gracefully without memory spikes or crashing. | `code_scanner.py` internal bound |

---

### 2. TLS Network Scanner (`tls_scanner.py`)

| Test ID | Test Description | Target / Input | Expected Output | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **TC-TLS-01** | Standard HTTPS Telemetry | `google.com:443` | Negotiated TLS version (TLS 1.3), cipher suite (AES-256-GCM / ChaCha20), and X.509 cert. | `main.py --host google.com` |
| **TC-TLS-02** | Hybrid Post-Quantum KEM | Target with `X25519MLKEM768` | Detects post-quantum hybrid group flag `post_quantum_or_hybrid_group=True`. | `test_tls_conversion_success` |
| **TC-TLS-03** | Obsolete Protocol Acceptance | Target supporting TLS 1.0/1.1 | Flags `Deprecated-TLSv1.0` / `Deprecated-TLSv1.1` as High severity conventional findings. | `test_integration.py` |
| **TC-TLS-04** | Explicit Network Timeout | Slow/unresponsive host with `--timeout 2.0` | Socket times out in $\le 2.0$s and records graceful error without hanging. | `test_pipeline_graceful_network_failure` |

---

### 3. Adapters & Finding Normalization (`adapters.py`)

| Test ID | Test Description | Condition | Expected Output | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **TC-ADP-01** | ECDH Key Exchange Disambiguation | Code calling `server_key.exchange(ec.ECDH(), ...)` | Normalizes to `usage="key_exchange"` and `algorithm="ECDH P-256"`, NOT `signature`! | `test_ecdh_key_exchange_adapter_normalization` |
| **TC-ADP-02** | RSA OAEP Key Encapsulation | Code calling `padding.OAEP(...)` | Normalizes to `usage="key_exchange"` and recommends `ML-KEM-768`, NOT `ML-DSA`! | `test_rsa_oaep_recommends_ml_kem` |
| **TC-ADP-03** | Finding Deduplication | Multiple regex rules triggering on the same code line | Single deduplicated `Finding` generated; no duplicate cards in UI or report. | `test_code_findings_deduplication_on_same_line` |
| **TC-ADP-04** | Secure KDF Preservation | Code calling `hashlib.pbkdf2_hmac(...)` | Normalizes as secure KDF, NOT misclassified as raw fast SHA-256 password storage. | `adapters.py` unit pass |

---

### 4. Defensible Risk Engine (`risk_engine.py`)

| Test ID | Test Description | Condition | Expected Output | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **TC-RSK-01** | Strict Track Separation | Combined scan of host and source repository | Post-quantum findings (RSA, ECDH) are strictly isolated from classical flaws (MD5, ECB). | `test_track_filtering` |
| **TC-RSK-02** | Mosca's Theorem ($X+Y > Z$) | Data lifetime $X=15$, Migration $Y=5$, CRQC $Z=15$ | $X+Y=20 > 15 \Rightarrow$ Delta $+5.0$ years $\Rightarrow$ `CRITICAL` severity with HNDL warning. | `test_mosca_critical_exposure` |
| **TC-RSK-03** | Scenario Modeling | Switch scenario from `relaxed` (25y) to `conservative` (10y) | CRQC horizon shifts severity upwards proportionally for long-lived assets. | `test_scenario_override_shifts_severity` |
| **TC-RSK-04** | Defensible Remediation | SHA-256 password storage finding | Recommends Argon2id/bcrypt; explicitly explains that PQC does NOT solve this flaw. | `test_sha256_password_storage_conventional_recommendation` |
| **TC-RSK-05** | Confidence Scoring Provenance | Certificate vs. Network vs. Static vs. Heuristic | Certificate/Network yield `HIGH` confidence; heuristic matches yield `LOW` confidence. | `test_certificate_evidence_gives_high_confidence` |

---

### 5. Error Recovery & Graceful Degradation (`main.py`)

| Test ID | Test Description | Trigger | Expected Behavior | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **TC-ERR-01** | Unresolvable Hostname | `--host invalid-offline-target.test` | Logs clean warning in `metadata.errors`; continues code scan without unhandled exception. | `main.py --demo` (Step 2) |
| **TC-ERR-02** | Missing Directory Path | `--repo /non/existent/path/xyz` | Records error in `metadata.errors`; generates clean report with 0 code findings. | `test_pipeline_missing_repo_path` |
| **TC-ERR-03** | Corrupted / Binary File | Non-UTF8 binary file in scanned directory | Skips unreadable content with `errors="replace"` without aborting the batch scan. | `code_scanner.py` regression |

---

### 6. Controlled Before/After Migration Demonstration (`demo_migration.py`)

| Test ID | Test Description | Target Environments | Expected Output | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **TC-MIG-01** | Before vs. After Static Scan | `sample_vulnerable_app` vs `sample_remediated_app` | Conventional flaws drop from 4 to 0; Critical flaws drop to 0. | `demo_migration.py` Stage 1 & 2 |
| **TC-MIG-02** | Live Runtime Execution | Remediated Python cryptographic modules | Live runtime execution verifies: AES-256-GCM roundtrip, PBKDF2 verification, and SHA-256 checksum. | `demo_migration.py` Stage 3 |
| **TC-MIG-03** | Evidence Provenance Distinction | Static AST vs. Dynamic Runtime | Terminal summary explicitly contrasts static AST syntax detection with runtime operational verification. | `demo_migration.py` Stage 5 |

---

## ⚡ Execution Commands

```bash
# 1. Run Complete Automated Unit & Integration Suite (35 Tests)
python -m unittest discover -s . -p "test_*.py" -v

# 2. Run Bytecode Compilation & Syntax Check
python -m py_compile main.py tls_scanner.py code_scanner.py risk_engine.py adapters.py dashboard.py demo_workflow.py demo_migration.py test_integration.py test_risk_engine.py sample_vulnerable_app/auth.py sample_vulnerable_app/crypto_service.py sample_remediated_app/auth.py sample_remediated_app/crypto_service.py

# 3. Execute End-to-End Automated Judge Demo
python main.py --demo

# 4. Execute Controlled Before/After Migration Demonstration
python demo_migration.py
```
