# Q-SHIELD scanner audit — 29 October 2026

> Historical pre-fix findings. The fixes and current verification results are recorded in [SCANNER_FIX_VERIFICATION.md](SCANNER_FIX_VERIFICATION.md).

The scanner currently produces both false reassurance and false alarms. Its readiness score and post-quantum migration claims should not be treated as reliable security decisions until the high-priority findings below are addressed. This audit reports defects; production scanner code was not changed.

## Scope and results

- Repository revision: `15ba051`, Windows, Python 3.12.14, cryptography 50.0.2, OpenSSL 3.5.8.
- Existing regression suite: **85 tests passed** in 26.088 seconds with the access needed for sockets and temporary files. The first sandboxed run had 36 environment errors; those are not counted as product defects.
- Independent diagnostic harness: **61 checks, 7 met expectations, 54 unmet expectations**. These deliberately target edge cases and coverage gaps, so 54 is neither a defect count nor an estimated real-world failure rate. Related failures are grouped into **23 findings** below.
- Controlled live tests: four loopback TLS servers (TLS 1.2, TLS 1.3, RSA-1024, expired certificate), deep cipher enumeration, API health/static files, malformed requests, path traversal, scan history, cross-origin behavior, and nested comparison validation.
- Browser: loaded the dashboard, scanned the MD5 fixture, observed **100/100 with one critical finding**, and opened its evidence/migration inspector successfully.
- No public targets were scanned. PQC group variations, weak certificate signature input, and probe timeout behavior were tested with deterministic mocked telemetry. Their results demonstrate adapter/assessment behavior, not successful negotiation of those groups on a real server.

## Highest-priority findings

### 01 — P1: Critical conventional findings can receive 100/100 readiness

**Reproduce:** scan `output/scanner-audit/fixtures/md5_score.py`, `sha1_score.py`, `ecb_score.py`, or `password_score.py`.

**Actual:** MD5 is assessed as critical, but the summary says `readiness_score: 100`, `PQC Resilient / Hybrid Ready`. The browser reproduces the contradiction.

**Expected:** score and posture must reflect known vulnerabilities and distinguish limited coverage from validated readiness.

**Cause:** `scan_results.py:141` checks rule IDs such as `BROKEN_HASH_MD5` and `BROKEN_CIPHER_DES`, while `rules.json` emits `MD5_USAGE`, `SHA1_USAGE`, `DES_OR_3DES_CIPHER`, and `ECB_MODE_USAGE`. Password-storage and weak-RSA findings also have no corresponding penalty. An exposed-key inventory entry has no assessment rule and likewise scores 100.

### 02 — P1: The migration demo claims ML-KEM protection without executing ML-KEM

**Actual:** `sample_remediated_app/crypto_service.py:24` generates P-384 ECDH keys, creates 32 random local bytes, concatenates the secrets, and hashes them. There is no ML-KEM key generation, encapsulation, decapsulation, or two-party agreement. It also describes X25519 while executing P-384.

`demo_migration.py:156` only asserts that the result is 48 bytes, then prints that a hybrid ML-KEM exchange was runtime verified. Its comparison table asserts `PROTECTED (Post-Quantum KEM)`. The existing integration test accepts a zero demo exit code, so this misleading demonstration passes the suite.

**Expected:** implement and test a real two-party KEM exchange, or clearly label the flow as a simulation without security claims. Output length cannot establish cryptographic security. [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) specifies the actual ML-KEM operations.

### 03 — P1: Secret redaction is bypassed in the complete result

**Reproduce:** the live audit scans a one-line PEM-style string containing the synthetic marker `SYNTHETIC_AUDIT_ONLY`.

**Actual:** `inventory.findings[*].attributes.code_snippet` is redacted, but the unredacted marker remains in `modules.code_scanner.findings[*].code_snippet`. The API returns that raw module, and full JSON export/history retains it. No real credentials were used.

**Expected:** redact all result paths before returning, recording, or exporting data. `adapters.py:221` sanitizes only the adapted copy; `main.py` retains the raw scanner result.

### 04 — P1: Dashboard API accepts untrusted origins and exposes local scans/history

**Reproduce:** send `Origin: https://untrusted.audit.invalid` to the loopback API with a synthetic repository scan, then read `/api/history`.

**Actual:** both return 200 with `Access-Control-Allow-Origin: *`. OPTIONS explicitly allows POST and DELETE. There is no authentication/origin guard, repository validation allows arbitrary non-system local paths, and `start_dashboard()` binds to `0.0.0.0` (`dashboard.py:845`). This combines dangerously with finding 03.

**Expected:** default to loopback, enforce an explicit origin policy and appropriate access protection, and restrict allowed scan roots. Network exposure depends on host firewall settings. The test establishes API behavior; it does not claim to bypass browser private-network protections or demonstrate a remote exploit.

### 05 — P1: Source RSA key sizes are fabricated, hiding RSA-1024

**Reproduce:** `rsa1024.py` contains `rsa.generate_private_key(public_exponent=65537,key_size=1024)`.

**Actual:** inventory says `RSA-2048`, and only `RSA_SIGNATURE` is assessed. `WEAK_RSA_KEY_LENGTH` is absent. A multiline RSA-4096 call also becomes RSA-2048.

**Cause:** `adapters.py:374` extracts bits from the generic detector label, not call arguments, and defaults to 2048.

**Expected:** preserve explicit key-size arguments; leave genuinely unknown sizes unknown. The live TLS RSA-1024 test correctly detects the certificate size and weak-key rule, isolating this defect to source normalization.

### 06 — P1: AES-128 and unknown AES widths become AES-256

**Reproduce:** `aes128_gcm.py` uses `key=b"0"*16; AESGCM(key)`. `aes_unknown_gcm.py` accepts a caller-supplied key. `ecb_score.py` only selects an ECB mode.

**Actual:** all acquire a fabricated 256-bit AES width; the AES-128 case emits `AES256_QUANTUM_SAFE` instead of the AES-128 quantum-margin rule.

**Cause:** `adapters.py:394` searches isolated snippets for loose digit substrings and defaults to 256. Selecting a block-cipher mode alone does not establish cipher identity or width.

**Expected:** resolve parameters where supported, otherwise report width unknown. Do not infer safety from missing data.

### 07 — P2: EC curves and finite-field DH are changed into different algorithms

**Actual:** `ec.generate_private_key(ec.SECP384R1())` becomes `ECDSA P-256`, 256 bits. A mocked TLS `ffdhe2048` group becomes `ECDH ffdhe2048`. The source normalizer's DH branch similarly defaults to P-256.

**Expected:** preserve curve/family parameters and avoid assigning a signature purpose to generic EC key generation without use-site evidence. See `adapters.py:355`, `:388`, and `:293`.

### 08 — P1: Informational AES-256 findings become high severity

**Actual:** `AES256_QUANTUM_SAFE` is defined as `severity: info`, but assessed as high. This also occurs on the live TLS servers and pollutes priority charts and migration plans.

**Cause:** `risk_engine.py:1157` uses `rule.severity or Severity.HIGH`; `Severity.INFO` is integer zero and therefore false.

**Expected:** test explicitly for `None`, preserving INFO.

### 09 — P2: Quoted examples are reported as confirmed active calls

**Reproduce:** `python_string.py` contains `example = "hashlib.md5(password)"`; `js_string.js` contains a string with `crypto.createHash('md5')`.

**Actual:** both produce HIGH-confidence `CONFIRMED_CALL` evidence; the Python string produces two critical assessments.

**Expected:** classify ordinary string references separately from calls. The Python AST is currently used to locate docstrings, not to validate regex-matched call syntax (`code_scanner.py:691`).

### 10 — P1: Comment parsing suppresses real executable code

**Reproduce with `ignore_comments=True`:**

```python
x="#"; y=hashlib.md5(b"test")
```

```javascript
const url="https://example.test"; crypto.createHash("md5");
/* note */ crypto.createHash("md5");
crypto.createHash("md5"); /* note */
```

**Actual:** the real MD5 calls are omitted. Comment delimiters inside strings and any block comment on the same line can suppress the whole line.

**Cause:** naive `line.find('#')`, `line.find('//')`, and whole-line block-comment tracking (`code_scanner.py:710`, `:804`, `:854`). Use lexical spans/AST nodes.

### 11 — P1: Common source syntax and crypto APIs are missed

**Actual:** the fixtures demonstrate missing MD5 detections for Python module aliases, `from hashlib import md5`, Node destructured `createHash`, and a multiline `createHash` argument. Standard Node `createCipheriv('aes-128-ecb',...)`, Python `Cipher(algorithms.AES(...), modes.CBC(...))`, and `dsa.generate_private_key(...)` are also missed. The common `dh.generate_parameters(...)` spelling is missed because the pattern expects `diffie_hellman`.

**Expected:** support common import bindings, multiline arguments, and advertised algorithm families, or clearly communicate these detection limits. A clean result is not proof of absence.

### 12 — P2: Important algorithms normalize to unknown and receive no assessments

**Actual:** direct normalizer probes return `family: unknown` for DSA-2048, Ed448, ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305, and PBKDF2-HMAC. These findings produce no assessments under the current rules.

**Expected:** model supported migration targets and classical vulnerable families explicitly. Unsupported algorithms must not silently count as ready. This is partly a coverage limitation, rather than a claim that every safe primitive needs a vulnerability finding. See `risk_engine.py:586`.

### 13 — P1: Certificate trust failures and weak signing hashes are not assessed

**Live evidence:** self-signed and expired loopback certificates return `certificate_validation.trusted: false`, but the assessed conventional count is zero for RSA-2048 examples. The expired leaf also has `certificate.expired: true`. Raw `scan_status: ok` reasonably means inspection completed, but the risk summary has no trust/expiry remediation.

**Mocked evidence:** a `sha1WithRSAEncryption` certificate signature produces no SHA-1 assessment. Missing certificate-key telemetry becomes an invented RSA-2048 certificate finding.

**Expected:** translate validity, trust, and signing-hash evidence into actionable findings; preserve unknown public-key data. An invalid certificate should not be represented only through unrelated quantum migration advice. See `adapters.py:22` and `:277`.

### 14 — P1: Deep cipher enumeration findings are discarded by risk assessment

**Reproduce:** mocked `supported_tls12_ciphers` includes `RC4-SHA` while the negotiated suite is otherwise safe.

**Actual:** no `RC4_CIPHER` assessment. `convert_tls_results_to_findings()` consumes only the negotiated cipher; accepted alternate suites are ignored.

**Expected:** assess all observed accepted unsafe suites when deep enumeration is requested. Otherwise the extra scan cost does not affect risk results.

### 15 — P1: Unknown or static-RSA TLS exchanges become ECDHE

**Actual:** a TLS 1.3 exchange with no reported group is assessed as classical ECDHE even though TLS 1.3 suite names do not establish the negotiated group. A known `RSA (static key transport)` exchange also becomes ECDHE, with a forward-secrecy purpose description. Inventory confidence MEDIUM is subsequently upgraded to HIGH by the engine.

**Expected:** preserve static RSA transport and its lack of forward secrecy; retain unknown PQ status when group evidence is absent. See `adapters.py:293`, `:116`, and `risk_engine.py:987`.

### 16 — P1: PQC group names cause invented ML-KEM and compliance claims

**Mocked evidence:** `X25519Frodo640` and `X25519Kyber768Draft00` become an assessment whose text specifically asserts ML-KEM-768 + X25519 and NIST/CNSA compliance. Other ML-KEM-shaped groups without an X25519 substring receive no PQC assessment, yet score 100. These strings are synthetic adapter inputs, not proven supported TLS configurations.

**Cause:** substring PQ markers plus a postprocessor that replaces only `ECDH_KEY_EXCHANGE` and inserts hard-coded ML-KEM text (`tls_scanner.py:343`, `scan_results.py:23`).

**Expected:** identify exact groups and parameter sets, retain experimental/draft distinctions, and avoid compliance certification from a single negotiated primitive. Specifically, [NSA's CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) specifies ML-KEM-1024, so the generic CNSA claim for ML-KEM-768 is wrong.

### 17 — P1: One PQC exchange masks another asset's classical exchange

**Reproduce:** combine the confirmed PQC telemetry fixture with the source ECDH fixture.

**Actual:** the result includes both `PQC_HYBRID_KEM_DEPLOYED` and `ECDH_KEY_EXCHANGE` but stays at 100/100.

**Cause:** global `has_pqc_hybrid` takes precedence over `has_classical_kx` (`scan_results.py:151`). Ed25519 signature findings are also absent from the classical-signature penalty IDs.

**Expected:** calculate remaining exposure per asset/use; protection on one connection cannot remediate another.

### 18 — P2: Comment evidence is promoted into active critical risk

**Reproduce:** scan `comments_default.py`, containing only `# hashlib.md5(password)`, with default settings.

**Actual:** detector marks both matches LOW / COMMENT_ONLY, but the engine produces two critical assessments with MEDIUM confidence. The fast-hash adapter also relabels the MD5 password use as SHA-256 because `fast hash` wins before digest-specific matching (`adapters.py:345`).

**Expected:** retain provenance/confidence and distinguish inactive references from active risk. Preserve the digest named in evidence.

### 19 — P2: Successful empty scans and skipped files have misleading coverage status

**Actual:** `clean.py` returns no diagnostics but says `N/A (Scan Failed / Host Unreachable)` and posture `failed`. A file larger than 10 MiB is counted as scanned, silently skipped, and has no coverage diagnostic. Unreadable-file exceptions are also swallowed in the same code path.

**Expected:** separate successful/no findings, unsupported/skipped, partial, and failed states. Count attempted and successfully scanned files separately. See `code_scanner.py:665` and `scan_results.py:117`.

### 20 — P2: Protocol probe timeouts are reported as server rejection

**Reproduce:** make `_connect()` raise `TimeoutError` for each protocol probe.

**Actual:** protocol support values become false, rather than unknown. This could hide legacy protocol support during packet loss or rate limiting.

**Expected:** distinguish explicit TLS rejection from transport failure; use null plus diagnostics for inconclusive tests (`tls_scanner.py:389`).

### 21 — P2: Invalid key sizes are accepted or truncated

**Actual:** `Finding.from_dict()` accepts key sizes -1, 0, true, and 128.5. The latter two become 1 and 128 through `int()` coercion.

**Expected:** validate strictly positive non-boolean integral values before assessment (`risk_engine.py:528`). This concerns the engine's structured finding input, not the dashboard port field, which has its own validation.

### 22 — P2: Malformed nested comparison payload causes HTTP 500

**Reproduce:** POST `/api/compare` with:

```json
{"baseline":{"metadata":null},"comparison":{"metadata":{}}}
```

**Actual:** 500 with `'NoneType' object has no attribute 'get'`.

**Expected:** validate nested report structure and return 400 for invalid client data. Only the top-level dictionaries are checked (`dashboard.py:800`).

### 23 — P2: Reusing CodeScanner contaminates later target results

**Reproduce:** call `scan_path()` on the MD5 fixture, then call it on the clean fixture using the same `CodeScanner` instance.

**Actual:** the second result still contains the first file's findings. Counters accumulate too.

**Expected:** reset state per scan, or clearly expose an explicit accumulating API. Current `scan_code()` creates a new instance and avoids this bug, so the direct class API is affected (`code_scanner.py:644`).

## What worked

- Existing CLI parsing, error exit codes, JSON/Markdown exports, history capacity/concurrency, mode isolation, and scenario/risk-model regression assertions passed.
- Direct MD5/SHA-1 calls in supported Python/JS forms were detected; the explicit ignore-comments control removed a true whole-line comment.
- Live TLS scans correctly identified negotiated TLS 1.2 versus TLS 1.3 and observed RSA public-key size. The live RSA-1024 certificate triggered `WEAK_RSA_KEY_LENGTH`.
- Malformed JSON bodies returned 400; tested traversal attempts and missing history IDs returned 404. Static HTML and CSS returned 200.
- Browser scan submission and opening the finding inspector worked. This does not validate every UI filter, keyboard interaction, viewport, or export download.

## Reproduce and inspect evidence

From the repository root, using a Python environment with the project requirements:

```powershell
python -m unittest discover -v
python tmp/scanner_audit.py
python tmp/scanner_live_audit.py
python main.py --repo output/scanner-audit/fixtures/rsa1024.py --json
python main.py --repo output/scanner-audit/fixtures/md5_score.py --json
```

- `output/scanner-audit-tests-unrestricted.log`: complete passing regression run.
- `output/scanner-audit/probes.json`: all 61 expectations and observed results.
- `output/scanner-audit/live-results.json`: live TLS/API results.
- `output/scanner-audit/*.json`: individual pipeline snapshots.
- `output/scanner-audit/fixtures/`: synthetic source reproduction files.
- `output/scanner-audit/environment.json`: runtime versions.

Only synthetic secret markers were used. Temporary generated TLS private keys were removed. Tests ran local API servers; none require publication or scanning third-party systems.

## Recommended fix order and remaining limits

1. Correct readiness scoring, INFO severity, and unsupported/unknown coverage handling.
2. Fix complete-result redaction and dashboard access/origin controls.
3. Stop the simulated ML-KEM and compliance claims; implement real exchange tests if the demo must prove migration.
4. Parse source bindings/parameters and comments structurally; preserve unknown parameters rather than assigning safe defaults.
5. Assess certificate trust/expiry/signatures and all deep-scan cipher evidence; retain TLS uncertainty.
6. Add the reproductions as independent regression expectations, then rerun both synthetic and controlled live tests.

This is a broad diagnostic audit, not exhaustive verification of every possible program, TLS implementation, load condition, or deployment. No sustained denial-of-service/load test, hostile-browser exploit chain, real PQC server negotiation, full certificate-revocation validation, or cross-platform/version matrix was performed. The leaf/system-trust checks alone do not establish that every runtime rejects eMudhra's affected CA chains. The 85 passing existing tests should therefore be interpreted together with the independent failures, not as security certification.
