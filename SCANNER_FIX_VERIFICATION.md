# Scanner audit fixes and verification

All 23 grouped findings in `SCANNER_AUDIT.md` have been addressed. That document records the pre-fix behavior; this document describes the resulting implementation and verification.

## Verification results

- **114 unittest tests passed**, including all 85 existing tests and 29 new permanent regression tests in `test_audit_regressions.py`.
- **61/61 independent audit probes passed**, with a nonzero process exit on any unmet expectation.
- Controlled loopback TLS/API assertions passed: TLS 1.2 and TLS 1.3, RSA-1024, self-signed and expired certificates, deep cipher enumeration, redaction, rejected untrusted origins, clean scan status, malformed payloads, and traversal checks.
- Browser verified: critical MD5 now reports **55/100 — Migration or remediation required**. A caller-supplied AES key with unknown width reports **N/A — Incomplete evidence / readiness undetermined**.
- `git diff --check` passed. No public systems were scanned and no deployment was performed. Temporary TLS private keys and the preview server were cleaned up.

## Fix mapping

| Audit finding | Resulting behavior |
| --- | --- |
| 01. Unsafe findings score 100 | Readiness uses the actual assessment IDs and conventional severities. Exposed keys have an explicit critical rule. The score no longer claims PQ readiness or compliance. |
| 02. Simulated ML-KEM demo | Real two-party X25519 + ML-KEM-768 encapsulation/decapsulation, independent HKDF derivations, key confirmation, and ciphertext-tamper rejection. No simulated fallback. |
| 03. Raw secret disclosure | Shared recursive redaction covers raw modules, inventory, API responses, history and exports. Exposed-secret snippets are removed in full, including partial PEM literals. |
| 04. Permissive local API | Loopback binding; strict local Host, browser Origin and fetch-site checks; no wildcard CORS; resolved repository paths restricted to this workspace. CLI remains available for other authorized local repositories. |
| 05. Fabricated RSA sizes | Python AST call arguments and Node options preserve explicit sizes. Missing sizes remain unknown. Generic key generation is distinguished from confirmed signature/encryption use. |
| 06. Fabricated AES widths | Bounded literal/binding evaluation preserves actual bytes and key widths. Unknown keys stay unknown; a mode alone cannot establish AES-256. Caller parameters cannot inherit a same-named global's width. |
| 07. EC/DH confusion | Observed curves retained; generic EC key material has a generic purpose; finite-field DH remains distinct from ECDH. |
| 08. INFO becomes HIGH | Explicit None handling preserves zero-valued INFO severity. |
| 09. Strings become calls | Python call nodes and JS token/call spans distinguish quoted examples from calls. |
| 10. Comment delimiters hide calls | Python token comments and JS lexical comment spans preserve neighboring code and delimiters inside strings. |
| 11. Missed common source forms | Supported module aliases, imported/destructured functions, multiline calls, standard AES/Cipher APIs, Node createCipheriv, DSA and DH APIs. |
| 12. Unknown primitive families | DSA, Ed448, ML-KEM, ML-DSA, ChaCha20, PBKDF2 and scrypt have explicit normalization. Observations do not claim unverified parameter strength. |
| 13. Missing certificate risks | Chain/hostname failures, validity failures and weak signing hashes reach conventional assessments. Unknown certificate keys remain unknown. |
| 14. Ignored deep cipher findings | Every observed accepted suite is adapted for assessment. Unsupported bulk ciphers retain their identity as unknown rather than being confused with authentication keys. |
| 15. Invented TLS ECDHE | Static RSA transport remains RSA without forward-secrecy claims. Unreported TLS 1.3 groups remain unknown. Detector confidence is respected. |
| 16. False PQC identity/compliance | Exact recognized ML-KEM group identities replace substring guesses. Pure ML-KEM and hybrid variants receive their own accurate descriptions. Draft/experimental or unrecognized groups remain unknown. No hard-coded CNSA certification. |
| 17. One PQC asset masks another | Remaining classical key-exchange/signature findings still affect posture, including Ed25519, Ed448, DSA and generic asymmetric keys. |
| 18. Inactive evidence promoted | Comments remain optional inventory references without active vulnerability assessments. Confidence ceilings and actual password digest identity are preserved. |
| 19. Misleading empty/skipped status | Separate no-findings, partial/unknown and failed states. Oversized, unreadable, unsupported and parse-failed files receive diagnostics; attempted and analyzed counts are separated. |
| 20. Timeout means unsupported | Transport failures produce null/unknown protocol outcomes. Inconclusive protocol probes mark the scan partial with diagnostics. |
| 21. Invalid structured key sizes | Only strictly positive non-boolean integers are accepted; fractional and string values are rejected rather than coerced. |
| 22. Malformed comparison crashes | Nested report objects, arrays, counts and identifying fields are validated; invalid client reports return 400. |
| 23. Scanner state leaks across targets | Each scan resets findings, counters and diagnostics. |

The controlled deep scan also exposed an additional issue during implementation: `RSA` in an unsupported ARIA cipher suite was mistaken for a short RSA public key. Bulk-cipher normalization now prevents that classification, and a permanent regression test covers it.

## Implementation and compatibility

`crypto_source.py` supplies Python AST analysis and JS/TS lexical call analysis. `crypto_evidence.py` supplies exact ML-KEM group identities and common redaction. Risk rules remain identical between `rules.json` and the embedded defaults, with a regression assertion preventing drift.

The educational migration demo now requires **cryptography >= 50** and an ML-KEM-capable backend. `requirements.txt` has been updated. Run `python -m pip install -r requirements.txt` in the project's Python environment. Unsupported backends fail explicitly instead of claiming a simulated exchange is secure.

The original exploratory harness had name-specific checks that only allowed two PQ group cases to pass and assumed generic EC generation meant ECDSA. Its post-fix assertions now check exact group identities, experimental-group uncertainty, and generic EC purpose. The permanent unittest regressions independently check these semantics; the expectations were not changed to accept invented parameters or unsupported compliance claims.

## Evidence

The evidence artifacts listed below were generated locally and are not included in this source commit; test logs contain machine-specific paths.

- `output/scanner-fixed-final-tests.log`: complete 114-test regression run.
- `output/scanner-fixed-final-probes.log` and `output/scanner-audit/probes.json`: 61 independent probe results.
- `output/scanner-fixed-final-live.log` and `output/scanner-audit/live-results.json`: controlled TLS/API evidence and assertions.
- `output/scanner-audit/fixed-dashboard.png`: corrected MD5 score in the browser.
- `output/scanner-audit/fixed-unknown.png`: unknown parameters shown as undetermined.
- Local-only diagnostic harnesses `tmp/scanner_audit.py` and `tmp/scanner_live_audit.py` used synthetic data; they are not included.

## Practical limits

These fixes do not turn static syntax evidence into runtime proof. JS/TS analysis is lexical, not a full language parser; dynamic dispatch, unsupported syntax, unresolved parameters and unrecognized algorithms can require manual review. Incomplete observations explicitly leave readiness undetermined.

The hybrid exchange is a local educational round trip, not an authenticated production transport or compliance certification. Real deployment still needs an appropriate reviewed protocol and authentication. TLS system-trust/leaf checks do not independently prove global revocation enforcement, including all eMudhra distrust updates. No third-party exploitation, sustained load testing, or full operating-system/runtime version matrix was performed.
