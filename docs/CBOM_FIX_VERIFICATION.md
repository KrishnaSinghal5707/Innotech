# CBOM fix verification

All five defects from the final audit were fixed in `D:\Btech\Innotech'26\repo2\Innotech`.

- Website exports bind the displayed scan's ID, safely URL-encode it, and show errors for unsaved/expired scans and network failures. They never fall back to the latest scan. Actual history API requests and execution of the real website handler are covered.
- Removed fabricated classical strength from all algorithm components; observed sizes remain parameter metadata. No algorithm strength estimate is inferred from key length.
- Corrected ML-DSA-44 to NIST category 2; tests retain the other ML-DSA and ML-KEM categories.
- CBOM stdout is one parseable JSON document. Simultaneous JSON/CBOM stdout requests are rejected with exit 2; mixed file/stdout exports remain supported.
- Declared jsonschema as a required dependency. Formal validation uses the bundled schema or the explicit requested schema and fails honestly when unavailable, invalid, or unreadable. Removed the machine-specific external schema fallback.

## Results

- `.venv\Scripts\python.exe -m unittest test_cbom_correctness test_cbom -v`: **25 passed**. Log: `output/final-verification/fix-targeted-tests.log`.
- `.venv\Scripts\python.exe -m unittest discover -v`: **174 run, 173 passed, 1 skipped**, in 21.240 seconds. The skipped test requires Windows symlink privileges; mocked no-follow tests passed. Log: `output/final-verification/fix-full-tests.log`.
- `node --test tests/cbom_export.test.cjs`: **4 passed**, including selected historical ID, missing saved ID, expired ID and network failure.
- Fresh source and IaC CBOM files passed formal schema validation. IaC JSON/Markdown retained one issue, partial evidence, null readiness and expected exit 1. Samples: `output/final-verification/fixed/`.
- `git diff --check`: passed.

Installed the declared requirements into the existing project virtual environment. No commit or push performed. Temporary HTTP servers shut down after tests. Browser handler tests mock browser APIs; no new manual visual walkthrough was performed.

Behavior and usage are documented in [CBOM_EXPORTS.md](CBOM_EXPORTS.md). The earlier audit report and its samples remain historical evidence of the pre-fix checkout.
