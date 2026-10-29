# CBOM exports and validation

Install the project dependencies with `python -m pip install -r requirements.txt`.
The `jsonschema` dependency is required for formal CycloneDX 1.6 validation.

```powershell
python main.py --repo sample_vulnerable_app --cbom crypto-bom.json
python main.py --repo sample_vulnerable_app --cbom -
python main.py --repo sample_vulnerable_app --json scan.json --cbom -
```

`--cbom -` writes one JSON document to stdout without the terminal report. Combining
`--json -` and `--cbom -` is rejected because both request the same output stream.
Either format can still be written to a file while the other uses stdout.

The dashboard exports the currently displayed saved scan by its scan ID, including
when loading an older scan from history. Expired IDs, network errors, and reports
without saved IDs show an error instead of downloading a different scan.

Observed key sizes remain in algorithm parameter metadata. CBOM exports omit
`classicalSecurityLevel`: key length alone does not establish classical security
strength across RSA, EC, symmetric algorithms, usages, and incomplete parameters.
An omitted field means no strength assertion is made. The NIST quantum categories
for ML-DSA-44/65/87 are 2/3/5; ML-KEM-512/768/1024 are 1/3/5.

`validate_cbom_schema(document, schema_path=None)` validates against the bundled
`docs/bom-1.6.schema.json` by default. An explicit schema path is authoritative.
It returns `(False, explanation)` for invalid documents, a missing validator,
unreadable or invalid schemas, or unresolved references. Structural checks are
never presented as successful full schema validation. Schema conformance checks
format and types; it does not establish that cryptographic facts are correct.

Regression checks:

```powershell
python -m unittest discover -v
node --test tests/cbom_export.test.cjs
```

The Node tests execute the actual website export handler with mocked browser APIs;
the Python tests exercise schema failures, CLI output streams, parameter metadata,
NIST categories, and actual localhost history/export requests.
