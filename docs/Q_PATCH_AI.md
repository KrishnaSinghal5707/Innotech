# Q-Patch AI

Q-Patch explains **actual saved scan findings** and proposes a reviewable unified
diff. It does not apply patches, write source files, execute generated commands,
install packages, or claim that a proposed change was verified.

## Setup

Install the existing project requirements, then set these variables in the same
backend process that starts the dashboard:

```powershell
$env:QSHIELD_AI_PROVIDER = 'openai'
$env:OPENAI_API_KEY = '<your backend API key>'
$env:QSHIELD_AI_MODEL = '<a model available to your project supporting Responses structured outputs>'
$env:QSHIELD_AI_TIMEOUT = '45'
.\.venv\Scripts\python.exe main.py --dashboard
```

The model is deliberately required rather than hardcoded. `QSHIELD_AI_PROVIDER`
defaults to `openai`; the timeout defaults to 45 seconds and accepts 1â€“120 seconds.
The real adapter calls `https://api.openai.com/v1/responses` using a backend Bearer
header and structured JSON output, with `store: false`, no tools, no redirects,
and no automatic retries. A ChatGPT subscription does not configure this API key.
Keys never belong in browser scripts, scan reports, Git, or API request bodies.
No `.env` file is automatically loaded. Missing configuration produces a clear
503 response without affecting ordinary scans or reports.

The OpenAI transport lives in `ai_provider.py` behind the `AIProvider.generate_json`
interface. `q_patch.py` owns the Q-Patch policy and diff generation. A future Ask
Q-SHIELD feature can reuse the transport without depending on patch logic. Only
the OpenAI adapter is implemented; another provider requires an adapter and a
factory entry, not changes to the scanner.

API shape reference: [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).

## Website

1. Run a real code, IaC or TLS scan, then open an assessed finding in the inspector.
2. Open **Q-Patch AI**, select the cryptographic purpose, and explicitly consent to
   sending bounded finding/source evidence to the configured provider.
3. Select **Generate Q-Patch proposal**. Review the explanation, migration design,
   validation steps, and any diff. **Download proposed diff** saves a proposal to
   your browser's download location; it does not change repository files.

Saved scan history is supported. Demo datasets and comparison-only findings cannot
be submitted; open the corresponding real saved scan instead. The existing source
scanner can identify cryptographic calls without establishing their business
purpose. When purpose is unknown, the model is asked for clarification/guidance
and the backend forbids edits. A declared purpose is a review input, not proof.

## API

`POST /api/q-patch` accepts only:

```json
{
  "scan_id": "<saved scan ID>",
  "finding_id": "<inventory finding ID with an assessment>",
  "purpose": "integrity",
  "consent": true
}
```

Purposes: `unknown`, `integrity`, `checksum`, `password`, `signature`, `encryption`,
`key_exchange`, `tls_configuration`. Arbitrary client findings, paths, replacement
text, and API credentials are rejected. Missing history returns 404; invalid or
unsafe requests 400; busy requests 429; provider/configuration failures 503. The
endpoint inherits the dashboard's loopback/Host/Origin protections and permits
at most two concurrent AI calls. Each explicit generation can incur provider cost.

Responses have `proposal_only: true`, status `proposal`, `architecture_required`
or `insufficient_evidence`, explanation, remediation, architectural changes,
validation steps, warnings, and `diff` (empty when no safe edit is available).
Accepted diffs also have a repository-relative path and a SHA-256 of the source
used to generate them. Review that hash/source before manually applying anything.

## Safety and supported scope

- Single-file proposals are limited to assessed, confirmed static source calls
  with a unique, still-present scanner snippet at the reported location. The
  existing Python and JS/TS scanners supply those observations. At most one exact
  replacement in one existing file is accepted; the server constructs the diff.
- The source must stay inside both the scan repository and dashboard workspace.
  Traversal, links/junctions, hidden/environment/generated paths, unsupported
  suffixes, binary files, unreadable files, files above 64 KB, and context above
  12 KB are refused. Only a small context window is sent, not the whole repository.
  UTF-8 source is required. Source changes during generation invalidate the proposal.
- Source evidence with detected private keys or credential-like literals is
  withheld. Exposed-key findings get local rotation/incident-response guidance
  without an AI call. Credential detection is conservative and heuristic, not a
  complete secret scanner; false positives and undetected secret formats remain
  possible. Only submit source you are authorized to share.
- Password storage, signatures, encryption and key exchange require architecture
  review in this first release. Quantum-track findings cannot receive a direct
  replacement even if the model proposes one. Password-related evidence also
  blocks edits when a user incorrectly labels it as an integrity hash. Password
  migration must cover salts, verification and old-record migration; RSA/PQC
  migration must cover protocols, formats, certificates and interoperability.
- TLS telemetry and IaC findings currently receive explanation/guidance only;
  Q-Patch does not infer source locations or effective runtime TLS settings.
- Model output is schema-checked and untrusted. Refusals, incomplete or oversized
  responses, invalid paths, nonmatching before-text, and contradictory statuses
  are rejected. Errors never include raw provider bodies or headers. There is no
  apply endpoint, shell tool, or model command execution.
- Diffs are proposals, not guaranteed compilable, secure or behavior-compatible
  fixes. The backend checks evidence/path integrity, not full semantic correctness.
  Review new APIs/dependencies, compatibility, authentication, data formats and
  relevant tests before manually adopting a proposal. Prompt injection in source
  can affect model suggestions despite instructions; it cannot grant filesystem
  writes or command execution through this feature.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest test_q_patch -v
.\.venv\Scripts\python.exe -m unittest discover -v
node --test tests/cbom_export.test.cjs
```

Q-Patch tests use the real scanner and local HTTP server with a mocked provider.
They require no API key and make no live model calls. The fixture in
`tests/fixtures/q_patch/digest.py` is deliberately vulnerable scanner input.

Optional JSX/interaction regression tests use isolated Node dependencies:

```powershell
npm install --prefix output/qpatch-ui --ignore-scripts --no-audit --no-fund @babel/core@7 @babel/preset-react@7 react@18 react-test-renderer@18
$env:NODE_PATH = (Join-Path (Get-Location).Path 'output/qpatch-ui/node_modules')
node --test tests/q_patch_ui.test.cjs tests/cbom_export.test.cjs
```

These packages are only for tests. The production dashboard keeps its existing
React/CDN setup and has no new browser dependency or build step.
