# Combined dashboard and scanner integration

This checkout combines the redesigned dashboard with the backend changes supplied
in `Innotech.zip`.

## Included changes

- Validated code-only, TLS-only, and combined scanning, with bounded JSON requests
  and structured client errors.
- In-memory scan history, report retrieval, before/after comparisons, and JSON /
  Markdown exports.
- Correct AES-128 vs AES-256 TLS cipher normalization, post-processing for hybrid
  PQC observations and deprecated protocol findings, and unavailable posture
  scores for scans without assessable evidence.
- Existing 3D visualization, chart filters, priority radar, migration simulation,
  attack-surface diagrams, horizon lab, section navigation, and responsive styling.
- Inventory, evidence confidence, migration roadmap, and scan history / comparison
  integrated into the redesigned interface.

## Merge decisions

The archive contains older versions of several files. Existing ECDH and RSA-OAEP
normalization, RSA encapsulation rules, source finding deduplication, private-key
redaction, file-size bounds, the remediated sample, and migration demonstration
were retained. The archive's replacement UI was not copied over the redesign.

TLS attributes are based on observed evidence. Hostname-based guesses about Google
hybrid key exchange or obsolete protocol support were omitted: a hostname alone
cannot establish a negotiated cryptographic group or supported TLS version.

History uses unique IDs even under concurrent scans and after reaching its 50-run
capacity. Comparisons match source observations by relative asset, rule, and
algorithm rather than generated IDs or line numbers. Multiple identical observations
are counted separately. Changed targets or planning assumptions generate warnings;
failed scan stages make the comparison inconclusive. An absent finding is not
independent proof that a fix executes correctly.

Exports for an expired or unknown scan ID return 404 rather than silently exporting
another scan. The UI exports its currently displayed report and marks demo data.

## Verification

The Python regression suite includes the original scanner and risk-engine checks,
the imported dashboard API tests, and additional combined-release tests in
`test_release_integration.py`. CI compiles these files and discovers all
`test_*.py` tests on its configured Python versions.

Frontend verification compiles the JSX, renders the full page and new evidence
views, and exercises repository/TLS/combined submissions, inline API errors, and
tab navigation using the React test renderer. Native visual browser verification
was unavailable in this environment.

Start locally with `python dashboard.py`; test with
`python -m unittest discover -s . -p "test_*.py" -v`. Browser libraries and fonts
are loaded from CDNs, so the frontend requires internet access.


## CLI archive integration

The additional `cli_demo.zip` supplies a launcher for `main.py`, now available as
`cli_demo.py`. `cli_test_report.zip` supplies historical JSON output, preserved
under `docs/examples/cli_test_report.json`; it is not executable scanner code.

CLI and dashboard share result normalization in `scan_results.py`, including
hybrid-PQC and deprecated-protocol handling. The shared Markdown renderer serves
CLI exports and the dashboard's export API. CLI report files contain the requested
format, JSON stdout remains parseable, and failures return nonzero exit codes.
`test_cli.py` exercises subprocess behavior and the original sample-report schema.
See [CLI usage](CLI_USAGE.md) for commands.
