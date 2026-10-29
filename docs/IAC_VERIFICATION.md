# IaC scanner verification — 29 October 2026

## Website integration — 30 October 2026

Following the requested transfer, current source files and website integration are in `D:\Btech\Innotech'26\repo2\Innotech`. The worktree information below describes the original implementation stage.

The dashboard now provides **Scan Configuration → IaC & Docker → Scan IaC & Docker**, with a **Try IaC example (issue + unknown)** preset. Reports open in **IaC & Docker Evidence**, including filters, file/line evidence, remediation, source links and sanitized coverage diagnostics. History and JSON/Markdown exports retain the IaC data. The API uses `scan_type: "iac"`, ignores the unused host/port, enables the static IaC pass and disables irrelevant network/quantum-only options. Workspace and same-origin restrictions remain enforced.

Verification in repo2's `.venv`:

- `python -m unittest discover -v`: **149 tests, 148 passed, 1 skipped**, no failures/errors. The existing real-symlink host-permission skip remains. Log: `output/iac/website-tests.log`.
- `python -m unittest test_iac_dashboard -v`: **4/4 passed** after final UI changes. Covers real sample execution, scope isolation, path validation, history, Markdown export and served controls. Log: `output/iac/website-api-tests.log`.
- Browser: selected IaC mode, ran the sample, confirmed one issue plus one unknown and partial coverage, exercised the Unknown/All filters and opened the finding inspector.
- Screenshot: `output/iac/website-evidence.png`. `git diff --check` passed. Nothing was committed or pushed.

## Branch isolation

- Dedicated managed worktree: `C:\Users\Kartik\.codex\worktrees\version-1-2\Innotech`.
- Branch: `version-1.2` (Git branch names cannot contain the space in “version 1.2”).
- Base revision: `b5feb8c82771713c618781719ee9740b8edafe59`.
- `member/lead` remains at that same revision; `main` remains at `aff6d3da10c74ba04ee743c63c63c0679f6fed9e`.
- No commit, merge, push, reset or overwrite of the original checkout was performed. Its existing untracked `output/` and `tmp/` were left alone.
- Existing `code_scanner.py`, `tls_scanner.py`, `risk_engine.py`, `rules.json`, `dashboard.py` and dashboard assets were not changed. The integration is confined to the opt-in orchestration, report coverage section, parser dependencies and new dedicated IaC modules/tests/docs.

## Commands and actual results

Commands below ran from the dedicated worktree using `.venv\Scripts\python.exe`.

| Command | Result |
| --- | --- |
| Bundled Python `-m venv --system-site-packages .venv` | Created an isolated parser/test environment, retaining the existing cryptography runtime. |
| `.venv\Scripts\python.exe -m pip install "PyYAML>=6.0.2,<7" "python-hcl2>=7.3.1,<8"` | Installed PyYAML 6.0.3, python-hcl2 7.3.1 and parser dependencies. |
| `.venv\Scripts\python.exe -m unittest discover -v` before new IaC tests | Original **114/114 tests passed**. Log: `output/iac/baseline-tests.log`. |
| `.venv\Scripts\python.exe -m py_compile iac_scanner.py iac_policies.py main.py scan_results.py` | Passed, exit 0. |
| `.venv\Scripts\python.exe -m unittest test_iac_scanner -v` | **31 tests: 30 passed, 1 skipped**. Log: `output/iac/iac-tests.log`. |
| `.venv\Scripts\python.exe -m unittest discover -v` after integration | **145 tests: 144 passed, 1 skipped**, no failures/errors. Final run: 15.299 seconds. Includes all original 114 regressions. Log: `output/iac/all-tests.log`. |
| `.venv\Scripts\python.exe main.py --repo docs/examples/iac_sample --iac --json docs/examples/iac_sample_report.json --output docs/examples/iac_sample_report.md` | Generated both reports; intentional exit **1** because a policy expression is unresolved. One high-severity static configuration assessment and one unknown observation; readiness is N/A. |
| `git diff --check` | Passed. |
| `git branch --show-current` / `git rev-parse member/lead` | Confirmed `version-1.2` and the unchanged lead revision above. |

Runtime: Python 3.12.14, cryptography 50.0.2, PyYAML 6.0.3, python-hcl2 7.3.1 on Windows.

The only skipped test is `test_actual_symlink_is_excluded`: this host did not permit creating a real directory symlink. The deterministic no-follow guard test, ancestor-link/junction guard path, traversal test, regular-file checks and unreadable-input tests ran. Real OS-level symlink creation therefore remains unverified on this host; no OS permissions or security settings were changed to enable it.

## Coverage exercised

- Fixture positives and negatives for all five rule IDs; every exact AWS policy in the catalog has a positive/nonmatching expectation.
- Multi-stage Dockerfile references, digest references, tabs, backslash continuations, legacy ENV syntax, quoted/dynamic values and unsupported heredocs.
- Supported Ingress annotations, multiple YAML documents, missing fields, templating, cipher exclusions, mixed weak/unknown tokens, custom tags, aliases, duplicate keys and nesting limits.
- Top-level Terraform resource scoping, Windows CRLF/EOF normalization, missing settings, expressions/functions, unrecognized identifiers, custom/default CloudFront certificate context and invalid SNI/SSLv3 combinations.
- Safe diagnostic output for malformed YAML/HCL/Dockerfiles, unreadable files/directories, oversized input, excluded state/tfvars, and missing parser dependencies.
- Secret sentinels in manifest payloads, Terraform variables, unknown configuration values and parser error cases never appear in output. Terraform state/tfvars are excluded before opening; tests prohibit opening them.
- Reusing the scanner does not accumulate prior results; the supported-candidate limit produces partial coverage.
- No subprocess or scanned shell command executes. HCL function expressions remain unresolved. No Terraform, Docker, Kubernetes client or deployment operation was run.
- End-to-end `--iac` JSON, terminal partial status, normalized Finding/risk integration and Markdown unknown-value escaping. Default source scan behavior remains unchanged.

See [exact supported rules and limitations](IAC_SCANNER.md), [sample JSON](examples/iac_sample_report.json), and [sample Markdown](examples/iac_sample_report.md). This verification does not establish full Kubernetes/Terraform/Docker security coverage or effective runtime TLS/PQC posture. CloudFormation was not added.
