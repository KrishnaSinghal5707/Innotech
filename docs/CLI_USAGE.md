# Q-SHIELD CLI usage

The scanner can run entirely from a terminal. `cli_demo.py` is the supplied launcher
for the existing `main.py` CLI; both accept the same options. Running a repository
or TLS scan does not start the website.

## 1. Set up

Use Python 3.11 or newer. From PowerShell:

```powershell
Set-Location -LiteralPath "D:\Btech\Innotech'26\repo2\Innotech"
python -m pip install -r requirements.txt
python cli_demo.py --help
```

On other machines, change the folder to wherever you cloned the repository.
If your Python command is `python3`, substitute it in the examples below.

## 2. First scan: no network target needed

```powershell
python cli_demo.py --repo sample_vulnerable_app
```

This scans the included deliberately vulnerable sample and prints findings,
severity, evidence confidence, and recommended actions. It does not execute the
scanned application. A report containing vulnerabilities can still exit with code
0: this means the scan completed, not that the application is secure.

For the included remediated sample:

```powershell
python cli_demo.py --repo sample_remediated_app
```

For another repository or a single file, quote paths that contain spaces:

```powershell
python cli_demo.py --repo "D:\projects\my application"
python cli_demo.py --repo "D:\projects\my application\auth.py"
```

Relative input and output paths resolve from your current terminal directory.

## 3. TLS and combined scans

Inspect a target endpoint:

```powershell
python cli_demo.py --host example.com --port 443
```

Combine source discovery with TLS evidence:

```powershell
python cli_demo.py --host example.com --repo sample_vulnerable_app --scenario central
```

Enumerate more TLS evidence or adjust connection timeout:

```powershell
python cli_demo.py --host example.com --deep --timeout 10
```

Repository-only scans need no TLS connection. Network scans require connectivity
to the chosen endpoint. TLS/DNS failures are recorded in report diagnostics; a
combined scan still retains the source-code results.

## 4. Save reports

Full JSON report:

```powershell
python cli_demo.py --repo sample_vulnerable_app --json scan-report.json
```

Readable Markdown:

```powershell
python cli_demo.py --repo sample_vulnerable_app --output scan-report.md
```

Plain text, without ANSI color codes:

```powershell
python cli_demo.py --repo sample_vulnerable_app --output scan-report.txt
```

Export both full JSON and Markdown in one scan:

```powershell
python cli_demo.py --repo sample_vulnerable_app --json scan-report.json --output scan-report.md
```

Print only JSON to stdout for scripts and pipelines:

```powershell
python cli_demo.py --repo sample_vulnerable_app --json -
```

`--json` without a filename also prints JSON to stdout. Export status messages and
failure notices go to stderr so they do not corrupt the JSON. `--output report.json`
also saves full JSON. Output directories must already exist; write failures return
code 1 with an error message. Use different paths for `--json FILE` and `--output`.

## 5. Filter and configure

Show only high or critical conventional findings:

```powershell
python cli_demo.py --repo sample_vulnerable_app --track conventional --min-severity high
```

Show quantum findings and export the filtered display to Markdown:

```powershell
python cli_demo.py --repo sample_vulnerable_app --track quantum --output quantum-report.md
```

Use a different planning scenario, ignore commented-out code, and disable colors:

```powershell
python cli_demo.py --repo sample_vulnerable_app --scenario conservative --ignore-comments --no-color
```

| Option | Meaning |
| --- | --- |
| `--repo`, `-r` | Local directory or file to inspect |
| `--host`, `-H` | TLS hostname, IP, or URL |
| `--port`, `-p` | TLS port, 1–65535; default 443 |
| `--scenario`, `-s` | `conservative` = 10 years, `central` = 15, `relaxed` = 25 |
| `--timeout` | Positive finite network timeout in seconds; default 6 |
| `--deep` | Additional TLS cipher enumeration |
| `--ignore-comments` | Omit commented-out source detections |
| `--quantum-only` | Restrict source discovery to its quantum-relevant categories |
| `--track`, `-t` | Display `all`, `quantum`, or `conventional` assessments |
| `--min-severity` | Minimum displayed severity: `info`, `low`, `medium`, `high`, `critical` |
| `--rules` | Custom rules JSON; load failures produce diagnostics and exit code 1 while using fallback rules |
| `--json [FILE]` | Full JSON report; omit FILE or use `-` for stdout |
| `--output`, `-o` | `.json`, `.md`/`.markdown`, or plain text output |
| `--no-color` | Disable terminal ANSI colors; redirected terminal output is also color-free |

`--track` and `--min-severity` filter terminal/Markdown assessment details. Summary
counts and JSON retain the full scan for auditing. `--quantum-only` changes source
discovery, so it is different from filtering the final displayed track and does
not filter TLS findings.

## 6. Exit codes and automation

| Code | Meaning |
| --- | --- |
| `0` | Scan completed without recorded pipeline errors; findings may still be present |
| `1` | Failed/partial scan, rules-loading problem, or report write failure |
| `2` | Invalid CLI arguments, such as out-of-range port or nonpositive timeout |

Immediately after a command in PowerShell, inspect `$LASTEXITCODE`. In Bash, use
`echo $?`. There is no automatic CI failure threshold for vulnerability severity;
inspect the JSON severity counts to implement your own policy.

## 7. Other modes

```powershell
python cli_demo.py --demo
python demo_migration.py
python cli_demo.py --dashboard --port-web 8080
```

`--demo` runs the existing multi-step demonstration, including network attempts
and demo report generation. It deliberately exercises failure handling and uses
its own demo result; the exit-code table above describes normal repository/TLS scans. `demo_migration.py` runs the local before/after sample
comparison. `--dashboard` explicitly starts the website; stop it with Ctrl+C.

## 8. Supplied sample report

[cli_test_report.json](examples/cli_test_report.json) is the original JSON from
`cli_test_report.zip`, preserved as historical reference output. It is not a new
scan of your machine. Its paths refer to the original author's environment, and
its finding counts can differ from the current scanner/rules. Generate a fresh
report using `--json` for your own target.

## 9. Verify the integration

```powershell
python -m unittest test_cli -v
python -m unittest discover -s . -p "test_*.py" -v
```

The CLI regression tests cover actual launcher subprocesses, reports, paths with
spaces, failure codes, filters, and shared CLI/dashboard assessment normalization.
