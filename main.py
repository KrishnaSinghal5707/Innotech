#!/usr/bin/env python3
"""
main.py - Q-SHIELD Cryptographic Post-Quantum Migration Orchestrator.

Integrates:
  * tls_scanner.py (Member 1) - Network TLS & X.509 Certificate Scanner
  * code_scanner.py (Member 2) - Static Source-Code Cryptography Scanner
  * risk_engine.py (Member 3) - Defensible Risk & PQC Migration Engine

Provides:
  - Unified CLI orchestrator for host and/or repo scans
  - Graceful failure recovery for network, DNS, and filesystem errors
  - Combined multi-modal findings normalization
  - Defensible risk assessment and priority scoring
  - Rich terminal reporting and JSON / Markdown exports
  - Lightweight interactive React dashboard launcher
  - Automated demo workflow
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Local module imports
try:
    from tls_scanner import normalize_target, scan_tls
    from code_scanner import scan_code
    from risk_engine import RiskEngine, RuleSet, Severity, Track, DEFAULT_RULES_JSON
    from adapters import convert_tls_results_to_findings, convert_code_results_to_findings
except ImportError:
    # Handle running from parent folder or package
    current_dir = Path(__file__).resolve().parent
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    from tls_scanner import normalize_target, scan_tls
    from code_scanner import scan_code
    from risk_engine import RiskEngine, RuleSet, Severity, Track, DEFAULT_RULES_JSON
    from adapters import convert_tls_results_to_findings, convert_code_results_to_findings

VERSION = "2.0.0"


# ============================================================================
# CORE ORCHESTRATION PIPELINE
# ============================================================================

def run_pipeline(
    host: Optional[str] = None,
    port: int = 443,
    repo_path: Optional[str] = None,
    scenario: str = "central",
    rules_path: Optional[str] = None,
    deep_tls: bool = False,
    ignore_comments: bool = False,
    quantum_only: bool = False,
    timeout: float = 6.0,
) -> Dict[str, Any]:
    """
    Executes the end-to-end multi-modal scanning and risk assessment pipeline.
    Handles network failures, missing paths, and partial scans gracefully.
    """
    scan_start = datetime.now(timezone.utc)
    target_summary = {"host": host, "port": port if host else None, "repo": repo_path}
    errors: List[Dict[str, str]] = []

    # 1. Initialize Rules & Risk Engine
    ruleset = None
    if rules_path and Path(rules_path).exists():
        try:
            ruleset = RuleSet.load_from_file(rules_path)
        except Exception as e:
            errors.append({"module": "rules", "error": f"Failed to load rules from {rules_path}: {e}"})

    if not ruleset:
        # Fall back to rules.json in current directory or embedded default
        local_rules = Path(__file__).resolve().parent / "rules.json"
        if local_rules.exists():
            try:
                ruleset = RuleSet.load_from_file(str(local_rules))
            except Exception:
                ruleset = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)
        else:
            ruleset = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)

    engine = RiskEngine(ruleset, scenario=scenario)

    # 2. Execute TLS / Network Scan (Member 1)
    tls_result: Optional[Dict[str, Any]] = None
    if host:
        try:
            norm_host, norm_port = normalize_target(host, port)
            tls_result = scan_tls(norm_host, norm_port, timeout=timeout, deep=deep_tls)
            if tls_result.get("scan_status") == "failed":
                errs = tls_result.get("errors", [])
                err_msg = errs[0].get("error") if errs else "Unknown connection error"
                errors.append({"module": "tls_scanner", "error": f"TLS scan failed for {norm_host}: {err_msg}"})
        except Exception as e:
            tls_result = {
                "scan_status": "failed",
                "target": {"host": host, "port": port},
                "errors": [{"stage": "init", "error": str(e)}],
            }
            errors.append({"module": "tls_scanner", "error": f"TLS scan exception: {e}"})

    # 3. Execute Source Code Scan (Member 2)
    code_result: Optional[Dict[str, Any]] = None
    if repo_path:
        target_p = Path(repo_path)
        if not target_p.exists():
            err_msg = f"Repository path does not exist: {repo_path}"
            errors.append({"module": "code_scanner", "error": err_msg})
            code_result = {
                "target_path": repo_path,
                "summary": {"scanned_files": 0, "scanned_lines": 0, "total_findings": 0},
                "findings": [],
                "error": err_msg,
            }
        else:
            try:
                code_result = scan_code(
                    target_p,
                    ignore_comments=ignore_comments,
                    quantum_only=quantum_only,
                )
            except Exception as e:
                err_msg = f"Source code scan failed: {e}"
                errors.append({"module": "code_scanner", "error": err_msg})
                code_result = {
                    "target_path": repo_path,
                    "summary": {"scanned_files": 0, "scanned_lines": 0, "total_findings": 0},
                    "findings": [],
                    "error": err_msg,
                }

    # 4. Normalize & Aggregate Findings via Adapters
    all_findings = []
    if tls_result:
        tls_findings = convert_tls_results_to_findings(tls_result)
        all_findings.extend(tls_findings)
    if code_result:
        code_findings = convert_code_results_to_findings(code_result)
        all_findings.extend(code_findings)

    # 5. Evaluate Cryptographic Risk & Migration Guidance (Member 3)
    report = engine.assess(all_findings)
    scan_end = datetime.now(timezone.utc)
    duration_s = round((scan_end - scan_start).total_seconds(), 2)

    # 6. Assemble Combined Result Package
    combined_result = {
        "metadata": {
            "orchestrator": "Q-SHIELD Cryptographic Migration Suite",
            "version": VERSION,
            "scan_started_at": scan_start.isoformat(),
            "scan_finished_at": scan_end.isoformat(),
            "duration_seconds": duration_s,
            "targets": target_summary,
            "scenario": scenario,
            "crqc_horizon_years": engine.planning.crqc_years,
            "errors": errors,
        },
        "modules": {
            "tls_scanner": tls_result,
            "code_scanner": code_result,
        },
        "inventory": {
            "total_items": len(all_findings),
            "findings": [
                {
                    "id": f.id,
                    "asset": f.asset,
                    "algorithm": f.algorithm,
                    "usage": f.usage,
                    "key_bits": f.key_bits,
                    "exposure": f.exposure,
                    "criticality": f.criticality,
                    "evidence_source": f.evidence_source,
                    "location": f.location,
                    "attributes": f.attributes,
                }
                for f in all_findings
            ],
        },
        "risk_assessment": report.to_dict(),
    }

    return combined_result


# ============================================================================
# POLISHED TERMINAL FORMATTER
# ============================================================================

class TerminalFormatter:
    """Renders ANSI-colored, polished terminal reports for Q-SHIELD scans."""

    # ANSI Colors
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def print_banner(cls) -> None:
        print(f"\n{cls.CYAN}{cls.BOLD}" + "=" * 80 + cls.RESET)
        print(f"{cls.CYAN}{cls.BOLD}   🛡️  Q-SHIELD: INTEGRATED POST-QUANTUM MIGRATION & CRYPTOGRAPHIC SUITE{cls.RESET}")
        print(f"{cls.CYAN}{cls.BOLD}" + "=" * 80 + cls.RESET)

    @classmethod
    def print_report(
        cls,
        result: Dict[str, Any],
        track_filter: Optional[str] = None,
        min_severity: Optional[str] = None,
    ) -> None:
        cls.print_banner()

        meta = result.get("metadata", {})
        targets = meta.get("targets", {})
        assessment = result.get("risk_assessment", {})
        summary = assessment.get("summary", {})
        sev_counts = summary.get("severity", {})
        track_counts = summary.get("track", {})
        assessments = assessment.get("assessments", [])
        errors = meta.get("errors", [])

        # Filter assessments if requested
        if track_filter and track_filter != "all":
            assessments = [a for a in assessments if a.get("track") == track_filter]
        if min_severity:
            min_val = int(Severity.parse(min_severity))
            assessments = [a for a in assessments if int(Severity.parse(a.get("severity"))) >= min_val]

        # Scan Targets & Metadata Header
        print(f"{cls.BOLD}  SCAN METADATA & CONFIGURATION{cls.RESET}")
        print(f"  Target Host      : {cls.WHITE}{targets.get('host') or 'None (Code-only scan)'}{cls.RESET}")
        if targets.get("port") and targets.get("host"):
            print(f"  Target Port      : {targets.get('port')}")
        print(f"  Target Repo/Path : {cls.WHITE}{targets.get('repo') or 'None (Host-only scan)'}{cls.RESET}")
        print(f"  CRQC Scenario    : {cls.MAGENTA}{meta.get('scenario', 'central').title()}{cls.RESET} "
              f"(Quantum Horizon: {cls.BOLD}{meta.get('crqc_horizon_years')} years{cls.RESET})")
        print(f"  Duration         : {meta.get('duration_seconds')} seconds")

        # Telemetry from modules
        tls_mod = result.get("modules", {}).get("tls_scanner")
        if tls_mod:
            status = tls_mod.get("scan_status", "unknown").upper()
            status_color = cls.GREEN if status == "OK" else (cls.YELLOW if status == "PARTIAL" else cls.RED)
            print(f"  TLS Status       : {status_color}{status}{cls.RESET}")
            if tls_mod.get("connection"):
                conn = tls_mod["connection"]
                cs = tls_mod.get("cipher_suite", {})
                kx = tls_mod.get("key_exchange", {})
                print(f"    └─ Negotiated  : {conn.get('tls_version')} | {cs.get('name')} | Group: {kx.get('group') or 'classical'}")

        code_mod = result.get("modules", {}).get("code_scanner")
        if code_mod and not code_mod.get("error"):
            c_sum = code_mod.get("summary", {})
            print(f"  Code Scanner     : {cls.GREEN}OK{cls.RESET} ({c_sum.get('scanned_files')} files, "
                  f"{c_sum.get('scanned_lines', 0):,} lines, {c_sum.get('total_findings')} detections)")

        # Any errors during scan
        if errors:
            print(f"\n{cls.YELLOW}{cls.BOLD}  ⚠️  SCAN WARNINGS & FAILURES (Handled Gracefully):{cls.RESET}")
            for err in errors:
                print(f"    - [{err.get('module')}]: {err.get('error')}")

        # Metrics Summary Dashboard
        print("\n" + cls.BOLD + "━" * 80 + cls.RESET)
        print(f"{cls.BOLD}  EXECUTIVE SUMMARY METRICS{cls.RESET}")
        print("━" * 80)
        print(f"  Total Assessed Risk Items : {cls.BOLD}{summary.get('total_assessments', 0)}{cls.RESET}")
        print(f"  Track A (Post-Quantum)    : {cls.CYAN}{track_counts.get('quantum', 0)} items{cls.RESET} (Shor's / Grover's / HNDL risk)")
        print(f"  Track B (Conventional)    : {cls.YELLOW}{track_counts.get('conventional', 0)} items{cls.RESET} (Classical algorithmic weaknesses)")
        print(f"  Severity Distribution     : "
              f"{cls.RED}{cls.BOLD}Critical: {sev_counts.get('critical', 0)}{cls.RESET} | "
              f"{cls.YELLOW}{cls.BOLD}High: {sev_counts.get('high', 0)}{cls.RESET} | "
              f"{cls.CYAN}Medium: {sev_counts.get('medium', 0)}{cls.RESET} | "
              f"{cls.DIM}Low/Info: {sev_counts.get('low', 0) + sev_counts.get('info', 0)}{cls.RESET}")
        print("━" * 80)

        # Assessments Section
        if not assessments:
            print(f"\n  {cls.GREEN}✓ No cryptographic risks detected under current filters.{cls.RESET}\n")
            print("=" * 80 + "\n")
            return

        # Track A: Post-Quantum Migration
        quantum_list = [a for a in assessments if a.get("track") == "quantum"]
        if quantum_list:
            print(f"\n{cls.CYAN}{cls.BOLD}  === TRACK A: POST-QUANTUM CRYPTOGRAPHY (PQC) MIGRATION ==={cls.RESET}")
            print(f"  {cls.DIM}Vulnerable to Shor's/Grover's algorithms. Requires transition to NIST FIPS 203/204/205.{cls.RESET}\n")
            for idx, a in enumerate(quantum_list, start=1):
                cls._print_assessment_card(idx, a)

        # Track B: Conventional Weaknesses
        conv_list = [a for a in assessments if a.get("track") == "conventional"]
        if conv_list:
            print(f"\n{cls.YELLOW}{cls.BOLD}  === TRACK B: CONVENTIONAL CRYPTOGRAPHIC HYGIENE & WEAKNESSES ==={cls.RESET}")
            print(f"  {cls.DIM}Classical flaws (e.g. fast hashing for passwords, deprecated ciphers). NOT solved by PQC.{cls.RESET}\n")
            for idx, a in enumerate(conv_list, start=1):
                cls._print_assessment_card(idx, a)

        print("\n" + cls.CYAN + "=" * 80 + cls.RESET + "\n")

    @classmethod
    def _print_assessment_card(cls, idx: int, a: Dict[str, Any]) -> None:
        sev = a.get("severity", "MEDIUM").upper()
        sev_color = cls.RED if sev == "CRITICAL" else (cls.YELLOW if sev == "HIGH" else cls.CYAN)
        priority = a.get("priority", 0.0)
        rec = a.get("recommendation", {})
        conf = a.get("confidence", "MEDIUM")

        print(f"  [{idx}] {sev_color}{cls.BOLD}[{sev}]{cls.RESET} "
              f"{cls.BOLD}{a.get('title')}{cls.RESET} "
              f"{cls.DIM}(Priority: {priority:.1f}/100 | {conf} Confidence){cls.RESET}")
        print(f"      Asset       : {cls.WHITE}{a.get('asset')}{cls.RESET} | Algorithm: {cls.MAGENTA}{a.get('algorithm')}{cls.RESET}")
        print(f"      Rationale   : {a.get('rationale')}")

        threat = a.get("threat_analysis", {})
        if threat.get("details"):
            print(f"      Threat Model: {cls.DIM}{threat.get('details')}{cls.RESET}")

        print(f"      Action ({rec.get('timeframe', 'planned').upper()}) : {cls.GREEN}{rec.get('action')}{cls.RESET}")
        print(f"      Reason      : {rec.get('reason')}")

        alts = rec.get("alternatives", [])
        if alts:
            alts_str = ", ".join(alts)
            print(f"      Alternatives: {cls.CYAN}{alts_str}{cls.RESET}")
        print("  " + "┄" * 76)


# ============================================================================
# CLI PARSER & ENTRYPOINT
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Q-SHIELD: Integrated Cryptographic Post-Quantum Migration & Risk Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan remote hostname TLS and certificates
  python3 main.py --host example.com

  # Scan local source code repository
  python3 main.py --repo .

  # Multi-modal combined scan (Host + Code) with JSON output
  python3 main.py --host example.com --repo . --json output.json

  # Launch the interactive lightweight React dashboard
  python3 main.py --dashboard

  # Run automated reliable demo workflow
  python3 main.py --demo
        """,
    )
    # Targets
    target_group = parser.add_argument_group("Scan Targets (Specify at least one, or use --dashboard / --demo)")
    target_group.add_argument("--host", "-H", help="Target hostname, IP, or URL to inspect for TLS/PQC posture")
    target_group.add_argument("--port", "-p", type=int, default=443, help="Port for network TLS scan (default: 443)")
    target_group.add_argument("--repo", "-r", help="Local repository path or file to scan for cryptographic calls")

    # Options
    opts_group = parser.add_argument_group("Scan & Assessment Options")
    opts_group.add_argument(
        "--scenario", "-s",
        choices=["conservative", "central", "relaxed"],
        default="central",
        help="CRQC timeline scenario: conservative (10y), central (15y), relaxed (25y)",
    )
    opts_group.add_argument("--rules", help="Path to external custom rules JSON file")
    opts_group.add_argument("--deep", action="store_true", help="Perform deep TLS scan (enumerate all supported ciphers)")
    opts_group.add_argument("--ignore-comments", action="store_true", help="Ignore commented out source code matches")
    opts_group.add_argument("--quantum-only", action="store_true", help="Filter for quantum-relevant findings only")
    opts_group.add_argument("--timeout", type=float, default=6.0, help="Network timeout in seconds (default: 6.0)")

    # Output & Filtering
    out_group = parser.add_argument_group("Output & Formatting")
    out_group.add_argument("--json", nargs="?", const="-", default=None, help="Export output as JSON (to file or '-' for stdout)")
    out_group.add_argument("--output", "-o", help="Save formatted terminal report or JSON to file")
    out_group.add_argument("--track", "-t", choices=["all", "quantum", "conventional"], default="all", help="Filter output by risk track")
    out_group.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default=None, help="Filter minimum severity")

    # Operations & Demo
    op_group = parser.add_argument_group("Modes & Operations")
    op_group.add_argument("--dashboard", "--serve", action="store_true", help="Launch the lightweight interactive React dashboard")
    op_group.add_argument("--port-web", type=int, default=8080, help="Port for the web dashboard (default: 8080)")
    op_group.add_argument("--demo", action="store_true", help="Run the reliable end-to-end automated demo workflow")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # 1. Automated Demo Mode
    if args.demo:
        try:
            from demo_workflow import run_demo
            return run_demo()
        except ImportError:
            print("Error: demo_workflow.py not found.", file=sys.stderr)
            return 1

    # 2. Web Dashboard Mode
    if args.dashboard:
        try:
            from dashboard import start_dashboard
            start_dashboard(port=args.port_web)
            return 0
        except ImportError:
            print("Error: dashboard.py not found.", file=sys.stderr)
            return 1

    # 3. Interactive prompt if no target specified
    if not args.host and not args.repo:
        TerminalFormatter.print_banner()
        print("\n  Welcome to Q-SHIELD. No scan target was specified.\n")
        print("  Quick Start Options:")
        print("    1. python3 main.py --host google.com")
        print("    2. python3 main.py --repo .")
        print("    3. python3 main.py --host google.com --repo . --json report.json")
        print("    4. python3 main.py --dashboard    (Start Web UI)")
        print("    5. python3 main.py --demo         (Run full demo workflow)\n")
        parser.print_help()
        return 0

    # 4. Execute Pipeline
    result = run_pipeline(
        host=args.host,
        port=args.port,
        repo_path=args.repo,
        scenario=args.scenario,
        rules_path=args.rules,
        deep_tls=args.deep,
        ignore_comments=args.ignore_comments,
        quantum_only=args.quantum_only,
        timeout=args.timeout,
    )

    # 5. Render Output
    json_export = args.json is not None
    json_path = args.json if (args.json and args.json != "-") else None

    if json_export:
        json_str = json.dumps(result, indent=2)
        if json_path:
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"[✓] Combined scan results exported to {json_path}")
        else:
            print(json_str)
    else:
        TerminalFormatter.print_report(
            result,
            track_filter=args.track,
            min_severity=args.min_severity,
        )

    # Save to --output if requested
    if args.output and not json_path:
        with open(args.output, "w", encoding="utf-8") as f:
            if args.output.endswith(".json"):
                json.dump(result, f, indent=2)
            else:
                # Capture text report
                import io
                from contextlib import redirect_stdout
                buf = io.StringIO()
                with redirect_stdout(buf):
                    TerminalFormatter.print_report(result, track_filter=args.track, min_severity=args.min_severity)
                f.write(buf.getvalue())
        print(f"[✓] Report written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

