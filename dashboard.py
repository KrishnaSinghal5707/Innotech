#!/usr/bin/env python3
"""
dashboard.py - Enterprise-Grade HTTP Server for Q-SHIELD Dashboard.

Serves the modern single-page React dashboard and provides REST API endpoints:
  - GET  /                     : Interactive React 18 Dashboard UI
  - GET  /api/health           : System status and engine health
  - GET  /api/demo             : Instant offline demo dataset
  - GET  /api/history          : Session scan history list
  - GET  /api/history/<scan_id>: Full scan result for a recorded scan
  - POST /api/scan             : Execute validated multi-modal or single-flow scan
  - POST /api/compare          : Defensible before/after cryptographic scan comparison
  - GET  /api/export           : Structured JSON / Markdown export

Zero external web framework dependencies: utilizes only Python 3 standard library.
Enforces strict input validation to avoid shell injection, SSRF, arbitrary local file access,
and unsafe subprocess execution.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
import threading
import urllib.parse
import webbrowser
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scan_results import post_process_scan_result, render_markdown
from crypto_evidence import redact_evidence

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure local imports work
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

try:
    from main import run_pipeline, VERSION
    from risk_engine import Report, RuleSet, DEFAULT_RULES_JSON
except ImportError:
    from .main import run_pipeline, VERSION
    from .risk_engine import Report, RuleSet, DEFAULT_RULES_JSON

WEB_DIR = CURRENT_DIR / "web"
MAX_PAYLOAD_SIZE = 1_000_000  # 1MB limit for POST bodies
ALLOWED_SCENARIOS = {"conservative", "central", "relaxed"}

# In-memory history store (thread-safe, persists for the life of the server process)
SCAN_HISTORY_LOCK = threading.RLock()
SCAN_HISTORY: List[Dict[str, Any]] = []
MAX_HISTORY_ENTRIES = 50


# ============================================================================
# INPUT VALIDATION HELPERS (PRIORITY 7)
# ============================================================================

def validate_host_input(raw_host: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Validate host/URL syntax and retain explicit ports, including IPv6 URLs."""
    if raw_host is None or raw_host == "":
        return None, None, None
    if not isinstance(raw_host, str):
        return None, "Host must be a string.", None
    text = raw_host.strip()
    if not text:
        return None, None, None
    if any(c in text for c in ";&|`$()<>\n\r\0\\'\""):
        return None, "Invalid host target: shell metacharacters are prohibited.", None
    explicit_port = None
    match = re.search(r"[\s,]+port\s*[=:]\s*(\d+)\s*$", text, re.IGNORECASE)
    if match:
        explicit_port = int(match.group(1))
        text = text[:match.start()].strip()
    try:
        # An unbracketed IPv6 literal has no attached port.
        try:
            ipaddress.ip_address(text)
            host = text
        except ValueError:
            parsed = urllib.parse.urlsplit(text if "://" in text else "//" + text)
            if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
                return None, "Only HTTP/HTTPS target URLs are supported.", None
            if parsed.username is not None or parsed.password is not None:
                return None, "Target URLs must not contain credentials.", None
            host = parsed.hostname or ""
            if parsed.port is not None:
                explicit_port = parsed.port
            elif parsed.netloc.endswith(":"):
                return None, "Missing target port.", None
    except ValueError:
        return None, "Invalid hostname, IPv6 address, or port.", None
    if explicit_port is not None:
        _, error = validate_port_input(explicit_port)
        if error:
            return None, error, None
    host = host.lower().rstrip(".")
    if host in {"169.254.169.254", "169.254.170.2", "metadata.google.internal"}:
        return None, "Target host is restricted for security reasons.", None
    try:
        address = ipaddress.ip_address(host)
        if getattr(address, "ipv4_mapped", None) in {
            ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("169.254.170.2")
        }:
            return None, "Target host is restricted for security reasons.", None
    except ValueError:
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if host != "localhost" and (len(host) > 253 or not re.fullmatch(pattern, host)):
            return None, "Invalid target hostname or IP format.", None
    return host, None, explicit_port



def validate_port_input(raw_port: Any) -> Tuple[int, Optional[str]]:
    """Validates port integer within RFC range [1, 65535]."""
    if raw_port is None or raw_port == "":
        return 443, None
    if isinstance(raw_port, bool) or not isinstance(raw_port, (int, str)):
        return 443, "Port must be a valid integer."
    try:
        p = int(raw_port)
        if 1 <= p <= 65535:
            return p, None
        return 443, "Port number must be an integer between 1 and 65535."
    except (ValueError, TypeError):
        return 443, "Port must be a valid integer."


def validate_repo_input(raw_repo: Optional[str], base_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates repository path to prevent path traversal and arbitrary system file access.
    Returns (resolved_path_string, error_message).
    """
    if not raw_repo:
        return None, None

    if not isinstance(raw_repo, str):
        return None, "Repository path must be a string."
    s = raw_repo.strip()
    if not s:
        return None, None

    # Check for null bytes and control chars
    if any(c in s for c in ["\0", "\r", "\n", "\t"]):
        return None, "Invalid repository path: control characters detected."

    try:
        path_obj = Path(s)
        if path_obj.is_absolute():
            resolved = path_obj.resolve()
        else:
            resolved = (base_dir / path_obj).resolve()
    except Exception as e:
        return None, f"Repository path resolution failed: {e}"

    if not resolved.exists():
        return None, f"Repository path does not exist: {s}"

    if not resolved.is_relative_to(base_dir.resolve()):
        return None, "Repository must be inside the dashboard workspace. Use the CLI for other authorized paths."

    # Disallow root drive directly (e.g. C:\ or /)
    if resolved == resolved.anchor or resolved.parent == resolved:
        return None, "Scanning the filesystem root directly is restricted for security reasons."

    # Prohibit scanning critical operating system directories
    restricted_system_dirs = [
        Path("C:\\Windows").resolve(),
        Path("C:\\Program Files").resolve(),
        Path("C:\\Program Files (x86)").resolve(),
        Path("/etc").resolve(),
        Path("/var").resolve(),
        Path("/usr").resolve(),
        Path("/bin").resolve(),
        Path("/sbin").resolve(),
        Path("/root").resolve(),
        Path("/sys").resolve(),
        Path("/proc").resolve(),
    ]

    for sys_dir in restricted_system_dirs:
        try:
            if resolved == sys_dir or sys_dir in resolved.parents:
                return None, "Access to system directory is prohibited."
        except Exception:
            pass

    return str(resolved), None


def validate_scenario(raw_scenario: Any) -> Tuple[str, Optional[str]]:
    """Ensures scenario is one of the supported CRQC planning horizons."""
    sc = str(raw_scenario or "central").strip().lower()
    if sc not in ALLOWED_SCENARIOS:
        return "central", f"Scenario must be one of {sorted(list(ALLOWED_SCENARIOS))}."
    return sc, None


# ============================================================================
# SCAN HISTORY & SESSION MANAGEMENT (PRIORITY 5 & 6)
# ============================================================================

def record_scan_history(scan_result: Dict[str, Any], flow_type: str = "full") -> str:
    """Stores an executed real scan in memory history and tags it with a unique ID."""
    safe = redact_evidence(scan_result)
    scan_result.clear()
    scan_result.update(safe)
    now_utc = datetime.now(timezone.utc)
    scan_id = f"scan_{uuid.uuid4().hex}"

    metadata = scan_result.setdefault("metadata", {})
    metadata["scan_id"] = scan_id
    metadata["flow_type"] = flow_type

    summary = scan_result.get("risk_assessment", {}).get("summary", {})
    targets = metadata.get("targets", {})

    target_labels = []
    if targets.get("repo"):
        repo_name = Path(targets["repo"]).name or targets["repo"]
        target_labels.append(f"Repo: {repo_name}")
    if targets.get("host"):
        target_labels.append(f"TLS: {targets['host']}:{targets.get('port', 443)}")
    target_summary_label = " | ".join(target_labels) or "Target Audit"

    record = {
        "id": scan_id,
        "timestamp": metadata.get("scan_finished_at") or now_utc.isoformat(),
        "flow_type": flow_type,
        "target_label": target_summary_label,
        "targets": targets,
        "scenario": metadata.get("scenario", "central"),
        "duration_seconds": metadata.get("duration_seconds", 0.0),
        "total_findings": scan_result.get("inventory", {}).get("total_items", 0),
        "total_assessments": summary.get("total_assessments", 0),
        "severity_counts": summary.get("severity", {}),
        "track_counts": summary.get("track", {}),
        "full_data": scan_result,
    }

    with SCAN_HISTORY_LOCK:
        SCAN_HISTORY.insert(0, record)
        if len(SCAN_HISTORY) > MAX_HISTORY_ENTRIES:
            SCAN_HISTORY.pop()

    return scan_id


def get_scan_history_list() -> List[Dict[str, Any]]:
    """Returns summary cards of recorded scans for the history dashboard."""
    with SCAN_HISTORY_LOCK:
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "flow_type": r["flow_type"],
                "target_label": r["target_label"],
                "targets": r["targets"],
                "scenario": r["scenario"],
                "duration_seconds": r["duration_seconds"],
                "total_findings": r["total_findings"],
                "total_assessments": r["total_assessments"],
                "severity_counts": r["severity_counts"],
                "track_counts": r["track_counts"],
            }
            for r in SCAN_HISTORY
        ]


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full scan result by ID."""
    with SCAN_HISTORY_LOCK:
        for r in SCAN_HISTORY:
            if r["id"] == scan_id:
                return r["full_data"]
    return None


def _validate_comparison_report(report):
    if not isinstance(report, dict) or not report:
        raise ValueError('Comparison scans must be nonempty objects.')
    for field in ('metadata', 'risk_assessment', 'inventory'):
        if not isinstance(report.get(field, {}), dict):
            raise ValueError(field+' must be an object.')
    meta = report.get('metadata', {})
    if not isinstance(meta.get('targets', {}), dict) or not isinstance(meta.get('errors', []), list):
        raise ValueError('Invalid metadata targets or diagnostics.')
    risk = report.get('risk_assessment', {})
    summary = risk.get('summary', {})
    if not isinstance(summary, dict):
        raise ValueError('summary must be an object.')
    for field in ('severity', 'track'):
        values = summary.get(field, {})
        if not isinstance(values, dict) or any(type(n) is not int or n < 0 for n in values.values()):
            raise ValueError(field+' counts must be nonnegative integers.')
    if type(summary.get('total_assessments', 0)) is not int or summary.get('total_assessments', 0) < 0:
        raise ValueError('total_assessments must be a nonnegative integer.')
    for values in (risk.get('assessments', []), report.get('inventory', {}).get('findings', [])):
        if not isinstance(values, list) or any(not isinstance(x, dict) for x in values):
            raise ValueError('Assessments and findings must be arrays of objects.')
        for item in values:
            for field in ('id', 'finding_id', 'assessment_id', 'asset', 'algorithm', 'rule_id', 'title'):
                if field in item and not isinstance(item[field], str):
                    raise ValueError(field+' must be a string.')
            if not isinstance(item.get('attributes', {}), dict):
                raise ValueError('Finding attributes must be an object.')


def compare_scans(baseline_scan: Dict[str, Any], current_scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes an authentic, mathematically grounded comparison between two scans.
    Tracks resolved findings, newly introduced risks, and severity count deltas.
    """
    _validate_comparison_report(baseline_scan)
    _validate_comparison_report(current_scan)
    base_meta = baseline_scan.get("metadata", {})
    curr_meta = current_scan.get("metadata", {})

    base_sum = baseline_scan.get("risk_assessment", {}).get("summary", {})
    curr_sum = current_scan.get("risk_assessment", {}).get("summary", {})

    base_assessments = baseline_scan.get("risk_assessment", {}).get("assessments", [])
    curr_assessments = current_scan.get("risk_assessment", {}).get("assessments", [])

    def group_findings(scan):
        groups = {}
        repo = str(scan.get("metadata", {}).get("targets", {}).get("repo") or "").replace("\\", "/").rstrip("/")
        inventory = {f.get("id"): f for f in scan.get("inventory", {}).get("findings", [])}
        for a in scan.get("risk_assessment", {}).get("assessments", []):
            asset = str(a.get("asset") or "").replace("\\", "/")
            source = inventory.get(a.get("finding_id"), {}).get("evidence_source")
            if source == "code" or str(a.get("finding_id", "")).startswith("code-"):
                # Source line numbers and generated finding IDs shift when code changes.
                asset = re.sub(r":\d+$", "", asset)
                if repo and asset.startswith(repo + "/"):
                    asset = asset[len(repo) + 1:]
            key = (asset or str(a.get("assessment_id") or a.get("title") or "unknown"),
                   str(a.get("rule_id") or a.get("title") or ""), str(a.get("algorithm") or ""))
            groups.setdefault(key, []).append(a)
        return groups

    base_map, curr_map = group_findings(baseline_scan), group_findings(current_scan)
    resolved_list, new_list, persistent_list = [], [], []
    for key in sorted(set(base_map) | set(curr_map)):
        before, after = base_map.get(key, []), curr_map.get(key, [])
        paired = min(len(before), len(after))
        persistent_list.extend(after[:paired])
        resolved_list.extend(before[paired:])
        new_list.extend(after[paired:])

    # Severity deltas
    base_sev = base_sum.get("severity", {})
    curr_sev = curr_sum.get("severity", {})
    severity_delta = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        severity_delta[sev] = curr_sev.get(sev, 0) - base_sev.get(sev, 0)

    # Track deltas
    base_track = base_sum.get("track", {})
    curr_track = curr_sum.get("track", {})
    track_delta = {
        "quantum": curr_track.get("quantum", 0) - base_track.get("quantum", 0),
        "conventional": curr_track.get("conventional", 0) - base_track.get("conventional", 0),
    }

    # Total delta
    total_delta = curr_sum.get("total_assessments", 0) - base_sum.get("total_assessments", 0)

    # Status classification based strictly on actual risk deltas
    crit_diff = severity_delta["critical"]
    high_diff = severity_delta["high"]
    if crit_diff < 0 or (crit_diff == 0 and high_diff < 0):
        status = "improved"
        status_note = "Critical or high finding counts decreased in the comparison scan."
    elif crit_diff > 0 or high_diff > 0:
        status = "degraded"
        status_note = "Risk elevated: New high-severity cryptographic vulnerabilities were identified."
    elif len(resolved_list) > 0 and len(new_list) == 0:
        status = "improved"
        status_note = f"{len(resolved_list)} findings are absent from the comparison scan."
    elif len(new_list) > 0 and len(resolved_list) == 0:
        status = "degraded"
        status_note = f"New risks introduced: {len(new_list)} new findings detected."
    else:
        status = "unchanged"
        status_note = "Security posture is comparable between both scans."

    if base_meta.get("errors") or curr_meta.get("errors"):
        status = "inconclusive"
        status_note = "At least one scan has diagnostics or failed stages. Missing findings do not verify remediation."

    warnings = []
    if base_meta.get("scenario") != curr_meta.get("scenario"):
        warnings.append("Planning scenarios differ; severity changes can reflect horizon assumptions.")
    if base_meta.get("targets") != curr_meta.get("targets"):
        warnings.append("Scan targets differ. Check that the repositories or endpoints represent the intended before/after scope.")
    if base_meta.get("is_demo") or curr_meta.get("is_demo"):
        warnings.append("Comparison includes illustrative demo data.")

    return {
        "warnings": warnings,
        "status": status,
        "status_note": status_note,
        "baseline": {
            "id": base_meta.get("scan_id", "baseline"),
            "timestamp": base_meta.get("scan_finished_at"),
            "targets": base_meta.get("targets", {}),
            "total_assessments": base_sum.get("total_assessments", 0),
            "severity": base_sev,
            "track": base_track,
        },
        "comparison": {
            "id": curr_meta.get("scan_id", "current"),
            "timestamp": curr_meta.get("scan_finished_at"),
            "targets": curr_meta.get("targets", {}),
            "total_assessments": curr_sum.get("total_assessments", 0),
            "severity": curr_sev,
            "track": curr_track,
        },
        "deltas": {
            "total_assessments": total_delta,
            "severity": severity_delta,
            "track": track_delta,
        },
        "resolved_findings": resolved_list,
        "new_findings": new_list,
        "persistent_findings": persistent_list,
    }


# ============================================================================
# DEMO DATA GENERATOR
# ============================================================================

def _get_demo_data() -> Dict[str, Any]:
    """Generates or loads representative demo data showcasing both tracks with zero network latency."""
    sample_repo = CURRENT_DIR / "sample_vulnerable_app"
    repo_arg = str(sample_repo) if sample_repo.exists() else str(CURRENT_DIR)

    # 1. Run local source code scan (instant, zero network latency)
    result = run_pipeline(
        repo_path=repo_arg,
        scenario="central",
    )

    # 2. Add realistic TLS telemetry for rich UI preview
    mock_tls = {
        "module": "tls_scanner",
        "schema_version": "1.0",
        "scan_status": "ok",
        "target": {"host": "api.corp.internal", "port": 443, "input": "api.corp.internal:443"},
        "connection": {
            "tls_version": "TLSv1.3",
            "alpn_protocol": "h2",
            "ip_address": "192.168.1.100"
        },
        "cipher_suite": {
            "name": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3",
            "secret_bits": 256,
            "encryption": "aes-256-gcm",
            "mac_or_aead": "AEAD"
        },
        "key_exchange": {
            "method": "ECDHE (ephemeral)",
            "group": "X25519",
            "forward_secrecy": True,
            "post_quantum_or_hybrid_group": False,
            "note": "Standard classical Curve25519; vulnerable to HNDL once CRQC is realized."
        },
        "certificate": {
            "subject": {"common_name": "api.corp.internal"},
            "issuer": {"common_name": "Corp Internal CA 2024"},
            "public_key": {"algorithm": "RSA", "key_size_bits": 2048, "curve": None},
            "signature": {"algorithm": "sha256WithRSAEncryption", "hash": "sha256"},
            "days_until_expiry": 420,
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z"
        },
        "supported_protocols": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
    }

    result["metadata"]["targets"]["host"] = "api.corp.internal"
    result["metadata"]["targets"]["port"] = 443
    result["modules"]["tls_scanner"] = mock_tls

    # 3. Combine both tracks through adapters & evaluate risk
    from adapters import convert_tls_results_to_findings, convert_code_results_to_findings
    from risk_engine import RiskEngine, RuleSet, DEFAULT_RULES_JSON

    rules_file = CURRENT_DIR / "rules.json"
    if rules_file.exists():
        try:
            ruleset = RuleSet.load_from_file(str(rules_file))
        except Exception:
            ruleset = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)
    else:
        ruleset = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)

    engine = RiskEngine(ruleset, scenario="central")
    all_findings = []
    all_findings.extend(convert_tls_results_to_findings(mock_tls))
    all_findings.extend(convert_code_results_to_findings(result["modules"]["code_scanner"]))

    report = engine.assess(all_findings)
    result["inventory"] = {
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
        ]
    }
    result["risk_assessment"] = report.to_dict()
    result["metadata"]["is_demo"] = True
    result["metadata"]["flow_type"] = "demo"
    return post_process_scan_result(result)


# ============================================================================
# SCAN RESULT POST-PROCESSING (PQC HYBRID & PROTOCOL NORMALIZATION)
# ============================================================================



# ============================================================================
# HTTP REQUEST HANDLER
# ============================================================================

class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for static dashboard assets and REST APIs."""

    def parse_request(self):
        if not super().parse_request():
            return False
        # Local native clients are trusted; browser requests must be same-origin.
        host = self.headers.get('Host', '')
        try:
            target = urllib.parse.urlsplit('http://'+host)
            valid_host = (target.hostname in ('localhost', '127.0.0.1', '::1')
                          and (target.port or 80) == self.server.server_port
                          and not target.username and not target.password)
            local = ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            valid_host = local = False
        origin = self.headers.get('Origin')
        if (not local or not valid_host or (origin is not None and origin != 'http://'+host)
                or self.headers.get('Sec-Fetch-Site') in ('cross-site', 'same-site')):
            self.send_error_json(403, 'Only local same-origin dashboard access is allowed.')
            return False
        return True

    def log_message(self, format: str, *args: Any) -> None:
        """Concise server logging."""
        code = args[1] if len(args) > 1 else (args[0] if args else "-")
        sys.stderr.write(f"[{self.log_date_time_string()}] {getattr(self, 'command', '-')} {getattr(self, 'path', '-')} -> {code}\n")
        sys.stderr.flush()

    def send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(redact_evidence(data), indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(payload)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"error": message, "status": status})

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.end_headers()

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # 1. API: System Health
        if path == "/api/health":
            self.send_json(200, {
                "status": "ok",
                "version": VERSION,
                "engine": "active",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return

        # 2. API: Demo Data
        if path == "/api/demo":
            demo_data = _get_demo_data()
            # Automatically record into history as baseline if history is empty
            with SCAN_HISTORY_LOCK:
                if not SCAN_HISTORY:
                    record_scan_history(demo_data, flow_type="demo")
            self.send_json(200, demo_data)
            return

        # 3. API: Scan History
        if path == "/api/history":
            history_list = get_scan_history_list()
            self.send_json(200, {"history": history_list, "total": len(history_list)})
            return

        # 4. API: Scan History Item by ID
        if path.startswith("/api/history/"):
            scan_id = path.split("/api/history/")[-1]
            scan_data = get_scan_by_id(scan_id)
            if scan_data:
                self.send_json(200, scan_data)
            else:
                self.send_error_json(404, f"Scan history item not found: {scan_id}")
            return

        # 5. API: Report Export (JSON or Markdown)
        if path == "/api/export":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            fmt = query_params.get("format", ["json"])[0].lower()
            scan_id = query_params.get("id", [None])[0]

            scan_data = None
            if scan_id:
                scan_data = get_scan_by_id(scan_id)
            if scan_id and not scan_data:
                self.send_error_json(404, "Requested scan is no longer available in this session.")
                return
            if fmt not in {"json", "markdown"}:
                self.send_error_json(400, "Export format must be json or markdown.")
                return
            if not scan_id:
                with SCAN_HISTORY_LOCK:
                    scan_data = SCAN_HISTORY[0].get("full_data") if SCAN_HISTORY else None

            if not scan_data:
                self.send_error_json(404, "No scan data available to export.")
                return

            if fmt == "markdown":
                md_body = render_markdown(scan_data)
                md_bytes = md_body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="qshield_report.md"')
                self.send_header("Content-Length", str(len(md_bytes)))
                self.end_headers()
                self.wfile.write(md_bytes)
                return
            else:
                json_bytes = json.dumps(scan_data, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="qshield_report.json"')
                self.send_header("Content-Length", str(len(json_bytes)))
                self.end_headers()
                self.wfile.write(json_bytes)
                return

        # 6. Static Web Dashboard (index.html)
        if path in ("/", "/index.html"):
            index_path = WEB_DIR / "index.html"
            if index_path.exists():
                content = index_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error_json(404, f"Dashboard HTML not found at {index_path}")
            return

        # 7. Other static assets (with path traversal security check)
        try:
            rel_path = path.lstrip("/")
            static_file = (WEB_DIR / rel_path).resolve()
            # Ensure file is inside WEB_DIR
            if static_file.is_relative_to(WEB_DIR) and static_file.exists() and static_file.is_file():
                mime = "text/plain"
                if path.endswith(".js"):
                    mime = "application/javascript"
                elif path.endswith(".css"):
                    mime = "text/css"
                elif path.endswith(".json"):
                    mime = "application/json"
                elif path.endswith(".svg"):
                    mime = "image/svg+xml"
                elif path.endswith(".png"):
                    mime = "image/png"
                elif path.endswith(".ico"):
                    mime = "image/x-icon"

                content = static_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(content)
                return
        except Exception:
            pass

        self.send_error_json(404, f"Path not found: {self.path}")

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Check payload length
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_error_json(400, "Invalid Content-Length header.")
            return

        if length < 0:
            self.send_error_json(400, "Content-Length must not be negative.")
            return

        if length > MAX_PAYLOAD_SIZE:
            self.send_error_json(413, f"Request payload too large (max {MAX_PAYLOAD_SIZE} bytes).")
            return

        try:
            body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            payload = json.loads(body) if body.strip() else {}
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            self.send_error_json(400, f"Malformed JSON request body: {err}")
            return

        if not isinstance(payload, dict):
            self.send_error_json(400, "Request body must be a JSON object.")
            return

        # 1. API: Execute Scan
        if path == "/api/scan":
            raw_host = payload.get("host")
            raw_port = payload.get("port", 443)
            raw_repo = payload.get("repo")
            raw_scenario = payload.get("scenario", "central")
            scan_type = str(payload.get("scan_type", "auto")).lower()

            deep = bool(payload.get("deep", False))
            ignore_comments = bool(payload.get("ignore_comments", False))
            quantum_only = bool(payload.get("quantum_only", False))

            if scan_type not in {"auto", "code", "tls", "full"}:
                self.send_error_json(400, "Unknown scan type.")
                return
            if any(not isinstance(payload.get(key, False), bool) for key in ("deep", "ignore_comments", "quantum_only")):
                self.send_error_json(400, "Scan options must be JSON booleans.")
                return
            if scan_type == "code":
                raw_host = None
                raw_port = 443
            elif scan_type == "tls":
                raw_repo = None

            # Input validation (Priority 7)
            clean_host, host_err, extracted_port = validate_host_input(raw_host)
            if host_err:
                self.send_error_json(400, f"Host validation error: {host_err}")
                return

            # Use extracted port from host string if user entered e.g. 'google.com port=9999' or 'host:9999'
            if extracted_port is not None:
                raw_port = extracted_port

            clean_port, port_err = validate_port_input(raw_port)
            if port_err:
                self.send_error_json(400, f"Port validation error: {port_err}")
                return

            clean_repo, repo_err = validate_repo_input(raw_repo, CURRENT_DIR)
            if repo_err:
                self.send_error_json(400, f"Repository path validation error: {repo_err}")
                return

            clean_scenario, sc_err = validate_scenario(raw_scenario)
            if sc_err:
                self.send_error_json(400, f"Scenario validation error: {sc_err}")
                return

            # Apply scan_type filtering (Priority 2: Separate flows for code vs TLS)
            target_host = clean_host if scan_type != "code" else None
            target_repo = clean_repo if scan_type != "tls" else None

            if not target_host and not target_repo:
                self.send_error_json(
                    400,
                    "No valid scan target provided. Please provide an authorized repository path, target TLS host, or both."
                )
                return

            try:
                raw_result = run_pipeline(
                    host=target_host,
                    port=clean_port,
                    repo_path=target_repo,
                    scenario=clean_scenario,
                    deep_tls=deep,
                    ignore_comments=ignore_comments,
                    quantum_only=quantum_only,
                )

                # Post-process to ensure PQC hybrid and protocol findings are cleanly represented
                scan_result = post_process_scan_result(raw_result)

                # Record in session history
                flow_label = "code" if not target_host else ("tls" if not target_repo else "full")
                record_scan_history(scan_result, flow_type=flow_label)

                self.send_json(200, scan_result)
            except Exception as e:
                self.send_error_json(500, f"Scan execution error: {e}")
            return

        # 2. API: Compare Two Scans (Priority 5 & 6)
        if path == "/api/compare":
            baseline_id = payload.get("baseline_id")
            comparison_id = payload.get("comparison_id")

            baseline_scan = payload.get("baseline") or (get_scan_by_id(baseline_id) if baseline_id else None)
            comparison_scan = payload.get("comparison") or (get_scan_by_id(comparison_id) if comparison_id else None)

            if not isinstance(baseline_scan, dict) or not isinstance(comparison_scan, dict) or not baseline_scan or not comparison_scan:
                self.send_error_json(
                    400,
                    "Comparison requires two valid scans. Provide 'baseline_id' and 'comparison_id', or full scan objects."
                )
                return

            try:
                diff_result = compare_scans(baseline_scan, comparison_scan)
                self.send_json(200, diff_result)
            except ValueError as e:
                self.send_error_json(400, f"Invalid comparison: {e}")
            except Exception as e:
                self.send_error_json(500, f"Comparison error: {e}")
            return

        self.send_error_json(404, f"POST endpoint not found: {self.path}")

    def do_DELETE(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/history":
            with SCAN_HISTORY_LOCK:
                SCAN_HISTORY.clear()
            self.send_json(200, {"message": "Scan history cleared successfully."})
            return

        self.send_error_json(404, f"DELETE endpoint not found: {self.path}")


# ============================================================================
# SERVER LIFECYCLE
# ============================================================================

def find_free_port(start_port: int = 8080, max_attempts: int = 20) -> int:
    """Finds an open port starting from start_port."""
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("localhost", p)) != 0:
                return p
    return start_port


def start_dashboard(port: int = 8080, open_browser: bool = True) -> None:
    """Launches the lightweight HTTP server and optionally opens browser."""
    actual_port = find_free_port(port)
    server_address = ("127.0.0.1", actual_port)
    httpd = ThreadingHTTPServer(server_address, DashboardRequestHandler)
    url = f"http://localhost:{actual_port}"

    print("\n" + "=" * 75)
    print("  🚀  Q-SHIELD POST-QUANTUM MIGRATION DASHBOARD RUNNING")
    print("=" * 75)
    print(f"  URL              :  \033[96m\033[1m{url}\033[0m")
    print(f"  Local Host       :  http://127.0.0.1:{actual_port}")
    print(f"  REST API Scan    :  {url}/api/scan")
    print(f"  REST API History :  {url}/api/history")
    print(f"  REST API Compare :  {url}/api/compare")
    print("  Status           :  Press Ctrl+C to stop the dashboard server")
    print("=" * 75 + "\n")

    sys.stdout.flush()

    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Dashboard server shut down gracefully.")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Q-SHIELD React Dashboard Server")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Server port (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    start_dashboard(port=args.port, open_browser=not args.no_browser)
