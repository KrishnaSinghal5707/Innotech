#!/usr/bin/env python3
"""
dashboard.py - Lightweight HTTP Server for Q-SHIELD React Dashboard.

Serves the modern single-page React dashboard and provides REST API endpoints:
  - GET  /              : Interactive React 18 Dashboard UI
  - POST /api/scan      : Run multi-modal scan and return combined findings & risk analysis
  - GET  /api/demo      : Instant demo dataset for offline and fast previewing
  - GET  /api/health    : System status and engine health

Requires only Python 3 standard library; zero external web framework dependencies.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import webbrowser
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Optional

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
except ImportError:
    from .main import run_pipeline, VERSION

WEB_DIR = CURRENT_DIR / "web"


def _get_demo_data() -> Dict[str, Any]:
    """Generates or loads representative demo data showcasing both tracks."""
    sample_repo = CURRENT_DIR / "sample_vulnerable_app"
    repo_arg = str(sample_repo) if sample_repo.exists() else str(CURRENT_DIR)

    # Run on sample app with mock TLS data for instant offline response
    result = run_pipeline(
        host="api.corp.internal",
        port=443,
        repo_path=repo_arg,
        scenario="central",
    )

    # Enhance with realistic TLS telemetry for rich UI preview
    if result.get("modules", {}).get("tls_scanner", {}).get("scan_status") == "failed":
        result["modules"]["tls_scanner"] = {
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
    return result


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for static dashboard assets and REST APIs."""

    def log_message(self, format: str, *args: Any) -> None:
        """Custom concise logging."""
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.command} {self.path} -> {args[1]}\n")

    def send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        # 1. API: System Health
        if path == "/api/health":
            self.send_json(200, {"status": "ok", "version": VERSION, "engine": "active"})
            return

        # 2. API: Demo Data
        if path == "/api/demo":
            demo_data = _get_demo_data()
            self.send_json(200, demo_data)
            return

        # 3. Static Web Dashboard (index.html)
        if path in ("/", "/index.html"):
            index_path = WEB_DIR / "index.html"
            if index_path.exists():
                content = index_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_json(404, {"error": "Dashboard HTML not found at " + str(index_path)})
            return

        # 4. Other static assets
        static_file = WEB_DIR / path.lstrip("/")
        if static_file.exists() and static_file.is_file():
            mime = "text/plain"
            if path.endswith(".js"):
                mime = "application/javascript"
            elif path.endswith(".css"):
                mime = "text/css"
            elif path.endswith(".json"):
                mime = "application/json"
            content = static_file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_json(404, {"error": f"Path not found: {self.path}"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        # 1. API: Execute Scan
        if path == "/api/scan":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                payload = json.loads(body) if body else {}

                host = payload.get("host")
                port = int(payload.get("port", 443))
                repo = payload.get("repo")
                scenario = payload.get("scenario", "central")
                deep = bool(payload.get("deep", False))
                ignore_comments = bool(payload.get("ignore_comments", False))
                quantum_only = bool(payload.get("quantum_only", False))

                # If repo is specified as relative, resolve against project dir
                if repo and not Path(repo).is_absolute():
                    candidate = CURRENT_DIR / repo
                    if candidate.exists():
                        repo = str(candidate)

                scan_result = run_pipeline(
                    host=host,
                    port=port,
                    repo_path=repo,
                    scenario=scenario,
                    deep_tls=deep,
                    ignore_comments=ignore_comments,
                    quantum_only=quantum_only,
                )

                self.send_json(200, scan_result)
            except Exception as e:
                self.send_json(500, {"error": f"Internal scan execution error: {e}"})
            return

        self.send_json(404, {"error": f"POST endpoint not found: {self.path}"})


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
    server_address = ("0.0.0.0", actual_port)
    httpd = ThreadingHTTPServer(server_address, DashboardRequestHandler)
    url = f"http://localhost:{actual_port}"

    print("\n" + "=" * 70)
    print("  🚀  Q-SHIELD POST-QUANTUM MIGRATION DASHBOARD RUNNING")
    print("=" * 70)
    print(f"  URL              :  \033[96m\033[1m{url}\033[0m")
    print(f"  Local Host       :  http://127.0.0.1:{actual_port}")
    print(f"  REST API Endpoint:  {url}/api/scan")
    print("  Status           :  Press Ctrl+C to stop the dashboard server")
    print("=" * 70 + "\n")

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

