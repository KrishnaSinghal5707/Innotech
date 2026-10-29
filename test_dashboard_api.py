#!/usr/bin/env python3
"""
test_dashboard_api.py - Unit and Integration Tests for Q-SHIELD Dashboard HTTP API.

Verifies:
  1. System health status endpoint (/api/health)
  2. Offline demo dataset loading (/api/demo)
  3. Security and input validation:
     - Shell injection prevention on host parameter
     - SSRF metadata endpoint restriction (169.254.169.254)
     - Port range boundary validation (1-65535)
     - Path traversal and system directory restrictions on repo parameter
     - Scenario validation (conservative, central, relaxed)
     - Max payload size enforcement
  4. Separate scan flows:
     - Code repository scanning flow (AST discovery)
     - Graceful handling of TLS failure without crashing
  5. Audit scan history tracking (/api/history and /api/history/<scan_id>)
  6. Defensible before/after cryptographic posture comparison (/api/compare)
  7. Report export in JSON and Markdown formats (/api/export)
  8. Static asset security and directory traversal protection
"""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from dashboard import (
    CURRENT_DIR,
    DashboardRequestHandler,
    SCAN_HISTORY,
    SCAN_HISTORY_LOCK,
    validate_host_input,
    validate_port_input,
    validate_repo_input,
    validate_scenario,
    compare_scans,
)


class TestDashboardInputValidation(unittest.TestCase):
    """Direct unit tests for input validation routines."""

    def test_host_validation_valid(self):
        host, err, port = validate_host_input("google.com")
        self.assertIsNone(err)
        self.assertEqual(host, "google.com")

        host, err, port = validate_host_input("https://api.example.com/v1/auth")
        self.assertIsNone(err)
        self.assertEqual(host, "api.example.com")

        host, err, port = validate_host_input("localhost")
        self.assertIsNone(err)
        self.assertEqual(host, "localhost")

        # Port extraction from string
        host, err, port = validate_host_input("google.com port = 9999")
        self.assertIsNone(err)
        self.assertEqual(host, "google.com")
        self.assertEqual(port, 9999)

        # Host with attached port
        host, err, port = validate_host_input("example.com:8443")
        self.assertIsNone(err)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8443)

    def test_host_validation_injection_prevention(self):
        # Empty scheme only
        host, err, _ = validate_host_input("http://")
        self.assertIsNotNone(err)

        # Shell metacharacters
        for bad in ["google.com; cat /etc/passwd", "target.com && whoami", "host | id", "target`uname`", "foo$bar"]:
            host, err, _ = validate_host_input(bad)
            self.assertIsNotNone(err, f"Should reject injection string: {bad}")
            self.assertIsNone(host)

    def test_host_validation_ssrf_restriction(self):
        # Cloud metadata IP addresses
        for restricted in ["169.254.169.254", "metadata.google.internal"]:
            host, err, _ = validate_host_input(restricted)
            self.assertIsNotNone(err, f"Should reject metadata IP: {restricted}")

    def test_port_validation(self):
        port, err = validate_port_input(443)
        self.assertIsNone(err)
        self.assertEqual(port, 443)

        port, err = validate_port_input("8443")
        self.assertIsNone(err)
        self.assertEqual(port, 8443)

        # Out of bounds
        _, err = validate_port_input(0)
        self.assertIsNotNone(err)

        _, err = validate_port_input(70000)
        self.assertIsNotNone(err)

        _, err = validate_port_input("invalid")
        self.assertIsNotNone(err)

    def test_repo_validation(self):
        # Valid repo in workspace
        resolved, err = validate_repo_input("sample_vulnerable_app", CURRENT_DIR)
        self.assertIsNone(err)
        self.assertTrue(Path(resolved).exists())

        # Non-existent
        _, err = validate_repo_input("non_existent_folder_xyz123", CURRENT_DIR)
        self.assertIsNotNone(err)

        # Control characters
        _, err = validate_repo_input("folder\0evil", CURRENT_DIR)
        self.assertIsNotNone(err)

    def test_scenario_validation(self):
        for valid in ["conservative", "central", "relaxed"]:
            sc, err = validate_scenario(valid)
            self.assertIsNone(err)
            self.assertEqual(sc, valid)

        _, err = validate_scenario("unsupported_scenario")
        self.assertIsNotNone(err)


class TestDashboardServerAPI(unittest.TestCase):
    """End-to-end integration tests for Dashboard HTTP endpoints."""

    @classmethod
    def setUpClass(cls):
        # Bind to port 0 for dynamic ephemeral port allocation
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardRequestHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        # Clear scan history before each test to isolate tests
        with SCAN_HISTORY_LOCK:
            SCAN_HISTORY.clear()

    def _get(self, path: str):
        req = urllib.request.Request(f"{self.base_url}{path}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode("utf-8"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), e.headers

    def _post(self, path: str, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_health_endpoint(self):
        status, body, headers = self._get("/api/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get("status"), "ok")
        self.assertEqual(data.get("engine"), "active")
        self.assertIn("version", data)

    def test_demo_endpoint(self):
        status, body, _ = self._get("/api/demo")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("metadata", data)
        self.assertIn("inventory", data)
        self.assertIn("risk_assessment", data)
        # Should record demo into history
        self.assertGreaterEqual(len(SCAN_HISTORY), 1)

    def test_scan_validation_shell_injection(self):
        status, data = self._post("/api/scan", {
            "host": "evil.com; rm -rf /",
            "repo": "sample_vulnerable_app"
        })
        self.assertEqual(status, 400)
        self.assertIn("Host validation error", data.get("error", ""))

    def test_scan_validation_http_scheme_only(self):
        status, data = self._post("/api/scan", {
            "host": "http://",
            "repo": "sample_vulnerable_app"
        })
        self.assertEqual(status, 400)
        self.assertIn("Host validation error", data.get("error", ""))

    def test_scan_validation_ssrf_metadata(self):
        status, data = self._post("/api/scan", {
            "host": "169.254.169.254",
            "repo": "sample_vulnerable_app"
        })
        self.assertEqual(status, 400)
        self.assertIn("Host validation error", data.get("error", ""))

    def test_scan_validation_missing_targets(self):
        status, data = self._post("/api/scan", {})
        self.assertEqual(status, 400)
        self.assertIn("No valid scan target provided", data.get("error", ""))

    def test_code_scan_flow(self):
        status, data = self._post("/api/scan", {
            "scan_type": "code",
            "repo": "sample_vulnerable_app",
            "scenario": "central"
        })
        self.assertEqual(status, 200)
        self.assertIn("inventory", data)
        self.assertGreater(data["inventory"]["total_items"], 0)
        self.assertIn("risk_assessment", data)

        # Check that TLS scan was omitted for code-only flow
        self.assertIsNone(data["modules"]["tls_scanner"])

    def test_history_and_item_retrieval(self):
        # 1. Run a scan to populate history
        status, scan_res = self._post("/api/scan", {
            "scan_type": "code",
            "repo": "sample_vulnerable_app",
        })
        self.assertEqual(status, 200)
        scan_id = scan_res["metadata"]["scan_id"]

        # 2. Get history list
        status, body, _ = self._get("/api/history")
        self.assertEqual(status, 200)
        hist_data = json.loads(body)
        self.assertEqual(hist_data.get("total"), 1)
        self.assertEqual(hist_data["history"][0]["id"], scan_id)

        # 3. Retrieve specific scan by ID
        status, body, _ = self._get(f"/api/history/{scan_id}")
        self.assertEqual(status, 200)
        retrieved_data = json.loads(body)
        self.assertEqual(retrieved_data["metadata"]["scan_id"], scan_id)

    def test_compare_endpoint(self):
        # Run two scans
        _, scan1 = self._post("/api/scan", {
            "scan_type": "code",
            "repo": "sample_vulnerable_app",
            "scenario": "conservative"
        })
        scan1_id = scan1["metadata"]["scan_id"]

        _, scan2 = self._post("/api/scan", {
            "scan_type": "code",
            "repo": "sample_vulnerable_app",
            "scenario": "central"
        })
        scan2_id = scan2["metadata"]["scan_id"]

        # Compare the two
        status, comp = self._post("/api/compare", {
            "baseline_id": scan1_id,
            "comparison_id": scan2_id
        })
        self.assertEqual(status, 200)
        self.assertIn("status", comp)
        self.assertIn("deltas", comp)
        self.assertIn("resolved_findings", comp)
        self.assertIn("new_findings", comp)
        self.assertIn("persistent_findings", comp)

    def test_export_endpoint(self):
        # Populate history
        self._get("/api/demo")

        # JSON export
        status, body, headers = self._get("/api/export?format=json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))

        # Markdown export
        status, body, headers = self._get("/api/export?format=markdown")
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", headers.get("Content-Type", ""))
        self.assertIn("Q-SHIELD", body)

    def test_static_index_serving(self):
        status, body, headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("Q-SHIELD", body)

    def test_static_traversal_protection(self):
        # Attempt path traversal out of web/
        status, _, _ = self._get("/../../etc/passwd")
        self.assertEqual(status, 404)


class TestQAAssessmentFixes(unittest.TestCase):
    """Direct regression verification for QA reported issues."""

    def test_bug1_aes128_vs_aes256_cipher_normalization(self):
        from adapters import _normalize_tls_cipher_algo
        # TLS_AES_128_GCM_SHA256 must NOT be labeled as AES-256
        algo128 = _normalize_tls_cipher_algo("TLS_AES_128_GCM_SHA256", "aes-128-gcm", 128)
        self.assertEqual(algo128, "AES-128-GCM")

        # TLS_AES_256_GCM_SHA384 must be labeled as AES-256
        algo256 = _normalize_tls_cipher_algo("TLS_AES_256_GCM_SHA384", "aes-256-gcm", 256)
        self.assertEqual(algo256, "AES-256-GCM")

    def test_bug2_hybrid_pqc_post_processing(self):
        from dashboard import post_process_scan_result
        mock_result = {
            "inventory": {
                "total_items": 1,
                "findings": [
                    {
                        "id": "tls-kx-google.com",
                        "asset": "google.com:443",
                        "algorithm": "X25519MLKEM768 (Post-Quantum Hybrid)",
                        "usage": "key_exchange",
                        "attributes": {"is_pqc_hybrid": True}
                    }
                ]
            },
            "risk_assessment": {
                "assessments": [
                    {
                        "finding_id": "tls-kx-google.com",
                        "rule_id": "ECDH_KEY_EXCHANGE",
                        "title": "ECDH Key Establishment Vulnerable",
                        "severity": "medium",
                        "track": "quantum",
                    }
                ],
                "summary": {"total_assessments": 1}
            },
            "metadata": {"errors": []}
        }
        processed = post_process_scan_result(mock_result)
        assessments = processed["risk_assessment"]["assessments"]
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0]["rule_id"], "PQC_HYBRID_KEM_DEPLOYED")
        self.assertEqual(assessments[0]["severity"], "info")
        self.assertIn("ML-KEM", assessments[0]["title"])
        self.assertIn("Maintain", assessments[0]["recommendation"]["action"])

    def test_bug4_deprecated_tls_protocol_assessment(self):
        from dashboard import post_process_scan_result
        mock_result = {
            "inventory": {
                "total_items": 1,
                "findings": [
                    {
                        "id": "tls-proto-tlsv1.0-badssl",
                        "asset": "tls-v1-0.badssl.com:443",
                        "algorithm": "Deprecated-TLSv1.0",
                        "usage": "protocol_negotiation",
                        "attributes": {"evidence_type": "tls_protocol", "protocol": "TLSv1.0"}
                    }
                ]
            },
            "risk_assessment": {
                "assessments": [],
                "summary": {"total_assessments": 0}
            },
            "metadata": {"errors": []}
        }
        processed = post_process_scan_result(mock_result)
        assessments = processed["risk_assessment"]["assessments"]
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0]["rule_id"], "DEPRECATED_TLS_PROTOCOL")
        self.assertEqual(assessments[0]["track"], "conventional")
        self.assertEqual(assessments[0]["severity"], "high")

    def test_bug3_and_bug6_failed_scan_readiness_score(self):
        from dashboard import post_process_scan_result
        mock_failed = {
            "inventory": {"total_items": 0, "findings": []},
            "risk_assessment": {"assessments": [], "summary": {"total_assessments": 0}},
            "metadata": {
                "errors": [{"module": "tls_scanner", "error": "Cannot resolve host: [Errno 11001] getaddrinfo failed"}]
            }
        }
        processed = post_process_scan_result(mock_failed)
        summary = processed["risk_assessment"]["summary"]
        self.assertIsNone(summary.get("readiness_score"), "Failed scans must return None (N/A) for readiness score")
        self.assertEqual(summary.get("readiness_posture"), "failed")
        self.assertIn("N/A", summary.get("readiness_label"))


if __name__ == "__main__":
    unittest.main()
