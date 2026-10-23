#!/usr/bin/env python3
"""
test_integration.py - Integration and End-to-End Test Suite for Q-SHIELD.

Tests:
  1. Adapter transformations from TLS scanner results to Risk Engine findings
  2. Adapter transformations from Code scanner results to Risk Engine findings
  3. Graceful failure recovery on invalid hosts, closed ports, and missing directories
  4. Multi-modal pipeline execution and combined JSON generation
  5. Strict separation of Track A (Quantum) and Track B (Conventional) risks
  6. CLI flag parsing and output options
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from adapters import (
    convert_tls_results_to_findings,
    convert_code_results_to_findings,
)
from main import run_pipeline, build_parser
from risk_engine import RiskEngine, RuleSet, Severity, Track


class TestAdapters(unittest.TestCase):
    def test_tls_conversion_success(self):
        sample_tls = {
            "module": "tls_scanner",
            "scan_status": "ok",
            "target": {"host": "example.com", "port": 443},
            "connection": {"tls_version": "TLSv1.3"},
            "cipher_suite": {
                "name": "TLS_AES_256_GCM_SHA384",
                "secret_bits": 256,
                "encryption": "aes-256-gcm"
            },
            "key_exchange": {
                "method": "ECDHE",
                "group": "X25519MLKEM768",
                "post_quantum_or_hybrid_group": True
            },
            "certificate": {
                "subject": {"common_name": "example.com"},
                "public_key": {"algorithm": "ECDSA", "key_size_bits": 256, "curve": "secp256r1"},
                "signature": {"algorithm": "ecdsa-with-SHA256"},
                "days_until_expiry": 180
            },
            "supported_protocols": {"TLSv1.0": False, "TLSv1.2": True, "TLSv1.3": True}
        }
        findings = convert_tls_results_to_findings(sample_tls)
        self.assertGreaterEqual(len(findings), 3)

        # Check cert finding
        cert_f = next(f for f in findings if "cert" in f.id)
        self.assertEqual(cert_f.asset, "example.com:443")
        self.assertIn("ECDSA", cert_f.algorithm)
        self.assertEqual(cert_f.evidence_source, "certificate")

        # Check KX finding
        kx_f = next(f for f in findings if "kx" in f.id)
        self.assertIn("Post-Quantum", kx_f.algorithm)

        # Check Cipher finding
        c_f = next(f for f in findings if "cipher" in f.id)
        self.assertIn("AES-256", c_f.algorithm)

    def test_tls_conversion_failed_scan(self):
        failed_tls = {
            "scan_status": "failed",
            "target": {"host": "unreachable.test", "port": 443},
            "errors": [{"stage": "dns", "error": "Name or service not known"}]
        }
        findings = convert_tls_results_to_findings(failed_tls)
        self.assertEqual(findings, [])

    def test_code_conversion(self):
        sample_code = {
            "target_path": "src/",
            "findings": [
                {
                    "file_path": "auth.py",
                    "line_number": 10,
                    "detected_algorithm": "SHA-256",
                    "likely_purpose": "Weak Password Storage",
                    "confidence": "HIGH",
                    "match_type": "CONFIRMED_CALL",
                    "quantum_risk": "NOT_APPLICABLE",
                    "code_snippet": "hashlib.sha256(password.encode())",
                    "is_comment": False
                },
                {
                    "file_path": "crypto.py",
                    "line_number": 25,
                    "detected_algorithm": "RSA (Rivest-Shamir-Adleman)",
                    "likely_purpose": "Asymmetric Key Pair Generation",
                    "confidence": "HIGH",
                    "match_type": "CONFIRMED_CALL",
                    "quantum_risk": "CRITICAL_VULNERABLE",
                    "code_snippet": "rsa.generate_private_key(key_size=1024)",
                    "is_comment": False
                }
            ]
        }
        findings = convert_code_results_to_findings(sample_code)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].usage, "password_storage")
        self.assertEqual(findings[0].evidence_source, "static")
        self.assertIn("RSA", findings[1].algorithm)


class TestPipeline(unittest.TestCase):
    def test_pipeline_repo_scan(self):
        sample_dir = Path(__file__).resolve().parent / "sample_vulnerable_app"
        result = run_pipeline(repo_path=str(sample_dir), scenario="central")

        self.assertIn("metadata", result)
        self.assertIn("modules", result)
        self.assertIn("risk_assessment", result)

        assessments = result["risk_assessment"]["assessments"]
        self.assertGreater(len(assessments), 0)

        # Check track separation
        tracks = {a["track"] for a in assessments}
        self.assertIn("quantum", tracks)
        self.assertIn("conventional", tracks)

    def test_pipeline_graceful_network_failure(self):
        result = run_pipeline(
            host="non-existent-hostname-12345.invalid",
            timeout=1.0
        )
        tls_mod = result["modules"]["tls_scanner"]
        self.assertEqual(tls_mod["scan_status"], "failed")
        self.assertGreater(len(result["metadata"]["errors"]), 0)
        # Should not throw exception
        self.assertIn("risk_assessment", result)

    def test_pipeline_missing_repo_path(self):
        result = run_pipeline(
            repo_path="/path/to/non/existent/repo/xyz",
        )
        self.assertGreater(len(result["metadata"]["errors"]), 0)
        self.assertIn("risk_assessment", result)

    def test_cli_parser_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["--host", "example.com", "--repo", "."])
        self.assertEqual(args.host, "example.com")
        self.assertEqual(args.repo, ".")
        self.assertEqual(args.scenario, "central")
        self.assertEqual(args.port, 443)


if __name__ == "__main__":
    unittest.main()
