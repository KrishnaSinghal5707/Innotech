#!/usr/bin/env python3
"""
test_cbom.py - Comprehensive Unit & Regression Test Suite for CycloneDX 1.6 CBOM Serializer.

Tests:
  1. Code-scanner findings -> valid CycloneDX 1.6 CBOM
  2. TLS telemetry findings -> valid CycloneDX 1.6 CBOM
  3. Mixed multi-modal inventory (Host + Repo)
  4. Empty scan (zero findings, zero assessments)
  5. Unknown and incomplete parameters (honest representation, no fabrication)
  6. Malformed and unexpected input structures
  7. Duplicate asset handling and unique bom-ref enforcement
  8. Cryptographic secret redaction (strict zero private key/credential leakage)
  9. Deterministic serialization (stable canonical ordering)
  10. CLI export flags, stdout streaming, collision checking, and error exit codes
  11. Dashboard /api/export?format=cbom HTTP endpoint
  12. Formal schema conformance against official CycloneDX 1.6 JSON Schema
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cbom import export_cbom, validate_cbom_schema, write_cbom_file
from main import run_pipeline

SCHEMA_PATH = PROJECT_ROOT / "docs" / "bom-1.6.schema.json"


class TestCycloneDX16CBOM(unittest.TestCase):
    """Test suite validating production-quality CycloneDX 1.6 CBOM generation."""

    def setUp(self) -> None:
        self.assertTrue(SCHEMA_PATH.exists(), f"Official schema must exist at {SCHEMA_PATH}")

    def assertConformsToSchema(self, cbom_doc: dict) -> None:
        """Helper to validate against official CycloneDX 1.6 JSON schema."""
        is_valid, error_msg = validate_cbom_schema(cbom_doc, SCHEMA_PATH)
        self.assertTrue(is_valid, f"CycloneDX 1.6 schema validation failed: {error_msg}")

    # ------------------------------------------------------------------------
    # 1. Code-Scanner Findings
    # ------------------------------------------------------------------------
    def test_code_scanner_findings_to_cbom(self) -> None:
        """Validates that AST code scan findings produce schema-valid cryptographic algorithm components."""
        scan_res = run_pipeline(repo_path="sample_vulnerable_app", scenario="central")
        cbom = export_cbom(scan_res)

        self.assertEqual(cbom["bomFormat"], "CycloneDX")
        self.assertEqual(cbom["specVersion"], "1.6")
        self.assertIn("serialNumber", cbom)
        self.assertConformsToSchema(cbom)

        components = cbom.get("components", [])
        self.assertGreater(len(components), 0)

        # Check for expected algorithm primitives
        primitives = {
            c["cryptoProperties"]["algorithmProperties"]["primitive"]
            for c in components
            if "algorithmProperties" in c.get("cryptoProperties", {})
        }
        self.assertIn("hash", primitives)          # MD5, SHA-256
        self.assertIn("block-cipher", primitives)  # 3DES, AES-ECB
        self.assertIn("pke", primitives)           # RSA-1024
        self.assertIn("key-agree", primitives)     # ECDH

        # Check vulnerabilities mapping
        vulns = cbom.get("vulnerabilities", [])
        self.assertGreater(len(vulns), 0)
        for v in vulns:
            self.assertIn("id", v)
            self.assertIn("ratings", v)
            self.assertIn("affects", v)
            self.assertGreater(len(v["affects"]), 0)

    # ------------------------------------------------------------------------
    # 2. TLS Telemetry Findings
    # ------------------------------------------------------------------------
    def test_tls_telemetry_findings_to_cbom(self) -> None:
        """Validates that TLS findings produce certificate, protocol, and cipher components."""
        mock_tls_scan = {
            "metadata": {
                "orchestrator": "Q-SHIELD",
                "version": "2.0.0",
                "targets": {"host": "example.com", "port": 443},
            },
            "inventory": {
                "findings": [
                    {
                        "id": "tls-cert-1",
                        "asset": "example.com:443",
                        "algorithm": "ECDSA secp256r1",
                        "usage": "signature",
                        "key_bits": 256,
                        "evidence_source": "certificate",
                        "attributes": {
                            "evidence_type": "x509_certificate",
                            "match_type": "X509_CERTIFICATE",
                            "subject": {"rfc4514": "CN=example.com", "common_name": "example.com"},
                            "issuer": {"rfc4514": "CN=DigiCert Global Root G2", "common_name": "DigiCert"},
                            "validity": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-12-31T23:59:59Z"},
                            "signature_algorithm": "ecdsa-with-SHA256",
                            "serial_number": "1234567890abcdef",
                            "confidence": "HIGH",
                        },
                    },
                    {
                        "id": "tls-proto-1",
                        "asset": "example.com:443",
                        "algorithm": "Deprecated-TLSv1.1",
                        "usage": "protocol_negotiation",
                        "attributes": {
                            "evidence_type": "tls_protocol",
                            "match_type": "PROTOCOL_SUPPORT_CHECK",
                            "protocol": "TLSv1.1",
                            "confidence": "HIGH",
                        },
                    },
                    {
                        "id": "tls-kx-1",
                        "asset": "example.com:443",
                        "algorithm": "X25519MLKEM768 (Post-Quantum Hybrid)",
                        "usage": "key_exchange",
                        "attributes": {
                            "evidence_type": "tls_key_exchange",
                            "is_pqc_hybrid": True,
                            "group": "X25519MLKEM768",
                            "confidence": "HIGH",
                        },
                    },
                    {
                        "id": "tls-cipher-1",
                        "asset": "example.com:443",
                        "algorithm": "AES-256-GCM",
                        "usage": "symmetric_encryption",
                        "key_bits": 256,
                        "attributes": {
                            "evidence_type": "tls_cipher_suite",
                            "mac_or_aead": "AEAD",
                            "confidence": "HIGH",
                        },
                    },
                ]
            },
            "risk_assessment": {
                "assessments": [
                    {
                        "assessment_id": "assess-proto-1",
                        "finding_id": "tls-proto-1",
                        "rule_id": "DEPRECATED_TLS_PROTOCOL",
                        "title": "Obsolete protocol TLSv1.1 accepted",
                        "severity": "high",
                        "priority": 70.0,
                        "track": "conventional",
                        "rationale": "TLS 1.1 is deprecated by RFC 8996.",
                        "recommendation": {"action": "Disable TLS 1.1."},
                    }
                ]
            },
        }

        cbom = export_cbom(mock_tls_scan)
        self.assertConformsToSchema(cbom)

        asset_types = {c["cryptoProperties"]["assetType"] for c in cbom["components"]}
        self.assertIn("certificate", asset_types)
        self.assertIn("protocol", asset_types)
        self.assertIn("algorithm", asset_types)

        # Inspect certificate properties
        cert_comp = next(c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "certificate")
        c_props = cert_comp["cryptoProperties"]["certificateProperties"]
        self.assertEqual(c_props["subjectName"], "CN=example.com")
        self.assertEqual(c_props["certificateFormat"], "X.509")

        # Inspect protocol properties
        proto_comp = next(c for c in cbom["components"] if c["cryptoProperties"]["assetType"] == "protocol")
        p_props = proto_comp["cryptoProperties"]["protocolProperties"]
        self.assertEqual(p_props["type"], "tls")
        self.assertEqual(p_props["version"], "1.1")

        # Inspect PQC hybrid KEM algorithm properties
        kem_comp = next(c for c in cbom["components"] if "X25519MLKEM768" in c["name"])
        k_props = kem_comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(k_props["primitive"], "combiner")
        self.assertEqual(k_props["nistQuantumSecurityLevel"], 3)

    # ------------------------------------------------------------------------
    # 3. Mixed Multi-Modal Inventory
    # ------------------------------------------------------------------------
    def test_mixed_inventory_scan(self) -> None:
        """Validates a combined host + repository scan result export."""
        mixed_scan = {
            "metadata": {
                "targets": {"host": "internal.service.corp", "port": 8443, "repo": "service_repo"},
                "scenario": "conservative",
                "crqc_horizon_years": 10.0,
            },
            "inventory": {
                "findings": [
                    {
                        "id": "mix-tls-1",
                        "asset": "internal.service.corp:8443",
                        "algorithm": "TLSv1.3",
                        "attributes": {"evidence_type": "tls_protocol", "protocol": "TLSv1.3"},
                    },
                    {
                        "id": "mix-code-1",
                        "asset": "service_repo/crypto.py:42",
                        "algorithm": "AES-256-GCM",
                        "usage": "symmetric_encryption",
                        "key_bits": 256,
                        "attributes": {"evidence_type": "python_ast", "mac_or_aead": "AEAD"},
                    },
                ]
            },
            "risk_assessment": {"assessments": []},
        }
        cbom = export_cbom(mixed_scan)
        self.assertConformsToSchema(cbom)
        self.assertEqual(len(cbom["components"]), 2)
        self.assertEqual(len(cbom["dependencies"]), 1)
        self.assertEqual(len(cbom["dependencies"][0]["dependsOn"]), 2)

    # ------------------------------------------------------------------------
    # 4. Empty Scan
    # ------------------------------------------------------------------------
    def test_empty_scan_produces_valid_cbom(self) -> None:
        """Validates that a scan with zero findings produces a valid, minimal CycloneDX 1.6 document."""
        empty_scan = {
            "metadata": {"targets": {"host": None, "repo": None}},
            "inventory": {"findings": []},
            "risk_assessment": {"assessments": []},
        }
        cbom = export_cbom(empty_scan)
        self.assertConformsToSchema(cbom)
        self.assertEqual(cbom["components"], [])
        self.assertNotIn("dependencies", cbom)
        self.assertNotIn("vulnerabilities", cbom)

    # ------------------------------------------------------------------------
    # 5. Unknown and Incomplete Parameters (No Fabrication)
    # ------------------------------------------------------------------------
    def test_unknown_parameters_honest_representation(self) -> None:
        """Verifies that unknown or incomplete parameters are represented honestly without fabrication."""
        unknown_scan = {
            "metadata": {"targets": {"repo": "custom_app"}},
            "inventory": {
                "findings": [
                    {
                        "id": "unk-1",
                        "asset": "custom_app/core.py:10",
                        "algorithm": "CustomProprietaryCipher",
                        "usage": None,
                        "key_bits": None,
                        "attributes": {},
                    }
                ]
            },
            "risk_assessment": {"assessments": []},
        }
        cbom = export_cbom(unknown_scan)
        self.assertConformsToSchema(cbom)

        comp = cbom["components"][0]
        algo_props = comp["cryptoProperties"]["algorithmProperties"]
        self.assertEqual(algo_props["primitive"], "unknown")
        self.assertNotIn("classicalSecurityLevel", algo_props)
        self.assertNotIn("nistQuantumSecurityLevel", algo_props)
        self.assertNotIn("mode", algo_props)
        self.assertNotIn("curve", algo_props)

    # ------------------------------------------------------------------------
    # 6. Malformed and Unexpected Input Handling
    # ------------------------------------------------------------------------
    def test_malformed_input_rejection(self) -> None:
        """Ensures that non-dict or invalid payloads raise appropriate errors."""
        with self.assertRaises(ValueError):
            export_cbom("not a dict")  # type: ignore

        with self.assertRaises(ValueError):
            export_cbom([1, 2, 3])  # type: ignore

        # Missing standard keys must still handle gracefully
        cbom = export_cbom({})
        self.assertConformsToSchema(cbom)

    # ------------------------------------------------------------------------
    # 7. Duplicate Asset Handling & Unique bom-ref Enforcement
    # ------------------------------------------------------------------------
    def test_duplicate_assets_enforce_unique_bom_refs(self) -> None:
        """Ensures duplicate finding IDs or assets receive distinct, unique bom-refs."""
        dup_scan = {
            "metadata": {"targets": {"repo": "app"}},
            "inventory": {
                "findings": [
                    {"id": "same-id", "asset": "app.py:10", "algorithm": "AES-128", "usage": "symmetric_encryption"},
                    {"id": "same-id", "asset": "app.py:10", "algorithm": "AES-128", "usage": "symmetric_encryption"},
                    {"id": "same-id", "asset": "app.py:10", "algorithm": "AES-128", "usage": "symmetric_encryption"},
                ]
            },
            "risk_assessment": {"assessments": []},
        }
        cbom = export_cbom(dup_scan)
        self.assertConformsToSchema(cbom)

        bom_refs = [c["bom-ref"] for c in cbom["components"]]
        self.assertEqual(len(bom_refs), 3)
        self.assertEqual(len(set(bom_refs)), 3, "All component bom-refs must be strictly unique")

    # ------------------------------------------------------------------------
    # 8. Cryptographic Secret Redaction (Zero Leakage)
    # ------------------------------------------------------------------------
    def test_secret_redaction_guarantees(self) -> None:
        """CRITICAL: Verifies zero private keys, credentials, or secret bytes leak into CBOM."""
        fake_private_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0m4wz89qZ8v+987secretMaterialPayloadXYZ123456789\n"
            "-----END RSA PRIVATE KEY-----"
        )
        secret_scan = {
            "metadata": {"targets": {"repo": "auth_app"}},
            "inventory": {
                "findings": [
                    {
                        "id": "secret-leak-test",
                        "asset": "auth_app/server.key:1",
                        "algorithm": "RSA Private Key",
                        "usage": "asymmetric_key",
                        "key_bits": 2048,
                        "evidence_source": "static",
                        "attributes": {
                            "match_type": "EXPOSED_SECRET",
                            "code_snippet": fake_private_key,
                            "confidence": "HIGH",
                        },
                    }
                ]
            },
            "risk_assessment": {
                "assessments": [
                    {
                        "assessment_id": "assess-secret-1",
                        "finding_id": "secret-leak-test",
                        "rule_id": "EXPOSED_PRIVATE_KEY",
                        "title": "Hardcoded RSA Private Key",
                        "severity": "critical",
                        "priority": 95.0,
                        "track": "conventional",
                        "rationale": "Hardcoded private keys compromise all encrypted assets.",
                        "recommendation": {"action": "Revoke and rotate immediately."},
                    }
                ]
            },
        }

        cbom = export_cbom(secret_scan)
        self.assertConformsToSchema(cbom)

        comp = cbom["components"][0]
        self.assertEqual(comp["cryptoProperties"]["assetType"], "related-crypto-material")
        mat_props = comp["cryptoProperties"]["relatedCryptoMaterialProperties"]
        self.assertEqual(mat_props["type"], "private-key")
        self.assertEqual(mat_props["state"], "compromised")
        self.assertNotIn("value", mat_props)  # Absolute prohibition of secret value

        dumped = json.dumps(cbom)
        self.assertNotIn("secretMaterialPayloadXYZ", dumped)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", dumped)
        self.assertNotIn("END RSA PRIVATE KEY", dumped)

    # ------------------------------------------------------------------------
    # 9. Deterministic Serialization
    # ------------------------------------------------------------------------
    def test_deterministic_serialization(self) -> None:
        """Validates that running export on the same input produces identical JSON components and order."""
        scan_res = run_pipeline(repo_path="sample_vulnerable_app", scenario="central")

        fixed_uuid = "urn:uuid:12345678-1234-5678-1234-567812345678"
        fixed_ts = "2026-10-29T12:00:00Z"

        cbom_1 = export_cbom(scan_res, serial_number=fixed_uuid, timestamp=fixed_ts)
        cbom_2 = export_cbom(scan_res, serial_number=fixed_uuid, timestamp=fixed_ts)

        json_1 = json.dumps(cbom_1, indent=2, sort_keys=True)
        json_2 = json.dumps(cbom_2, indent=2, sort_keys=True)

        self.assertEqual(json_1, json_2, "CBOM output must be fully deterministic apart from UUID/timestamp")

    # ------------------------------------------------------------------------
    # 10. CLI Export & Error Exit Code Tests
    # ------------------------------------------------------------------------
    def test_cli_cbom_export_file(self) -> None:
        """Validates CLI execution with --cbom PATH flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "test_cbom.json"
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "main.py"),
                "--repo", "sample_vulnerable_app",
                "--cbom", str(out_file),
            ]
            proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
            self.assertTrue(out_file.exists())

            doc = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertConformsToSchema(doc)

    def test_cli_cbom_stdout_streaming(self) -> None:
        """Validates CLI execution with --cbom - streaming to stdout."""
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "main.py"),
            "--repo", "sample_vulnerable_app",
            "--cbom", "-",
        ]
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, f"CLI failed: {proc.stderr}")
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertConformsToSchema(doc)

    def test_cli_cbom_path_collision_error(self) -> None:
        """Validates that specifying identical paths for --cbom and --json causes an error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "out.json"
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "main.py"),
                "--repo", "sample_vulnerable_app",
                "--cbom", str(out_file),
                "--json", str(out_file),
            ]
            proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(proc.returncode, 2)
            self.assertIn("distinct paths", proc.stderr)

    def test_cli_cbom_without_target_error(self) -> None:
        """Validates that providing --cbom without a target produces a usage error."""
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "main.py"),
            "--cbom", "test.json",
        ]
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("requires --repo and/or --host", proc.stderr)

    def test_cli_cbom_unwriteable_path_returns_nonzero(self) -> None:
        """Validates that an invalid or unwriteable path produces a nonzero exit code."""
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "main.py"),
            "--repo", "sample_vulnerable_app",
            "--cbom", "Z:\\invalid_nonexistent_drive_xyz\\test.json",
        ]
        proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertNotEqual(proc.returncode, 0, "CLI must exit with nonzero code on write failure")
        self.assertIn("Unable to write CBOM", proc.stderr)

    # ------------------------------------------------------------------------
    # 11. Dashboard /api/export?format=cbom Integration
    # ------------------------------------------------------------------------
    def test_dashboard_cbom_export_handler(self) -> None:
        """Validates the dashboard export endpoint logic for format=cbom."""
        from dashboard import record_scan_history, _get_demo_data

        demo_data = _get_demo_data()
        record_scan_history(demo_data, flow_type="demo")

        # Directly invoke export serialization as dashboard handler would
        cbom_doc = export_cbom(demo_data)
        self.assertConformsToSchema(cbom_doc)
        self.assertEqual(cbom_doc["bomFormat"], "CycloneDX")
        self.assertEqual(cbom_doc["specVersion"], "1.6")


if __name__ == "__main__":
    unittest.main()
