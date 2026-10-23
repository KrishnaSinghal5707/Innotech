#!/usr/bin/env python3
"""
test_risk_engine.py - Comprehensive Unit & Integration Tests for RiskEngine.

Tests verify:
1. Strict separation of Quantum vs. Conventional risk tracks.
2. Defensible recommendations (e.g. Argon2id for password storage; PQC/hybrid for ECDH/RSA).
3. Mosca's Theorem (HNDL) mathematical evaluation (X + Y vs Z).
4. Signature trust lifetime horizon calculations.
5. Evidence provenance and confidence scoring.
6. Environmental exposure & asset criticality adjustments.
7. Algorithm normalization across diverse formats.
8. Report serialization (Markdown & JSON) and filtering.
"""

import json
import unittest
from pathlib import Path

from risk_engine import (
    Confidence,
    Finding,
    FindingError,
    NormalizedFinding,
    Report,
    RiskEngine,
    RuleError,
    RuleSet,
    Severity,
    Track,
    normalize_algorithm,
    normalize_finding,
)


class TestAlgorithmNormalization(unittest.TestCase):
    """Test algorithm string parsing and normalization."""

    def test_rsa_variations(self):
        cases = ["RSA-2048", "rsa_4096", "RSA2048", "rsa-1024"]
        expected_bits = [2048, 4096, 2048, 1024]
        for c, bits in zip(cases, expected_bits):
            n = normalize_algorithm(c)
            self.assertEqual(n.family, "rsa")
            self.assertEqual(n.key_bits, bits)
            self.assertEqual(n.usage_hint, "signature")

    def test_ecdsa_and_curves(self):
        n1 = normalize_algorithm("ECDSA P-256")
        self.assertEqual(n1.family, "ec_dsa")
        self.assertEqual(n1.curve, "p-256")
        self.assertEqual(n1.key_bits, 256)

        n2 = normalize_algorithm("ecdsa_secp384r1")
        self.assertEqual(n2.family, "ec_dsa")
        self.assertEqual(n2.curve, "p-384")
        self.assertEqual(n2.key_bits, 384)

        n3 = normalize_algorithm("Ed25519")
        self.assertEqual(n3.family, "ed25519")
        self.assertEqual(n3.curve, "curve25519")

    def test_ecdh_and_dh(self):
        n1 = normalize_algorithm("ECDH P-256")
        self.assertEqual(n1.family, "ec_dh")
        self.assertEqual(n1.usage_hint, "key_exchange")

        n2 = normalize_algorithm("X25519")
        self.assertEqual(n2.family, "ec_dh")
        self.assertEqual(n2.curve, "x25519")

        n3 = normalize_algorithm("DH-2048")
        self.assertEqual(n3.family, "dh")
        self.assertEqual(n3.key_bits, 2048)

    def test_hashes_and_symmetric(self):
        n_sha256 = normalize_algorithm("SHA-256")
        self.assertEqual(n_sha256.family, "sha2")
        self.assertEqual(n_sha256.hash, "sha256")

        n_md5 = normalize_algorithm("MD5")
        self.assertEqual(n_md5.family, "md5")

        n_aes = normalize_algorithm("AES-128-CBC")
        self.assertEqual(n_aes.family, "aes")
        self.assertEqual(n_aes.key_bits, 128)
        self.assertEqual(n_aes.mode, "cbc")

        n_3des = normalize_algorithm("3DES-ECB")
        self.assertEqual(n_3des.family, "des")
        self.assertEqual(n_3des.mode, "ecb")


class TestTrackSeparationAndRecommendations(unittest.TestCase):
    """Verify quantum vs conventional separation and appropriate recommendations."""

    @classmethod
    def setUpClass(cls):
        rules_path = Path(__file__).parent / "rules.json"
        if rules_path.exists():
            cls.rules = RuleSet.load_from_file(rules_path)
        else:
            from risk_engine import DEFAULT_RULES_JSON
            cls.rules = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)
        cls.engine = RiskEngine(cls.rules)

    def test_sha256_password_storage_conventional_recommendation(self):
        """Direct SHA-256 password storage must be CONVENTIONAL and recommend memory-hard schemes, NOT quantum fixes."""
        finding = Finding(
            id="test-pwd-1",
            asset="auth-database",
            algorithm="SHA-256",
            usage="password_storage",
            exposure="internal",
            criticality="critical",
            evidence_source="static"
        )
        assessments = self.engine.assess_finding(finding)
        self.assertEqual(len(assessments), 1)
        a = assessments[0]

        # 1. Track must be CONVENTIONAL
        self.assertEqual(a.track, Track.CONVENTIONAL)
        self.assertEqual(a.rule_id, "SHA256_PASSWORD_STORAGE")

        # 2. Severity must be CRITICAL
        self.assertEqual(a.severity, Severity.CRITICAL)

        # 3. Action must recommend memory-hard hashing
        action_lower = a.recommendation["action"].lower()
        self.assertTrue("argon2" in action_lower or "bcrypt" in action_lower or "scrypt" in action_lower)
        self.assertFalse("quantum" in action_lower)
        self.assertFalse("kyber" in action_lower)
        self.assertFalse("dilithium" in action_lower)

        # 4. Reason must emphasize GPU/offline cracking and dismiss quantum relevance
        reason_lower = a.recommendation["reason"].lower()
        self.assertTrue("offline" in reason_lower or "brute-force" in reason_lower or "gpu" in reason_lower)
        self.assertIn("not a quantum risk", a.quantum_relevance.lower())

    def test_rsa_signature_quantum_recommendation(self):
        """RSA signature finding must be QUANTUM track and recommend PQC signature schemes."""
        finding = Finding(
            id="test-rsa-sig",
            asset="pki-root-ca",
            algorithm="RSA-4096",
            usage="signature",
            trust_lifetime_years=15.0,
            migration_years=4.0,
            exposure="internet",
            criticality="critical",
            evidence_source="certificate"
        )
        assessments = self.engine.assess_finding(finding)
        self.assertTrue(any(a.rule_id == "RSA_SIGNATURE" for a in assessments))

        a = [a for a in assessments if a.rule_id == "RSA_SIGNATURE"][0]
        self.assertEqual(a.track, Track.QUANTUM)
        self.assertIn("shor", a.rationale.lower())

        action_lower = a.recommendation["action"].lower()
        self.assertTrue("post-quantum" in action_lower or "pqc" in action_lower)
        self.assertTrue(any("ML-DSA" in alt for alt in a.recommendation["alternatives"]))

    def test_ecdh_key_exchange_quantum_hndl_recommendation(self):
        """ECDH key exchange must recommend hybrid or PQC KEM against HNDL."""
        finding = Finding(
            id="test-ecdh-kex",
            asset="tls-terminator",
            algorithm="ECDH P-256",
            usage="key_exchange",
            data_lifetime_years=12.0,
            migration_years=4.0,
            exposure="internet",
            criticality="high",
            evidence_source="config"
        )
        assessments = self.engine.assess_finding(finding)
        self.assertTrue(any(a.rule_id == "ECDH_KEY_EXCHANGE" for a in assessments))

        a = [a for a in assessments if a.rule_id == "ECDH_KEY_EXCHANGE"][0]
        self.assertEqual(a.track, Track.QUANTUM)
        self.assertIn("hndl", a.threat_analysis.model)

        action_lower = a.recommendation["action"].lower()
        self.assertTrue("kem" in action_lower or "hybrid" in action_lower or "ml-kem" in action_lower)
        self.assertTrue(any("ML-KEM" in alt for alt in a.recommendation["alternatives"]))


class TestMoscaTheoremEvaluation(unittest.TestCase):
    """Test Mosca's Theorem (X + Y > Z) mathematical evaluation."""

    @classmethod
    def setUpClass(cls):
        from risk_engine import DEFAULT_RULES_JSON
        cls.rules = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)

    def test_mosca_critical_exposure(self):
        """When X + Y exceeds Z by >= 5 years, severity must be CRITICAL."""
        # Central scenario has Z = 15 years
        engine = RiskEngine(self.rules, scenario="central")
        # X = 20, Y = 5 -> X+Y = 25 -> Delta = +10 >= 5
        finding = Finding(
            id="f-crit",
            asset="health-records-kex",
            algorithm="ECDH P-384",
            usage="key_exchange",
            data_lifetime_years=20.0,
            migration_years=5.0,
            exposure="partner",
            criticality="high",
            evidence_source="config"
        )
        assessments = engine.assess_finding(finding)
        a = assessments[0]
        self.assertEqual(a.severity, Severity.CRITICAL)
        self.assertEqual(a.threat_analysis.mosca_delta, 10.0)
        self.assertIn("Critical HNDL exposure window", a.threat_analysis.details)

    def test_mosca_high_exposure(self):
        """When 0 < X + Y - Z < 5, severity must be HIGH."""
        engine = RiskEngine(self.rules, scenario="central")
        # X = 13, Y = 3 -> X+Y = 16 -> Delta = +1.0
        finding = Finding(
            id="f-high",
            asset="financial-txn-kex",
            algorithm="ECDH P-256",
            usage="key_exchange",
            data_lifetime_years=13.0,
            migration_years=3.0,
            exposure="internet",
            criticality="critical",
            evidence_source="config"
        )
        assessments = engine.assess_finding(finding)
        a = assessments[0]
        self.assertEqual(a.severity, Severity.HIGH)
        self.assertEqual(a.threat_analysis.mosca_delta, 1.0)

    def test_mosca_low_safe_buffer(self):
        """When X + Y <= Z with comfortable margin (>3 yrs), severity is LOW."""
        engine = RiskEngine(self.rules, scenario="central")
        # X = 3, Y = 2 -> X+Y = 5 <= 15 -> Margin = 10 yrs
        finding = Finding(
            id="f-low",
            asset="ephemeral-session-kex",
            algorithm="ECDH P-256",
            usage="key_exchange",
            data_lifetime_years=3.0,
            migration_years=2.0,
            exposure="internal",
            criticality="low",
            evidence_source="config"
        )
        assessments = engine.assess_finding(finding)
        a = assessments[0]
        self.assertEqual(a.severity, Severity.LOW)
        self.assertEqual(a.threat_analysis.mosca_delta, -10.0)

    def test_scenario_override_shifts_severity(self):
        """Conservative scenario (Z=10) should escalate risks compared to relaxed scenario (Z=25)."""
        finding = Finding(
            id="f-shift",
            asset="crm-kex",
            algorithm="ECDH P-256",
            usage="key_exchange",
            data_lifetime_years=8.0,
            migration_years=4.0,  # X+Y = 12
            exposure="internet",
            criticality="high",
            evidence_source="config"
        )
        # In Conservative (Z=10): 12 > 10 -> Delta = +2 -> HIGH
        eng_conservative = RiskEngine(self.rules, scenario="conservative")
        a_cons = eng_conservative.assess_finding(finding)[0]
        self.assertEqual(a_cons.severity, Severity.HIGH)

        # In Relaxed (Z=25): 12 <= 25 -> Buffer = 13 -> LOW
        eng_relaxed = RiskEngine(self.rules, scenario="relaxed")
        a_relax = eng_relaxed.assess_finding(finding)[0]
        self.assertEqual(a_relax.severity, Severity.LOW)


class TestConventionalVulnerabilities(unittest.TestCase):
    """Test detection of classical vulnerabilities: weak keys, broken hashes, ciphers, modes."""

    @classmethod
    def setUpClass(cls):
        from risk_engine import DEFAULT_RULES_JSON
        cls.rules = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)
        cls.engine = RiskEngine(cls.rules)

    def test_sub_2048_bit_rsa_key(self):
        """RSA key with < 2048 bits triggers WEAK_RSA_KEY_LENGTH."""
        finding = Finding(
            id="f-rsa-1024",
            asset="legacy-server",
            algorithm="RSA-1024",
            usage="signature",
            exposure="internal",
            criticality="medium",
            evidence_source="certificate"
        )
        assessments = self.engine.assess_finding(finding)
        rule_ids = [a.rule_id for a in assessments]
        self.assertIn("WEAK_RSA_KEY_LENGTH", rule_ids)
        weak_a = [a for a in assessments if a.rule_id == "WEAK_RSA_KEY_LENGTH"][0]
        self.assertEqual(weak_a.track, Track.CONVENTIONAL)
        self.assertEqual(weak_a.severity, Severity.CRITICAL)

    def test_broken_ciphers_des_and_rc4(self):
        f_des = Finding(id="f-des", algorithm="3DES-EDE-CBC", asset="pos-terminal", evidence_source="binary")
        ass_des = self.engine.assess_finding(f_des)
        self.assertTrue(any(a.rule_id == "DES_OR_3DES_CIPHER" for a in ass_des))

        f_rc4 = Finding(id="f-rc4", algorithm="RC4-128", asset="old-gateway", evidence_source="config")
        ass_rc4 = self.engine.assess_finding(f_rc4)
        self.assertTrue(any(a.rule_id == "RC4_CIPHER" for a in ass_rc4))

    def test_ecb_mode_detection(self):
        f_ecb = Finding(id="f-ecb", algorithm="AES-128-ECB", asset="backup-disk", evidence_source="config")
        ass_ecb = self.engine.assess_finding(f_ecb)
        self.assertTrue(any(a.rule_id == "ECB_MODE_USAGE" for a in ass_ecb))
        a = [x for x in ass_ecb if x.rule_id == "ECB_MODE_USAGE"][0]
        self.assertEqual(a.track, Track.CONVENTIONAL)
        self.assertIn("GCM", a.recommendation["alternatives"][0])


class TestConfidenceAndPriorityScoring(unittest.TestCase):
    """Test confidence evaluation and priority scoring formulas."""

    @classmethod
    def setUpClass(cls):
        from risk_engine import DEFAULT_RULES_JSON
        cls.rules = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)
        cls.engine = RiskEngine(cls.rules)

    def test_certificate_evidence_gives_high_confidence(self):
        finding = Finding(
            id="f-cert",
            algorithm="RSA-2048",
            usage="signature",
            evidence_source="certificate"
        )
        nf = normalize_finding(finding)
        conf, score, rationale = self.engine.evaluate_confidence(nf)
        self.assertEqual(conf, Confidence.HIGH)
        self.assertGreaterEqual(score, 2.5)

    def test_heuristic_evidence_gives_low_confidence(self):
        finding = Finding(
            id="f-heur",
            algorithm="unknown_algo",
            evidence_source="heuristic"
        )
        nf = normalize_finding(finding)
        conf, score, rationale = self.engine.evaluate_confidence(nf)
        self.assertEqual(conf, Confidence.LOW)
        self.assertLess(score, 1.5)

    def test_priority_score_ranking(self):
        """Critical internet-facing finding should outrank an internal low-severity finding."""
        f_crit = Finding(
            id="f-top",
            asset="core-api",
            algorithm="ECDH P-256",
            usage="key_exchange",
            data_lifetime_years=25.0,
            migration_years=5.0,
            exposure="internet",
            criticality="critical",
            evidence_source="certificate"
        )
        f_low = Finding(
            id="f-bottom",
            asset="dev-scratch",
            algorithm="ECDH P-256",
            usage="key_exchange",
            data_lifetime_years=1.0,
            migration_years=1.0,
            exposure="isolated",
            criticality="low",
            evidence_source="heuristic"
        )

        rep = self.engine.assess([f_crit, f_low])
        self.assertEqual(len(rep.assessments), 2)
        # Assess sorted by priority descending
        self.assertGreater(rep.assessments[0].priority, rep.assessments[1].priority)
        self.assertGreater(rep.assessments[0].priority, 80.0)


class TestReportingAndFiltering(unittest.TestCase):
    """Test report formatting, filtering, and CLI outputs."""

    @classmethod
    def setUpClass(cls):
        from risk_engine import DEFAULT_RULES_JSON, DEFAULT_FINDINGS_JSON
        cls.rules = RuleSet.load_from_json_string(DEFAULT_RULES_JSON)
        cls.engine = RiskEngine(cls.rules)
        cls.findings = json.loads(DEFAULT_FINDINGS_JSON)["findings"]

    def test_markdown_and_json_serialization(self):
        report = self.engine.assess(self.findings)

        # JSON
        json_str = report.to_json()
        parsed = json.loads(json_str)
        self.assertIn("summary", parsed)
        self.assertIn("assessments", parsed)
        self.assertGreater(len(parsed["assessments"]), 0)

        # Markdown
        md_str = report.to_markdown()
        self.assertIn("# Cryptographic Risk & Migration Assessment Report", md_str)
        self.assertIn("Track A: Post-Quantum Cryptography", md_str)
        self.assertIn("Track B: Conventional Cryptographic & Hygiene Weaknesses", md_str)

    def test_track_filtering(self):
        report = self.engine.assess(self.findings)
        quantum_only = report.filter(track=Track.QUANTUM)
        self.assertTrue(all(a.track == Track.QUANTUM for a in quantum_only.assessments))

        conv_only = report.filter(track=Track.CONVENTIONAL)
        self.assertTrue(all(a.track == Track.CONVENTIONAL for a in conv_only.assessments))


class TestFindingErrorHandling(unittest.TestCase):
    """Test input validation and error raising."""

    def test_invalid_finding_format(self):
        with self.assertRaises(FindingError):
            Finding.from_dict("not a dict")  # type: ignore

    def test_missing_id(self):
        with self.assertRaises(FindingError):
            Finding.from_dict({"algorithm": "RSA-2048"})

    def test_missing_algorithm(self):
        with self.assertRaises(FindingError):
            Finding.from_dict({"id": "f1"})

    def test_invalid_years(self):
        with self.assertRaises(FindingError):
            Finding.from_dict({"id": "f1", "algorithm": "RSA", "data_lifetime_years": -5})


if __name__ == "__main__":
    unittest.main()

