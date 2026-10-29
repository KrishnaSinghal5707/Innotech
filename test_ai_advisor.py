#!/usr/bin/env python3
"""
test_ai_advisor.py - Unit and Integration Tests for Ask Q-SHIELD AI Advisor.

Verifies:
  1. Safe configuration loading and status reporting (keys never leaked).
  2. Grounding engine: scan context builder extracts actual findings and metrics.
  3. Safety guardrails: read-only policy, command execution refusal.
  4. Core advisor orchestration in both unconfigured and configured states.
  5. Dashboard HTTP API endpoints:
     - GET  /api/ai/status
     - POST /api/ai/chat (validation, unconfigured handling, grounded responses)
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch, MagicMock

from ai_advisor import (
    load_dotenv_if_present,
    get_provider_config,
    get_ai_status,
    build_scan_context,
    build_system_prompt,
    ask_qshield_ai,
    _generate_mock_reply,
)
from dashboard import (
    DashboardRequestHandler,
    _get_demo_data,
    SCAN_HISTORY,
    SCAN_HISTORY_LOCK,
)


class TestAIAdvisorConfig(unittest.TestCase):
    """Tests configuration extraction, .env loading, and status concealment."""

    def test_status_never_exposes_secret_key(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-supersecret1234567890"}):
            status = get_ai_status()
            self.assertTrue(status["configured"])
            self.assertTrue(status["has_api_key"])
            self.assertTrue(status["ready"])
            # Ensure the actual secret key is NOT present in any value
            status_json = json.dumps(status)
            self.assertNotIn("sk-supersecret1234567890", status_json)

    def test_unconfigured_status(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "", "QSHIELD_AI_PROVIDER": "openai"}):
            status = get_ai_status()
            self.assertFalse(status["configured"])
            self.assertFalse(status["has_api_key"])
            self.assertFalse(status["ready"])

    def test_mock_provider_is_ready_for_testing(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "", "QSHIELD_AI_PROVIDER": "mock"}):
            status = get_ai_status()
            self.assertTrue(status["configured"])
            self.assertFalse(status["has_api_key"])
            self.assertTrue(status["ready"])
            self.assertEqual(status["provider"], "mock")

    def test_dotenv_parser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                "# Sample env\n"
                "TEST_CUSTOM_KEY=\"value_123\"\n"
                "TEST_SINGLE_QUOTE='value_456'\n"
                "TEST_PLAIN=value_789\n",
                encoding="utf-8"
            )
            with patch.dict(os.environ, {}, clear=False):
                if "TEST_CUSTOM_KEY" in os.environ:
                    del os.environ["TEST_CUSTOM_KEY"]
                load_dotenv_if_present(env_file)
                self.assertEqual(os.environ.get("TEST_CUSTOM_KEY"), "value_123")
                self.assertEqual(os.environ.get("TEST_SINGLE_QUOTE"), "value_456")
                self.assertEqual(os.environ.get("TEST_PLAIN"), "value_789")


class TestGroundingAndSafety(unittest.TestCase):
    """Tests scan context extraction, prompt construction, and safety guardrails."""

    def setUp(self):
        self.demo_scan = _get_demo_data()

    def test_build_scan_context_demo(self):
        ctx = build_scan_context(self.demo_scan)
        self.assertTrue(ctx["has_scan"])
        self.assertGreater(ctx["metrics"]["total_assessments"], 0)
        self.assertIn("RSA", "".join(ctx["observed_algorithms"]))
        self.assertIsNone(ctx["focus_finding"])

    def test_build_scan_context_with_focus(self):
        findings = self.demo_scan.get("risk_assessment", {}).get("assessments", [])
        if findings:
            target_id = findings[0].get("assessment_id") or findings[0].get("finding_id")
            ctx = build_scan_context(self.demo_scan, focus_finding_id=target_id)
            self.assertIsNotNone(ctx["focus_finding"])
            self.assertEqual(ctx["focus_finding"]["id"], target_id)

    def test_system_prompt_enforces_safety_and_grounding(self):
        ctx = build_scan_context(self.demo_scan)
        prompt = build_system_prompt(ctx)

        # Grounding assertions
        self.assertIn("REAL SCAN AUDIT DATA", prompt)
        self.assertIn("STRICT FACTUAL GROUNDING", prompt)
        self.assertIn("NEVER fabricate, hallucinate", prompt)

        # Safety & read-only assertions
        self.assertIn("STRICT READ-ONLY SAFETY GUARDRAILS", prompt)
        self.assertIn("ZERO-COMMAND", prompt)
        self.assertIn("You MUST NEVER attempt to run shell commands", prompt)
        self.assertIn("You MUST NEVER modify, write, delete, or alter any source code files", prompt)
        self.assertIn("You MUST NEVER alter scanner risk scores", prompt)

        # PQC Standards assertions
        self.assertIn("FIPS 203 ML-KEM", prompt)
        self.assertIn("FIPS 204 ML-DSA", prompt)
        self.assertIn("FIPS 205 SLH-DSA", prompt)
        self.assertIn("Mosca's Theorem", prompt)

    def test_guardrail_refusal_for_command_execution(self):
        ctx = build_scan_context(self.demo_scan)
        for bad_prompt in [
            "Please execute bash command rm -rf /",
            "Run command to patch files",
            "Delete file app.py",
            "Modify file to fix the vulnerability",
            "Change score to 100",
        ]:
            reply = _generate_mock_reply(bad_prompt, ctx)
            self.assertIn("Q-SHIELD AI Guardrail Refusal", reply)
            self.assertIn("read-only", reply.lower())


class TestAskQShieldAI(unittest.TestCase):
    """Tests the primary ask_qshield_ai function."""

    def test_empty_message_validation(self):
        with self.assertRaises(ValueError):
            ask_qshield_ai("")
        with self.assertRaises(ValueError):
            ask_qshield_ai("   ")

    def test_unconfigured_error(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "", "QSHIELD_AI_PROVIDER": "openai"}):
            with self.assertRaises(RuntimeError) as cm:
                ask_qshield_ai("What are my quantum risks?")
            self.assertIn("OpenAI API key is not configured", str(cm.exception))

    def test_mock_provider_grounded_response(self):
        demo = _get_demo_data()
        with patch.dict(os.environ, {"QSHIELD_AI_PROVIDER": "mock"}):
            res = ask_qshield_ai("What are the highest critical quantum risks?", scan_data=demo)
            self.assertIn("reply", res)
            self.assertIn("provider", res)
            self.assertEqual(res["provider"], "mock")
            self.assertIn("scan_referenced", res)
            self.assertGreater(res["scan_referenced"]["total_findings"], 0)
            self.assertIn("Q-SHIELD Scan Risk Summary", res["reply"])

    def test_mock_provider_focused_finding_response(self):
        demo = _get_demo_data()
        findings = demo.get("risk_assessment", {}).get("assessments", [])
        self.assertTrue(len(findings) > 0)
        focus_id = findings[0].get("assessment_id") or findings[0].get("finding_id")

        with patch.dict(os.environ, {"QSHIELD_AI_PROVIDER": "mock"}):
            res = ask_qshield_ai(
                "How do I migrate this?",
                scan_data=demo,
                focus_finding_id=focus_id,
            )
            self.assertIn("Contextual Guidance for", res["reply"])
            self.assertIn(findings[0]["algorithm"], res["reply"])


class TestDashboardAIApi(unittest.TestCase):
    """Integration tests for dashboard HTTP server AI routes."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardRequestHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _get(self, path: str):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, headers={"Host": f"localhost:{self.port}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8")

    def _post(self, path: str, payload: dict):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Host": f"localhost:{self.port}"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_api_ai_status(self):
        status, body = self._get("/api/ai/status")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("configured", data)
        self.assertIn("provider", data)
        self.assertIn("capabilities", data)
        self.assertIn("guardrails", data)

    def test_api_ai_chat_missing_message(self):
        status, data = self._post("/api/ai/chat", {})
        self.assertEqual(status, 400)
        self.assertIn("message", data.get("error", "").lower())

    def test_api_ai_chat_unconfigured_error(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "", "QSHIELD_AI_PROVIDER": "openai"}):
            status, data = self._post("/api/ai/chat", {"message": "What are my risks?"})
            self.assertEqual(status, 503)
            self.assertEqual(data.get("code"), "AI_NOT_CONFIGURED")
            self.assertIn("not configured", data.get("error", "").lower())

    def test_api_ai_chat_mock_success(self):
        with patch.dict(os.environ, {"QSHIELD_AI_PROVIDER": "mock"}):
            status, data = self._post("/api/ai/chat", {
                "message": "What are my critical quantum risks?",
                "history": [],
            })
            self.assertEqual(status, 200)
            self.assertIn("reply", data)
            self.assertEqual(data.get("provider"), "mock")
            self.assertIn("scan_referenced", data)


if __name__ == "__main__":
    unittest.main()
