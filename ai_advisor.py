#!/usr/bin/env python3
"""
ai_advisor.py - Ask Q-SHIELD AI Backend Advisor Module.

Provides contextual post-quantum migration guidance and cryptographic risk analysis
grounded strictly in actual Q-SHIELD scan data.

Features:
  - Backend-only API key handling via environment variables or .env file.
  - Zero external web framework or client library dependencies (standard urllib).
  - Configurable AI providers (OpenAI API by default, extensible base URL/model, and mock test mode).
  - Strict grounding in actual scan findings: refuses hallucination of nonexistent findings.
  - Strict read-only safety guardrails: refuses command execution, file modifications, or risk alterations.
  - Clear, user-friendly error diagnostics when keys are unconfigured or APIs fail.

==============================================================================
CONFIGURATION & API KEY SETUP:
==============================================================================
To configure your OpenAI API key, set the OPENAI_API_KEY environment variable:

  Linux / macOS:
    export OPENAI_API_KEY="sk-..."

  Windows PowerShell:
    $env:OPENAI_API_KEY="sk-..."

  Windows Command Prompt:
    set OPENAI_API_KEY=sk-...

Or create a .env file in the project root:
  # INSERT YOUR OPENAI API KEY HERE:
  OPENAI_API_KEY=sk-...

Configurable environment variables:
  - OPENAI_API_KEY        : OpenAI API Secret Key (REQUIRED for live AI)
  - QSHIELD_AI_PROVIDER   : "openai" (default), or "mock" (offline test mode)
  - QSHIELD_AI_MODEL      : "gpt-4o-mini" (default), "gpt-4o", "gpt-3.5-turbo", etc.
  - QSHIELD_AI_BASE_URL   : "https://api.openai.com/v1" (default, or custom proxy / Ollama endpoint)
  - QSHIELD_AI_TIMEOUT    : API timeout in seconds (default: 30)
==============================================================================
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = Path(__file__).resolve().parent


# ============================================================================
# LIGHTWEIGHT .ENV LOADER (NO EXTERNAL DEPENDENCIES)
# ============================================================================

def load_dotenv_if_present(env_path: Optional[Path] = None) -> None:
    """
    Loads environment variables from a .env file into os.environ if present.
    Does NOT overwrite already-set environment variables.
    """
    if env_path is None:
        # Check current directory and project root
        candidates = [CURRENT_DIR / ".env", CURRENT_DIR.parent / ".env"]
        for cand in candidates:
            if cand.is_file():
                env_path = cand
                break

    if not env_path or not env_path.is_file():
        return

    try:
        content = env_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                # Strip matched single or double quotes
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                # Only set if not already defined in environment
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        # Silent pass if .env reading fails
        pass


# Automatically attempt loading .env on module import
load_dotenv_if_present()


# ============================================================================
# CONFIGURATION HELPERS
# ============================================================================

def get_provider_config() -> Dict[str, Any]:
    """
    Retrieves the current AI provider configuration.
    API keys are kept strictly on the backend and never exposed.
    """
    load_dotenv_if_present()

    # INSERT YOUR OPENAI API KEY HERE OR IN YOUR ENVIRONMENT:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        api_key = os.environ.get("QSHIELD_AI_API_KEY", "").strip()

    provider = os.environ.get("QSHIELD_AI_PROVIDER", "openai").strip().lower()
    model = (
        os.environ.get("QSHIELD_AI_MODEL", "")
        or os.environ.get("OPENAI_MODEL", "")
        or "gpt-4o-mini"
    ).strip()
    base_url = (
        os.environ.get("QSHIELD_AI_BASE_URL", "")
        or os.environ.get("OPENAI_BASE_URL", "")
        or "https://api.openai.com/v1"
    ).strip().rstrip("/")

    try:
        timeout = float(os.environ.get("QSHIELD_AI_TIMEOUT", "30"))
    except ValueError:
        timeout = 30.0

    return {
        "api_key": api_key,
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "timeout": timeout,
    }


def get_ai_status() -> Dict[str, Any]:
    """
    Safe public status descriptor. NEVER exposes secret API keys.
    """
    cfg = get_provider_config()
    is_mock = cfg["provider"] in ("mock", "offline")
    has_key = bool(cfg["api_key"])
    is_configured = has_key or is_mock

    return {
        "configured": is_configured,
        "has_api_key": has_key,
        "provider": cfg["provider"],
        "model": cfg["model"],
        "base_url": cfg["base_url"],
        "ready": is_configured,
        "capabilities": [
            "scan_findings_analysis",
            "cryptographic_threat_rationale",
            "post_quantum_migration_guidance",
            "mosca_horizon_evaluation",
        ],
        "guardrails": [
            "strict_read_only",
            "no_command_execution",
            "no_code_modification",
            "no_risk_score_alteration",
            "grounded_scan_findings_only",
        ],
    }


# ============================================================================
# REAL SCAN DATA CONTEXT BUILDER (GROUNDING ENGINE)
# ============================================================================

def build_scan_context(
    scan_data: Optional[Dict[str, Any]],
    focus_finding_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Extracts structured, factual cryptographic context from an actual Q-SHIELD scan report.
    This ensures all AI advice is grounded in real findings and avoids hallucinations.
    """
    if not scan_data or not isinstance(scan_data, dict):
        return {
            "has_scan": False,
            "summary": "No active scan data available in session.",
            "findings": [],
            "focus_finding": None,
        }

    meta = scan_data.get("metadata", {})
    risk_assessment = scan_data.get("risk_assessment", {})
    summary = risk_assessment.get("summary", {})
    assessments = risk_assessment.get("assessments", [])
    inventory = scan_data.get("inventory", {}).get("findings", [])

    # Map inventory for quick lookup
    inv_map = {item.get("id"): item for item in inventory if isinstance(item, dict) and item.get("id")}

    parsed_findings: List[Dict[str, Any]] = []
    focus_finding_data: Optional[Dict[str, Any]] = None

    for idx, a in enumerate(assessments):
        if not isinstance(a, dict):
            continue
        fid = str(a.get("assessment_id") or a.get("finding_id") or f"finding_{idx}")
        rec = a.get("recommendation", {}) or {}
        threat = a.get("threat_analysis", {}) or {}

        # Look up matching inventory item
        inv_item = inv_map.get(a.get("finding_id")) or {}
        location = a.get("location") or inv_item.get("location") or "unspecified"
        code_snippet = (
            inv_item.get("attributes", {}).get("code_snippet")
            or a.get("attributes", {}).get("code_snippet")
            or None
        )

        finding_dict = {
            "id": fid,
            "title": a.get("title", "Unnamed Cryptographic Finding"),
            "algorithm": a.get("algorithm", "Unknown"),
            "asset": a.get("asset", "Unknown Asset"),
            "severity": (a.get("severity") or "info").lower(),
            "priority": a.get("priority", 0.0),
            "track": a.get("track", "conventional"),
            "location": location,
            "rationale": a.get("rationale", ""),
            "threat_details": threat.get("details", ""),
            "recommendation": {
                "action": rec.get("action", "Review cryptographic implementation"),
                "timeframe": rec.get("timeframe", "planned"),
                "reason": rec.get("reason", ""),
                "alternatives": rec.get("alternatives", []),
            },
            "code_snippet": code_snippet,
            "confidence": a.get("confidence", "medium"),
            "rule_id": a.get("rule_id", ""),
        }

        parsed_findings.append(finding_dict)

        # Check if this matches focus
        if focus_finding_id and (
            focus_finding_id == fid
            or focus_finding_id == a.get("finding_id")
            or focus_finding_id == a.get("assessment_id")
        ):
            focus_finding_data = finding_dict

    # Extract distinct observed algorithms
    observed_algorithms = sorted(list({f["algorithm"] for f in parsed_findings if f.get("algorithm")}))

    context_dict = {
        "has_scan": True,
        "is_demo": bool(meta.get("is_demo", False)),
        "scan_id": meta.get("scan_id", "session_scan"),
        "scan_time": meta.get("scan_finished_at", "Unknown"),
        "scenario": meta.get("scenario", "central"),
        "crqc_horizon_years": meta.get("crqc_horizon_years", 15),
        "targets": {
            "host": meta.get("targets", {}).get("host"),
            "port": meta.get("targets", {}).get("port"),
            "repo": meta.get("targets", {}).get("repo"),
        },
        "metrics": {
            "total_assessments": summary.get("total_assessments", len(parsed_findings)),
            "readiness_score": summary.get("readiness_score"),
            "readiness_label": summary.get("readiness_label", "Undetermined"),
            "severity_counts": summary.get("severity", {}),
            "track_counts": summary.get("track", {}),
        },
        "observed_algorithms": observed_algorithms,
        "findings": parsed_findings,
        "focus_finding": focus_finding_data,
    }

    return context_dict


# ============================================================================
# SYSTEM PROMPT BUILDER (GROUNDING & SAFETY GUARDRAILS)
# ============================================================================

def build_system_prompt(scan_context: Dict[str, Any]) -> str:
    """
    Constructs a rigid, safety-aligned system prompt incorporating real scan findings.
    Enforces read-only behavior, hallucination prevention, and post-quantum expertise.
    """
    has_scan = scan_context.get("has_scan", False)

    if has_scan:
        metrics = scan_context.get("metrics", {})
        sev = metrics.get("severity_counts", {})
        track = metrics.get("track_counts", {})
        targets = scan_context.get("targets", {})

        findings_summary_lines = []
        for f in scan_context.get("findings", [])[:25]:  # Bound top findings for prompt length
            loc_str = f" at {f['location']}" if f.get("location") and f['location'] != "unspecified" else ""
            findings_summary_lines.append(
                f"- [{f['severity'].upper()}] {f['algorithm']} in {f['asset']}{loc_str} "
                f"(Track: {f['track']}, Priority: {f['priority']}/100, Action: {f['recommendation']['action']}, "
                f"Alternatives: {', '.join(f['recommendation']['alternatives']) or 'None listed'})"
            )

        findings_text = "\n".join(findings_summary_lines) if findings_summary_lines else "No findings recorded."
        focus = scan_context.get("focus_finding")
        focus_text = ""
        if focus:
            snippet_str = f"\n  Code Snippet: `{focus['code_snippet']}`" if focus.get("code_snippet") else ""
            focus_text = f"""
CURRENT USER FOCUS FINDING:
- ID: {focus['id']}
- Title: {focus['title']}
- Algorithm: {focus['algorithm']}
- Asset: {focus['asset']}
- Severity: {focus['severity'].upper()}
- Location: {focus['location']}
- Rationale: {focus['rationale']}
- Recommended Action: {focus['recommendation']['action']}
- Recommended Alternatives: {', '.join(focus['recommendation']['alternatives'])}
- Threat Analysis: {focus['threat_details']}{snippet_str}
"""

        scan_section = f"""
REAL SCAN AUDIT DATA (GROUND TRUTH):
- Target Repository : {targets.get('repo') or 'None'}
- Target TLS Host   : {targets.get('host') or 'None'}:{targets.get('port') or 443}
- Scenario / Horizon: {scan_context.get('scenario')} ({scan_context.get('crqc_horizon_years')} years to CRQC)
- Readiness Score   : {metrics.get('readiness_score')}/100 ({metrics.get('readiness_label')})
- Total Findings    : {metrics.get('total_assessments')} (Critical: {sev.get('critical', 0)}, High: {sev.get('high', 0)}, Medium: {sev.get('medium', 0)}, Low: {sev.get('low', 0)})
- Track Breakdown   : Track A (Post-Quantum): {track.get('quantum', 0)} | Track B (Conventional): {track.get('conventional', 0)}
- Detected Algorithms: {', '.join(scan_context.get('observed_algorithms', [])) or 'None'}

OBSERVED SCAN FINDINGS LIST:
{findings_text}
{focus_text}
"""
    else:
        scan_section = """
REAL SCAN AUDIT DATA:
No active scan has been executed yet in this session. The user is in an uninitialized or idle state.
Remind the user they can run a scan on a repository or TLS endpoint, or load the instant demo data in the dashboard.
"""

    system_prompt = f"""You are "Ask Q-SHIELD AI", the elite cryptographic security advisor embedded in the Q-SHIELD Post-Quantum Migration & Cryptographic Risk Orchestrator.

YOUR MISSION:
Help cybersecurity architects, developers, and security leads understand actual cryptographic scan findings, evaluate Shor/Grover quantum threats (Harvest Now, Decrypt Later - HNDL), and provide contextual, step-by-step post-quantum migration guidance based on official standards (NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, hybrid key exchanges, AES-256-GCM, PBKDF2/Argon2id).

{scan_section}

MANDATORY RULES & SAFETY GUARDRAILS:
1. STRICT FACTUAL GROUNDING:
   - Base all finding-specific analysis strictly on the REAL SCAN AUDIT DATA provided above.
   - NEVER fabricate, hallucinate, or pretend that vulnerabilities, files, or algorithms exist if they are not in the scan data.
   - If the user asks about an algorithm or flaw not present in this scan, clearly state that it was not observed in the current scan results.

2. STRICT READ-ONLY SAFETY GUARDRAILS (ZERO-COMMAND & ZERO-MUTATION):
   - You operate strictly as a read-only advisor. You DO NOT possess command execution, file modification, or risk scoring alteration capabilities.
   - You MUST NEVER attempt to run shell commands, bash scripts, or PowerShell cmdlets.
   - You MUST NEVER modify, write, delete, or alter any source code files on disk.
   - You MUST NEVER alter scanner risk scores, readiness ratings, or finding severities.
   - If a user asks or commands you to execute terminal commands, modify files directly on the system, or alter scanner scores, politely and firmly REFUSE: Explain that Q-SHIELD AI is an isolated read-only advisor without execution or filesystem mutation privileges.

3. POST-QUANTUM & CRYPTOGRAPHIC ADVISORY KNOWLEDGE:
   - Track A (Post-Quantum): Asymmetric cryptosystems (RSA, ECDH, ECDSA, DSA, DH) are vulnerable to Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC). Symmetric ciphers (AES-128) suffer effective key halving under Grover's algorithm (64-bit quantum margin = critical HNDL exposure).
   - Post-Quantum Replacements:
     * Key Exchange: FIPS 203 ML-KEM (ML-KEM-768 / ML-KEM-1024) or hybrid schemes (X25519 + ML-KEM-768).
     * Digital Signatures: FIPS 204 ML-DSA (ML-DSA-65 / ML-DSA-87) or FIPS 205 SLH-DSA.
     * Symmetric Encryption: AES-256-GCM (128-bit quantum security under Grover).
   - Track B (Conventional): Weak classical algorithms (MD5, SHA-1, 3DES, AES-ECB, fast unsalted hashing) are immediately exploitable today via classical attacks (collisions, padding oracles, Rainbow tables).
   - Mosca's Theorem (X + Y > Z): Explain the relation between data shelf-life (X), migration time (Y), and quantum horizon (Z).

4. COMMUNICATION STYLE:
   - Professional, authoritative, technically rigorous, and concise.
   - Use clean Markdown formatting, bullet points, and code diff blocks where demonstrating recommended code patterns.
"""
    return system_prompt.strip()


# ============================================================================
# MOCK ADVISOR (FOR UNIT TESTING, OFFLINE DEMOS & CI)
# ============================================================================

def _generate_mock_reply(
    user_message: str,
    scan_context: Dict[str, Any],
    focus_finding: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generates an intelligent, deterministic response grounded in scan data
    for offline testing and environments without external network/API keys.
    """
    msg_lower = user_message.lower()

    # Safety refusal check
    if any(k in msg_lower for k in ["execute", "run command", "rm -rf", "delete file", "modify file", "change score", "alter score"]):
        return (
            "🔒 **Q-SHIELD AI Guardrail Refusal**: As a strictly read-only advisory system, "
            "I cannot execute shell commands, edit source files, or alter risk engine scores. "
            "I can, however, provide recommended remediation code snippets and migration strategies "
            "that your engineering team can review and apply."
        )

    has_scan = scan_context.get("has_scan", False)
    if not has_scan:
        return (
            "No active scan data was detected in your session. Please initiate a scan via the "
            "Q-SHIELD dashboard or click **Instant Demo Data** to populate cryptographic findings."
        )

    findings = scan_context.get("findings", [])
    metrics = scan_context.get("metrics", {})
    sev = metrics.get("severity_counts", {})
    algos = scan_context.get("observed_algorithms", [])

    if focus_finding:
        algo = focus_finding.get("algorithm", "Cryptographic Primitive")
        asset = focus_finding.get("asset", "target")
        severity = focus_finding.get("severity", "info").upper()
        action = focus_finding.get("recommendation", {}).get("action", "Migrate to post-quantum standards")
        alts = focus_finding.get("recommendation", {}).get("alternatives", [])
        alts_str = ", ".join(alts) if alts else "ML-KEM-768 or AES-256-GCM"

        return (
            f"### Contextual Guidance for **{algo}** in `{asset}` ({severity})\n\n"
            f"**Cryptographic Threat Rationale:**\n{focus_finding.get('rationale', 'Cryptographic vulnerability detected.')}\n\n"
            f"**Recommended Action ({focus_finding.get('recommendation', {}).get('timeframe', 'immediate').upper()}):**\n"
            f"- {action}\n\n"
            f"**Recommended NIST PQC / Robust Alternatives:**\n"
            f"- `{alts_str}`\n\n"
            f"**Migration Guidance:**\n"
            f"1. Replace `{algo}` with `{alts[0] if alts else 'AES-256-GCM'}`.\n"
            f"2. Ensure constant-time verification and appropriate key derivation.\n"
            f"3. Run a rescan in Q-SHIELD to verify risk mitigation."
        )

    if any(k in msg_lower for k in ["critical", "high", "quantum", "risk", "highest"]):
        crit_findings = [f for f in findings if f.get("severity") in ("critical", "high")]
        findings_bullets = "\n".join(
            f"- **{f['algorithm']}** in `{f['asset']}` ({f['severity'].upper()}): {f['recommendation']['action']}"
            for f in crit_findings[:6]
        ) or "- No critical or high risks observed."

        return (
            f"### Q-SHIELD Scan Risk Summary\n\n"
            f"Your scan identified **{metrics.get('total_assessments', 0)} assessed findings** with a readiness score of "
            f"**{metrics.get('readiness_score', 'N/A')}/100** ({metrics.get('readiness_label', '')}).\n\n"
            f"**Key High-Severity Exposures:**\n"
            f"{findings_bullets}\n\n"
            f"**Post-Quantum Horizon (Mosca's Theorem):**\n"
            f"With a **{scan_context.get('crqc_horizon_years', 15)}-year horizon**, asymmetric primitives like RSA and classical ECDH "
            f"must be migrated to **ML-KEM (FIPS 203)** or **ML-DSA (FIPS 204)** to protect against Harvest Now, Decrypt Later (HNDL) attacks."
        )

    if any(k in msg_lower for k in ["hndl", "harvest", "mosca"]):
        return (
            "### Harvest Now, Decrypt Later (HNDL) & Mosca's Theorem\n\n"
            "**HNDL Threat Profile:**\n"
            "Adversaries actively intercept and store encrypted network traffic and ciphertexts today. "
            "When a Cryptographically Relevant Quantum Computer (CRQC) becomes operational, stored ciphertexts "
            "encrypted with classical public key algorithms (e.g. RSA, ECDH) can be retroactively decrypted.\n\n"
            "**Mosca's Inequality:**\n"
            "If `X + Y > Z`, your system is already vulnerable:\n"
            "- **X (Data Shelf-Life)**: Duration data must remain confidential.\n"
            "- **Y (Migration Time)**: Time needed to upgrade cryptographic infrastructure.\n"
            "- **Z (Quantum Horizon)**: Years until a functional quantum computer emerges.\n\n"
            "**Recommended Defense:** Deploy hybrid key exchange (e.g. X25519 + ML-KEM-768) immediately for all transport and stored data."
        )

    # General grounded overview
    return (
        f"### Ask Q-SHIELD AI Cryptographic Consultation\n\n"
        f"Based on your current scan of **{scan_context.get('targets', {}).get('repo') or scan_context.get('targets', {}).get('host') or 'your targets'}**:\n\n"
        f"- **Total Assessed Items:** {metrics.get('total_assessments', 0)}\n"
        f"- **Critical Vulnerabilities:** {sev.get('critical', 0)}\n"
        f"- **Detected Algorithms:** {', '.join(algos) if algos else 'None'}\n"
        f"- **Assessed Readiness:** {metrics.get('readiness_score', 'N/A')}/100\n\n"
        f"You can ask me to analyze specific algorithms (e.g., *'How do I replace RSA-1024?'*), explain HNDL risks, or suggest a prioritized migration plan."
    )


# ============================================================================
# MAIN AI QUERY RUNNER
# ============================================================================

def ask_qshield_ai(
    message: str,
    history: Optional[List[Dict[str, str]]] = None,
    scan_data: Optional[Dict[str, Any]] = None,
    focus_finding_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main orchestration entry point for Ask Q-SHIELD AI.

    Validates inputs, formats real scan context, applies safety guardrails,
    and calls the configured AI provider.

    Returns:
      {
        "reply": str,
        "provider": str,
        "model": str,
        "scan_referenced": {
          "total_findings": int,
          "critical_count": int,
          "algorithms": list[str]
        }
      }

    Raises:
      ValueError: for invalid user input.
      RuntimeError: if AI provider is not configured or upstream call fails.
    """
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message must be a non-empty string.")

    cleaned_message = message.strip()
    if len(cleaned_message) > 4000:
        cleaned_message = cleaned_message[:4000]

    # Validate message for command execution attempts
    # We do not execute commands; we guide the AI prompt, but also guard against injection
    cfg = get_provider_config()
    provider = cfg["provider"]
    model = cfg["model"]
    api_key = cfg["api_key"]
    base_url = cfg["base_url"]
    timeout = cfg["timeout"]

    # Grounding context
    scan_context = build_scan_context(scan_data, focus_finding_id=focus_finding_id)
    system_prompt = build_system_prompt(scan_context)

    # Sanitize history
    sanitized_history: List[Dict[str, str]] = []
    if history and isinstance(history, list):
        for item in history[-10:]:  # Limit conversation history to last 10 messages
            if isinstance(item, dict) and "role" in item and "content" in item:
                role = str(item["role"]).lower()
                content = str(item["content"])[:2000]
                if role in ("user", "assistant"):
                    sanitized_history.append({"role": role, "content": content})

    # Prepare metadata return
    scan_ref = {
        "total_findings": scan_context.get("metrics", {}).get("total_assessments", 0),
        "critical_count": scan_context.get("metrics", {}).get("severity_counts", {}).get("critical", 0),
        "algorithms": scan_context.get("observed_algorithms", []),
    }

    # 1. Handle Mock / Offline Mode
    if provider in ("mock", "offline"):
        reply = _generate_mock_reply(
            cleaned_message,
            scan_context,
            focus_finding=scan_context.get("focus_finding")
        )
        return {
            "reply": reply,
            "provider": "mock",
            "model": "offline-advisor-engine",
            "scan_referenced": scan_ref,
        }

    # 2. Check API Key configuration for real AI providers
    if not api_key:
        raise RuntimeError(
            "OpenAI API key is not configured on the Q-SHIELD backend. "
            "Please set the OPENAI_API_KEY environment variable (e.g. export OPENAI_API_KEY=\"sk-...\") "
            "or add OPENAI_API_KEY to your .env file to enable live AI guidance."
        )

    # 3. Call OpenAI / OpenAI-compatible Chat Completions API
    request_messages = [{"role": "system", "content": system_prompt}]
    request_messages.extend(sanitized_history)
    request_messages.append({"role": "user", "content": cleaned_message})

    payload_data = {
        "model": model,
        "messages": request_messages,
        "temperature": 0.2,  # Low temperature for precise cryptographic answers
        "max_tokens": 1200,
    }

    target_endpoint = f"{base_url}/chat/completions"
    json_bytes = json.dumps(payload_data).encode("utf-8")

    req = urllib.request.Request(
        target_endpoint,
        data=json_bytes,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Q-SHIELD-AI-Advisor/2.0",
        },
        method="POST"
    )

    # Configure secure SSL context
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            resp_body = response.read().decode("utf-8")
            resp_data = json.loads(resp_body)
            choices = resp_data.get("choices", [])
            if not choices or not isinstance(choices, list):
                raise RuntimeError("AI provider returned an empty or invalid completion choices list.")

            first_choice = choices[0]
            reply_text = first_choice.get("message", {}).get("content", "").strip()
            if not reply_text:
                raise RuntimeError("AI provider returned an empty response message.")

            return {
                "reply": reply_text,
                "provider": provider,
                "model": model,
                "scan_referenced": scan_ref,
            }

    except urllib.error.HTTPError as http_err:
        err_msg = f"AI Provider HTTP Error {http_err.code}"
        try:
            err_body = http_err.read().decode("utf-8", errors="replace")
            err_json = json.loads(err_body)
            if "error" in err_json and isinstance(err_json["error"], dict):
                detailed = err_json["error"].get("message")
                if detailed:
                    err_msg = f"{err_msg}: {detailed}"
        except Exception:
            pass

        if http_err.code == 401:
            raise RuntimeError(
                f"Authentication failed with AI provider (HTTP 401). "
                f"Please verify that your OPENAI_API_KEY is active and valid. ({err_msg})"
            )
        elif http_err.code == 429:
            raise RuntimeError(
                f"AI provider rate limit or quota exceeded (HTTP 429). "
                f"Please verify your account quota or retry in a few moments. ({err_msg})"
            )
        elif http_err.code >= 500:
            raise RuntimeError(
                f"Upstream AI provider service error (HTTP {http_err.code}). "
                f"The AI service may temporarily be degraded. ({err_msg})"
            )
        else:
            raise RuntimeError(err_msg)

    except urllib.error.URLError as url_err:
        raise RuntimeError(
            f"Failed to connect to AI provider at {base_url}: {url_err.reason}. "
            "Please check network connectivity or your QSHIELD_AI_BASE_URL setting."
        )
    except TimeoutError:
        raise RuntimeError(
            f"AI provider request timed out after {timeout} seconds. "
            "Please try asking a more focused question or increase QSHIELD_AI_TIMEOUT."
        )
    except Exception as general_err:
        raise RuntimeError(f"Unexpected error communicating with AI provider: {general_err}")
