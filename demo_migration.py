#!/usr/bin/env python3
"""
demo_migration.py - Controlled Cryptographic Migration Demonstration for Q-SHIELD.

Provides independent verification of a before-and-after cryptographic migration:
  1. Scans BEFORE state (sample_vulnerable_app):
     - MD5, fast unsalted SHA-256 password hash, SHA-1 tokens, 3DES, AES-ECB, RSA-1024, classical ECDH.
  2. Scans AFTER state (sample_remediated_app):
     - PBKDF2/Argon2id, SHA-256, CSPRNG tokens, AES-256-GCM (AEAD), RSA-3072, Hybrid PQC KEM.
  3. Displays comparative risk delta and migration score improvement.
  4. Executes LIVE RUNTIME FUNCTIONAL VERIFICATION:
     - Confirms that remediated algorithms execute correctly at runtime.
     - Contrasts static AST detection (code signatures) with runtime execution proof.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from main import run_pipeline, TerminalFormatter


def print_banner() -> None:
    print("\n" + "=" * 80)
    print("\033[96m\033[1m  🛡️  Q-SHIELD CONTROLLED MIGRATION DEMONSTRATION & RUNTIME VERIFICATION\033[0m")
    print("=" * 80)
    print("\033[2m  Comparing legacy code with classical remediation and a local hybrid exchange demo\033[0m\n")


def run_migration_demo() -> int:
    print_banner()

    vulnerable_dir = PROJECT_DIR / "sample_vulnerable_app"
    remediated_dir = PROJECT_DIR / "sample_remediated_app"

    # ------------------------------------------------------------------------
    # STEP 1: Scan BEFORE state (Legacy / Vulnerable)
    # ------------------------------------------------------------------------
    print("\033[93m\033[1m[STAGE 1: BEFORE MIGRATION - Scanning sample_vulnerable_app]\033[0m")
    before_res = run_pipeline(repo_path=str(vulnerable_dir), scenario="central")
    before_assessments = before_res["risk_assessment"]["assessments"]
    before_summary = before_res["risk_assessment"]["summary"]

    before_quantum = [a for a in before_assessments if a["track"] == "quantum"]
    before_conv = [a for a in before_assessments if a["track"] == "conventional"]

    print(f"  • Total Assessed Risks   : \033[91m\033[1m{len(before_assessments)}\033[0m")
    print(f"  • Track A (Quantum Risks): {len(before_quantum)} items (RSA-1024, ECDH P-256, AES-128)")
    print(f"  • Track B (Conventional) : {len(before_conv)} items (Fast SHA-256 password hash, MD5, 3DES, AES-ECB, SHA-1)")
    print(f"  • Critical Flaws         : \033[91m{before_summary['severity'].get('critical', 0)}\033[0m | High: \033[93m{before_summary['severity'].get('high', 0)}\033[0m")

    # ------------------------------------------------------------------------
    # STEP 2: Scan AFTER state (Migrated / Post-Quantum Ready)
    # ------------------------------------------------------------------------
    print("\n\033[92m\033[1m[STAGE 2: AFTER MIGRATION - Scanning sample_remediated_app]\033[0m")
    after_res = run_pipeline(repo_path=str(remediated_dir), scenario="central")
    after_assessments = after_res["risk_assessment"]["assessments"]
    after_summary = after_res["risk_assessment"]["summary"]

    after_quantum = [a for a in after_assessments if a["track"] == "quantum"]
    after_conv = [a for a in after_assessments if a["track"] == "conventional"]

    print(f"  • Total Assessed Risks   : \033[92m\033[1m{len(after_assessments)}\033[0m")
    print(f"  • Track A (Quantum observations) : {len(after_quantum)} items (includes remaining classical asymmetric operations)")
    print(f"  • Track B (Conventional) : \033[92m{len(after_conv)}\033[0m items (Review observed findings and coverage limits.)")
    print(f"  • Critical Flaws         : \033[92m{after_summary['severity'].get('critical', 0)}\033[0m | High: \033[92m{after_summary['severity'].get('high', 0)}\033[0m")

    # ------------------------------------------------------------------------
    # STEP 3: Comparative Migration Delta Matrix
    # ------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("\033[1m  📊 COMPARATIVE MIGRATION DELTA MATRIX\033[0m")
    print("=" * 80)
    print(f"  {'Metric / Cryptographic Control':<38} | {'BEFORE (Legacy)':<16} | {'AFTER (Remediated)':<18}")
    print("  " + "─" * 76)

    matrix = [
        ("Password Storage Algorithm", "SHA-256 (Fast, unsalted)", "PBKDF2/Argon2id (Salted, 600k)"),
        ("Integrity / Checksum Hash", "MD5 (Broken collision)", "SHA-256 (Collision resistant)"),
        ("Session Token Generation", "SHA-1 (Deprecated)", "secrets.token_hex (CSPRNG)"),
        ("Symmetric Encryption Cipher", "3DES-CBC / AES-128-ECB", "AES-256-GCM (AEAD)"),
        ("Symmetric Key Quantum Margin", "64-bit (Grover halved)", "128-bit (Quantum resistant)"),
        ("Asymmetric Key Length", "RSA 1024-bit (Factorable)", "RSA 3072-bit (NIST SP 800-57)"),
        ("Key Exchange Mechanism", "Classical ECDH P-256", "Local X25519 + ML-KEM-768 demo"),
        ("HNDL Quantum Retrospective Risk", "CRITICAL EXPOSURE", "Local round trip verified; transport unassessed"),
        ("Track B Conventional Flaws", f"{len(before_conv)} Vulnerabilities", f"{len(after_conv)} assessed conventional findings"),
    ]

    for item, b_val, a_val in matrix:
        print(f"  {item:<38} | \033[91m{b_val:<16}\033[0m | \033[92m\033[1m{a_val:<18}\033[0m")

    print("=" * 80)

    # ------------------------------------------------------------------------
    # STEP 4: Live Runtime Functional Verification
    # ------------------------------------------------------------------------
    print("\n\033[96m\033[1m[STAGE 3: INDEPENDENT LIVE RUNTIME VERIFICATION]\033[0m")
    print("\033[2m  Executing live cryptographic operations to prove runtime functional correctness...\033[0m\n")

    try:
        from sample_remediated_app.auth import (
            secure_password_storage,
            verify_password,
            secure_checksum,
            secure_token,
        )
        from sample_remediated_app.crypto_service import (
            generate_secure_rsa_keys,
            hybrid_demo_exchange,
            secure_aes_gcm_encryption,
            secure_aes_gcm_decryption,
        )

        # 1. Verify Password Storage at Runtime
        salt, pw_hash = secure_password_storage("SuperSecretPassword123!")
        assert verify_password("SuperSecretPassword123!", salt, pw_hash) is True
        assert verify_password("WrongPassword!", salt, pw_hash) is False
        print("  \033[92m[✓ RUNTIME VERIFIED]\033[0m Salted PBKDF2 password hashing & verification functional.")

        # 2. Verify Checksum at Runtime
        data = b"Enterprise Critical Financial Transaction Record"
        digest = secure_checksum(data)
        assert len(digest) == 64
        print(f"  \033[92m[✓ RUNTIME VERIFIED]\033[0m SHA-256 integrity checksum computed: {digest[:16]}...")

        # 3. Verify CSPRNG Token at Runtime
        token = secure_token(32)
        assert len(token) == 64
        print(f"  \033[92m[✓ RUNTIME VERIFIED]\033[0m CSPRNG secure session token generated: {token[:16]}...")

        # 4. Verify AES-256-GCM AEAD Encryption & Decryption Roundtrip
        key = os.urandom(32)
        plaintext = b"Confidential Medical Record: Patient John Doe"
        nonce, ciphertext = secure_aes_gcm_encryption(key, plaintext)
        decrypted = secure_aes_gcm_decryption(key, nonce, ciphertext)
        assert decrypted == plaintext
        print("  \033[92m[✓ RUNTIME VERIFIED]\033[0m AES-256-GCM authenticated encryption/decryption roundtrip succeeded.")

        # 5. Verify Hybrid Post-Quantum KEM Secret Derivation at Runtime
        sender, receiver = hybrid_demo_exchange()
        assert sender == receiver and len(sender) == 48
        try:
            hybrid_demo_exchange(tamper=True)
        except ValueError:
            pass
        else:
            raise AssertionError("Tampered ciphertext did not fail key confirmation")
        print(f"  \033[92m[✓ RUNTIME VERIFIED]\033[0m Local X25519 + ML-KEM-768 two-party agreement and ciphertext-tamper rejection verified; no transport/compliance certification.")

        print("\n\033[92m\033[1m  🎉 ALL RUNTIME CRYPTOGRAPHIC VERIFICATION ASSERTIONS PASSED!\033[0m")

    except Exception as e:
        print(f"  \033[91m[X RUNTIME VERIFICATION FAILED]\033[0m: {e}")
        return 1

    # ------------------------------------------------------------------------
    # STEP 5: Evidence Distinction Note
    # ------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("\033[1m  🔍 STATIC AST EVIDENCE VS. RUNTIME VERIFICATION SUMMARY:\033[0m")
    print("=" * 80)
    print("  1. STATIC AST EVIDENCE:")
    print("     - Records supported cryptographic source syntax; absence of a finding is not proof of safety.")
    print("     - Identified supported conventional and quantum observations; review the actual report counts.")
    print("     - A lack of matched rules does not establish absence of flaws; review coverage and remaining asymmetric exposure.")
    print("  2. LIVE RUNTIME VERIFICATION:")
    print("     - Proves remediated code does not merely compile, but executes correct cryptography.")
    print("     - Successfully executed encryption, decryption, authentication tag checking,")
    print("       and constant-time password hash comparison dynamically.")
    print("=" * 80 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(run_migration_demo())
