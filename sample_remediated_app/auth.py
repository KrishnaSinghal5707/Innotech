# Remediated Authentication Service for Q-SHIELD Demo (Post-Migration)
"""
sample_remediated_app/auth.py - Demonstrates remediated cryptographic hygiene.
- Replaces fast unsalted SHA-256 with memory-hard / salted PBKDF2-HMAC-SHA256 (600,000 iterations)
  or Argon2id in accordance with OWASP and NIST SP 800-63B.
- Replaces MD5 with SHA-256 for collision-resistant data checksums.
- Replaces SHA-1 with cryptographically secure random token generation (secrets module).
"""
import hashlib
import os
import secrets
from typing import Tuple

def secure_password_storage(password: str) -> Tuple[bytes, bytes]:
    """
    REMEDIATED: Password storage with cryptographic salt and 600,000 iterations
    (satisfying NIST SP 800-63B & OWASP password storage guidelines).
    Defends against offline GPU/ASIC dictionary attacks.
    """
    salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=600_000)
    return salt, pw_hash

def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """Verifies a password against the stored PBKDF2 hash using constant-time comparison."""
    computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=600_000)
    return secrets.compare_digest(computed, expected_hash)

def secure_checksum(data: bytes) -> str:
    """REMEDIATED: Replaces collision-broken MD5 with SHA-256."""
    return hashlib.sha256(data).hexdigest()

def secure_token(num_bytes: int = 32) -> str:
    """REMEDIATED: Replaces collision-prone SHA-1 tokens with CSPRNG hex tokens."""
    return secrets.token_hex(num_bytes)
