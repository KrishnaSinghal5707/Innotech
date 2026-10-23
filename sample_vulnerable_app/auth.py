# Sample Vulnerable Auth Service for Q-SHIELD Demo
import hashlib
import os

def insecure_password_storage(password: str) -> str:
    # VULNERABLE: Fast unsalted SHA-256 for password storage is vulnerable to offline dictionary/GPU cracking
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def legacy_checksum(data: bytes) -> str:
    # VULNERABLE: MD5 is cryptographically broken by collisions
    return hashlib.md5(data).hexdigest()

def deprecated_sha1_token(token_seed: bytes) -> str:
    # VULNERABLE: SHA-1 is deprecated and collision-prone
    return hashlib.sha1(token_seed).hexdigest()
