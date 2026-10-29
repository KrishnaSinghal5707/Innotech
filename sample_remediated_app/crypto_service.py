# Remediated Cryptographic Service for Q-SHIELD Demo (Post-Migration)
"""
sample_remediated_app/crypto_service.py - Demonstrates remediated cryptographic agility.
- Replaces weak RSA-1024 with RSA-3072 / 4096 (classical security >= 128-bit) and explicit remaining quantum exposure.
- Replaces classical ECDH with hybrid PQC KEM architecture (combining X25519 with ML-KEM-768 / FIPS 203).
- Replaces 3DES and ECB mode with authenticated AES-256-GCM (128-bit Grover quantum margin + AEAD).
"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_secure_rsa_keys():
    """
    REMEDIATED: Sub-2048 bit keys upgraded to RSA-3072.
    Provides 128-bit classical factoring margin according to NIST SP 800-57.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    return private_key

def hybrid_demo_exchange(tamper=False):
    """Educational two-party X25519 + ML-KEM-768 round trip.

    This verifies agreement and ciphertext-tamper detection in this local demo;
    it is not an authenticated network protocol or a compliance certification.
    Requires cryptography >= 50 and an ML-KEM-capable backend. No simulation fallback.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
    except ImportError as error:
        raise RuntimeError('Real ML-KEM demo requires cryptography >= 50; install requirements.txt') from error
    alice = x25519.X25519PrivateKey.generate()
    bob = x25519.X25519PrivateKey.generate()
    kem_private = mlkem.MLKEM768PrivateKey.generate()
    sender_pq, ciphertext = kem_private.public_key().encapsulate()
    received = bytes([ciphertext[0] ^ 1])+ciphertext[1:] if tamper else ciphertext
    receiver_pq = kem_private.decapsulate(received)
    # Bind both public keys and KEM ciphertext into the demo derivation context.
    transcript = alice.public_key().public_bytes_raw()+bob.public_key().public_bytes_raw()+ciphertext
    def derive(classical, post_quantum):
        return HKDF(algorithm=hashes.SHA384(), length=48, salt=None,
                    info=b'Q-SHIELD educational hybrid demo v1'+transcript).derive(classical+post_quantum)
    sender = derive(alice.exchange(bob.public_key()), sender_pq)
    receiver = derive(bob.exchange(alice.public_key()), receiver_pq)
    if not hmac.compare_digest(sender, receiver):
        raise ValueError('Hybrid key confirmation failed')
    return sender, receiver


def establish_hybrid_pqc_kem_secret():
    """Return a locally confirmed demo secret; no authenticated transport claim."""
    sender, receiver = hybrid_demo_exchange()
    return sender


def secure_aes_gcm_encryption(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    REMEDIATED: Replaces 3DES and ECB mode with AES-256-GCM.
    - 256-bit key ensures 128-bit quantum security against Grover's algorithm ($O(\\sqrt{N})$).
    - Authenticated encryption (AEAD) prevents padding oracles and structural pattern leakage.
    - Unique 96-bit (12-byte) initialization vector per encryption.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def secure_aes_gcm_decryption(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Verifies authenticity tag and decrypts ciphertext using AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
