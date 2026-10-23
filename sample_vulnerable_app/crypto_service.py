# Sample Vulnerable Cryptographic Service for Q-SHIELD Demo
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_legacy_rsa_keys():
    # VULNERABLE: Sub-2048 bit RSA keys are classically factorable; RSA is broken by Shor's algorithm
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    return private_key

def establish_ecdh_shared_secret():
    # VULNERABLE: Elliptic Curve Diffie-Hellman (P-256) is broken by Shor's algorithm (HNDL threat)
    server_key = ec.generate_private_key(ec.SECP256R1())
    return server_key

def legacy_des_encryption(key: bytes, plaintext: bytes):
    # VULNERABLE: 3DES has a 64-bit block size susceptible to Sweet32 collision attacks
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b"12345678"))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def insecure_ecb_mode(key: bytes, plaintext: bytes):
    # VULNERABLE: ECB mode lacks diffusion and semantic security
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
