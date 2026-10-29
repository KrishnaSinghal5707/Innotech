"""Deliberately weak integrity hash used only as scanner test input."""
import hashlib

def digest(data):
    return hashlib.md5(data).hexdigest()
