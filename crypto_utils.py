import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 100_000

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password)

def encrypt_data(data: bytes, password: bytes) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, data, None)
    encrypted = salt + nonce + ciphertext

    # 🔑 BASE64 ADDED HERE
    return base64.b64encode(encrypted)

def decrypt_data(data: bytes, password: bytes) -> bytes:
    # 🔑 BASE64 REMOVED HERE
    raw = base64.b64decode(data)

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, None)
