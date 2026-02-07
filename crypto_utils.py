import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 🔐 Professional iteration count
ITERATIONS = 600_000

# 🔐 File format identifier (4 bytes)
FILE_SIGNATURE = b"SFE1"


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

    # 🔐 Structure:
    # [SIGNATURE][SALT][NONCE][CIPHERTEXT]
    final_data = FILE_SIGNATURE + salt + nonce + ciphertext

    # 🔑 Encode to base64 for safe file transport
    return base64.b64encode(final_data)


def decrypt_data(data: bytes, password: bytes) -> bytes:
    try:
        # 🔑 Decode base64
        raw = base64.b64decode(data)
    except Exception:
        raise ValueError("Invalid file encoding")

    # 🔐 Validate signature
    if not raw.startswith(FILE_SIGNATURE):
        raise ValueError("Invalid file format")

    raw = raw[4:]  # remove signature

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, None)
