import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =========================================================
# AES FILE ENCRYPTION
# =========================================================

def generate_aes_key():

    return AESGCM.generate_key(bit_length=256)


def encrypt_file_data(data: bytes, aes_key: bytes) -> bytes:

    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    return nonce + ciphertext


def decrypt_file_data(
    encrypted_data: bytes,
    aes_key: bytes
) -> bytes:

    nonce = encrypted_data[:12]

    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )


# =========================================================
# RSA KEY GENERATION
# =========================================================

def generate_rsa_key_pair():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


# =========================================================
# KEY SERIALIZATION
# =========================================================

def serialize_public_key(public_key):

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(private_key):

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def load_public_key(public_key_pem: bytes):

    return serialization.load_pem_public_key(
        public_key_pem
    )


def load_private_key(private_key_pem: bytes):

    return serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )


# =========================================================
# RSA ENCRYPTION OF AES KEY
# =========================================================

def encrypt_aes_key_for_recipient(
    aes_key: bytes,
    recipient_public_key
):

    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(
        encrypted_key
    )


def decrypt_aes_key_for_recipient(
    encrypted_aes_key: bytes,
    recipient_private_key
):

    encrypted_key = base64.b64decode(
        encrypted_aes_key
    )

    return recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =========================================================
# PASSWORD PROTECTION FOR PRIVATE RSA KEY
# =========================================================

PRIVATE_KEY_ITERATIONS = 600_000


def derive_password_key(
    password: str,
    salt: bytes
) -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PRIVATE_KEY_ITERATIONS
    )

    return kdf.derive(
        password.encode()
    )


def encrypt_private_key(
    private_key_pem: bytes,
    password: str
) -> bytes:

    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_password_key(
        password,
        salt
    )

    aesgcm = AESGCM(key)

    encrypted_private_key = aesgcm.encrypt(
        nonce,
        private_key_pem,
        None
    )

    return (
        salt
        + nonce
        + encrypted_private_key
    )


def decrypt_private_key(
    encrypted_data: bytes,
    password: str
) -> bytes:

    salt = encrypted_data[:16]

    nonce = encrypted_data[16:28]

    ciphertext = encrypted_data[28:]

    key = derive_password_key(
        password,
        salt
    )

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )


# =========================================================
# TEMPORARY PENDING SHARE KEY PROTECTION
#
# Used only until an invited external recipient creates
# an account. After registration, the AES key is encrypted
# with the recipient's own RSA public key.
# =========================================================

def get_pending_share_key():

    secret = os.environ.get(
        "PENDING_SHARE_SECRET"
    )

    if not secret:

        secret = os.environ.get(
            "SECRET_KEY",
            "development-only-secret-change-this"
        )

    return hashes.Hash(
        hashes.SHA256()
    ), secret.encode()


def derive_pending_share_key():

    _, secret = get_pending_share_key()

    digest = hashes.Hash(
        hashes.SHA256()
    )

    digest.update(secret)

    return digest.finalize()


def encrypt_pending_aes_key(
    aes_key: bytes
) -> bytes:

    key = derive_pending_share_key()

    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    encrypted_data = aesgcm.encrypt(
        nonce,
        aes_key,
        None
    )

    return nonce + encrypted_data


def decrypt_pending_aes_key(
    encrypted_data: bytes
) -> bytes:

    key = derive_pending_share_key()

    nonce = encrypted_data[:12]

    ciphertext = encrypted_data[12:]

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )