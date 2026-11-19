"""Symmetric encryption of private keys at rest, and password hashing.

Private keys are encrypted with AES-256-GCM. The AES key is derived (SHA-256)
from the ``NOT_MY_KEY`` environment variable, so any string can be used as the
secret. A fresh random 12-byte nonce (IV) is generated for every encryption and
stored in front of the ciphertext: ``nonce || ciphertext+tag``. GCM also
authenticates the data, so a tampered or wrongly-keyed blob fails to decrypt.

Passwords are hashed with Argon2id.
"""
import hashlib
import os

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENV_VAR = "NOT_MY_KEY"
NONCE_SIZE = 12

# Argon2id settings (roughly the OWASP-recommended minimums).
password_hasher = PasswordHasher(
    time_cost=3,          # iterations
    memory_cost=65536,    # KiB (64 MiB)
    parallelism=4,
    hash_len=32,          # bytes
    salt_len=16,          # bytes, random per hash
)


def load_key(env=None):
    """Return the 32-byte AES key derived from NOT_MY_KEY.

    Raises RuntimeError if the variable is missing or empty.
    """
    env = os.environ if env is None else env
    secret = env.get(ENV_VAR)
    if not secret:
        raise RuntimeError(f"environment variable {ENV_VAR} must be set")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt(aes_key, plaintext):
    """Encrypt bytes, returning nonce || ciphertext."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)


def decrypt(aes_key, blob):
    """Decrypt a blob produced by `encrypt`.

    Raises cryptography.exceptions.InvalidTag if the key is wrong or the blob
    was modified.
    """
    blob = bytes(blob)
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def hash_password(password):
    """Return an Argon2id hash string (includes params and salt)."""
    return password_hasher.hash(password)
