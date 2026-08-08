"""DES, 3DES and AES helpers used by the performance experiment.

The algorithms are provided by PyCryptodome.  This module handles key
validation, CBC-mode encryption/decryption, PKCS#7 padding and IV transport.
All public functions accept and return bytes so they also work with binary
files, not only UTF-8 text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext: bytes
    iv: bytes


def _require_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")


def _encrypt_cbc(
    plaintext: bytes,
    key: bytes,
    cipher_factory: Callable[..., object],
    block_size: int,
) -> EncryptionResult:
    _require_bytes(plaintext, "plaintext")
    _require_bytes(key, "key")
    cipher = cipher_factory.new(key, cipher_factory.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, block_size))
    return EncryptionResult(ciphertext=ciphertext, iv=cipher.iv)


def _decrypt_cbc(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    cipher_factory: Callable[..., object],
    block_size: int,
) -> bytes:
    _require_bytes(ciphertext, "ciphertext")
    _require_bytes(key, "key")
    _require_bytes(iv, "iv")
    if len(iv) != block_size:
        raise ValueError(f"IV must be {block_size} bytes")
    if not ciphertext or len(ciphertext) % block_size != 0:
        raise ValueError("ciphertext length must be a non-zero block multiple")
    cipher = cipher_factory.new(key, cipher_factory.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), block_size)


def generate_des_key() -> bytes:
    return get_random_bytes(8)


def generate_3des_key() -> bytes:
    """Generate a valid 24-byte 3DES key, retrying rare degenerate keys."""
    while True:
        try:
            return DES3.adjust_key_parity(get_random_bytes(24))
        except ValueError:
            continue


def generate_aes_key() -> bytes:
    return get_random_bytes(16)  # AES-128


def des_encrypt(plaintext: bytes, key: bytes) -> EncryptionResult:
    return _encrypt_cbc(plaintext, key, DES, DES.block_size)


def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return _decrypt_cbc(ciphertext, key, iv, DES, DES.block_size)


def triple_des_encrypt(plaintext: bytes, key: bytes) -> EncryptionResult:
    return _encrypt_cbc(plaintext, key, DES3, DES3.block_size)


def triple_des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return _decrypt_cbc(ciphertext, key, iv, DES3, DES3.block_size)


def aes_encrypt(plaintext: bytes, key: bytes) -> EncryptionResult:
    return _encrypt_cbc(plaintext, key, AES, AES.block_size)


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return _decrypt_cbc(ciphertext, key, iv, AES, AES.block_size)
