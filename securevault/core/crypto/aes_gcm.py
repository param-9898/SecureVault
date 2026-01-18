"""
AES-256-GCM Authenticated Encryption
====================================

Implements AES-256-GCM with per-operation random key and nonce generation.

Security Properties:
    - 256-bit key (128-bit security level)
    - 96-bit nonce (NIST recommended)
    - 128-bit authentication tag
    - Authenticated Additional Data (AAD) support
    - Random key generation per file/operation

NIST SP 800-38D Compliance:
    - GCM mode with 96-bit IV
    - Unique nonce for each encryption under same key

WARNING:
    - Never reuse (key, nonce) pairs
    - Always verify tag before using plaintext
    - Keys should be wiped from memory after use
"""

from __future__ import annotations

import os
import hmac
import secrets
from dataclasses import dataclass
from typing import Final, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Constants following NIST recommendations
AES_KEY_SIZE: Final[int] = 32  # 256 bits
AES_NONCE_SIZE: Final[int] = 12  # 96 bits (NIST recommended for GCM)
AES_TAG_SIZE: Final[int] = 16  # 128 bits


@dataclass(frozen=True, slots=True)
class AesGcmResult:
    """
    Immutable result of AES-GCM encryption.

    Attributes:
        ciphertext: Encrypted data with appended authentication tag
        nonce: Unique nonce used for this encryption (must be stored with ciphertext)
        key: The random key used (caller must securely manage/encapsulate this)
    """

    ciphertext: bytes
    nonce: bytes
    key: bytes

    def __repr__(self) -> str:
        """Safe representation without exposing key material."""
        return f"AesGcmResult(ciphertext_len={len(self.ciphertext)}, nonce_len={len(self.nonce)})"


class AesGcmCipher:
    """
    AES-256-GCM Authenticated Encryption with Associated Data (AEAD).

    This class provides secure symmetric encryption with:
    - Per-encryption random key generation
    - Automatic nonce generation (never reused)
    - Integrity verification before decryption output

    Usage:
        cipher = AesGcmCipher()

        # Encrypt with random key
        result = cipher.encrypt(plaintext, aad=b"context")

        # Decrypt (validates integrity first)
        plaintext = cipher.decrypt(
            ciphertext=result.ciphertext,
            nonce=result.nonce,
            key=result.key,
            aad=b"context"
        )

    Security Notes:
        - The returned key must be securely encapsulated (e.g., with Kyber)
        - Never store keys in plaintext on disk
        - Wipe keys from memory after use
    """

    __slots__ = ()

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a cryptographically secure random AES-256 key.

        Returns:
            32 bytes of cryptographic random data

        Security:
            Uses OS CSPRNG via secrets module (FIPS 140-2 compliant on most systems)
        """
        return secrets.token_bytes(AES_KEY_SIZE)

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a cryptographically secure random nonce.

        Returns:
            12 bytes of cryptographic random data

        Security:
            96-bit nonces with random generation have negligible collision
            probability for up to 2^32 encryptions under same key.
        """
        return secrets.token_bytes(AES_NONCE_SIZE)

    def encrypt(
        self,
        plaintext: bytes,
        key: Optional[bytes] = None,
        aad: Optional[bytes] = None,
    ) -> AesGcmResult:
        """
        Encrypt plaintext using AES-256-GCM.

        Args:
            plaintext: Data to encrypt (can be empty)
            key: Optional 32-byte key. If None, generates a new random key.
            aad: Additional Authenticated Data (authenticated but not encrypted)

        Returns:
            AesGcmResult containing ciphertext, nonce, and key

        Raises:
            ValueError: If key is provided but wrong size

        Security Notes:
            - Generates unique nonce for each encryption
            - Authentication tag is appended to ciphertext
            - AAD is authenticated but transmitted in clear
        """
        if key is None:
            key = self.generate_key()
        elif len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be exactly {AES_KEY_SIZE} bytes")

        nonce = self.generate_nonce()

        # Create cipher and encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        return AesGcmResult(
            ciphertext=ciphertext,
            nonce=nonce,
            key=key,
        )

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        key: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM with integrity verification.

        Args:
            ciphertext: Encrypted data with authentication tag
            nonce: The nonce used during encryption
            key: The 32-byte encryption key
            aad: Additional Authenticated Data (must match encryption AAD)

        Returns:
            Decrypted plaintext bytes

        Raises:
            ValueError: If parameters are invalid
            cryptography.exceptions.InvalidTag: If authentication fails

        Security Notes:
            - Integrity is verified BEFORE any plaintext is returned
            - InvalidTag means data was tampered or wrong key/nonce/AAD
            - Do NOT catch InvalidTag silently - it indicates attack or corruption
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be exactly {AES_KEY_SIZE} bytes")
        if len(nonce) != AES_NONCE_SIZE:
            raise ValueError(f"Nonce must be exactly {AES_NONCE_SIZE} bytes")
        if len(ciphertext) < AES_TAG_SIZE:
            raise ValueError("Ciphertext too short (missing authentication tag)")

        aesgcm = AESGCM(key)

        # Decrypt and verify (raises InvalidTag on failure)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        return plaintext

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Perform constant-time comparison of two byte strings.

        This prevents timing attacks when comparing authentication tags
        or other sensitive values.

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if equal, False otherwise

        Security:
            Uses hmac.compare_digest which is designed to be constant-time
        """
        return hmac.compare_digest(a, b)
