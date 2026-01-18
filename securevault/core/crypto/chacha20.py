"""
ChaCha20-Poly1305 Authenticated Encryption
==========================================

Implements ChaCha20-Poly1305 as a secondary encryption layer.

Security Properties:
    - 256-bit key
    - 96-bit nonce
    - 128-bit Poly1305 authentication tag
    - IETF RFC 8439 compliant

Why ChaCha20-Poly1305 as secondary layer:
    - Algorithm diversity (defense against AES-specific attacks)
    - No timing vulnerabilities (constant-time on all platforms)
    - Strong in software (no AES-NI dependency)
    - Different mathematical foundations than AES

WARNING:
    - Never reuse (key, nonce) pairs
    - Always verify tag before using plaintext
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Final, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Constants per RFC 8439
CHACHA_KEY_SIZE: Final[int] = 32  # 256 bits
CHACHA_NONCE_SIZE: Final[int] = 12  # 96 bits (IETF variant)
CHACHA_TAG_SIZE: Final[int] = 16  # 128 bits Poly1305


@dataclass(frozen=True, slots=True)
class ChaChaResult:
    """
    Immutable result of ChaCha20-Poly1305 encryption.

    Attributes:
        ciphertext: Encrypted data with appended Poly1305 tag
        nonce: Unique nonce used for this encryption
        key: The random key used (caller must securely manage this)
    """

    ciphertext: bytes
    nonce: bytes
    key: bytes

    def __repr__(self) -> str:
        """Safe representation without exposing key material."""
        return f"ChaChaResult(ciphertext_len={len(self.ciphertext)}, nonce_len={len(self.nonce)})"


class ChaCha20Cipher:
    """
    ChaCha20-Poly1305 AEAD cipher (RFC 8439).

    Provides authenticated encryption with:
    - Per-encryption random key generation
    - Automatic nonce generation
    - Constant-time operations (timing-attack resistant)

    Usage:
        cipher = ChaCha20Cipher()

        # Encrypt
        result = cipher.encrypt(plaintext, aad=b"context")

        # Decrypt
        plaintext = cipher.decrypt(
            ciphertext=result.ciphertext,
            nonce=result.nonce,
            key=result.key,
            aad=b"context"
        )

    Security Notes:
        - ChaCha20 is constant-time in software (no lookup tables)
        - Poly1305 provides one-time authenticator security
        - Combined provides IND-CCA2 security
    """

    __slots__ = ()

    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a cryptographically secure random ChaCha20 key.

        Returns:
            32 bytes of cryptographic random data
        """
        return secrets.token_bytes(CHACHA_KEY_SIZE)

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate a cryptographically secure random nonce.

        Returns:
            12 bytes of cryptographic random data

        Security:
            96-bit random nonces safe for ~2^32 messages per key
        """
        return secrets.token_bytes(CHACHA_NONCE_SIZE)

    def encrypt(
        self,
        plaintext: bytes,
        key: Optional[bytes] = None,
        aad: Optional[bytes] = None,
    ) -> ChaChaResult:
        """
        Encrypt plaintext using ChaCha20-Poly1305.

        Args:
            plaintext: Data to encrypt
            key: Optional 32-byte key. If None, generates random key.
            aad: Additional Authenticated Data

        Returns:
            ChaChaResult containing ciphertext, nonce, and key

        Raises:
            ValueError: If key is wrong size
        """
        if key is None:
            key = self.generate_key()
        elif len(key) != CHACHA_KEY_SIZE:
            raise ValueError(f"Key must be exactly {CHACHA_KEY_SIZE} bytes")

        nonce = self.generate_nonce()

        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)

        return ChaChaResult(
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
        Decrypt ciphertext using ChaCha20-Poly1305 with integrity verification.

        Args:
            ciphertext: Encrypted data with Poly1305 tag
            nonce: The nonce used during encryption
            key: The 32-byte encryption key
            aad: Additional Authenticated Data

        Returns:
            Decrypted plaintext bytes

        Raises:
            ValueError: If parameters are invalid
            cryptography.exceptions.InvalidTag: If authentication fails

        Security:
            Integrity verified before ANY plaintext returned
        """
        if len(key) != CHACHA_KEY_SIZE:
            raise ValueError(f"Key must be exactly {CHACHA_KEY_SIZE} bytes")
        if len(nonce) != CHACHA_NONCE_SIZE:
            raise ValueError(f"Nonce must be exactly {CHACHA_NONCE_SIZE} bytes")
        if len(ciphertext) < CHACHA_TAG_SIZE:
            raise ValueError("Ciphertext too short (missing authentication tag)")

        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, aad)

        return plaintext

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Perform constant-time comparison of two byte strings.

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)
