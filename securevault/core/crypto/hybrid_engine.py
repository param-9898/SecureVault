"""
Hybrid Post-Quantum Encryption Engine
======================================

Combines multiple encryption layers for defense-in-depth:
    1. ChaCha20-Poly1305 (inner layer)
    2. AES-256-GCM (outer layer)
    3. Kyber768 KEM (key encapsulation)

Security Properties:
    - Post-quantum key exchange (Kyber)
    - Dual symmetric encryption (algorithm diversity)
    - Authenticated encryption at both layers
    - Keys never touch disk
    - Integrity verification before decryption

Encryption Flow:
    plaintext
        ↓ ChaCha20-Poly1305 (key1, nonce1)
    inner_ciphertext
        ↓ AES-256-GCM (key2, nonce2)
    outer_ciphertext
        ↓ Kyber encapsulate (key1 || key2)
    final_package (ciphertext + encapsulated_keys + metadata)

Decryption Flow:
    final_package
        ↓ Kyber decapsulate → key1, key2
    outer_ciphertext
        ↓ AES-256-GCM decrypt (verify integrity)
    inner_ciphertext  
        ↓ ChaCha20-Poly1305 decrypt (verify integrity)
    plaintext

WARNING:
    - Requires Kyber keypair for operations
    - Both layers MUST pass integrity check
    - Any failure = complete rejection (fail-closed)
"""

from __future__ import annotations

import json
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final, Optional, Dict, Any
from base64 import b64encode, b64decode

from securevault.core.crypto.aes_gcm import AesGcmCipher, AES_KEY_SIZE, AES_NONCE_SIZE
from securevault.core.crypto.chacha20 import ChaCha20Cipher, CHACHA_KEY_SIZE, CHACHA_NONCE_SIZE
from securevault.core.crypto.kyber_pqc import KyberKEM, KyberKeypair, SHARED_SECRET_SIZE

# Version for format compatibility
PACKAGE_VERSION: Final[int] = 1
MAGIC_BYTES: Final[bytes] = b"SVHQ"  # SecureVault Hybrid Quantum


@dataclass(frozen=True, slots=True)
class EncryptedPackage:
    """
    Immutable container for hybrid-encrypted data.

    Contains all data needed for decryption (except secret key):
    - Encrypted ciphertext (dual-layer)
    - Encapsulated symmetric keys
    - Nonces and metadata
    - Integrity information

    This can be safely serialized and stored.
    """

    version: int
    ciphertext: bytes
    kyber_ciphertext: bytes
    aes_nonce: bytes
    chacha_nonce: bytes
    aad_hash: bytes
    created_at: str
    kyber_level: int

    def to_bytes(self) -> bytes:
        """
        Serialize package to bytes for storage.

        Format:
            MAGIC (4) | VERSION (1) | KYBER_LEVEL (2) |
            KYBER_CT_LEN (2) | KYBER_CT | 
            AES_NONCE (12) | CHACHA_NONCE (12) |
            AAD_HASH (32) | CREATED_LEN (2) | CREATED |
            CT_LEN (4) | CIPHERTEXT
        """
        created_bytes = self.created_at.encode("utf-8")

        parts = [
            MAGIC_BYTES,
            struct.pack("<B", self.version),
            struct.pack("<H", self.kyber_level),
            struct.pack("<H", len(self.kyber_ciphertext)),
            self.kyber_ciphertext,
            self.aes_nonce,
            self.chacha_nonce,
            self.aad_hash,
            struct.pack("<H", len(created_bytes)),
            created_bytes,
            struct.pack("<I", len(self.ciphertext)),
            self.ciphertext,
        ]

        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedPackage":
        """
        Deserialize package from bytes.

        Raises:
            ValueError: If data is malformed or corrupted
        """
        if len(data) < 4 or data[:4] != MAGIC_BYTES:
            raise ValueError("Invalid package: bad magic bytes")

        offset = 4

        # Version
        version = struct.unpack_from("<B", data, offset)[0]
        offset += 1
        if version != PACKAGE_VERSION:
            raise ValueError(f"Unsupported package version: {version}")

        # Kyber level
        kyber_level = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        # Kyber ciphertext
        kyber_ct_len = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        kyber_ciphertext = data[offset : offset + kyber_ct_len]
        offset += kyber_ct_len

        # Nonces
        aes_nonce = data[offset : offset + AES_NONCE_SIZE]
        offset += AES_NONCE_SIZE
        chacha_nonce = data[offset : offset + CHACHA_NONCE_SIZE]
        offset += CHACHA_NONCE_SIZE

        # AAD hash
        aad_hash = data[offset : offset + 32]
        offset += 32

        # Created timestamp
        created_len = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        created_at = data[offset : offset + created_len].decode("utf-8")
        offset += created_len

        # Ciphertext
        ct_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        ciphertext = data[offset : offset + ct_len]

        return cls(
            version=version,
            ciphertext=ciphertext,
            kyber_ciphertext=kyber_ciphertext,
            aes_nonce=aes_nonce,
            chacha_nonce=chacha_nonce,
            aad_hash=aad_hash,
            created_at=created_at,
            kyber_level=kyber_level,
        )

    def to_json(self) -> str:
        """Serialize to JSON string with base64-encoded binary data."""
        return json.dumps({
            "version": self.version,
            "ciphertext": b64encode(self.ciphertext).decode(),
            "kyber_ciphertext": b64encode(self.kyber_ciphertext).decode(),
            "aes_nonce": b64encode(self.aes_nonce).decode(),
            "chacha_nonce": b64encode(self.chacha_nonce).decode(),
            "aad_hash": b64encode(self.aad_hash).decode(),
            "created_at": self.created_at,
            "kyber_level": self.kyber_level,
        })

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedPackage":
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        return cls(
            version=data["version"],
            ciphertext=b64decode(data["ciphertext"]),
            kyber_ciphertext=b64decode(data["kyber_ciphertext"]),
            aes_nonce=b64decode(data["aes_nonce"]),
            chacha_nonce=b64decode(data["chacha_nonce"]),
            aad_hash=b64decode(data["aad_hash"]),
            created_at=data["created_at"],
            kyber_level=data["kyber_level"],
        )

    def __repr__(self) -> str:
        """Safe representation."""
        return (
            f"EncryptedPackage(v{self.version}, "
            f"ct_len={len(self.ciphertext)}, "
            f"kyber={self.kyber_level})"
        )


class HybridCryptoEngine:
    """
    Hybrid Post-Quantum Encryption Engine.

    Provides defense-in-depth encryption using:
    - Kyber768 for post-quantum key encapsulation
    - AES-256-GCM for primary symmetric encryption
    - ChaCha20-Poly1305 for secondary symmetric encryption

    Usage:
        # Initialize engine
        engine = HybridCryptoEngine()

        # Generate keypair
        keypair = engine.generate_keypair()

        # Encrypt data
        package = engine.encrypt(plaintext, keypair.public_key)

        # Decrypt data
        plaintext = engine.decrypt(package, keypair.secret_key)

    Security Notes:
        - All operations are authenticated
        - Keys are derived per-operation (never reused)
        - Integrity verified before any plaintext returned
        - Keys never touch disk - manage keypair securely!
    """

    __slots__ = ("_aes", "_chacha", "_kyber", "_kyber_level")

    def __init__(self, kyber_level: int = 768) -> None:
        """
        Initialize the hybrid crypto engine.

        Args:
            kyber_level: Kyber security level (512, 768, 1024)
        """
        self._aes = AesGcmCipher()
        self._chacha = ChaCha20Cipher()
        self._kyber = KyberKEM(security_level=kyber_level)
        self._kyber_level = kyber_level

    @property
    def kyber_level(self) -> int:
        """Get the Kyber security level."""
        return self._kyber_level

    @property
    def is_post_quantum_secure(self) -> bool:
        """Check if using real post-quantum cryptography."""
        return not self._kyber.is_simulated

    def generate_keypair(self) -> KyberKeypair:
        """
        Generate a new Kyber keypair for encryption/decryption.

        Returns:
            KyberKeypair with public and secret keys

        Security:
            - Store secret_key ONLY in secure memory
            - NEVER write secret_key to disk in plaintext
            - public_key can be freely distributed
        """
        return self._kyber.generate_keypair()

    def encrypt(
        self,
        plaintext: bytes,
        public_key: bytes,
        aad: Optional[bytes] = None,
    ) -> EncryptedPackage:
        """
        Encrypt data using hybrid post-quantum encryption.

        Args:
            plaintext: Data to encrypt
            public_key: Recipient's Kyber public key
            aad: Additional Authenticated Data (optional)

        Returns:
            EncryptedPackage containing encrypted data and metadata

        Process:
            1. Generate random ChaCha20 key, encrypt plaintext
            2. Generate random AES key, encrypt ChaCha ciphertext
            3. Combine keys, encapsulate with Kyber
            4. Package everything for storage/transmission

        Security:
            - New random keys generated for each encryption
            - Both symmetric layers authenticated
            - AAD is hashed and verified on decryption
        """
        # Compute AAD hash for later verification
        aad_hash = hashlib.sha256(aad or b"").digest()

        # Layer 1: ChaCha20-Poly1305 encryption
        chacha_result = self._chacha.encrypt(plaintext, aad=aad)

        # Layer 2: AES-256-GCM encryption
        # Include ChaCha nonce in AAD for binding
        aes_aad = aad_hash + chacha_result.nonce if aad else chacha_result.nonce
        aes_result = self._aes.encrypt(chacha_result.ciphertext, aad=aes_aad)

        # Combine symmetric keys for encapsulation
        combined_keys = chacha_result.key + aes_result.key
        assert len(combined_keys) == CHACHA_KEY_SIZE + AES_KEY_SIZE

        # Encapsulate keys with Kyber
        kyber_result = self._kyber.encapsulate(public_key)

        # XOR combined keys with Kyber shared secret (key wrapping)
        # This binds the symmetric keys to the KEM output
        wrapped_keys = self._xor_bytes(
            combined_keys,
            self._expand_secret(kyber_result.shared_secret, len(combined_keys))
        )

        # Build final ciphertext: wrapped_keys || aes_ciphertext
        final_ciphertext = wrapped_keys + aes_result.ciphertext

        return EncryptedPackage(
            version=PACKAGE_VERSION,
            ciphertext=final_ciphertext,
            kyber_ciphertext=kyber_result.ciphertext,
            aes_nonce=aes_result.nonce,
            chacha_nonce=chacha_result.nonce,
            aad_hash=aad_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
            kyber_level=self._kyber_level,
        )

    def decrypt(
        self,
        package: EncryptedPackage,
        secret_key: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt hybrid-encrypted data.

        Args:
            package: EncryptedPackage from encrypt()
            secret_key: Kyber secret key
            aad: Additional Authenticated Data (must match encryption)

        Returns:
            Decrypted plaintext bytes

        Raises:
            ValueError: If package is invalid
            cryptography.exceptions.InvalidTag: If integrity check fails

        Security:
            - Verifies AAD hash before decryption
            - Both symmetric layers must pass integrity check
            - Any failure = complete rejection (fail-closed)
        """
        # Verify AAD hash
        expected_aad_hash = hashlib.sha256(aad or b"").digest()
        if not hmac.compare_digest(expected_aad_hash, package.aad_hash):
            raise ValueError("AAD mismatch - possible tampering or wrong context")

        # Decapsulate Kyber to get shared secret
        shared_secret = self._kyber.decapsulate(
            package.kyber_ciphertext, 
            secret_key
        )

        # Extract wrapped keys and ciphertext
        key_len = CHACHA_KEY_SIZE + AES_KEY_SIZE
        wrapped_keys = package.ciphertext[:key_len]
        aes_ciphertext = package.ciphertext[key_len:]

        # Unwrap symmetric keys
        combined_keys = self._xor_bytes(
            wrapped_keys,
            self._expand_secret(shared_secret, key_len)
        )
        chacha_key = combined_keys[:CHACHA_KEY_SIZE]
        aes_key = combined_keys[CHACHA_KEY_SIZE:]

        # Layer 2: AES-256-GCM decryption
        aes_aad = expected_aad_hash + package.chacha_nonce if aad else package.chacha_nonce
        chacha_ciphertext = self._aes.decrypt(
            aes_ciphertext,
            package.aes_nonce,
            aes_key,
            aad=aes_aad,
        )

        # Layer 1: ChaCha20-Poly1305 decryption
        plaintext = self._chacha.decrypt(
            chacha_ciphertext,
            package.chacha_nonce,
            chacha_key,
            aad=aad,
        )

        return plaintext

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte strings of equal length."""
        if len(a) != len(b):
            raise ValueError("Byte strings must be same length for XOR")
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def _expand_secret(secret: bytes, length: int) -> bytes:
        """
        Expand a secret to desired length using SHAKE256.

        This is used to derive key material from Kyber shared secret.
        """
        return hashlib.shake_256(secret).digest(length)

    def encrypt_with_password(
        self,
        plaintext: bytes,
        password: str,
        aad: Optional[bytes] = None,
    ) -> tuple[EncryptedPackage, bytes]:
        """
        Encrypt data using a password-derived keypair.

        This is a convenience method that derives a Kyber keypair from
        a password using a memory-hard KDF.

        Args:
            plaintext: Data to encrypt
            password: User's password
            aad: Additional Authenticated Data

        Returns:
            Tuple of (EncryptedPackage, salt)
            Store salt alongside the package for decryption.

        Security:
            - Uses Argon2id for password-based key derivation
            - Salt is randomly generated per encryption
        """
        from securevault.core.crypto.kdf import derive_kyber_keypair
        
        salt = secrets.token_bytes(32)
        keypair = derive_kyber_keypair(password, salt, self._kyber_level)
        package = self.encrypt(plaintext, keypair.public_key, aad)
        
        return package, salt

    def decrypt_with_password(
        self,
        package: EncryptedPackage,
        password: str,
        salt: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data using password-derived keypair.

        Args:
            package: EncryptedPackage to decrypt
            password: User's password
            salt: Salt from encryption
            aad: Additional Authenticated Data

        Returns:
            Decrypted plaintext
        """
        from securevault.core.crypto.kdf import derive_kyber_keypair
        
        keypair = derive_kyber_keypair(password, salt, self._kyber_level)
        return self.decrypt(package, keypair.secret_key, aad)
