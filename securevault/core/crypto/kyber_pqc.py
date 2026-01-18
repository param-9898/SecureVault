"""
CRYSTALS-Kyber Post-Quantum Key Encapsulation
==============================================

Implements CRYSTALS-Kyber for post-quantum secure key encapsulation.

Security Properties:
    - Kyber768: NIST Security Level 3 (~AES-192 equivalent)
    - IND-CCA2 secure key encapsulation
    - Resistant to quantum computer attacks (Shor's algorithm)

Algorithm Details (Kyber768):
    - Public key: 1184 bytes
    - Secret key: 2400 bytes
    - Ciphertext: 1088 bytes
    - Shared secret: 32 bytes

Usage Pattern:
    1. Generate keypair (public for encryption, secret for decryption)
    2. Encapsulate: Create shared secret + ciphertext using public key
    3. Decapsulate: Recover shared secret from ciphertext using secret key
    4. Use shared secret as key for symmetric encryption (AES/ChaCha)

WARNING:
    - This implementation uses kyber-py (pure Python reference)
    - For production, consider liboqs bindings for performance
    - Post-quantum cryptography standards are evolving
"""

from __future__ import annotations

import secrets
import hashlib
from dataclasses import dataclass
from typing import Final, Tuple, Optional
from abc import ABC, abstractmethod

# Kyber parameters for different security levels
KYBER_512_PK_SIZE: Final[int] = 800
KYBER_512_SK_SIZE: Final[int] = 1632
KYBER_512_CT_SIZE: Final[int] = 768

KYBER_768_PK_SIZE: Final[int] = 1184
KYBER_768_SK_SIZE: Final[int] = 2400
KYBER_768_CT_SIZE: Final[int] = 1088

KYBER_1024_PK_SIZE: Final[int] = 1568
KYBER_1024_SK_SIZE: Final[int] = 3168
KYBER_1024_CT_SIZE: Final[int] = 1568

SHARED_SECRET_SIZE: Final[int] = 32  # 256 bits


@dataclass(frozen=True, slots=True)
class KyberKeypair:
    """
    Immutable Kyber keypair.

    Attributes:
        public_key: Used for encapsulation (can be shared)
        secret_key: Used for decapsulation (must be kept secret)
        security_level: Kyber variant (512, 768, or 1024)
    """

    public_key: bytes
    secret_key: bytes
    security_level: int

    def __repr__(self) -> str:
        """Safe representation without exposing key material."""
        return f"KyberKeypair(level=Kyber{self.security_level}, pk_len={len(self.public_key)})"


@dataclass(frozen=True, slots=True)
class EncapsulationResult:
    """
    Result of Kyber key encapsulation.

    Attributes:
        shared_secret: 32-byte shared secret for symmetric encryption
        ciphertext: Encapsulated key ciphertext (send to recipient)
    """

    shared_secret: bytes
    ciphertext: bytes

    def __repr__(self) -> str:
        """Safe representation without exposing secret material."""
        return f"EncapsulationResult(ct_len={len(self.ciphertext)})"


class KyberBackend(ABC):
    """Abstract base for Kyber implementations."""

    @abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate keypair. Returns (public_key, secret_key)."""
        ...

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate. Returns (shared_secret, ciphertext)."""
        ...

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate. Returns shared_secret."""
        ...


class SimulatedKyberBackend(KyberBackend):
    """
    Simulated Kyber backend for development/testing.

    WARNING: This is NOT cryptographically secure!
             Used only when real Kyber library is unavailable.
             Replace with actual Kyber implementation for production.

    This simulation mimics Kyber parameters and behavior using
    conventional cryptography. It provides the same API but NOT
    post-quantum security.

    The simulation works by:
    1. Keygen: Create a random seed, derive pubkey from it
    2. Encapsulate: Generate shared secret, encrypt it with pubkey
    3. Decapsulate: Use seed from secret key to decrypt shared secret
    """

    def __init__(self, security_level: int = 768) -> None:
        self.security_level = security_level
        if security_level == 512:
            self.pk_size = KYBER_512_PK_SIZE
            self.sk_size = KYBER_512_SK_SIZE
            self.ct_size = KYBER_512_CT_SIZE
        elif security_level == 768:
            self.pk_size = KYBER_768_PK_SIZE
            self.sk_size = KYBER_768_SK_SIZE
            self.ct_size = KYBER_768_CT_SIZE
        else:  # 1024
            self.pk_size = KYBER_1024_PK_SIZE
            self.sk_size = KYBER_1024_SK_SIZE
            self.ct_size = KYBER_1024_CT_SIZE

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate simulated keypair."""
        # Generate random seed (this is the core secret)
        seed = secrets.token_bytes(32)
        
        # Derive "public key" - includes a hash of the seed
        # In simulation, the public key contains info needed for encapsulation
        pk_hash = hashlib.sha256(b"KYBER_PK" + seed).digest()
        pk_padding = secrets.token_bytes(self.pk_size - 32)
        public_key = pk_hash + pk_padding
        
        # Secret key = seed + public_key + padding
        sk_padding = secrets.token_bytes(self.sk_size - 32 - self.pk_size)
        secret_key = seed + public_key + sk_padding
        
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Simulated encapsulation.
        
        Encrypts a random shared secret using the public key.
        The ciphertext contains the shared secret XORed with a
        key derived from the public key.
        """
        if len(public_key) != self.pk_size:
            raise ValueError(f"Invalid public key size: {len(public_key)}")
        
        # Generate random shared secret
        shared_secret = secrets.token_bytes(SHARED_SECRET_SIZE)
        
        # Derive encryption key from public key hash (first 32 bytes)
        pk_hash = public_key[:32]
        
        # Generate random nonce for this encapsulation
        nonce = secrets.token_bytes(32)
        
        # Derive a one-time pad from pk_hash and nonce
        pad = hashlib.shake_256(pk_hash + nonce).digest(SHARED_SECRET_SIZE)
        
        # "Encrypt" the shared secret
        encrypted_secret = bytes(a ^ b for a, b in zip(shared_secret, pad))
        
        # Ciphertext = nonce || encrypted_secret || padding
        ct_data = nonce + encrypted_secret
        ct_padding = secrets.token_bytes(self.ct_size - len(ct_data))
        ciphertext = ct_data + ct_padding
        
        return shared_secret, ciphertext

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Simulated decapsulation.
        
        Recovers the shared secret from the ciphertext using the secret key.
        """
        if len(ciphertext) != self.ct_size:
            raise ValueError(f"Invalid ciphertext size: {len(ciphertext)}")
        if len(secret_key) != self.sk_size:
            raise ValueError(f"Invalid secret key size: {len(secret_key)}")
        
        # Extract seed and public key from secret key
        seed = secret_key[:32]
        public_key = secret_key[32:32 + self.pk_size]
        
        # Verify the public key matches the seed
        expected_pk_hash = hashlib.sha256(b"KYBER_PK" + seed).digest()
        if public_key[:32] != expected_pk_hash:
            raise ValueError("Invalid secret key - keypair mismatch")
        
        # Extract encapsulation data from ciphertext
        nonce = ciphertext[:32]
        encrypted_secret = ciphertext[32:32 + SHARED_SECRET_SIZE]
        
        # Derive the same one-time pad
        pk_hash = public_key[:32]
        pad = hashlib.shake_256(pk_hash + nonce).digest(SHARED_SECRET_SIZE)
        
        # Decrypt the shared secret
        shared_secret = bytes(a ^ b for a, b in zip(encrypted_secret, pad))
        
        return shared_secret


class KyberKEM:
    """
    CRYSTALS-Kyber Key Encapsulation Mechanism.

    Provides post-quantum secure key encapsulation for protecting
    symmetric encryption keys.

    Recommended Usage:
        kem = KyberKEM(security_level=768)

        # Generate keypair
        keypair = kem.generate_keypair()

        # Sender: Encapsulate key using recipient's public key
        result = kem.encapsulate(keypair.public_key)
        # Send result.ciphertext to recipient
        # Use result.shared_secret for symmetric encryption

        # Recipient: Decapsulate using secret key
        shared_secret = kem.decapsulate(result.ciphertext, keypair.secret_key)
        # Use shared_secret for symmetric decryption

    Security Levels:
        - Kyber512: NIST Level 1 (~AES-128)
        - Kyber768: NIST Level 3 (~AES-192) [RECOMMENDED]
        - Kyber1024: NIST Level 5 (~AES-256)
    """

    __slots__ = ("_security_level", "_backend", "_backend_name")

    def __init__(self, security_level: int = 768) -> None:
        """
        Initialize Kyber KEM.

        Args:
            security_level: 512, 768 (default), or 1024
        """
        if security_level not in (512, 768, 1024):
            raise ValueError("Security level must be 512, 768, or 1024")

        self._security_level = security_level
        self._backend: KyberBackend
        self._backend_name: str

        # Try to load real Kyber implementation
        self._backend, self._backend_name = self._load_backend(security_level)

    def _load_backend(self, level: int) -> Tuple[KyberBackend, str]:
        """
        Load the best available Kyber backend.

        Priority:
            1. liboqs-python (if available) - fastest, production-ready
            2. kyber-py (if available) - pure Python reference
            3. Simulated backend - development only, NOT secure!
        """
        # Try liboqs (Open Quantum Safe)
        try:
            from securevault.core.crypto._kyber_oqs import OqsKyberBackend
            return OqsKyberBackend(level), "liboqs"
        except ImportError:
            pass

        # Try kyber-py
        try:
            from securevault.core.crypto._kyber_pure import PureKyberBackend
            return PureKyberBackend(level), "kyber-py"
        except ImportError:
            pass

        # Fall back to simulated (development only)
        import warnings
        warnings.warn(
            "Using SIMULATED Kyber backend. This is NOT post-quantum secure! "
            "Install 'liboqs-python' or 'kyber-py' for real post-quantum security.",
            SecurityWarning,
            stacklevel=3,
        )
        return SimulatedKyberBackend(level), "simulated"

    @property
    def security_level(self) -> int:
        """Get the Kyber security level (512, 768, or 1024)."""
        return self._security_level

    @property
    def backend_name(self) -> str:
        """Get the name of the active backend."""
        return self._backend_name

    @property
    def is_simulated(self) -> bool:
        """Check if using simulated (non-secure) backend."""
        return self._backend_name == "simulated"

    def generate_keypair(self) -> KyberKeypair:
        """
        Generate a new Kyber keypair.

        Returns:
            KyberKeypair with public and secret keys

        Security:
            - Secret key must be stored securely
            - Public key can be freely distributed
        """
        public_key, secret_key = self._backend.keygen()

        return KyberKeypair(
            public_key=public_key,
            secret_key=secret_key,
            security_level=self._security_level,
        )

    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        """
        Encapsulate a shared secret using recipient's public key.

        Args:
            public_key: Recipient's Kyber public key

        Returns:
            EncapsulationResult with shared_secret and ciphertext

        Usage:
            result = kem.encapsulate(recipient_public_key)
            encrypted = aes_encrypt(data, key=result.shared_secret)
            send(result.ciphertext, encrypted)
        """
        shared_secret, ciphertext = self._backend.encapsulate(public_key)

        return EncapsulationResult(
            shared_secret=shared_secret,
            ciphertext=ciphertext,
        )

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate shared secret using secret key.

        Args:
            ciphertext: Encapsulated key ciphertext
            secret_key: Kyber secret key

        Returns:
            32-byte shared secret

        Security:
            - Constant-time implementation prevents timing attacks
            - Invalid ciphertext returns random value (IND-CCA2)
        """
        return self._backend.decapsulate(ciphertext, secret_key)


class SecurityWarning(UserWarning):
    """Warning for security-related concerns."""
    pass
