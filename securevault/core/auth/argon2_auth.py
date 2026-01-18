"""
Argon2id Password Hashing
=========================

Implements secure password hashing using Argon2id.

Security Properties:
- Memory-hard (resistant to GPU/ASIC attacks)
- Time-hard (configurable iterations)
- Parallelism support
- Salt automatically managed
- Constant-time verification

Parameters (OWASP 2023 recommendations):
- memory_cost: 102400 KiB (100 MB)
- time_cost: 2 iterations
- parallelism: 4 threads

References:
- RFC 9106: Argon2 Memory-Hard Function
- OWASP Password Storage Cheat Sheet
"""

from __future__ import annotations

import ctypes
import secrets
import hmac
from dataclasses import dataclass
from typing import Final, Optional
from enum import Enum


# Argon2id parameters (OWASP 2023 recommended minimums)
ARGON2_MEMORY_COST: Final[int] = 102400  # 100 MB in KiB
ARGON2_TIME_COST: Final[int] = 2  # iterations
ARGON2_PARALLELISM: Final[int] = 4  # threads
ARGON2_HASH_LENGTH: Final[int] = 32  # 256 bits
ARGON2_SALT_LENGTH: Final[int] = 16  # 128 bits


class Argon2Type(Enum):
    """Argon2 algorithm variants."""
    ARGON2D = "argon2d"
    ARGON2I = "argon2i"
    ARGON2ID = "argon2id"  # Recommended


@dataclass(frozen=True, slots=True)
class HashResult:
    """
    Immutable result of password hashing.
    
    Attributes:
        hash: The derived key/hash bytes
        salt: Random salt used
        encoded: Full encoded string for storage
    """
    hash: bytes
    salt: bytes
    encoded: str
    
    def __repr__(self) -> str:
        """Safe representation without exposing hash."""
        return f"HashResult(encoded_len={len(self.encoded)})"


def _secure_zero_memory(data: bytearray | memoryview) -> None:
    """
    Securely zero memory to prevent password leakage.
    
    This attempts to overwrite memory containing sensitive data
    before it can be garbage collected.
    
    Note: This is best-effort; Python's memory management may
    leave copies. Use with caution for high-security needs.
    """
    if isinstance(data, memoryview):
        for i in range(len(data)):
            data[i] = 0
    else:
        ctypes.memset(ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data)), 0, len(data))


class Argon2Hasher:
    """
    Argon2id password hasher with secure defaults.
    
    Provides memory-hard password hashing resistant to:
    - Brute-force attacks
    - GPU/ASIC acceleration
    - Time-memory trade-off attacks
    
    Usage:
        hasher = Argon2Hasher()
        
        # Hash a password
        result = hasher.hash("user_password")
        store(result.encoded)  # Store this in database
        
        # Verify a password
        is_valid = hasher.verify("user_password", stored_encoded)
    
    Security Notes:
        - Argon2id is the recommended variant (hybrid)
        - Memory cost should be as high as your system allows
        - Password is wiped from memory after use
    """
    
    __slots__ = (
        "_memory_cost", "_time_cost", "_parallelism",
        "_hash_length", "_salt_length", "_type"
    )
    
    def __init__(
        self,
        memory_cost: int = ARGON2_MEMORY_COST,
        time_cost: int = ARGON2_TIME_COST,
        parallelism: int = ARGON2_PARALLELISM,
        hash_length: int = ARGON2_HASH_LENGTH,
        salt_length: int = ARGON2_SALT_LENGTH,
    ) -> None:
        """
        Initialize the Argon2id hasher.
        
        Args:
            memory_cost: Memory usage in KiB (default: 102400 = 100MB)
            time_cost: Number of iterations (default: 2)
            parallelism: Degree of parallelism (default: 4)
            hash_length: Output hash length in bytes (default: 32)
            salt_length: Salt length in bytes (default: 16)
        """
        # Validate parameters meet minimum security requirements
        if memory_cost < 65536:  # 64 MB minimum
            raise ValueError("memory_cost must be at least 65536 KiB (64 MB)")
        if time_cost < 2:
            raise ValueError("time_cost must be at least 2")
        if parallelism < 1:
            raise ValueError("parallelism must be at least 1")
        if hash_length < 16:
            raise ValueError("hash_length must be at least 16 bytes")
        if salt_length < 8:
            raise ValueError("salt_length must be at least 8 bytes")
        
        self._memory_cost = memory_cost
        self._time_cost = time_cost
        self._parallelism = parallelism
        self._hash_length = hash_length
        self._salt_length = salt_length
        self._type = Argon2Type.ARGON2ID
    
    @property
    def parameters(self) -> dict[str, int]:
        """Get current hashing parameters."""
        return {
            "memory_cost": self._memory_cost,
            "time_cost": self._time_cost,
            "parallelism": self._parallelism,
            "hash_length": self._hash_length,
            "salt_length": self._salt_length,
        }
    
    def hash(self, password: str, salt: Optional[bytes] = None) -> HashResult:
        """
        Hash a password using Argon2id.
        
        Args:
            password: The password to hash
            salt: Optional salt (random if not provided)
        
        Returns:
            HashResult with hash, salt, and encoded string
        
        Security:
            - Password is converted to bytes and wiped after use
            - Salt is cryptographically random if not provided
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Generate random salt if not provided
        if salt is None:
            salt = secrets.token_bytes(self._salt_length)
        
        # Convert password to mutable bytes for secure wiping
        password_bytes = bytearray(password.encode("utf-8"))
        
        try:
            # Try to use argon2-cffi library
            try:
                import argon2
                from argon2.low_level import hash_secret_raw, Type
                
                hash_bytes = hash_secret_raw(
                    secret=bytes(password_bytes),
                    salt=salt,
                    time_cost=self._time_cost,
                    memory_cost=self._memory_cost,
                    parallelism=self._parallelism,
                    hash_len=self._hash_length,
                    type=Type.ID,
                )
                
                # Create encoded string for storage
                # Format: $argon2id$v=19$m=MEMORY,t=TIME,p=PARALLEL$SALT$HASH
                import base64
                salt_b64 = base64.b64encode(salt).decode("ascii").rstrip("=")
                hash_b64 = base64.b64encode(hash_bytes).decode("ascii").rstrip("=")
                encoded = (
                    f"$argon2id$v=19$m={self._memory_cost},t={self._time_cost},"
                    f"p={self._parallelism}${salt_b64}${hash_b64}"
                )
                
            except ImportError:
                # Fallback to hashlib (Python 3.11+)
                import hashlib
                hash_bytes = hashlib.scrypt(
                    password=bytes(password_bytes),
                    salt=salt,
                    n=2 ** 14,  # CPU/memory cost
                    r=8,  # Block size
                    p=self._parallelism,
                    dklen=self._hash_length,
                )
                
                import base64
                salt_b64 = base64.b64encode(salt).decode("ascii").rstrip("=")
                hash_b64 = base64.b64encode(hash_bytes).decode("ascii").rstrip("=")
                encoded = f"$scrypt$n=16384,r=8,p={self._parallelism}${salt_b64}${hash_b64}"
                
                import warnings
                warnings.warn(
                    "argon2-cffi not installed, using scrypt fallback. "
                    "Install argon2-cffi for Argon2id support.",
                    SecurityWarning,
                    stacklevel=2,
                )
            
            return HashResult(
                hash=hash_bytes,
                salt=salt,
                encoded=encoded,
            )
            
        finally:
            # Secure wipe password from memory
            _secure_zero_memory(password_bytes)
    
    def verify(self, password: str, encoded: str) -> bool:
        """
        Verify a password against an encoded hash.
        
        Args:
            password: The password to verify
            encoded: The encoded hash string from storage
        
        Returns:
            True if password matches, False otherwise
        
        Security:
            - Uses constant-time comparison
            - Password is wiped from memory after use
        """
        if not password or not encoded:
            return False
        
        password_bytes = bytearray(password.encode("utf-8"))
        
        try:
            # Try argon2-cffi
            try:
                import argon2
                from argon2 import PasswordHasher
                from argon2.exceptions import (
                    VerifyMismatchError,
                    VerificationError,
                    InvalidHash,
                )
                
                # Use library's verify for proper constant-time comparison
                ph = PasswordHasher(
                    time_cost=self._time_cost,
                    memory_cost=self._memory_cost,
                    parallelism=self._parallelism,
                    hash_len=self._hash_length,
                    salt_len=self._salt_length,
                )
                
                try:
                    ph.verify(encoded, password)
                    return True
                except (VerifyMismatchError, VerificationError, InvalidHash):
                    return False
                    
            except ImportError:
                # Fallback: parse encoded string and verify manually
                return self._verify_fallback(password, encoded)
                
        finally:
            _secure_zero_memory(password_bytes)
    
    def _verify_fallback(self, password: str, encoded: str) -> bool:
        """Fallback verification for when argon2-cffi is not available."""
        import base64
        
        try:
            parts = encoded.split("$")
            if len(parts) < 5:
                return False
            
            # Parse parameters
            if parts[1] == "scrypt":
                # Parse scrypt format
                params = dict(p.split("=") for p in parts[2].split(","))
                salt = base64.b64decode(parts[3] + "==")
                stored_hash = base64.b64decode(parts[4] + "==")
                
                import hashlib
                computed = hashlib.scrypt(
                    password=password.encode("utf-8"),
                    salt=salt,
                    n=int(params.get("n", 16384)),
                    r=int(params.get("r", 8)),
                    p=int(params.get("p", 4)),
                    dklen=len(stored_hash),
                )
                
                return hmac.compare_digest(computed, stored_hash)
            
            elif parts[1] == "argon2id":
                # Parse argon2id format
                params = dict(p.split("=") for p in parts[3].split(","))
                salt = base64.b64decode(parts[4] + "==")
                stored_hash = base64.b64decode(parts[5] + "==")
                
                # Re-hash and compare
                result = self.hash(password, salt=salt)
                return hmac.compare_digest(result.hash, stored_hash)
            
            return False
            
        except Exception:
            return False
    
    def needs_rehash(self, encoded: str) -> bool:
        """
        Check if a hash needs to be rehashed with current parameters.
        
        Returns True if the hash uses older/weaker parameters.
        """
        try:
            import argon2
            from argon2 import PasswordHasher
            
            ph = PasswordHasher(
                time_cost=self._time_cost,
                memory_cost=self._memory_cost,
                parallelism=self._parallelism,
            )
            return ph.check_needs_rehash(encoded)
        except ImportError:
            # If we can't check, assume it needs rehashing
            return True
        except Exception:
            return True


# Convenience functions
_default_hasher: Optional[Argon2Hasher] = None


def _get_hasher() -> Argon2Hasher:
    """Get or create default hasher instance."""
    global _default_hasher
    if _default_hasher is None:
        _default_hasher = Argon2Hasher()
    return _default_hasher


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id with secure defaults.
    
    Args:
        password: The password to hash
    
    Returns:
        Encoded hash string for storage
    """
    return _get_hasher().hash(password).encoded


def verify_password(password: str, encoded: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: The password to verify
        encoded: The stored encoded hash
    
    Returns:
        True if password matches, False otherwise
    """
    return _get_hasher().verify(password, encoded)


class SecurityWarning(UserWarning):
    """Warning for security-related concerns."""
    pass
