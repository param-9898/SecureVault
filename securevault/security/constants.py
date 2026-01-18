"""
Security Constants
==================

Defines security-related constants used throughout the application.
These values follow security best practices and should not be modified
without careful security review.
"""

from typing import Final

# Password Requirements
MIN_PASSWORD_LENGTH: Final[int] = 12
MAX_PASSWORD_LENGTH: Final[int] = 128
PASSWORD_REQUIRE_UPPERCASE: Final[bool] = True
PASSWORD_REQUIRE_LOWERCASE: Final[bool] = True
PASSWORD_REQUIRE_DIGIT: Final[bool] = True
PASSWORD_REQUIRE_SPECIAL: Final[bool] = True

# Encryption Settings
ENCRYPTION_ALGORITHM: Final[str] = "AES-256-GCM"
KEY_LENGTH_BYTES: Final[int] = 32  # 256 bits
IV_LENGTH_BYTES: Final[int] = 12  # 96 bits for GCM
TAG_LENGTH_BYTES: Final[int] = 16  # 128 bits

# Key Derivation
KEY_DERIVATION_FUNCTION: Final[str] = "PBKDF2-SHA256"
KDF_ITERATIONS: Final[int] = 600_000  # OWASP 2023 recommendation
SALT_LENGTH_BYTES: Final[int] = 32

# Session Security
SESSION_TIMEOUT_SECONDS: Final[int] = 900  # 15 minutes
MAX_LOGIN_ATTEMPTS: Final[int] = 5
LOCKOUT_DURATION_SECONDS: Final[int] = 300  # 5 minutes

# Memory Security
SECURE_MEMORY_WIPE: Final[bool] = True
CLIPBOARD_CLEAR_SECONDS: Final[int] = 30

# Entropy Requirements
MIN_ENTROPY_BITS: Final[int] = 60  # Minimum entropy for generated secrets
