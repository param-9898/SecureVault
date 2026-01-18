"""
SecureVault Authentication Module
=================================

Provides secure authentication with:
- Argon2id password hashing
- Role-based access control
- Session management with expiration
- Login throttling

Security Properties:
- Memory-hard password hashing
- Constant-time verification
- Secure session tokens
- Automatic lockout on failed attempts
"""

from securevault.core.auth.argon2_auth import (
    Argon2Hasher,
    hash_password,
    verify_password,
)
from securevault.core.auth.user_manager import (
    UserManager,
    User,
    UserRole,
)
from securevault.core.auth.session_control import (
    SessionManager,
    Session,
)

__all__ = [
    "Argon2Hasher",
    "hash_password",
    "verify_password",
    "UserManager",
    "User",
    "UserRole",
    "SessionManager",
    "Session",
]
