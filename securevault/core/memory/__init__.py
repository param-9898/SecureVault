"""
SecureVault Memory Security Module
===================================

Provides secure memory handling primitives.

Security Features:
- Locked memory buffers (prevent swapping)
- Explicit zeroization (don't rely on GC)
- Panic key trigger
- Forced vault lock
- Exception-safe cleanup

Components:
- secure_memory.py: Secure buffer implementations
- zeroization.py: Memory wiping utilities

WARNING:
- Python's memory model doesn't guarantee secure erasure
- These are best-effort mitigations
- For maximum security, consider native extensions
"""

from securevault.core.memory.secure_memory import (
    SecureBuffer,
    SecureString,
    LockedMemoryPool,
    MemoryGuard,
)
from securevault.core.memory.zeroization import (
    secure_zero,
    secure_zero_string,
    zeroize_on_exception,
    ZeroizeContext,
    PanicHandler,
    trigger_panic,
)

__all__ = [
    "SecureBuffer",
    "SecureString",
    "LockedMemoryPool",
    "MemoryGuard",
    "secure_zero",
    "secure_zero_string",
    "zeroize_on_exception",
    "ZeroizeContext",
    "PanicHandler",
    "trigger_panic",
]
