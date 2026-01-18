"""
Security module - Cryptographic and security components.

Security Considerations:
- Use only approved cryptographic algorithms (AES-256-GCM, Argon2/PBKDF2)
- Implement secure memory handling
- Follow fail-closed design principles
- No custom cryptography implementations
"""

from securevault.security.constants import (
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    ENCRYPTION_ALGORITHM,
    KEY_DERIVATION_FUNCTION,
)
from securevault.security.intrusion_detection import (
    IntrusionDetectionSystem,
    ThreatEvent,
    ThreatType,
    ThreatLevel,
    DebuggerDetector,
    VMDetector,
    LoginFailureMonitor,
)
from securevault.security.panic_key import (
    PanicKeySystem,
    PanicReason,
    PanicEvent,
    DuressDetector,
    trigger_emergency_panic,
)
from securevault.security.hardening import (
    CryptoSelfTest,
    StartupSecurityValidator,
    NonceTracker,
    KeyLifetimeManager,
)
from securevault.security.audit import (
    TamperAwareAuditLog,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    audit_log,
)

__all__ = [
    # Constants
    "MIN_PASSWORD_LENGTH",
    "MAX_PASSWORD_LENGTH", 
    "ENCRYPTION_ALGORITHM",
    "KEY_DERIVATION_FUNCTION",
    # Intrusion Detection
    "IntrusionDetectionSystem",
    "ThreatEvent",
    "ThreatType",
    "ThreatLevel",
    "DebuggerDetector",
    "VMDetector",
    "LoginFailureMonitor",
    # Panic Key
    "PanicKeySystem",
    "PanicReason",
    "PanicEvent",
    "DuressDetector",
    "trigger_emergency_panic",
    # Hardening
    "CryptoSelfTest",
    "StartupSecurityValidator",
    "NonceTracker",
    "KeyLifetimeManager",
    # Audit
    "TamperAwareAuditLog",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "audit_log",
]

