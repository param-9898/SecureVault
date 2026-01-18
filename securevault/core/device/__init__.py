"""
SecureVault Device Binding Module
=================================

Provides hardware fingerprinting and device lock functionality.

Security Features:
- Multiple hardware identifier sources
- Only hashes stored (never raw identifiers)
- Hard failure on device mismatch
- No bypass mechanisms

Components:
- hardware_fingerprint.py: Collect and hash hardware IDs
- device_lock.py: Enforce device binding
"""

from securevault.core.device.hardware_fingerprint import (
    HardwareFingerprint,
    get_device_fingerprint,
    FingerprintSource,
)
from securevault.core.device.device_lock import (
    DeviceLock,
    DeviceMismatchError,
    DeviceNotRegisteredError,
)

__all__ = [
    "HardwareFingerprint",
    "get_device_fingerprint",
    "FingerprintSource",
    "DeviceLock",
    "DeviceMismatchError",
    "DeviceNotRegisteredError",
]
