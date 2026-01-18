"""
SecureVault - A Security-First Vault Application
=================================================

This package provides secure storage and management capabilities
with a focus on security-first design principles.

Security Notice:
- No secrets are logged
- Fail-closed design pattern
- All paths are OS-aware
"""

from securevault.core.config import SecureConfig
from securevault.core.logging import get_secure_logger

__version__ = "0.1.0"
__author__ = "SecureVault Team"

__all__ = ["SecureConfig", "get_secure_logger", "__version__"]
