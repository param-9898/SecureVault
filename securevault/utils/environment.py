"""
Environment Validation Module
=============================

Validates Python version, virtual environment, and dependencies on startup.
Fails closed if requirements are not met.
"""

from __future__ import annotations

import os
import sys
import platform
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Final, Optional, List, Tuple


# Required Python version range
PYTHON_MIN_VERSION: Final[Tuple[int, int]] = (3, 11)
PYTHON_MAX_VERSION: Final[Tuple[int, int]] = (3, 13)


class ValidationResult(Enum):
    """Environment validation result."""
    PASS = auto()
    WARN = auto()
    FAIL = auto()


@dataclass
class ValidationCheck:
    """A single validation check result."""
    name: str
    result: ValidationResult
    message: str
    details: Optional[str] = None


class EnvironmentValidator:
    """
    Validates the runtime environment for SecureVault.
    
    Checks:
    - Python version (3.11-3.12)
    - Virtual environment active
    - Required dependencies installed
    - Cryptography backend security
    """
    
    def __init__(self, strict: bool = True):
        self._strict = strict
        self._checks: List[ValidationCheck] = []
    
    def validate_python_version(self) -> ValidationCheck:
        """Validate Python version is within required range."""
        version = sys.version_info[:2]
        version_str = f"{version[0]}.{version[1]}"
        
        if version < PYTHON_MIN_VERSION:
            return ValidationCheck(
                "Python Version",
                ValidationResult.FAIL,
                f"Python {version_str} is too old",
                f"Required: >={PYTHON_MIN_VERSION[0]}.{PYTHON_MIN_VERSION[1]}, <{PYTHON_MAX_VERSION[0]}.{PYTHON_MAX_VERSION[1]}"
            )
        
        if version >= PYTHON_MAX_VERSION:
            return ValidationCheck(
                "Python Version",
                ValidationResult.FAIL,
                f"Python {version_str} is too new (untested)",
                f"Required: >={PYTHON_MIN_VERSION[0]}.{PYTHON_MIN_VERSION[1]}, <{PYTHON_MAX_VERSION[0]}.{PYTHON_MAX_VERSION[1]}"
            )
        
        return ValidationCheck(
            "Python Version",
            ValidationResult.PASS,
            f"Python {version_str} ✓"
        )
    
    def validate_virtual_environment(self) -> ValidationCheck:
        """Validate running inside a virtual environment."""
        in_venv = (
            hasattr(sys, 'real_prefix') or  # virtualenv
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) or  # venv
            os.environ.get('VIRTUAL_ENV') is not None  # environment variable
        )
        
        if not in_venv:
            return ValidationCheck(
                "Virtual Environment",
                ValidationResult.FAIL if self._strict else ValidationResult.WARN,
                "Not running in a virtual environment",
                "Create and activate a venv: python -m venv .venv"
            )
        
        venv_path = os.environ.get('VIRTUAL_ENV', sys.prefix)
        return ValidationCheck(
            "Virtual Environment",
            ValidationResult.PASS,
            f"venv active: {Path(venv_path).name} ✓"
        )
    
    def validate_cryptography_backend(self) -> ValidationCheck:
        """Validate cryptography library and OpenSSL version."""
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.bindings.openssl import binding
            
            backend = default_backend()
            
            # Get OpenSSL version
            openssl_version = binding.Binding.lib.OPENSSL_VERSION_TEXT
            if isinstance(openssl_version, bytes):
                openssl_version = openssl_version.decode('utf-8')
            
            # Check for known insecure versions
            if "1.0." in openssl_version or "0.9." in openssl_version:
                return ValidationCheck(
                    "Cryptography Backend",
                    ValidationResult.FAIL,
                    f"Insecure OpenSSL: {openssl_version}",
                    "OpenSSL 1.1.1+ required"
                )
            
            return ValidationCheck(
                "Cryptography Backend",
                ValidationResult.PASS,
                f"OpenSSL: {openssl_version} ✓"
            )
            
        except ImportError:
            return ValidationCheck(
                "Cryptography Backend",
                ValidationResult.FAIL,
                "cryptography package not installed",
                "Install: pip install cryptography>=41.0.0"
            )
        except Exception as e:
            return ValidationCheck(
                "Cryptography Backend",
                ValidationResult.WARN,
                f"Could not verify: {e}"
            )
    
    def validate_gui_dependencies(self) -> ValidationCheck:
        """Validate GUI dependencies are available."""
        try:
            import PySide6
            from PySide6.QtCore import __version__ as qt_version
            
            return ValidationCheck(
                "GUI Framework",
                ValidationResult.PASS,
                f"PySide6 {PySide6.__version__} (Qt {qt_version}) ✓"
            )
            
        except ImportError:
            return ValidationCheck(
                "GUI Framework",
                ValidationResult.WARN,
                "PySide6 not installed (GUI unavailable)",
                "Install: pip install PySide6>=6.5.0"
            )
    
    def validate_platform(self) -> ValidationCheck:
        """Validate and report platform information."""
        system = platform.system()
        machine = platform.machine()
        
        supported = system in ("Windows", "Linux", "Darwin")
        
        if not supported:
            return ValidationCheck(
                "Platform",
                ValidationResult.WARN,
                f"Untested platform: {system} {machine}"
            )
        
        return ValidationCheck(
            "Platform",
            ValidationResult.PASS,
            f"{system} {machine} ✓"
        )
    
    def run_all_checks(self) -> bool:
        """
        Run all environment checks.
        
        Returns:
            True if all critical checks pass, False otherwise
        """
        self._checks = [
            self.validate_python_version(),
            self.validate_virtual_environment(),
            self.validate_cryptography_backend(),
            self.validate_gui_dependencies(),
            self.validate_platform(),
        ]
        
        # Count results
        failures = sum(1 for c in self._checks if c.result == ValidationResult.FAIL)
        warnings = sum(1 for c in self._checks if c.result == ValidationResult.WARN)
        
        return failures == 0
    
    def get_checks(self) -> List[ValidationCheck]:
        """Get all check results."""
        return self._checks.copy()
    
    def print_report(self):
        """Print a formatted validation report."""
        print("\n" + "=" * 50)
        print("SecureVault Environment Validation")
        print("=" * 50 + "\n")
        
        for check in self._checks:
            icon = {
                ValidationResult.PASS: "✓",
                ValidationResult.WARN: "⚠",
                ValidationResult.FAIL: "✗",
            }[check.result]
            
            color = {
                ValidationResult.PASS: "",
                ValidationResult.WARN: "",
                ValidationResult.FAIL: "",
            }[check.result]
            
            print(f"[{icon}] {check.name}: {check.message}")
            if check.details:
                print(f"    → {check.details}")
        
        # Summary
        failures = sum(1 for c in self._checks if c.result == ValidationResult.FAIL)
        warnings = sum(1 for c in self._checks if c.result == ValidationResult.WARN)
        passed = sum(1 for c in self._checks if c.result == ValidationResult.PASS)
        
        print("\n" + "-" * 50)
        print(f"Results: {passed} passed, {warnings} warnings, {failures} failures")
        
        if failures > 0:
            print("\n⛔ Environment validation FAILED. Cannot continue.")
        elif warnings > 0:
            print("\n⚠ Environment validation passed with warnings.")
        else:
            print("\n✓ Environment validation successful!")


def require_valid_environment(strict: bool = True) -> bool:
    """
    Validate environment and fail if requirements not met.
    
    Call this at application startup.
    
    Args:
        strict: If True, fail on warnings too
    
    Returns:
        True if valid
        
    Raises:
        SystemExit: If validation fails
    """
    validator = EnvironmentValidator(strict=strict)
    is_valid = validator.run_all_checks()
    
    if not is_valid:
        validator.print_report()
        print("\nPlease fix the above issues and try again.", file=sys.stderr)
        sys.exit(1)
    
    return True


def check_venv_or_exit():
    """Quick check that we're in a venv, exit if not."""
    in_venv = (
        hasattr(sys, 'real_prefix') or
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) or
        os.environ.get('VIRTUAL_ENV') is not None
    )
    
    if not in_venv:
        print("ERROR: SecureVault must run inside a virtual environment.", file=sys.stderr)
        print("\nTo create and activate a virtual environment:", file=sys.stderr)
        print("  python -m venv .venv", file=sys.stderr)
        if platform.system() == "Windows":
            print("  .venv\\Scripts\\activate", file=sys.stderr)
        else:
            print("  source .venv/bin/activate", file=sys.stderr)
        sys.exit(1)
