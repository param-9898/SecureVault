"""
Validation Utilities
====================

Input validation functions with security focus.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


class ValidationError(ValueError):
    """Raised when validation fails."""
    pass


def validate_path_safe(
    path: str | Path,
    base_directory: Optional[Path] = None,
    must_exist: bool = False,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate a path is safe and optionally within a base directory.
    
    Args:
        path: The path to validate
        base_directory: If provided, path must be within this directory
        must_exist: If True, path must exist
        allow_symlinks: If False, symlinks are rejected
        
    Returns:
        Validated, resolved Path object
        
    Raises:
        ValidationError: If validation fails
    """
    try:
        validated_path = Path(path).resolve()
    except (ValueError, RuntimeError) as e:
        raise ValidationError(f"Invalid path: {e}") from e
    
    # Check for path traversal attempts
    if ".." in str(path):
        raise ValidationError("Path traversal detected")
    
    # Check if within base directory
    if base_directory is not None:
        resolved_base = base_directory.resolve()
        if not validated_path.is_relative_to(resolved_base):
            raise ValidationError(
                f"Path must be within {resolved_base}"
            )
    
    # Check existence
    if must_exist and not validated_path.exists():
        raise ValidationError(f"Path does not exist: {validated_path}")
    
    # Check symlinks
    if not allow_symlinks and validated_path.exists() and validated_path.is_symlink():
        raise ValidationError("Symlinks are not allowed")
    
    return validated_path


def validate_string_safe(
    value: str,
    min_length: int = 0,
    max_length: int = 1000,
    allow_empty: bool = False,
    field_name: str = "value",
) -> str:
    """
    Validate a string value for safety.
    
    Args:
        value: The string to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        allow_empty: If False, empty strings are rejected
        field_name: Name of the field for error messages
        
    Returns:
        Validated string
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string")
    
    if not allow_empty and not value:
        raise ValidationError(f"{field_name} cannot be empty")
    
    if len(value) < min_length:
        raise ValidationError(
            f"{field_name} must be at least {min_length} characters"
        )
    
    if len(value) > max_length:
        raise ValidationError(
            f"{field_name} must be at most {max_length} characters"
        )
    
    # Check for null bytes (security risk)
    if "\x00" in value:
        raise ValidationError(f"{field_name} contains invalid characters")
    
    return value
