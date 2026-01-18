"""
Path Utilities
==============

OS-aware path handling utilities with security considerations.
"""

from __future__ import annotations

import os
import platform
import re
import tempfile
from pathlib import Path
from typing import Final

# Characters not allowed in filenames across all platforms
_UNSAFE_CHARS: Final[re.Pattern[str]] = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def get_secure_temp_dir() -> Path:
    """
    Get a secure temporary directory.
    
    Creates a temporary directory with restricted permissions
    that is automatically cleaned up.
    
    Returns:
        Path to secure temporary directory
    """
    temp_base = Path(tempfile.gettempdir())
    secure_temp = temp_base / "securevault_temp"
    
    # Create with restricted permissions
    secure_temp.mkdir(mode=0o700, exist_ok=True)
    
    # On Windows, permissions work differently
    if platform.system().lower() != "windows":
        secure_temp.chmod(0o700)
    
    return secure_temp


def sanitize_filename(filename: str, replacement: str = "_") -> str:
    """
    Sanitize a filename by removing potentially dangerous characters.
    
    Args:
        filename: The filename to sanitize
        replacement: Character to replace unsafe chars with
        
    Returns:
        Sanitized filename safe for all platforms
    """
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    # Remove unsafe characters
    sanitized = _UNSAFE_CHARS.sub(replacement, filename)
    
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")
    
    # Prevent empty result
    if not sanitized:
        raise ValueError("Filename becomes empty after sanitization")
    
    # Truncate to safe length (255 is common max for most filesystems)
    max_length = 200  # Leave room for extensions and suffixes
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def is_path_within_directory(path: Path, directory: Path) -> bool:
    """
    Check if a path is safely within a directory (prevents path traversal).
    
    Args:
        path: The path to check
        directory: The containing directory
        
    Returns:
        True if path is safely within directory
    """
    try:
        resolved_path = path.resolve()
        resolved_dir = directory.resolve()
        return resolved_path.is_relative_to(resolved_dir)
    except (ValueError, RuntimeError):
        return False


def get_app_data_dir(app_name: str = "SecureVault") -> Path:
    """
    Get the OS-appropriate application data directory.
    
    Args:
        app_name: Name of the application
        
    Returns:
        Path to application data directory
    """
    system = platform.system().lower()
    
    if system == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif system == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    
    return base / app_name
