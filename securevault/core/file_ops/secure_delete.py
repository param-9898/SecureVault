"""
Secure Deletion Module
======================

Provides secure file deletion with overwriting.

Security Properties:
- Multiple overwrite passes
- Pattern-based overwriting
- Verification after deletion
- OS-aware implementation
"""

from __future__ import annotations

import os
import secrets
import platform
from pathlib import Path
from typing import Final


# Deletion parameters
DEFAULT_OVERWRITE_PASSES: Final[int] = 3
BLOCK_SIZE: Final[int] = 4096


class SecureDeleteError(Exception):
    """Raised when secure deletion fails."""
    pass


def secure_delete(
    path: Path | str,
    passes: int = DEFAULT_OVERWRITE_PASSES,
    verify: bool = True,
) -> None:
    """
    Securely delete a file by overwriting before deletion.
    
    This makes file recovery significantly harder (though not
    impossible on some storage media like SSDs with wear leveling).
    
    Args:
        path: Path to file to delete
        passes: Number of overwrite passes
        verify: Whether to verify deletion
    
    Raises:
        SecureDeleteError: If deletion fails
    
    Overwrite Pattern (per Gutmann recommendations simplified):
        Pass 1: All zeros
        Pass 2: All ones  
        Pass 3+: Random data
    """
    path = Path(path)
    
    if not path.exists():
        return  # Already deleted
    
    if not path.is_file():
        raise SecureDeleteError(f"Not a file: {path}")
    
    try:
        file_size = path.stat().st_size
        
        # Open for binary write
        with open(path, "r+b") as f:
            for pass_num in range(passes):
                f.seek(0)
                
                if pass_num == 0:
                    # Pass 1: Zeros
                    pattern = b'\x00' * BLOCK_SIZE
                elif pass_num == 1:
                    # Pass 2: Ones
                    pattern = b'\xFF' * BLOCK_SIZE
                else:
                    # Pass 3+: Random
                    pattern = None  # Generate per block
                
                bytes_written = 0
                while bytes_written < file_size:
                    remaining = file_size - bytes_written
                    chunk_size = min(BLOCK_SIZE, remaining)
                    
                    if pattern is None:
                        data = secrets.token_bytes(chunk_size)
                    else:
                        data = pattern[:chunk_size]
                    
                    f.write(data)
                    bytes_written += chunk_size
                
                f.flush()
                os.fsync(f.fileno())
        
        # Truncate to zero length
        with open(path, "w") as f:
            pass
        
        # Delete the file
        path.unlink()
        
        # Verify deletion
        if verify and path.exists():
            raise SecureDeleteError(f"File still exists after deletion: {path}")
            
    except SecureDeleteError:
        raise
    except Exception as e:
        raise SecureDeleteError(f"Secure deletion failed: {e}") from e


def secure_delete_directory(
    path: Path | str,
    passes: int = DEFAULT_OVERWRITE_PASSES,
) -> int:
    """
    Securely delete all files in a directory.
    
    Args:
        path: Directory path
        passes: Number of overwrite passes
    
    Returns:
        Number of files deleted
    """
    path = Path(path)
    
    if not path.is_dir():
        raise SecureDeleteError(f"Not a directory: {path}")
    
    count = 0
    for item in path.rglob("*"):
        if item.is_file():
            secure_delete(item, passes=passes)
            count += 1
    
    # Remove empty directories
    for item in sorted(path.rglob("*"), reverse=True):
        if item.is_dir():
            try:
                item.rmdir()
            except OSError:
                pass  # Not empty
    
    try:
        path.rmdir()
    except OSError:
        pass
    
    return count
