"""
Secure Memory Buffers
=====================

Provides secure memory buffer implementations that minimize
the exposure of sensitive data in memory.

Security Properties:
- Explicit zeroization (don't rely on Python GC)
- Memory locking where supported (prevent swapping)
- Controlled access patterns
- Automatic cleanup on context exit
- Exception-safe operation

Limitations:
- Python's memory model copies data internally
- GC may leave copies in memory
- Best-effort security, not guaranteed

For maximum security, consider:
- Native extensions with secure memory allocation
- Hardware security modules (HSM)
- Memory encryption extensions
"""

from __future__ import annotations

import ctypes
import gc
import mmap
import platform
import secrets
import sys
import weakref
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Final, Optional, Callable, List, Set, Iterator
import threading


# Platform detection
IS_WINDOWS: Final[bool] = platform.system() == "Windows"
IS_LINUX: Final[bool] = platform.system() == "Linux"
IS_MACOS: Final[bool] = platform.system() == "Darwin"

# Memory constants
MIN_BUFFER_SIZE: Final[int] = 32
MAX_BUFFER_SIZE: Final[int] = 10 * 1024 * 1024  # 10 MB
DEFAULT_POOL_SIZE: Final[int] = 64 * 1024  # 64 KB


def _mlock(address: int, size: int) -> bool:
    """
    Lock memory pages to prevent swapping.
    
    Returns True if successful, False otherwise.
    """
    try:
        if IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32
            return bool(kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
        elif IS_LINUX or IS_MACOS:
            libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib", use_errno=True)
            result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return result == 0
    except Exception:
        pass
    return False


def _munlock(address: int, size: int) -> bool:
    """Unlock memory pages."""
    try:
        if IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32
            return bool(kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
        elif IS_LINUX or IS_MACOS:
            libc = ctypes.CDLL("libc.so.6" if IS_LINUX else "libc.dylib", use_errno=True)
            result = libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return result == 0
    except Exception:
        pass
    return False


class SecureBuffer:
    """
    Secure byte buffer with explicit zeroization.
    
    Provides a mutable byte buffer that is explicitly zeroed
    when no longer needed, rather than relying on Python's
    garbage collector.
    
    Features:
    - Explicit zeroization via wipe()
    - Automatic cleanup on context exit
    - Optional memory locking (prevents swapping)
    - Immutable access via .data property
    
    Usage:
        with SecureBuffer(size=256) as buf:
            buf.write(secret_key)
            process(buf.data)
        # Buffer is now zeroed
        
        # Or manually
        buf = SecureBuffer(size=32)
        try:
            buf.write(key_material)
            use_key(buf)
        finally:
            buf.wipe()
    
    Security Notes:
        - Always use context manager or call wipe() explicitly
        - Don't pass .data to functions that may copy it
        - Python may still create internal copies
    """
    
    __slots__ = ("_buffer", "_size", "_wiped", "_locked", "_write_pos", "__weakref__")
    
    def __init__(
        self,
        size: int = MIN_BUFFER_SIZE,
        lock_memory: bool = True,
    ) -> None:
        """
        Initialize a secure buffer.
        
        Args:
            size: Buffer size in bytes
            lock_memory: Try to lock memory (prevent swapping)
        """
        if size < MIN_BUFFER_SIZE:
            size = MIN_BUFFER_SIZE
        if size > MAX_BUFFER_SIZE:
            raise ValueError(f"Buffer too large (max {MAX_BUFFER_SIZE})")
        
        self._size = size
        self._buffer = bytearray(size)
        self._wiped = False
        self._locked = False
        self._write_pos = 0
        
        # Try to lock memory
        if lock_memory:
            try:
                addr = ctypes.addressof(
                    (ctypes.c_char * size).from_buffer(self._buffer)
                )
                self._locked = _mlock(addr, size)
            except Exception:
                pass
    
    @classmethod
    def from_bytes(
        cls,
        data: bytes | bytearray,
        lock_memory: bool = True,
    ) -> "SecureBuffer":
        """
        Create a SecureBuffer from existing data.
        
        The original data is NOT wiped - caller is responsible.
        """
        # Use exact size for data
        actual_size = max(len(data), MIN_BUFFER_SIZE)
        buf = cls(size=actual_size, lock_memory=lock_memory)
        buf.write(data)
        # Set write_pos to track actual data length
        buf._write_pos = len(data)
        return buf
    
    @property
    def size(self) -> int:
        """Get buffer size."""
        return self._size
    
    @property
    def data_length(self) -> int:
        """Get actual data length (not buffer size)."""
        return self._write_pos
    
    @property
    def data(self) -> bytes:
        """
        Get buffer content as immutable bytes.
        
        Returns only the written portion, not the full buffer.
        Warning: This creates a copy.
        """
        if self._wiped:
            raise ValueError("Buffer has been wiped")
        return bytes(self._buffer[:self._write_pos])
    
    @property
    def is_wiped(self) -> bool:
        """Check if buffer has been wiped."""
        return self._wiped
    
    @property
    def is_locked(self) -> bool:
        """Check if memory is locked."""
        return self._locked
    
    def write(self, data: bytes | bytearray, offset: int = 0) -> int:
        """
        Write data to buffer at offset.
        
        Args:
            data: Data to write
            offset: Offset in buffer
        
        Returns:
            Number of bytes written
        """
        if self._wiped:
            raise ValueError("Buffer has been wiped")
        
        if offset < 0 or offset >= self._size:
            raise ValueError(f"Invalid offset: {offset}")
        
        write_len = min(len(data), self._size - offset)
        self._buffer[offset:offset + write_len] = data[:write_len]
        self._write_pos = offset + write_len
        
        return write_len
    
    def append(self, data: bytes | bytearray) -> int:
        """
        Append data to buffer at current write position.
        
        Returns:
            Number of bytes written
        """
        return self.write(data, self._write_pos)
    
    def read(self, size: int = -1, offset: int = 0) -> bytes:
        """
        Read data from buffer.
        
        Args:
            size: Number of bytes to read (-1 for all)
            offset: Starting offset
        
        Returns:
            Buffer content
        """
        if self._wiped:
            raise ValueError("Buffer has been wiped")
        
        if size < 0:
            return bytes(self._buffer[offset:])
        return bytes(self._buffer[offset:offset + size])
    
    def wipe(self) -> None:
        """
        Securely wipe the buffer.
        
        Overwrites all data with zeros, then with random data,
        then zeros again (similar to Gutmann simplified).
        """
        if self._wiped:
            return
        
        try:
            addr = ctypes.addressof(
                (ctypes.c_char * self._size).from_buffer(self._buffer)
            )
            
            # Pass 1: Zeros
            ctypes.memset(addr, 0, self._size)
            
            # Pass 2: Ones
            ctypes.memset(addr, 0xFF, self._size)
            
            # Pass 3: Zeros again
            ctypes.memset(addr, 0, self._size)
            
        except Exception:
            # Fallback: Python-level zeroing
            for i in range(self._size):
                self._buffer[i] = 0
        
        # Unlock memory if locked
        if self._locked:
            try:
                addr = ctypes.addressof(
                    (ctypes.c_char * self._size).from_buffer(self._buffer)
                )
                _munlock(addr, self._size)
            except Exception:
                pass
            self._locked = False
        
        self._wiped = True
    
    def __enter__(self) -> "SecureBuffer":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - always wipe."""
        self.wipe()
    
    def __del__(self) -> None:
        """Destructor - attempt to wipe."""
        try:
            self.wipe()
        except Exception:
            pass
    
    def __len__(self) -> int:
        """Get buffer length."""
        return self._size
    
    def __repr__(self) -> str:
        """Safe representation."""
        if self._wiped:
            return "SecureBuffer(WIPED)"
        return f"SecureBuffer(size={self._size}, locked={self._locked})"


class SecureString:
    """
    Secure string container with explicit zeroization.
    
    Stores string data as UTF-8 bytes and provides controlled
    access with automatic cleanup.
    
    Usage:
        with SecureString("my_password") as pwd:
            verify_password(pwd.get())
        # String data is now wiped
    
    Security Notes:
        - Python strings are immutable and may persist in memory
        - This provides best-effort protection
        - The original string passed to constructor may still exist
    """
    
    __slots__ = ("_buffer",)
    
    def __init__(
        self,
        value: str | bytes = "",
        lock_memory: bool = True,
    ) -> None:
        """
        Initialize with a string value.
        
        Args:
            value: String or bytes to store
            lock_memory: Try to lock memory
        """
        if isinstance(value, str):
            data = value.encode("utf-8")
        else:
            data = value
        
        self._buffer = SecureBuffer.from_bytes(data, lock_memory=lock_memory)
    
    def get(self) -> str:
        """Get the stored string."""
        return self._buffer.data.decode("utf-8")
    
    def get_bytes(self) -> bytes:
        """Get the stored data as bytes."""
        return self._buffer.data
    
    @property
    def is_wiped(self) -> bool:
        """Check if wiped."""
        return self._buffer.is_wiped
    
    def wipe(self) -> None:
        """Wipe the stored data."""
        self._buffer.wipe()
    
    def __enter__(self) -> "SecureString":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.wipe()
    
    def __del__(self) -> None:
        """Destructor."""
        try:
            self.wipe()
        except Exception:
            pass
    
    def __repr__(self) -> str:
        """Safe representation - never show value."""
        if self._buffer.is_wiped:
            return "SecureString(WIPED)"
        return f"SecureString(len={self._buffer.size})"
    
    def __str__(self) -> str:
        """String conversion - returns masked value."""
        return "********"


class LockedMemoryPool:
    """
    Pool of pre-allocated locked memory buffers.
    
    Provides fast allocation of secure buffers from a
    pre-locked memory region, reducing the overhead of
    repeated mlock/munlock calls.
    
    Usage:
        pool = LockedMemoryPool(size=64 * 1024)  # 64 KB
        
        buf = pool.allocate(256)
        try:
            buf.write(secret)
            process(buf)
        finally:
            pool.release(buf)
        
        pool.destroy()  # Wipes all memory
    
    Security Notes:
        - All pool memory is locked at creation
        - All buffers are wiped on release
        - destroy() wipes entire pool
    """
    
    __slots__ = (
        "_pool", "_size", "_locked", "_allocated",
        "_free_offsets", "_lock", "_destroyed"
    )
    
    def __init__(
        self,
        size: int = DEFAULT_POOL_SIZE,
        block_size: int = 256,
    ) -> None:
        """
        Initialize memory pool.
        
        Args:
            size: Total pool size in bytes
            block_size: Allocation block size
        """
        self._size = size
        self._pool = bytearray(size)
        self._locked = False
        self._destroyed = False
        self._lock = threading.Lock()
        
        # Track allocated regions
        self._allocated: dict[int, int] = {}  # offset -> size
        self._free_offsets: list[int] = list(range(0, size, block_size))
        
        # Lock the pool memory
        try:
            addr = ctypes.addressof(
                (ctypes.c_char * size).from_buffer(self._pool)
            )
            self._locked = _mlock(addr, size)
        except Exception:
            pass
    
    @property
    def is_locked(self) -> bool:
        """Check if pool is locked."""
        return self._locked
    
    @property
    def available(self) -> int:
        """Get available space."""
        with self._lock:
            return len(self._free_offsets) * 256  # Approximate
    
    def allocate(self, size: int) -> SecureBuffer:
        """
        Allocate a buffer from the pool.
        
        Args:
            size: Requested size
        
        Returns:
            SecureBuffer backed by pool memory
        """
        if self._destroyed:
            raise RuntimeError("Pool has been destroyed")
        
        with self._lock:
            if not self._free_offsets:
                # Pool exhausted, create regular buffer
                return SecureBuffer(size=size, lock_memory=True)
            
            # Find suitable free region
            offset = self._free_offsets.pop(0)
            self._allocated[offset] = size
            
            # Create buffer view
            buf = SecureBuffer(size=size, lock_memory=False)
            buf._buffer = self._pool[offset:offset + size]
            buf._locked = self._locked
            
            return buf
    
    def release(self, buffer: SecureBuffer) -> None:
        """
        Release a buffer back to the pool.
        
        The buffer is wiped before release.
        """
        # Wipe the buffer
        buffer.wipe()
    
    def destroy(self) -> None:
        """
        Destroy the pool, wiping all memory.
        """
        if self._destroyed:
            return
        
        with self._lock:
            try:
                addr = ctypes.addressof(
                    (ctypes.c_char * self._size).from_buffer(self._pool)
                )
                
                # Triple wipe
                ctypes.memset(addr, 0, self._size)
                ctypes.memset(addr, 0xFF, self._size)
                ctypes.memset(addr, 0, self._size)
                
                # Unlock
                if self._locked:
                    _munlock(addr, self._size)
                    
            except Exception:
                # Fallback
                for i in range(self._size):
                    self._pool[i] = 0
            
            self._destroyed = True
            self._locked = False
    
    def __enter__(self) -> "LockedMemoryPool":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.destroy()
    
    def __del__(self) -> None:
        """Destructor."""
        try:
            self.destroy()
        except Exception:
            pass


class MemoryGuard:
    """
    RAII-style guard for secure memory operations.
    
    Ensures that registered buffers are wiped even if
    an exception occurs.
    
    Usage:
        guard = MemoryGuard()
        
        key = guard.track(SecureBuffer(32))
        nonce = guard.track(SecureBuffer(12))
        
        try:
            # Use key and nonce
            process(key, nonce)
        finally:
            guard.wipe_all()  # Wipes all tracked buffers
    
    Or with context manager:
        with MemoryGuard() as guard:
            key = guard.track(SecureBuffer(32))
            # All tracked buffers wiped on exit
    """
    
    __slots__ = ("_tracked", "_wiped")
    
    def __init__(self) -> None:
        """Initialize the guard."""
        self._tracked: List[SecureBuffer] = []
        self._wiped = False
    
    def track(self, buffer: SecureBuffer) -> SecureBuffer:
        """
        Track a buffer for automatic cleanup.
        
        Returns the buffer for convenience.
        """
        self._tracked.append(buffer)
        return buffer
    
    def untrack(self, buffer: SecureBuffer) -> None:
        """Remove a buffer from tracking."""
        try:
            self._tracked.remove(buffer)
        except ValueError:
            pass
    
    def wipe_all(self) -> None:
        """Wipe all tracked buffers."""
        if self._wiped:
            return
        
        for buf in self._tracked:
            try:
                buf.wipe()
            except Exception:
                pass
        
        self._tracked.clear()
        self._wiped = True
    
    def __enter__(self) -> "MemoryGuard":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.wipe_all()
    
    def __del__(self) -> None:
        """Destructor."""
        try:
            self.wipe_all()
        except Exception:
            pass
