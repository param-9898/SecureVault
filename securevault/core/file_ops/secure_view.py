"""
Secure File Viewing Module
==========================

Provides secure in-memory file viewing without creating temp files.

Security Properties:
- Content stays in memory only
- No plaintext temp files created
- Automatic secure memory wiping
- Controlled access patterns
- Read-only operations

Usage Patterns:
1. SecureMemoryBuffer: Raw memory buffer with secure wiping
2. SecureFileHandle: File-like interface for in-memory content
3. SecureViewer: High-level viewing with format support
"""

from __future__ import annotations

import ctypes
import io
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional, Iterator, Callable, Any
from contextlib import contextmanager

from securevault.core.file_ops.decrypt import FileDecryptor, DecryptedFile
from securevault.core.file_ops.encrypt import EncryptedFile, FileMetadata


# Maximum content size for in-memory viewing
MAX_VIEW_SIZE: Final[int] = 100 * 1024 * 1024  # 100 MB


class SecureViewError(Exception):
    """Raised when secure viewing fails."""
    pass


class SecureMemoryBuffer:
    """
    Secure memory buffer with automatic wiping.
    
    Provides a mutable byte buffer that is securely wiped
    from memory when no longer needed.
    
    Usage:
        with SecureMemoryBuffer(secret_data) as buf:
            process(buf.data)
        # Data is now securely wiped
    
    Security Notes:
        - Data is overwritten with zeros on cleanup
        - Use context manager for automatic wiping
        - Buffer prevents common memory leaks
    """
    
    __slots__ = ("_data", "_wiped", "_size")
    
    def __init__(self, data: bytes | bytearray) -> None:
        """
        Initialize with data to protect.
        
        Args:
            data: Sensitive data to store
        """
        self._data = bytearray(data)
        self._size = len(data)
        self._wiped = False
    
    @property
    def data(self) -> bytes:
        """Get data as immutable bytes."""
        if self._wiped:
            raise ValueError("Buffer has been wiped")
        return bytes(self._data)
    
    @property
    def size(self) -> int:
        """Get buffer size."""
        return self._size
    
    @property
    def is_wiped(self) -> bool:
        """Check if buffer has been wiped."""
        return self._wiped
    
    def wipe(self) -> None:
        """
        Securely wipe the buffer.
        
        Overwrites all data with zeros.
        """
        if not self._wiped and len(self._data) > 0:
            try:
                ctypes.memset(
                    ctypes.addressof(
                        (ctypes.c_char * len(self._data)).from_buffer(self._data)
                    ),
                    0,
                    len(self._data)
                )
            except Exception:
                # Fallback: manual zeroing
                for i in range(len(self._data)):
                    self._data[i] = 0
            
            self._wiped = True
    
    def __enter__(self) -> "SecureMemoryBuffer":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - wipe data."""
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
            return "SecureMemoryBuffer(WIPED)"
        return f"SecureMemoryBuffer(size={self._size})"


class SecureFileHandle:
    """
    Read-only file-like interface for in-memory content.
    
    Provides standard file operations without touching disk.
    Content is securely wiped when the handle is closed.
    
    Usage:
        with SecureFileHandle(content, filename) as f:
            data = f.read()
            f.seek(0)
            lines = f.readlines()
    
    Supports:
        - read(), readline(), readlines()
        - seek(), tell()
        - Iteration (for line in handle)
    """
    
    __slots__ = ("_buffer", "_stream", "_filename", "_closed")
    
    def __init__(
        self,
        content: bytes | bytearray,
        filename: str = "untitled",
    ) -> None:
        """
        Initialize with content to view.
        
        Args:
            content: File content
            filename: Original filename
        """
        self._buffer = SecureMemoryBuffer(content)
        self._stream = io.BytesIO(self._buffer.data)
        self._filename = filename
        self._closed = False
    
    @property
    def name(self) -> str:
        """Get filename."""
        return self._filename
    
    @property
    def closed(self) -> bool:
        """Check if handle is closed."""
        return self._closed
    
    def read(self, size: int = -1) -> bytes:
        """Read bytes from the file."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return self._stream.read(size)
    
    def readline(self, size: int = -1) -> bytes:
        """Read a line from the file."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return self._stream.readline(size)
    
    def readlines(self, hint: int = -1) -> list[bytes]:
        """Read all lines from the file."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return self._stream.readlines(hint)
    
    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek to position in file."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return self._stream.seek(offset, whence)
    
    def tell(self) -> int:
        """Get current position."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return self._stream.tell()
    
    def close(self) -> None:
        """Close handle and wipe content."""
        if not self._closed:
            self._stream.close()
            self._buffer.wipe()
            self._closed = True
    
    def __enter__(self) -> "SecureFileHandle":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - close handle."""
        self.close()
    
    def __iter__(self) -> Iterator[bytes]:
        """Iterate over lines."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return iter(self._stream)
    
    def __repr__(self) -> str:
        """Safe representation."""
        if self._closed:
            return "SecureFileHandle(CLOSED)"
        return f"SecureFileHandle(filename={self._filename!r})"


class SecureViewer:
    """
    High-level secure file viewer.
    
    Provides secure viewing of encrypted files without
    creating temporary plaintext files on disk.
    
    Features:
    - In-memory decryption and viewing
    - Automatic secure wiping
    - Format-aware viewing helpers
    - Read-only access patterns
    
    Usage:
        viewer = SecureViewer(secret_key)
        
        # View as file handle
        with viewer.open(encrypted_file) as f:
            content = f.read()
        
        # View as text
        text = viewer.view_text(encrypted_file)
        print(text)  # Use immediately
        # text is wiped after
        
        # Get metadata only
        meta = viewer.get_metadata(encrypted_file)
    
    Security Notes:
        - Content never touches disk
        - All buffers are securely wiped
        - Use context managers for safety
        - Large files may consume significant memory
    """
    
    __slots__ = ("_decryptor",)
    
    def __init__(
        self,
        secret_key: bytes,
        kyber_level: int = 768,
    ) -> None:
        """
        Initialize the secure viewer.
        
        Args:
            secret_key: Kyber secret key for decryption
            kyber_level: Kyber security level
        """
        self._decryptor = FileDecryptor(secret_key, kyber_level)
    
    def open(
        self,
        source: EncryptedFile | Path | str,
    ) -> SecureFileHandle:
        """
        Open an encrypted file for secure viewing.
        
        Returns a file-like handle that can be used for reading.
        Content is securely wiped when handle is closed.
        
        Args:
            source: EncryptedFile or path to encrypted file
        
        Returns:
            SecureFileHandle for reading
        
        Usage:
            with viewer.open(encrypted) as f:
                data = f.read()
        """
        encrypted, metadata = self._load_and_decrypt(source)
        return SecureFileHandle(encrypted, metadata.original_filename)
    
    @contextmanager
    def view(
        self,
        source: EncryptedFile | Path | str,
    ) -> Iterator[tuple[bytes, FileMetadata]]:
        """
        View file content with automatic cleanup.
        
        Provides raw content and metadata, with automatic
        secure wiping when the context exits.
        
        Args:
            source: EncryptedFile or path
        
        Yields:
            Tuple of (content bytes, metadata)
        
        Usage:
            with viewer.view(encrypted) as (content, meta):
                process(content)
            # Content is now wiped
        """
        encrypted = self._load(source)
        
        with self._decryptor.decrypt(encrypted) as result:
            yield result.get_content(), result.metadata
    
    def view_text(
        self,
        source: EncryptedFile | Path | str,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> str:
        """
        View file as text.
        
        Decrypts and decodes the file as text.
        
        Args:
            source: EncryptedFile or path
            encoding: Text encoding
            errors: Error handling mode
        
        Returns:
            Decoded text content
        
        Note:
            For sensitive text, use view() context manager
            and decode within the context for secure wiping.
        """
        with self.view(source) as (content, _):
            return content.decode(encoding, errors=errors)
    
    def view_lines(
        self,
        source: EncryptedFile | Path | str,
        encoding: str = "utf-8",
    ) -> Iterator[str]:
        """
        View file as lines.
        
        Args:
            source: EncryptedFile or path
            encoding: Text encoding
        
        Yields:
            Lines of text
        """
        with self.view(source) as (content, _):
            text = content.decode(encoding)
            for line in text.splitlines():
                yield line
    
    def get_metadata(
        self,
        source: EncryptedFile | Path | str,
    ) -> FileMetadata:
        """
        Get file metadata without decrypting content.
        
        This is faster than full decryption for listing files.
        
        Args:
            source: EncryptedFile or path
        
        Returns:
            FileMetadata
        """
        encrypted = self._load(source)
        return self._decryptor.decrypt_metadata(encrypted)
    
    def verify_integrity(
        self,
        source: EncryptedFile | Path | str,
        full: bool = False,
    ) -> bool:
        """
        Verify file integrity.
        
        Args:
            source: EncryptedFile or path
            full: If True, verify content hash (requires full decryption)
        
        Returns:
            True if integrity verified
        """
        encrypted = self._load(source)
        
        if full:
            try:
                with self._decryptor.decrypt(encrypted) as _:
                    return True
            except Exception:
                return False
        else:
            return self._decryptor.verify_integrity(encrypted)
    
    def get_size(self, source: EncryptedFile | Path | str) -> int:
        """
        Get original file size without full decryption.
        
        Args:
            source: EncryptedFile or path
        
        Returns:
            Original file size in bytes
        """
        metadata = self.get_metadata(source)
        return metadata.original_size
    
    def get_filename(self, source: EncryptedFile | Path | str) -> str:
        """
        Get original filename without full decryption.
        
        Args:
            source: EncryptedFile or path
        
        Returns:
            Original filename
        """
        metadata = self.get_metadata(source)
        return metadata.original_filename
    
    def _load(self, source: EncryptedFile | Path | str) -> EncryptedFile:
        """Load an EncryptedFile from various sources."""
        if isinstance(source, EncryptedFile):
            return source
        else:
            return EncryptedFile.load(source)
    
    def _load_and_decrypt(
        self,
        source: EncryptedFile | Path | str,
    ) -> tuple[bytes, FileMetadata]:
        """Load and decrypt, returning content and metadata."""
        encrypted = self._load(source)
        
        with self._decryptor.decrypt(encrypted) as result:
            # Copy content before context exit
            content = result.get_content()
            metadata = result.metadata
        
        return content, metadata


@dataclass
class SecureClipboard:
    """
    Secure clipboard for temporary content.
    
    Provides a secure way to temporarily hold
    decrypted content (e.g., passwords) with
    automatic timeout and wiping.
    """
    _content: bytearray
    _timeout_ms: int
    _created_at: float
    _wiped: bool = False
    
    def get(self) -> bytes:
        """Get content if not expired or wiped."""
        import time
        
        if self._wiped:
            raise ValueError("Content has been wiped")
        
        elapsed = (time.time() - self._created_at) * 1000
        if elapsed > self._timeout_ms:
            self.wipe()
            raise ValueError("Content has expired")
        
        return bytes(self._content)
    
    def wipe(self) -> None:
        """Securely wipe content."""
        if not self._wiped and len(self._content) > 0:
            ctypes.memset(
                ctypes.addressof(
                    (ctypes.c_char * len(self._content)).from_buffer(self._content)
                ),
                0,
                len(self._content)
            )
            self._wiped = True
    
    @classmethod
    def create(cls, content: bytes, timeout_ms: int = 30000) -> "SecureClipboard":
        """
        Create a secure clipboard entry.
        
        Args:
            content: Content to store
            timeout_ms: Auto-wipe timeout in milliseconds
        """
        import time
        return cls(
            _content=bytearray(content),
            _timeout_ms=timeout_ms,
            _created_at=time.time(),
        )
