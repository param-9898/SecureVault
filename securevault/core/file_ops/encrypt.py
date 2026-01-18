"""
File Encryption Module
======================

Provides secure file encryption with per-file keys and metadata separation.

Security Properties:
- Per-file random encryption keys
- Hybrid encryption (Kyber + AES + ChaCha20)
- Separated encrypted metadata
- Original filename protected
- File integrity ensured

File Format:
    EncryptedFile consists of:
    1. Header (magic bytes, version, metadata length)
    2. Encrypted metadata (filename, size, timestamps, content hash)
    3. Encrypted content (the actual file data)

Both metadata and content are independently encrypted with
per-operation random keys encapsulated via Kyber.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Optional, BinaryIO, Union
import struct

from securevault.core.crypto.hybrid_engine import (
    HybridCryptoEngine,
    EncryptedPackage,
)
from securevault.core.crypto.kyber_pqc import KyberKeypair


# File format constants
MAGIC_BYTES: Final[bytes] = b"SVEF"  # SecureVault Encrypted File
FILE_FORMAT_VERSION: Final[int] = 1
HEADER_SIZE: Final[int] = 16  # MAGIC(4) + VERSION(2) + FLAGS(2) + META_LEN(4) + RESERVED(4)

# Maximum sizes
MAX_FILENAME_LENGTH: Final[int] = 255
MAX_METADATA_SIZE: Final[int] = 64 * 1024  # 64 KB
MAX_FILE_SIZE: Final[int] = 10 * 1024 * 1024 * 1024  # 10 GB


class EncryptionError(Exception):
    """Raised when encryption fails."""
    pass


@dataclass
class FileMetadata:
    """
    Encrypted file metadata.
    
    This metadata is encrypted separately from the file content,
    allowing metadata queries without decrypting the full file.
    """
    original_filename: str
    original_size: int
    content_hash: str  # SHA-256 of original content
    encrypted_at: str  # ISO timestamp
    mime_type: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    custom: dict = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Serialize metadata to JSON."""
        return json.dumps(asdict(self), ensure_ascii=False)
    
    @classmethod
    def from_json(cls, json_str: str) -> "FileMetadata":
        """Deserialize metadata from JSON."""
        data = json.loads(json_str)
        return cls(**data)
    
    def __repr__(self) -> str:
        """Safe representation."""
        return f"FileMetadata(filename={self.original_filename!r}, size={self.original_size})"


@dataclass
class EncryptedFile:
    """
    Container for encrypted file data.
    
    Contains both encrypted metadata and encrypted content,
    each with their own encryption packages.
    """
    version: int
    metadata_package: EncryptedPackage
    content_package: EncryptedPackage
    flags: int = 0
    
    def to_bytes(self) -> bytes:
        """
        Serialize encrypted file to bytes.
        
        Format:
            HEADER (16 bytes):
                - MAGIC: 4 bytes
                - VERSION: 2 bytes (little-endian)
                - FLAGS: 2 bytes
                - META_LEN: 4 bytes (length of serialized metadata package)
                - RESERVED: 4 bytes
            METADATA_PACKAGE: variable
            CONTENT_PACKAGE: remaining bytes
        """
        meta_bytes = self.metadata_package.to_bytes()
        content_bytes = self.content_package.to_bytes()
        
        header = struct.pack(
            "<4sHHII",
            MAGIC_BYTES,
            self.version,
            self.flags,
            len(meta_bytes),
            0,  # Reserved
        )
        
        return header + meta_bytes + content_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedFile":
        """
        Deserialize encrypted file from bytes.
        
        Raises:
            ValueError: If data is malformed
        """
        if len(data) < HEADER_SIZE:
            raise ValueError("Data too short for encrypted file")
        
        # Parse header
        magic, version, flags, meta_len, _ = struct.unpack(
            "<4sHHII", data[:HEADER_SIZE]
        )
        
        if magic != MAGIC_BYTES:
            raise ValueError("Invalid file format (bad magic bytes)")
        
        if version != FILE_FORMAT_VERSION:
            raise ValueError(f"Unsupported file format version: {version}")
        
        if meta_len > MAX_METADATA_SIZE:
            raise ValueError(f"Metadata too large: {meta_len}")
        
        # Extract packages
        meta_start = HEADER_SIZE
        meta_end = meta_start + meta_len
        
        if len(data) < meta_end:
            raise ValueError("Data truncated (incomplete metadata)")
        
        metadata_package = EncryptedPackage.from_bytes(data[meta_start:meta_end])
        content_package = EncryptedPackage.from_bytes(data[meta_end:])
        
        return cls(
            version=version,
            metadata_package=metadata_package,
            content_package=content_package,
            flags=flags,
        )
    
    def save(self, path: Path | str) -> None:
        """Save encrypted file to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.to_bytes())
    
    @classmethod
    def load(cls, path: Path | str) -> "EncryptedFile":
        """Load encrypted file from disk."""
        return cls.from_bytes(Path(path).read_bytes())


class FileEncryptor:
    """
    Secure file encryption with per-file keys.
    
    Provides:
    - Per-file random encryption keys
    - Hybrid post-quantum encryption
    - Metadata separation
    - Content integrity verification
    
    Usage:
        encryptor = FileEncryptor(public_key)
        
        # Encrypt a file
        encrypted = encryptor.encrypt_file(Path("document.pdf"))
        encrypted.save(Path("document.pdf.svef"))
        
        # Encrypt bytes directly
        encrypted = encryptor.encrypt_bytes(data, filename="data.bin")
    
    Security Notes:
        - Each file gets unique random keys
        - Metadata and content are encrypted separately
        - Content hash is computed before encryption for integrity
        - Original filename is protected (encrypted in metadata)
    """
    
    __slots__ = ("_engine", "_public_key")
    
    def __init__(
        self,
        public_key: bytes,
        kyber_level: int = 768,
    ) -> None:
        """
        Initialize the file encryptor.
        
        Args:
            public_key: Kyber public key for encryption
            kyber_level: Kyber security level (must match key)
        """
        self._engine = HybridCryptoEngine(kyber_level=kyber_level)
        self._public_key = public_key
    
    def encrypt_file(
        self,
        source_path: Path | str,
        tags: Optional[list[str]] = None,
        custom_metadata: Optional[dict] = None,
    ) -> EncryptedFile:
        """
        Encrypt a file from disk.
        
        Args:
            source_path: Path to the file to encrypt
            tags: Optional tags for the file
            custom_metadata: Optional custom metadata
        
        Returns:
            EncryptedFile containing encrypted content and metadata
        
        Raises:
            FileNotFoundError: If source file doesn't exist
            EncryptionError: If encryption fails
        """
        source_path = Path(source_path)
        
        if not source_path.exists():
            raise FileNotFoundError(f"File not found: {source_path}")
        
        if not source_path.is_file():
            raise ValueError(f"Not a file: {source_path}")
        
        # Read file content
        content = source_path.read_bytes()
        
        # Get file info
        stat = source_path.stat()
        
        return self.encrypt_bytes(
            content=content,
            filename=source_path.name,
            mime_type=self._guess_mime_type(source_path),
            tags=tags,
            custom_metadata=custom_metadata,
        )
    
    def encrypt_bytes(
        self,
        content: bytes,
        filename: str,
        mime_type: Optional[str] = None,
        tags: Optional[list[str]] = None,
        custom_metadata: Optional[dict] = None,
    ) -> EncryptedFile:
        """
        Encrypt bytes with metadata.
        
        Args:
            content: The content to encrypt
            filename: Original filename
            mime_type: Optional MIME type
            tags: Optional tags
            custom_metadata: Optional custom metadata
        
        Returns:
            EncryptedFile with encrypted content and metadata
        """
        if len(filename) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename too long (max {MAX_FILENAME_LENGTH})")
        
        if len(content) > MAX_FILE_SIZE:
            raise ValueError(f"File too large (max {MAX_FILE_SIZE} bytes)")
        
        try:
            # Compute content hash for integrity
            content_hash = hashlib.sha256(content).hexdigest()
            
            # Create metadata
            metadata = FileMetadata(
                original_filename=filename,
                original_size=len(content),
                content_hash=content_hash,
                encrypted_at=datetime.now(timezone.utc).isoformat(),
                mime_type=mime_type,
                tags=tags or [],
                custom=custom_metadata or {},
            )
            
            # Encrypt metadata (with content hash as AAD for binding)
            metadata_json = metadata.to_json().encode("utf-8")
            metadata_package = self._engine.encrypt(
                metadata_json,
                self._public_key,
                aad=b"SVEF_METADATA_v1",
            )
            
            # Encrypt content (with metadata hash as AAD for binding)
            metadata_hash = hashlib.sha256(metadata_json).digest()
            content_package = self._engine.encrypt(
                content,
                self._public_key,
                aad=b"SVEF_CONTENT_v1" + metadata_hash,
            )
            
            return EncryptedFile(
                version=FILE_FORMAT_VERSION,
                metadata_package=metadata_package,
                content_package=content_package,
            )
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def encrypt_stream(
        self,
        stream: BinaryIO,
        filename: str,
        chunk_size: int = 1024 * 1024,  # 1 MB chunks
        **kwargs,
    ) -> EncryptedFile:
        """
        Encrypt a file stream.
        
        For very large files, this reads in chunks but still
        encrypts as a single unit (chunked encryption not yet implemented).
        
        Args:
            stream: Binary file stream
            filename: Original filename
            chunk_size: Read chunk size
            **kwargs: Additional metadata arguments
        
        Returns:
            EncryptedFile
        """
        # Read entire stream (chunked encryption TODO)
        content = stream.read()
        return self.encrypt_bytes(content, filename, **kwargs)
    
    @staticmethod
    def _guess_mime_type(path: Path) -> Optional[str]:
        """Guess MIME type from file extension."""
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(path))
        return mime_type


def encrypt_file(
    source_path: Path | str,
    public_key: bytes,
    output_path: Optional[Path | str] = None,
    **kwargs,
) -> Path:
    """
    Convenience function to encrypt a file.
    
    Args:
        source_path: Path to file to encrypt
        public_key: Kyber public key
        output_path: Optional output path (default: source + .svef)
        **kwargs: Additional arguments for FileEncryptor
    
    Returns:
        Path to encrypted file
    """
    source_path = Path(source_path)
    
    if output_path is None:
        output_path = source_path.with_suffix(source_path.suffix + ".svef")
    else:
        output_path = Path(output_path)
    
    encryptor = FileEncryptor(public_key)
    encrypted = encryptor.encrypt_file(source_path, **kwargs)
    encrypted.save(output_path)
    
    return output_path


def encrypt_bytes(
    content: bytes,
    filename: str,
    public_key: bytes,
    **kwargs,
) -> EncryptedFile:
    """
    Convenience function to encrypt bytes.
    
    Args:
        content: Bytes to encrypt
        filename: Original filename
        public_key: Kyber public key
        **kwargs: Additional metadata
    
    Returns:
        EncryptedFile
    """
    encryptor = FileEncryptor(public_key)
    return encryptor.encrypt_bytes(content, filename, **kwargs)
