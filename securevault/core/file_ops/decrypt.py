"""
File Decryption Module
======================

Provides secure file decryption with integrity verification.

Security Properties:
- Integrity checked BEFORE any content returned
- Fail-closed design (any error = complete failure)
- Metadata verified separately
- Content hash verified after decryption
- No partial decryption on failure

Decryption Flow:
1. Parse encrypted file header
2. Decrypt and verify metadata
3. Decrypt content with metadata binding
4. Verify content hash matches metadata
5. Return plaintext only if all checks pass
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional, Tuple, BinaryIO
import ctypes

from securevault.core.crypto.hybrid_engine import HybridCryptoEngine
from securevault.core.file_ops.encrypt import (
    EncryptedFile,
    FileMetadata,
    MAGIC_BYTES,
    FILE_FORMAT_VERSION,
)


class DecryptionError(Exception):
    """
    Raised when decryption fails.
    
    This is a generic error that doesn't reveal the cause
    (to prevent information leakage).
    """
    pass


class IntegrityError(DecryptionError):
    """
    Raised when integrity verification fails.
    
    This indicates tampering or corruption.
    """
    pass


@dataclass
class DecryptedFile:
    """
    Container for decrypted file content and metadata.
    
    Provides secure memory wiping when done.
    """
    content: bytearray  # Mutable for secure wiping
    metadata: FileMetadata
    _wiped: bool = False
    
    def __repr__(self) -> str:
        """Safe representation."""
        if self._wiped:
            return "DecryptedFile(WIPED)"
        return f"DecryptedFile(filename={self.metadata.original_filename!r})"
    
    def get_content(self) -> bytes:
        """Get content as immutable bytes."""
        if self._wiped:
            raise ValueError("Content has been securely wiped")
        return bytes(self.content)
    
    def secure_wipe(self) -> None:
        """
        Securely wipe the content from memory.
        
        This overwrites the content buffer with zeros
        to minimize the time sensitive data remains in memory.
        """
        if not self._wiped:
            # Overwrite with zeros
            ctypes.memset(
                ctypes.addressof((ctypes.c_char * len(self.content)).from_buffer(self.content)),
                0,
                len(self.content)
            )
            self._wiped = True
    
    def __enter__(self) -> "DecryptedFile":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - always wipe content."""
        self.secure_wipe()
    
    def __del__(self) -> None:
        """Destructor - attempt to wipe content."""
        try:
            self.secure_wipe()
        except Exception:
            pass  # Best effort


class FileDecryptor:
    """
    Secure file decryption with integrity verification.
    
    Provides:
    - Full integrity verification before returning plaintext
    - Metadata decryption and validation
    - Content hash verification
    - Fail-closed design
    
    Usage:
        decryptor = FileDecryptor(secret_key)
        
        # Decrypt a file
        with decryptor.decrypt_file(Path("document.svef")) as result:
            content = result.get_content()
            print(f"Original: {result.metadata.original_filename}")
            # Content is securely wiped on exit
        
        # Just get metadata (without decrypting content)
        metadata = decryptor.decrypt_metadata(encrypted_file)
    
    Security Notes:
        - NEVER returns partial content on failure
        - All verification happens before returning data
        - Use context manager for automatic secure wiping
    """
    
    __slots__ = ("_engine", "_secret_key")
    
    def __init__(
        self,
        secret_key: bytes,
        kyber_level: int = 768,
    ) -> None:
        """
        Initialize the file decryptor.
        
        Args:
            secret_key: Kyber secret key for decryption
            kyber_level: Kyber security level (must match key)
        """
        self._engine = HybridCryptoEngine(kyber_level=kyber_level)
        self._secret_key = secret_key
    
    def decrypt_file(
        self,
        source_path: Path | str,
        verify_content_hash: bool = True,
    ) -> DecryptedFile:
        """
        Decrypt an encrypted file from disk.
        
        Args:
            source_path: Path to encrypted file
            verify_content_hash: Whether to verify content hash
        
        Returns:
            DecryptedFile with content and metadata
        
        Raises:
            DecryptionError: If decryption fails
            IntegrityError: If integrity verification fails
        """
        source_path = Path(source_path)
        
        if not source_path.exists():
            raise FileNotFoundError(f"File not found: {source_path}")
        
        encrypted = EncryptedFile.load(source_path)
        return self.decrypt(encrypted, verify_content_hash=verify_content_hash)
    
    def decrypt(
        self,
        encrypted: EncryptedFile,
        verify_content_hash: bool = True,
    ) -> DecryptedFile:
        """
        Decrypt an EncryptedFile object.
        
        Args:
            encrypted: EncryptedFile to decrypt
            verify_content_hash: Whether to verify content hash
        
        Returns:
            DecryptedFile with content and metadata
        
        Raises:
            DecryptionError: If decryption fails
            IntegrityError: If integrity verification fails
        """
        try:
            # Step 1: Decrypt metadata
            metadata = self._decrypt_metadata(encrypted)
            
            # Step 2: Decrypt content with metadata binding
            metadata_json = metadata.to_json().encode("utf-8")
            metadata_hash = hashlib.sha256(metadata_json).digest()
            
            content = self._engine.decrypt(
                encrypted.content_package,
                self._secret_key,
                aad=b"SVEF_CONTENT_v1" + metadata_hash,
            )
            
            # Step 3: Verify content hash
            if verify_content_hash:
                actual_hash = hashlib.sha256(content).hexdigest()
                
                if not hmac.compare_digest(actual_hash, metadata.content_hash):
                    raise IntegrityError(
                        "Content hash mismatch - file may be corrupted or tampered"
                    )
            
            # Step 4: Verify size
            if len(content) != metadata.original_size:
                raise IntegrityError(
                    "Content size mismatch - file may be corrupted"
                )
            
            return DecryptedFile(
                content=bytearray(content),
                metadata=metadata,
            )
            
        except IntegrityError:
            raise
        except Exception as e:
            # Generic error to prevent information leakage
            raise DecryptionError("Decryption failed") from e
    
    def decrypt_metadata(
        self,
        encrypted: EncryptedFile,
    ) -> FileMetadata:
        """
        Decrypt only the file metadata.
        
        This is faster than full decryption and useful for
        listing files without decrypting content.
        
        Args:
            encrypted: EncryptedFile
        
        Returns:
            FileMetadata
        """
        return self._decrypt_metadata(encrypted)
    
    def _decrypt_metadata(self, encrypted: EncryptedFile) -> FileMetadata:
        """Internal metadata decryption."""
        try:
            metadata_bytes = self._engine.decrypt(
                encrypted.metadata_package,
                self._secret_key,
                aad=b"SVEF_METADATA_v1",
            )
            
            metadata_json = metadata_bytes.decode("utf-8")
            return FileMetadata.from_json(metadata_json)
            
        except Exception as e:
            raise DecryptionError("Metadata decryption failed") from e
    
    def decrypt_to_file(
        self,
        encrypted_path: Path | str,
        output_path: Path | str,
        verify_content_hash: bool = True,
    ) -> FileMetadata:
        """
        Decrypt an encrypted file and save to disk.
        
        Args:
            encrypted_path: Path to encrypted file
            output_path: Path to save decrypted content
            verify_content_hash: Whether to verify content hash
        
        Returns:
            FileMetadata of the decrypted file
        
        Note:
            This writes plaintext to disk. For sensitive files,
            prefer in-memory operations with secure_view.
        """
        with self.decrypt_file(encrypted_path, verify_content_hash) as result:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(result.get_content())
            return result.metadata
    
    def verify_integrity(self, encrypted: EncryptedFile) -> bool:
        """
        Verify the integrity of an encrypted file without full decryption.
        
        This decrypts and verifies metadata but not content.
        Full content verification requires decrypt().
        
        Args:
            encrypted: EncryptedFile to verify
        
        Returns:
            True if metadata decrypts correctly
        """
        try:
            self._decrypt_metadata(encrypted)
            return True
        except Exception:
            return False


def decrypt_file(
    encrypted_path: Path | str,
    secret_key: bytes,
    output_path: Optional[Path | str] = None,
) -> DecryptedFile | Path:
    """
    Convenience function to decrypt a file.
    
    Args:
        encrypted_path: Path to encrypted file
        secret_key: Kyber secret key
        output_path: If provided, save decrypted content here
    
    Returns:
        DecryptedFile if no output_path, else Path to output
    """
    decryptor = FileDecryptor(secret_key)
    
    if output_path:
        metadata = decryptor.decrypt_to_file(encrypted_path, output_path)
        return Path(output_path)
    else:
        return decryptor.decrypt_file(encrypted_path)


def decrypt_bytes(
    encrypted: EncryptedFile,
    secret_key: bytes,
) -> Tuple[bytes, FileMetadata]:
    """
    Convenience function to decrypt EncryptedFile to bytes.
    
    Args:
        encrypted: EncryptedFile to decrypt
        secret_key: Kyber secret key
    
    Returns:
        Tuple of (content bytes, metadata)
    
    Note:
        The returned bytes should be securely wiped when done.
        Consider using FileDecryptor with context manager instead.
    """
    decryptor = FileDecryptor(secret_key)
    with decryptor.decrypt(encrypted) as result:
        return result.get_content(), result.metadata
