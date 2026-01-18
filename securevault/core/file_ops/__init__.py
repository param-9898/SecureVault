"""
SecureVault File Operations Module
==================================

Provides secure file encryption, decryption, and viewing.

Security Features:
- Per-file random encryption keys
- Hybrid post-quantum encryption
- Metadata separated from content
- Secure in-memory viewing (no temp files)
- Integrity verification before decryption
- Fail-closed design
- Optional secure deletion

Components:
- encrypt.py: File encryption with metadata
- decrypt.py: File decryption with integrity check
- secure_view.py: In-memory secure viewing
"""

from securevault.core.file_ops.encrypt import (
    FileEncryptor,
    EncryptedFile,
    FileMetadata,
    encrypt_file,
    encrypt_bytes,
)
from securevault.core.file_ops.decrypt import (
    FileDecryptor,
    decrypt_file,
    decrypt_bytes,
    DecryptionError,
    IntegrityError,
)
from securevault.core.file_ops.secure_view import (
    SecureViewer,
    SecureFileHandle,
    SecureMemoryBuffer,
)

__all__ = [
    "FileEncryptor",
    "EncryptedFile",
    "FileMetadata",
    "encrypt_file",
    "encrypt_bytes",
    "FileDecryptor",
    "decrypt_file",
    "decrypt_bytes",
    "DecryptionError",
    "IntegrityError",
    "SecureViewer",
    "SecureFileHandle",
    "SecureMemoryBuffer",
]
