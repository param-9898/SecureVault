"""
SecureVault Cryptographic Core
==============================

Provides hybrid post-quantum encryption with authenticated encryption.

Architecture:
    1. AES-256-GCM: Primary symmetric encryption
    2. ChaCha20-Poly1305: Secondary symmetric layer
    3. CRYSTALS-Kyber: Post-quantum key encapsulation

Security Properties:
    - All encryption is authenticated (AEAD)
    - Keys never touch disk (memory-only)
    - Constant-time comparisons for authentication
    - Secure RNG for all random values
    - Defense-in-depth with dual symmetric layers

WARNING: This module handles sensitive cryptographic material.
         Incorrect usage can compromise security.
"""

from securevault.core.crypto.aes_gcm import AesGcmCipher
from securevault.core.crypto.chacha20 import ChaCha20Cipher
from securevault.core.crypto.hybrid_engine import HybridCryptoEngine, EncryptedPackage

__all__ = [
    "AesGcmCipher",
    "ChaCha20Cipher",
    "HybridCryptoEngine",
    "EncryptedPackage",
]
