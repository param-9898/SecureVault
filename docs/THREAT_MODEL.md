# SecureVault Threat Model

## Document Information
- **Version**: 1.0
- **Date**: 2026-01-03
- **Classification**: Internal Security Documentation

---

## 1. System Overview

SecureVault is a post-quantum secure file encryption vault providing:
- Hybrid encryption (Kyber768 + AES-256-GCM + ChaCha20-Poly1305)
- Multi-user authentication with Argon2id
- Hardware device binding
- Secure memory handling
- Intrusion detection

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing

| Threat | Attacker Capability | Attack Surface | Defense | Residual Risk |
|--------|---------------------|----------------|---------|---------------|
| Credential theft | Network access, phishing | Login interface | Argon2id hashing (102400 KiB), no plaintext storage | Medium - phishing still possible |
| Session hijacking | Network MITM | Session tokens | Cryptographically random tokens, server-side validation | Low - tokens are ephemeral |
| Device spoofing | Physical access | Hardware fingerprint | Multi-source fingerprinting (CPU, MB, TPM, BIOS) | Medium - virtualization can spoof |

### 2.2 Tampering

| Threat | Attacker Capability | Attack Surface | Defense | Residual Risk |
|--------|---------------------|----------------|---------|---------------|
| Encrypted file modification | File system access | .svef files | AEAD authentication (GCM/Poly1305), hash verification | Very Low - cryptographically detected |
| Audit log tampering | System access | Log files | Chained hashes, append-only design | Low - detectable via chain verification |
| Config manipulation | System access | Config files | Immutable config after load, hash verification | Low |

### 2.3 Repudiation

| Threat | Attacker Capability | Attack Surface | Defense | Residual Risk |
|--------|---------------------|----------------|---------|---------------|
| Deny file access | Insider | Audit system | Tamper-aware logging with timestamps, user IDs | Very Low |
| Deny login attempts | User | Auth system | Login attempt logging, IP/device tracking | Very Low |

### 2.4 Information Disclosure

| Threat | Attacker Capability | Attack Surface | Defense | Residual Risk |
|--------|---------------------|----------------|---------|---------------|
| Memory scraping | Process access, malware | RAM | Secure memory buffers, explicit zeroization, mlock | Medium - Python GC limitations |
| Encryption key extraction | Memory dump | Key storage | Keys wiped after use, panic key support | Medium |
| Plaintext file recovery | Disk forensics | Temp files | No temp files, in-memory viewing only | Low |
| Post-quantum attack | Future QC | Kyber ciphertext | Kyber768 (NIST PQC), hybrid with classical | Very Low |

### 2.5 Denial of Service

| Threat | Attacker Capability | Attack Surface | Defense | Residual Risk |
|--------|---------------------|----------------|---------|---------------|
| Account lockout abuse | Network access | Login | Lockout duration limited, admin unlock | Low |
| Resource exhaustion | Local access | Encryption ops | File size limits, operation timeouts | Low |

### 2.6 Elevation of Privilege

| Threat | Attacker Capability | Attack Surface | Defense | Residual Risk |
|--------|---------------------|----------------|---------|---------------|
| Role escalation | Authenticated user | User management | Role-based access, admin-only operations | Low |
| Session privilege elevation | Session access | Session tokens | Roles encoded at creation, server-validated | Very Low |

---

## 3. Threat Scenarios

### 3.1 Offline Attack

**Scenario**: Attacker obtains encrypted .svef files and attempts offline decryption.

**Defenses**:
1. Kyber768 post-quantum KEM (256-bit security)
2. Dual-layer encryption (AES-256-GCM + ChaCha20-Poly1305)
3. Per-file unique keys
4. No key material in file metadata

**Residual Risk**: Very Low - requires breaking Kyber AND both symmetric ciphers.

### 3.2 Online Brute-Force

**Scenario**: Attacker attempts rapid password guessing.

**Defenses**:
1. Argon2id with 102400 KiB memory cost (~100ms per attempt)
2. Login throttling (5 attempts → 5 min lockout)
3. Intrusion detection for excessive failures
4. Device binding prevents credential stuffing

**Residual Risk**: Low - throttling makes brute-force impractical.

### 3.3 Memory Scraping

**Scenario**: Malware or debugger attempts to extract keys from memory.

**Defenses**:
1. SecureBuffer with mlock (prevents swapping)
2. Explicit multi-pass zeroization
3. Debugger detection (IsDebuggerPresent, TracerPid)
4. Panic key for immediate wipe

**Residual Risk**: Medium - Python's memory model has limitations.

### 3.4 Insider Misuse

**Scenario**: Authorized user attempts unauthorized file access.

**Defenses**:
1. Per-user encryption keys
2. Comprehensive audit logging
3. Role-based access control
4. Session timeout enforcement

**Residual Risk**: Low - actions are logged and traceable.

### 3.5 Device Theft

**Scenario**: Laptop/device stolen with vault installed.

**Defenses**:
1. Hardware device binding (files only decrypt on registered devices)
2. No stored plaintext passwords
3. Session expiration
4. Encrypted configuration

**Residual Risk**: Medium - depends on device security state at theft.

### 3.6 Malware-Infected Host

**Scenario**: System compromised before/during vault use.

**Defenses**:
1. VM/sandbox detection
2. Debugger detection
3. Intrusion detection system
4. Panic key for emergency wipe

**Residual Risk**: High - kernel-level malware can bypass most protections.

### 3.7 Post-Quantum Adversary

**Scenario**: Future quantum computer breaks classical cryptography.

**Defenses**:
1. CRYSTALS-Kyber768 (NIST PQC winner)
2. Hybrid design preserves classical security
3. Dual symmetric layer

**Residual Risk**: Very Low - Kyber768 is quantum-resistant.

---

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED (In-Process)                      │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Crypto Core: Kyber, AES-GCM, ChaCha20, Argon2           │ │
│  │ - All operations in locked memory                       │ │
│  │ - Keys wiped immediately after use                      │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Auth Module: Password verification, session management  │ │
│  │ - Constant-time comparisons                             │ │
│  │ - No plaintext password storage                         │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                    ─ ─ ─ ─ ─│─ ─ ─ ─ ─  TRUST BOUNDARY
                              │
┌─────────────────────────────────────────────────────────────┐
│                  UNTRUSTED (External)                        │
│  • User input (passwords, file paths)                        │
│  • Encrypted files on disk                                   │
│  • Operating system                                          │
│  • Hardware (potentially spoofed)                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Mitigation Summary

| Defense Category | Implementation Status |
|------------------|-----------------------|
| Post-Quantum Crypto | ✅ Kyber768 hybrid |
| Password Security | ✅ Argon2id, policy enforcement |
| Memory Protection | ✅ SecureBuffer, zeroization |
| Device Binding | ✅ Multi-source fingerprinting |
| Intrusion Detection | ✅ Debugger, VM, login monitoring |
| Audit Logging | ✅ Tamper-aware, chained hashes |
| Panic Response | ✅ Immediate wipe, vault lock |

---

## 6. Acceptance Criteria

SecureVault is considered secure when:
1. All crypto self-tests pass on startup
2. No plaintext secrets in logs or memory dumps
3. Failed auth attempts trigger lockout
4. Device mismatch blocks decryption
5. Panic key responds within 100ms
6. Audit chain integrity verifiable
