# SecureVault Security Architecture

## 1. Overview

SecureVault implements defense-in-depth security across multiple layers:

```
┌────────────────────────────────────────────────────────────────┐
│                         GUI Layer                               │
│   • Panic key hotkey (Ctrl+Shift+X)                            │
│   • Session timeout auto-lock                                   │
│   • Secure input with memory wipe                               │
└────────────────────────────────────────────────────────────────┘
                               │
┌────────────────────────────────────────────────────────────────┐
│                    Intrusion Detection                          │
│   • Debugger detection (OS-aware)                               │
│   • VM/sandbox detection                                        │
│   • Login failure monitoring                                    │
└────────────────────────────────────────────────────────────────┘
                               │
┌────────────────────────────────────────────────────────────────┐
│                   Authentication Layer                          │
│   • Argon2id password hashing (OWASP compliant)                │
│   • Role-based access control                                   │
│   • Session management with concurrency limits                  │
└────────────────────────────────────────────────────────────────┘
                               │
┌────────────────────────────────────────────────────────────────┐
│                    Device Binding Layer                         │
│   • Hardware fingerprinting (CPU, MB, BIOS, TPM)               │
│   • Multi-device registration with limits                       │
│   • Verification on every decrypt                               │
└────────────────────────────────────────────────────────────────┘
                               │
┌────────────────────────────────────────────────────────────────┐
│                    Cryptographic Core                           │
│   • Hybrid KEM: Kyber768 + Classical                           │
│   • Dual symmetric: AES-256-GCM + ChaCha20-Poly1305            │
│   • Per-file unique keys                                        │
└────────────────────────────────────────────────────────────────┘
                               │
┌────────────────────────────────────────────────────────────────┐
│                    Memory Protection                            │
│   • SecureBuffer with mlock                                     │
│   • Explicit multi-pass zeroization                             │
│   • PanicHandler for emergency wipe                             │
└────────────────────────────────────────────────────────────────┘
```

---

## 2. Cryptographic Design

### 2.1 Hybrid Post-Quantum Encryption

SecureVault uses a hybrid encryption scheme combining:

1. **Key Encapsulation**: CRYSTALS-Kyber768 (NIST PQC standard)
2. **Primary Symmetric**: AES-256-GCM (NIST approved)
3. **Secondary Symmetric**: ChaCha20-Poly1305 (RFC 8439)

**Rationale**:
- Kyber provides post-quantum security (256-bit)
- Hybrid design ensures security even if Kyber is broken
- Dual symmetric layer protects against single-algorithm weaknesses

### 2.2 Key Derivation

Password-based key derivation uses:
- **Algorithm**: Argon2id (winner of Password Hashing Competition)
- **Memory Cost**: 102400 KiB (≈100 MB)
- **Time Cost**: 2 iterations
- **Parallelism**: 4 lanes

**Rationale**:
- Argon2id resists both GPU and ASIC attacks
- High memory cost makes parallel attacks expensive
- Exceeds OWASP minimum recommendations

### 2.3 Nonce Management

- 96-bit random nonces for AES-GCM
- 96-bit random nonces for ChaCha20-Poly1305
- Nonce uniqueness tracked per key context
- Nonce reuse triggers immediate key rotation

---

## 3. Key Lifecycle

```
1. KEY GENERATION
   ├── Password entered by user
   ├── Argon2id derives master key (64 bytes)
   ├── HKDF expands to symmetric keys
   └── Kyber keypair generated/derived

2. KEY USAGE
   ├── Per-operation random nonces
   ├── Operation count tracked
   ├── Age limit enforced (24h default)
   └── Keys held in locked memory

3. KEY DESTRUCTION
   ├── Multi-pass zeroization (0x00, 0xFF, 0x00)
   ├── Memory unlocked
   ├── Reference cleared
   └── GC triggered
```

---

## 4. Device Binding

### 4.1 Fingerprint Sources

| Source | Platform | Sensitivity |
|--------|----------|-------------|
| Machine GUID | Windows Registry / /etc/machine-id | Low |
| CPU ID | CPUID instruction | Low |
| Motherboard UUID | SMBIOS/DMI | Medium |
| BIOS Serial | SMBIOS | Medium |
| TPM Public Key | TPM 2.0 API | High |

### 4.2 Binding Process

1. Collect all available hardware identifiers
2. Concatenate with salt
3. SHA-256 hash to fingerprint
4. Store only hash (never raw identifiers)
5. Verify on every decrypt operation

---

## 5. Memory Safety

### 5.1 Strategies

| Strategy | Implementation |
|----------|----------------|
| Locked Memory | VirtualLock (Windows) / mlock (Linux) |
| Explicit Zeroization | ctypes.memset multi-pass |
| Context Managers | Automatic cleanup on exit |
| Weak References | PanicHandler tracking |
| No GC Reliance | Deterministic destruction |

### 5.2 Limitations

Python's memory model has inherent limitations:
- Immutable strings may persist
- GC may defer cleanup
- Interpreter may cache values

**Mitigation**: Use mutable bytearrays, explicit wipe, and SecureString wrapper.

---

## 6. Intrusion Detection

### 6.1 Detection Capabilities

| Detection | Method | Response |
|-----------|--------|----------|
| Debugger | IsDebuggerPresent / TracerPid | CRITICAL → Panic |
| VM | Registry/DMI strings | MEDIUM → Log |
| Sandbox | Process enumeration | HIGH → Lock |
| Brute Force | Login failure counting | HIGH → Lockout |

### 6.2 Response Actions

- **CRITICAL**: Trigger panic, wipe all memory, lock vault
- **HIGH**: Lock vault, require re-authentication
- **MEDIUM**: Log event, continue with warning
- **LOW**: Log only

---

## 7. Audit System

### 7.1 Logged Events

- All authentication attempts
- All encrypt/decrypt operations
- Device verification results
- Intrusion detections
- Panic triggers
- Configuration changes

### 7.2 Integrity Protection

- Append-only log files
- Chained SHA-256 hashes
- Tamper detection on read
- No plaintext secrets logged

---

## 8. Limitations & Non-Goals

### 8.1 Explicit Non-Goals

| Non-Goal | Rationale |
|----------|-----------|
| Cloud sync | Local-only design |
| Browser extension | Attack surface |
| Mobile support | Platform complexity |
| Key escrow | Security risk |

### 8.2 Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Python memory model | Keys may persist briefly | Explicit zeroization |
| Root/Admin access | Full system compromise | Out of scope (OS security) |
| Hardware keyloggers | Password capture | Out of scope (physical security) |
| Quantum computers | Future threat | Kyber768 post-quantum security |

---

## 9. Compliance Considerations

SecureVault design aligns with:
- **NIST SP 800-57**: Key management
- **NIST SP 800-38D**: AES-GCM usage
- **OWASP ASVS**: Authentication requirements
- **FIPS 140-2**: Crypto algorithm validation (conceptual)

---

## 10. Security Checklist

### Production Readiness

- [x] Cryptographic self-tests on startup
- [x] No debug shortcuts in production
- [x] All exceptions handled (fail-closed)
- [x] Audit logging enabled
- [x] Session timeout configured
- [x] Panic key functional
- [x] Device binding verified
- [x] Password policy enforced
