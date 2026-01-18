# Dependency Policy - Web Application

## Overview

SecureVaultX Web follows strict dependency management practices to ensure:
- **Reproducible builds** across all environments
- **Security** through pinned, verified packages
- **Stability** for cryptographic components

---

## Dependencies

### Backend Dependencies (`web/backend/requirements.txt`)

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | >=2.3.0 | Web framework |
| Flask-CORS | >=4.0.0 | Cross-origin resource sharing |
| cryptography | >=41.0.0 | AES-GCM, ChaCha20, key derivation |
| argon2-cffi | >=23.1.0 | Argon2id password hashing |
| gunicorn | >=21.0.0 | Production WSGI server |

### Frontend Dependencies

The frontend uses vanilla JavaScript with no external dependencies:
- Pure HTML5
- Vanilla CSS3
- Native JavaScript (ES6+)

---

## Version Pinning Rules

### Cryptography Packages

**STRICT PINNING** - Security-critical packages:

```
# ✓ Correct - minimum version with security updates
cryptography>=41.0.0

# Production - exact version recommended
cryptography==46.0.3
```

### Web Framework Packages

**Range pinning** with minor version bounds:

```
# ✓ Correct - bounded range
Flask>=2.3.0,<4.0.0
```

---

## Upgrade Policy

### When to Upgrade

1. **Security fixes**: Immediately
2. **Bug fixes**: Monthly review
3. **New features**: Quarterly evaluation

### Upgrade Checklist

Before upgrading any dependency:

- [ ] Check changelog for breaking changes
- [ ] Review security advisories
- [ ] Test API endpoints
- [ ] Test frontend functionality
- [ ] Update requirements.txt
- [ ] Document changes

### Upgrade Commands

```bash
cd web/backend

# Upgrade all packages
pip install --upgrade -r requirements.txt

# Check for vulnerabilities
pip audit

# Test the application
python app.py
```

---

## Cryptography-Specific Rules

### Supported Algorithms

| Algorithm | Use Case |
|-----------|----------|
| AES-256-GCM | File encryption |
| ChaCha20-Poly1305 | Alternative encryption |
| Argon2id | Password hashing (600K iterations) |
| PBKDF2-HMAC-SHA256 | Fallback key derivation |

### Key Derivation Parameters

```python
# Argon2id (primary)
time_cost = 3
memory_cost = 65536  # 64 MB
parallelism = 4
hash_len = 32

# PBKDF2 (fallback)
iterations = 600_000
algorithm = SHA256
```

### Banned Algorithms

Never import or use:
- DES, 3DES
- MD5, SHA1 (for security purposes)
- RC4
- Blowfish
- ECB mode

---

## Security Scanning

### Automated Checks

Run before every release:

```bash
# Check for known vulnerabilities
pip audit

# Static security analysis (if bandit installed)
pip install bandit
bandit -r web/backend/
```

### Vulnerability Response

| Severity | Response Time |
|----------|---------------|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | Next release |

---

## Deployment Dependencies

### Production Requirements

For deployment to Render, Heroku, or similar:

```
Flask>=2.3.0
Flask-CORS>=4.0.0
cryptography>=41.0.0
argon2-cffi>=23.1.0
gunicorn>=21.0.0
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| SECRET_KEY | Yes (prod) | Flask secret key |
| PORT | No | Server port (default: 5000) |
| FLASK_DEBUG | No | Debug mode (default: false) |

---

## Prohibited Practices

1. ❌ No floating versions in production without testing
2. ❌ No `pip install package` without updating requirements.txt
3. ❌ No ignoring security warnings
4. ❌ No committing secrets to version control
5. ❌ No using deprecated cryptographic algorithms

---

## Dependency Files Summary

| File | Purpose | Location |
|------|---------|----------|
| `requirements.txt` | Python backend dependencies | `web/backend/` |
| `Procfile` | Deployment configuration | `web/backend/` |
| `.gitignore` | Version control exclusions | Project root |
