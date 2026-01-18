# SecureVaultX Web

A security-first file encryption vault web application with post-quantum ready encryption.

![SecureVaultX](https://img.shields.io/badge/SecureVaultX-Post--Quantum%20Ready-00D4FF?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-Backend-green?style=flat-square)
![HTML5](https://img.shields.io/badge/HTML5-Frontend-orange?style=flat-square)

## Features

- 🔐 **Military-Grade Encryption**: AES-256-GCM, ChaCha20-Poly1305, Hybrid modes
- 🛡️ **Post-Quantum Ready**: Hybrid encryption for future-proof security
- 🔑 **Argon2id Key Derivation**: Memory-hard password hashing (600,000 iterations)
- 👤 **User Authentication**: Secure registration and login with session management
- 📁 **File Encryption/Decryption**: Encrypt any file type with preview support
- 📊 **Dashboard**: Real-time statistics and activity monitoring
- 🚨 **Panic Lock**: Emergency session termination
- 🎨 **Dark Futuristic UI**: Premium glassmorphic design with animations

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/SecureVaultX.git
   cd SecureVaultX
   ```

2. **Install backend dependencies:**
   ```bash
   cd web/backend
   pip install -r requirements.txt
   ```

3. **Start the backend server:**
   ```bash
   python app.py
   ```
   The API will be running at `http://localhost:5000`

4. **Open the frontend:**
   - Open `web/frontend/index.html` in your browser
   - Or serve it with a web server for production

### Using a Local Web Server (Optional)

For production-like environment:
```bash
cd web/frontend
python -m http.server 8080
```
Then open `http://localhost:8080`

## Project Structure

```
SecureVaultX/
├── web/
│   ├── backend/
│   │   ├── app.py           # Flask API server
│   │   ├── requirements.txt # Python dependencies
│   │   └── Procfile         # Deployment config
│   └── frontend/
│       ├── index.html       # Main application
│       ├── css/styles.css   # Dark futuristic theme
│       └── js/
│           ├── api.js       # API client
│           └── app.js       # Application logic
├── securevault/             # Core modules
│   ├── core/                # Auth, config, crypto
│   ├── security/            # Security utilities
│   ├── utils/               # General utilities
│   └── db/                  # Database layer
└── docs/                    # Documentation
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | User login |
| `/api/auth/logout` | POST | User logout |
| `/api/auth/validate` | GET | Validate session |
| `/api/encrypt` | POST | Encrypt file |
| `/api/decrypt` | POST | Decrypt file |
| `/api/files` | GET | List encrypted files |
| `/api/files/:id` | DELETE | Delete file |
| `/api/stats` | GET | Dashboard statistics |
| `/api/system/status` | GET | System status |

## Encryption Algorithms

| Algorithm | Description |
|-----------|-------------|
| **AES-256-GCM** | Industry standard, hardware-accelerated |
| **ChaCha20-Poly1305** | Constant-time, timing attack resistant |
| **Hybrid** | ChaCha20 + AES layered (post-quantum ready) |

All algorithms use:
- **Argon2id** for key derivation (time_cost=3, memory_cost=64MB, parallelism=4)
- **32-byte random salt** per file
- **12-byte random nonce** per encryption

## Deployment

### Render.com (Recommended - Free)

1. Push code to GitHub
2. Create new Web Service on Render
3. Connect your repository
4. Set build command: `pip install -r web/backend/requirements.txt`
5. Set start command: `gunicorn web.backend.app:app`

### Heroku

```bash
cd web/backend
heroku create your-app-name
git push heroku main
```

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY web/backend/requirements.txt .
RUN pip install -r requirements.txt
COPY web/backend/app.py .
EXPOSE 5000
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000"]
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | Auto-generated |
| `PORT` | Server port | 5000 |
| `FLASK_DEBUG` | Debug mode | false |
| `UPLOAD_FOLDER` | File storage path | /tmp/securevault_uploads |

## Security

- **No hardcoded secrets**: All keys derived at runtime
- **Secure session management**: 24-hour expiry, cryptographic tokens
- **CORS enabled**: Configurable for production
- **Password requirements**: Minimum 12 characters, strength validation
- **Memory protection**: Sensitive data cleared after use

See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for details.

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

**Built with 🔐 by SecureVaultX Team**
