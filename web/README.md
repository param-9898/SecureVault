# SecureVaultX Web Application

This is the web-based version of SecureVaultX, maintaining the exact same UI/UX and encryption logic as the desktop application.

## Features

- 🔐 **Post-Quantum Ready Encryption** - AES-256-GCM, ChaCha20-Poly1305, and Hybrid modes
- 🔒 **Argon2id Key Derivation** - OWASP recommended password hashing
- 🎨 **Dark Futuristic UI** - Same premium design as desktop app
- 📊 **Real-time Dashboard** - File statistics, session timer, activity feed
- 📜 **Audit Logs** - Live security event monitoring
- 🖥️ **Device Status** - Security verification dashboard

## Quick Start

### Backend (Python/Flask)

```bash
cd web/backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

The API will be available at `http://localhost:5000`

### Frontend

Simply open `web/frontend/index.html` in a browser, or serve it with:

```bash
cd web/frontend
python -m http.server 8080
```

Then open `http://localhost:8080`

## Free Hosting Options

### Backend (Render.com)

1. Create a new Web Service on [Render](https://render.com)
2. Connect your GitHub repository
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `gunicorn app:app`
5. Deploy!

### Frontend (Vercel/Netlify)

1. Create a new project on [Vercel](https://vercel.com) or [Netlify](https://netlify.com)
2. Point to the `web/frontend` folder
3. Deploy with default settings

**Important:** Update `API_BASE_URL` in `index.html` or `api.js` to point to your deployed backend URL.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | Login and get token |
| `/api/auth/logout` | POST | Logout and invalidate session |
| `/api/auth/validate` | GET | Validate current token |
| `/api/encrypt` | POST | Encrypt uploaded file |
| `/api/decrypt` | POST | Decrypt file |
| `/api/download/<id>` | GET | Download decrypted file |
| `/api/files` | GET | List encrypted files |
| `/api/files/<id>` | DELETE | Delete encrypted file |
| `/api/stats` | GET | Get dashboard statistics |
| `/api/system/status` | GET | Get device security status |

## Project Structure

```
web/
├── backend/
│   ├── app.py              # Flask API server
│   ├── requirements.txt    # Python dependencies
│   └── Procfile           # Render deployment config
│
└── frontend/
    ├── index.html          # Main HTML file
    ├── css/
    │   └── styles.css      # Dark futuristic theme
    └── js/
        ├── api.js          # API client
        └── app.js          # Main application logic
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | Random |
| `PORT` | Server port | 5000 |
| `UPLOAD_FOLDER` | Temp file storage | /tmp/securevault_uploads |

## Security Notes

- Passwords are hashed with Argon2id (OWASP recommended)
- Encryption uses authenticated ciphers (GCM, Poly1305)
- Session tokens are cryptographically secure
- For production, use a proper database instead of in-memory storage
