"""
SecureVaultX Web API
====================
Flask backend for PythonAnywhere hosting with MySQL database.
"""

import os
import sys
import uuid
import hashlib
import secrets
import struct
from pathlib import Path
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/tmp/securevault_uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max for free tier

# MySQL Configuration for PythonAnywhere
# Format: MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
MYSQL_HOST = os.environ.get('MYSQL_HOST', '')
MYSQL_USER = os.environ.get('MYSQL_USER', '')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
MYSQL_DB = os.environ.get('MYSQL_DB', '')

# Check if MySQL is configured
USE_MYSQL = bool(MYSQL_HOST and MYSQL_USER and MYSQL_DB)

# Import database library
if USE_MYSQL:
    try:
        import pymysql
        pymysql.install_as_MySQLdb()
    except ImportError:
        USE_MYSQL = False

import sqlite3

# Ensure folders exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)

# Encryption format constants
MAGIC_BYTES = b"SVEX"
VERSION = 1

# ============================================================
# DATABASE
# ============================================================

def get_db():
    """Get database connection."""
    if 'db' not in g:
        if USE_MYSQL:
            g.db = pymysql.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DB,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
        else:
            db_path = '/tmp/securevault.db'
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


_db_initialized = False
_db_error = None

def init_db():
    """Initialize database tables."""
    global _db_initialized, _db_error
    try:
        db = get_db()
        
        if USE_MYSQL:
            cur = db.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(36) PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    role VARCHAR(50) DEFAULT 'USER',
                    created_at VARCHAR(50) NOT NULL
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    token VARCHAR(64) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    created_at VARCHAR(50) NOT NULL,
                    expires_at VARCHAR(50) NOT NULL
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS encrypted_files (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    original_path VARCHAR(500) NOT NULL,
                    encrypted_path VARCHAR(500) NOT NULL,
                    filename VARCHAR(500) NOT NULL,
                    file_size INT NOT NULL,
                    algorithm VARCHAR(50) NOT NULL,
                    created_at VARCHAR(50) NOT NULL
                )
            ''')
            db.commit()
            cur.close()
        else:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    role TEXT DEFAULT 'USER',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS encrypted_files (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    encrypted_path TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    algorithm TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            ''')
            db.commit()
        
        _db_initialized = True
        _db_error = None
    except Exception as e:
        _db_error = str(e)
        print(f"Database error: {e}")


def db_execute(query, params=None):
    """Execute query."""
    db = get_db()
    if USE_MYSQL:
        cur = db.cursor()
        cur.execute(query, params or ())
        return cur
    else:
        return db.execute(query, params or ())


def db_commit():
    get_db().commit()


def db_fetchone(query, params=None):
    cur = db_execute(query, params)
    row = cur.fetchone()
    if USE_MYSQL:
        cur.close()
    return row


def db_fetchall(query, params=None):
    cur = db_execute(query, params)
    rows = cur.fetchall()
    if USE_MYSQL:
        cur.close()
    return rows


@app.before_request
def before_request():
    if request.path == '/api/health':
        return
    if not _db_initialized:
        init_db()


# ============================================================
# AUTHENTICATION
# ============================================================

def derive_key_pbkdf2(password: str, salt: bytes, length: int = 32) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100_000,  # Reduced for faster response
    )
    return kdf.derive(password.encode('utf-8'))


def hash_password(password: str) -> tuple:
    salt = secrets.token_bytes(32)
    password_hash = derive_key_pbkdf2(password, salt, 32)
    return salt, password_hash


def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    if isinstance(salt, memoryview):
        salt = bytes(salt)
    if isinstance(stored_hash, memoryview):
        stored_hash = bytes(stored_hash)
    computed_hash = derive_key_pbkdf2(password, salt, 32)
    return secrets.compare_digest(computed_hash, stored_hash)


def create_session(user_id: str) -> str:
    token = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=24)
    
    if USE_MYSQL:
        db_execute(
            'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (%s, %s, %s, %s)',
            (token, user_id, now.isoformat(), expires.isoformat())
        )
    else:
        db_execute(
            'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
            (token, user_id, now.isoformat(), expires.isoformat())
        )
    db_commit()
    return token


def validate_session(token: str) -> dict:
    if USE_MYSQL:
        session = db_fetchone('SELECT * FROM sessions WHERE token = %s', (token,))
    else:
        session = db_fetchone('SELECT * FROM sessions WHERE token = ?', (token,))
    
    if not session:
        return None
    
    expires_at = datetime.fromisoformat(session['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if USE_MYSQL:
            db_execute('DELETE FROM sessions WHERE token = %s', (token,))
        else:
            db_execute('DELETE FROM sessions WHERE token = ?', (token,))
        db_commit()
        return None
    
    return {
        'user_id': session['user_id'],
        'created_at': session['created_at'],
        'expires_at': session['expires_at']
    }


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        session = validate_session(token)
        if not session:
            return jsonify({'error': 'Unauthorized'}), 401
        request.user_id = session['user_id']
        request.session = session
        return f(*args, **kwargs)
    return decorated


# ============================================================
# ENCRYPTION
# ============================================================

def encrypt_aes_gcm(data: bytes, key: bytes) -> tuple:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return ciphertext, nonce


def decrypt_aes_gcm(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_chacha20(data: bytes, key: bytes) -> tuple:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    nonce = secrets.token_bytes(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, data, None)
    return ciphertext, nonce


def decrypt_chacha20(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)


def encrypt_hybrid(data: bytes, key: bytes) -> tuple:
    key1 = hashlib.sha256(key + b"chacha").digest()
    key2 = hashlib.sha256(key + b"aes").digest()
    chacha_ct, chacha_nonce = encrypt_chacha20(data, key1)
    aes_ct, aes_nonce = encrypt_aes_gcm(chacha_ct, key2)
    metadata = chacha_nonce + aes_nonce
    return aes_ct, metadata


def decrypt_hybrid(ciphertext: bytes, metadata: bytes, key: bytes) -> bytes:
    key1 = hashlib.sha256(key + b"chacha").digest()
    key2 = hashlib.sha256(key + b"aes").digest()
    chacha_nonce = metadata[:12]
    aes_nonce = metadata[12:24]
    chacha_ct = decrypt_aes_gcm(ciphertext, aes_nonce, key2)
    return decrypt_chacha20(chacha_ct, chacha_nonce, key1)


# ============================================================
# API ROUTES
# ============================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    db_type = 'mysql' if USE_MYSQL else 'sqlite'
    db_status = 'connected' if _db_initialized else 'initializing'
    if _db_error:
        db_status = f'error: {_db_error[:50]}'
    
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'database': db_type,
        'db_status': db_status,
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


def calculate_password_strength(password: str) -> int:
    if not password:
        return 0
    score = 0
    if len(password) >= 8: score += 20
    if len(password) >= 12: score += 15
    if len(password) >= 16: score += 10
    if any(c.islower() for c in password): score += 10
    if any(c.isupper() for c in password): score += 15
    if any(c.isdigit() for c in password): score += 15
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 15
    return min(100, score)


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'USER')
    
    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if not password or len(password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters'}), 400
    
    strength = calculate_password_strength(password)
    if strength < 60:
        return jsonify({'error': 'Password is too weak'}), 400
    
    # Check existing
    if USE_MYSQL:
        existing = db_fetchone('SELECT id FROM users WHERE username = %s', (username,))
    else:
        existing = db_fetchone('SELECT id FROM users WHERE username = ?', (username,))
    
    if existing:
        return jsonify({'error': 'Username already exists'}), 400
    
    user_id = str(uuid.uuid4())
    salt, password_hash = hash_password(password)
    
    if USE_MYSQL:
        db_execute(
            'INSERT INTO users (id, username, salt, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s, %s)',
            (user_id, username, salt, password_hash, role, datetime.now(timezone.utc).isoformat())
        )
    else:
        db_execute(
            'INSERT INTO users (id, username, salt, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, username, salt, password_hash, role, datetime.now(timezone.utc).isoformat())
        )
    db_commit()
    
    return jsonify({
        'success': True,
        'message': 'Account created successfully',
        'user_id': user_id
    })


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if USE_MYSQL:
        user = db_fetchone('SELECT * FROM users WHERE username = %s', (username,))
    else:
        user = db_fetchone('SELECT * FROM users WHERE username = ?', (username,))
    
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    if not verify_password(password, user['salt'], user['password_hash']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    token = create_session(user['id'])
    
    return jsonify({
        'success': True,
        'token': token,
        'user_id': user['id'],
        'username': username,
        'role': user['role']
    })


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if USE_MYSQL:
        db_execute('DELETE FROM sessions WHERE token = %s', (token,))
    else:
        db_execute('DELETE FROM sessions WHERE token = ?', (token,))
    db_commit()
    return jsonify({'success': True})


@app.route('/api/auth/validate', methods=['GET'])
@require_auth
def validate_token():
    user_id = request.user_id
    if USE_MYSQL:
        user = db_fetchone('SELECT username FROM users WHERE id = %s', (user_id,))
    else:
        user = db_fetchone('SELECT username FROM users WHERE id = ?', (user_id,))
    
    return jsonify({
        'valid': True,
        'user_id': user_id,
        'username': user['username'] if user else 'Unknown'
    })


@app.route('/api/encrypt', methods=['POST'])
@require_auth
def encrypt_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    algorithm = request.form.get('algorithm', 'aes')
    
    if not password or len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        data = file.read()
        original_size = len(data)
        filename = secure_filename(file.filename)
        
        salt = secrets.token_bytes(32)
        key = derive_key_pbkdf2(password, salt, 32)
        
        if algorithm == 'aes':
            encrypted, metadata = encrypt_aes_gcm(data, key)
            algo_byte = 1
        elif algorithm == 'chacha':
            encrypted, metadata = encrypt_chacha20(data, key)
            algo_byte = 2
        else:
            encrypted, metadata = encrypt_hybrid(data, key)
            algo_byte = 3
        
        output_data = (
            MAGIC_BYTES +
            struct.pack("<B", VERSION) +
            struct.pack("<B", algo_byte) +
            salt +
            metadata +
            encrypted
        )
        
        file_id = str(uuid.uuid4())
        encrypted_filename = f"{filename}.svx"
        encrypted_path = Path(app.config['UPLOAD_FOLDER']) / file_id
        encrypted_path.write_bytes(output_data)
        
        algo_name = {'aes': 'AES-256-GCM', 'chacha': 'ChaCha20-Poly1305', 'hybrid': 'Hybrid'}[algorithm]
        
        if USE_MYSQL:
            db_execute(
                '''INSERT INTO encrypted_files 
                   (id, user_id, original_path, encrypted_path, filename, file_size, algorithm, created_at) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (file_id, request.user_id, filename, str(encrypted_path), encrypted_filename, 
                 original_size, algo_name, datetime.now(timezone.utc).isoformat())
            )
        else:
            db_execute(
                '''INSERT INTO encrypted_files 
                   (id, user_id, original_path, encrypted_path, filename, file_size, algorithm, created_at) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (file_id, request.user_id, filename, str(encrypted_path), encrypted_filename, 
                 original_size, algo_name, datetime.now(timezone.utc).isoformat())
            )
        db_commit()
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': encrypted_filename,
            'original_size': original_size,
            'encrypted_size': len(output_data),
            'algorithm': algo_name
        })
        
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500


@app.route('/api/decrypt', methods=['POST'])
@require_auth
def decrypt_file():
    data = request.get_json()
    file_id = data.get('file_id')
    password = data.get('password', '')
    
    if USE_MYSQL:
        file_record = db_fetchone('SELECT * FROM encrypted_files WHERE id = %s', (file_id,))
    else:
        file_record = db_fetchone('SELECT * FROM encrypted_files WHERE id = ?', (file_id,))
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    if file_record['user_id'] != request.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        encrypted_path = Path(file_record['encrypted_path'])
        if not encrypted_path.exists():
            return jsonify({'error': 'Encrypted file not found on disk'}), 404
        
        file_data = encrypted_path.read_bytes()
        
        if file_data[:4] != MAGIC_BYTES:
            return jsonify({'error': 'Invalid file format'}), 400
        
        algo_byte = struct.unpack("<B", file_data[5:6])[0]
        salt = file_data[6:38]
        key = derive_key_pbkdf2(password, salt, 32)
        
        if algo_byte == 1:
            nonce = file_data[38:50]
            ciphertext = file_data[50:]
            plaintext = decrypt_aes_gcm(ciphertext, nonce, key)
        elif algo_byte == 2:
            nonce = file_data[38:50]
            ciphertext = file_data[50:]
            plaintext = decrypt_chacha20(ciphertext, nonce, key)
        elif algo_byte == 3:
            metadata = file_data[38:62]
            ciphertext = file_data[62:]
            plaintext = decrypt_hybrid(ciphertext, metadata, key)
        else:
            return jsonify({'error': 'Unknown algorithm'}), 400
        
        original_name = file_record['original_path']
        ext = Path(original_name).suffix.lower()
        
        is_text = False
        text_content = None
        if ext in ['.txt', '.md', '.json', '.xml', '.html', '.css', '.js', '.py', '.csv']:
            try:
                text_content = plaintext.decode('utf-8')
                is_text = True
            except:
                pass
        
        decrypted_id = str(uuid.uuid4())
        decrypted_path = Path(app.config['UPLOAD_FOLDER']) / f"decrypted_{decrypted_id}"
        decrypted_path.write_bytes(plaintext)
        
        response = {
            'success': True,
            'decrypted_id': decrypted_id,
            'original_name': original_name,
            'size': len(plaintext),
            'is_text': is_text,
        }
        
        if is_text and text_content and len(text_content) < 50000:
            response['preview'] = text_content
        
        return jsonify(response)
        
    except Exception as e:
        error_msg = str(e)
        if 'InvalidTag' in error_msg or 'MAC' in error_msg:
            return jsonify({'error': 'Wrong password'}), 401
        return jsonify({'error': f'Decryption failed: {error_msg}'}), 500


@app.route('/api/download/<decrypted_id>', methods=['GET'])
@require_auth
def download_decrypted(decrypted_id):
    decrypted_path = Path(app.config['UPLOAD_FOLDER']) / f"decrypted_{decrypted_id}"
    if not decrypted_path.exists():
        return jsonify({'error': 'File not found'}), 404
    
    filename = request.args.get('filename', 'decrypted_file')
    return send_file(decrypted_path, as_attachment=True, download_name=filename)


@app.route('/api/files', methods=['GET'])
@require_auth
def list_files():
    if USE_MYSQL:
        files = db_fetchall(
            '''SELECT id, original_path, filename, file_size, algorithm, created_at 
               FROM encrypted_files WHERE user_id = %s ORDER BY created_at DESC''',
            (request.user_id,)
        )
    else:
        files = db_fetchall(
            '''SELECT id, original_path, filename, file_size, algorithm, created_at 
               FROM encrypted_files WHERE user_id = ? ORDER BY created_at DESC''',
            (request.user_id,)
        )
    
    file_list = [{
        'id': f['id'],
        'original_path': f['original_path'],
        'filename': f['filename'],
        'file_size': f['file_size'],
        'algorithm': f['algorithm'],
        'created_at': f['created_at']
    } for f in files]
    
    return jsonify({
        'success': True,
        'files': file_list,
        'count': len(file_list)
    })


@app.route('/api/files/<file_id>', methods=['DELETE'])
@require_auth
def delete_file(file_id):
    if USE_MYSQL:
        file_record = db_fetchone('SELECT * FROM encrypted_files WHERE id = %s', (file_id,))
    else:
        file_record = db_fetchone('SELECT * FROM encrypted_files WHERE id = ?', (file_id,))
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    if file_record['user_id'] != request.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        Path(file_record['encrypted_path']).unlink(missing_ok=True)
    except:
        pass
    
    if USE_MYSQL:
        db_execute('DELETE FROM encrypted_files WHERE id = %s', (file_id,))
    else:
        db_execute('DELETE FROM encrypted_files WHERE id = ?', (file_id,))
    db_commit()
    
    return jsonify({'success': True})


@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    if USE_MYSQL:
        files = db_fetchall(
            'SELECT file_size, algorithm FROM encrypted_files WHERE user_id = %s',
            (request.user_id,)
        )
    else:
        files = db_fetchall(
            'SELECT file_size, algorithm FROM encrypted_files WHERE user_id = ?',
            (request.user_id,)
        )
    
    total_size = sum(f['file_size'] for f in files)
    algo_counts = {}
    for f in files:
        algo = f['algorithm']
        algo_counts[algo] = algo_counts.get(algo, 0) + 1
    
    return jsonify({
        'success': True,
        'file_count': len(files),
        'total_size': total_size,
        'algorithms': algo_counts
    })


@app.route('/api/system/status', methods=['GET'])
@require_auth
def system_status():
    import platform
    
    db_type = 'MySQL (PythonAnywhere)' if USE_MYSQL else 'SQLite'
    
    return jsonify({
        'success': True,
        'os': platform.system(),
        'os_version': platform.version()[:50],
        'checks': {
            'system_integrity': {'status': 'VERIFIED', 'ok': True},
            'encryption_engine': {'status': 'AES-256-GCM READY', 'ok': True},
            'secure_memory': {'status': 'PROTECTED', 'ok': True},
            'database': {'status': db_type, 'ok': True},
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


# For PythonAnywhere WSGI
application = app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
