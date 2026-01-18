"""
Session Control
================

Secure session management with automatic expiration.

Security Features:
- Cryptographically random session tokens
- Automatic session expiration
- Session invalidation
- Concurrent session limits
- Activity tracking
"""

from __future__ import annotations

import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Final, Optional, List
import hmac
import hashlib

from securevault.core.auth.user_manager import User, UserRole


# Session configuration
SESSION_TOKEN_LENGTH: Final[int] = 64  # bytes
DEFAULT_SESSION_TIMEOUT: Final[int] = 900  # 15 minutes
MAX_SESSIONS_PER_USER: Final[int] = 5
SESSION_EXTEND_THRESHOLD: Final[int] = 300  # Extend if less than 5 min left


@dataclass
class Session:
    """
    User session representation.
    
    A session represents an authenticated user's active login.
    Sessions expire after a period of inactivity.
    """
    id: str
    user_id: str
    token_hash: str  # We only store hash, never the actual token
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True
    
    def __repr__(self) -> str:
        """Safe representation without token."""
        return (
            f"Session(id={self.id!r}, user_id={self.user_id!r}, "
            f"expires_at={self.expires_at.isoformat()})"
        )
    
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the session is valid (active and not expired)."""
        return self.is_active and not self.is_expired()


class SessionError(Exception):
    """Base exception for session errors."""
    pass


class SessionExpiredError(SessionError):
    """Raised when a session has expired."""
    pass


class SessionInvalidError(SessionError):
    """Raised when a session token is invalid."""
    pass


class SessionLimitError(SessionError):
    """Raised when user has too many active sessions."""
    pass


class SessionManager:
    """
    Secure session management with SQLite backend.
    
    Provides:
    - Secure session token generation
    - Session creation and validation
    - Automatic expiration
    - Session cleanup
    - Activity tracking
    
    Usage:
        manager = SessionManager(db_path)
        manager.initialize_db()
        
        # Create a session after successful authentication
        token = manager.create_session(user)
        
        # Validate a session token
        session = manager.validate_session(token)
        
        # End a session (logout)
        manager.invalidate_session(token)
    
    Security Notes:
        - Tokens are cryptographically random (256 bits entropy)
        - Only token hashes are stored (tokens never hit disk)
        - Sessions automatically expire
        - Old sessions are cleaned up periodically
    """
    
    __slots__ = ("_db_path", "_timeout_seconds")
    
    _SCHEMA: Final[str] = """
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_activity TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    """
    
    def __init__(
        self,
        db_path: Path | str,
        timeout_seconds: int = DEFAULT_SESSION_TIMEOUT,
    ) -> None:
        """
        Initialize the session manager.
        
        Args:
            db_path: Path to SQLite database
            timeout_seconds: Session timeout in seconds (default: 15 min)
        """
        self._db_path = Path(db_path)
        self._timeout_seconds = timeout_seconds
        self.initialize_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(
            self._db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    
    def initialize_db(self) -> None:
        """Initialize the database schema."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            conn.executescript(self._SCHEMA)
            conn.commit()
    
    @staticmethod
    def _generate_token() -> str:
        """Generate a cryptographically secure session token."""
        return secrets.token_urlsafe(SESSION_TOKEN_LENGTH)
    
    @staticmethod
    def _hash_token(token: str) -> str:
        """
        Hash a session token for storage.
        
        We use SHA-256 for fast lookups while still preventing
        token recovery from the database.
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    def create_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """
        Create a new session for a user.
        
        Args:
            user: The authenticated user
            ip_address: Optional client IP address
            user_agent: Optional client user agent
        
        Returns:
            Session token (caller must securely store/transmit this)
        
        Raises:
            SessionLimitError: If user has too many active sessions
        """
        with self._get_connection() as conn:
            # Check session limit
            active_count = conn.execute("""
                SELECT COUNT(*) FROM sessions
                WHERE user_id = ? AND is_active = 1 AND expires_at > ?
            """, (user.id, datetime.now(timezone.utc).isoformat())).fetchone()[0]
            
            if active_count >= MAX_SESSIONS_PER_USER:
                # Invalidate oldest session
                conn.execute("""
                    UPDATE sessions
                    SET is_active = 0
                    WHERE id = (
                        SELECT id FROM sessions
                        WHERE user_id = ? AND is_active = 1
                        ORDER BY created_at ASC
                        LIMIT 1
                    )
                """, (user.id,))
            
            # Generate token
            token = self._generate_token()
            token_hash = self._hash_token(token)
            
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=self._timeout_seconds)
            
            session_id = str(uuid.uuid4())
            
            conn.execute("""
                INSERT INTO sessions (
                    id, user_id, token_hash, created_at, expires_at,
                    last_activity, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                user.id,
                token_hash,
                now.isoformat(),
                expires_at.isoformat(),
                now.isoformat(),
                ip_address,
                user_agent,
            ))
            conn.commit()
            
            return token
    
    def validate_session(
        self,
        token: str,
        extend: bool = True,
    ) -> Session:
        """
        Validate a session token and optionally extend its lifetime.
        
        Args:
            token: The session token to validate
            extend: Whether to extend the session on successful validation
        
        Returns:
            Valid Session object
        
        Raises:
            SessionInvalidError: If token is invalid
            SessionExpiredError: If session has expired
        """
        token_hash = self._hash_token(token)
        
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM sessions WHERE token_hash = ?
            """, (token_hash,)).fetchone()
            
            if not row:
                raise SessionInvalidError("Invalid session token")
            
            session = self._row_to_session(row)
            
            if not session.is_active:
                raise SessionInvalidError("Session has been invalidated")
            
            if session.is_expired():
                # Mark as inactive
                conn.execute("""
                    UPDATE sessions SET is_active = 0 WHERE id = ?
                """, (session.id,))
                conn.commit()
                raise SessionExpiredError("Session has expired")
            
            # Extend session if needed
            if extend:
                self._extend_session(conn, session)
            
            return session
    
    def _extend_session(self, conn: sqlite3.Connection, session: Session) -> None:
        """Extend a session's expiration time on activity."""
        now = datetime.now(timezone.utc)
        remaining = (session.expires_at - now).total_seconds()
        
        # Only extend if less than threshold remaining
        if remaining < SESSION_EXTEND_THRESHOLD:
            new_expires = now + timedelta(seconds=self._timeout_seconds)
            conn.execute("""
                UPDATE sessions
                SET expires_at = ?, last_activity = ?
                WHERE id = ?
            """, (new_expires.isoformat(), now.isoformat(), session.id))
        else:
            conn.execute("""
                UPDATE sessions SET last_activity = ? WHERE id = ?
            """, (now.isoformat(), session.id))
        
        conn.commit()
    
    def invalidate_session(self, token: str) -> None:
        """
        Invalidate a session (logout).
        
        Args:
            token: The session token to invalidate
        """
        token_hash = self._hash_token(token)
        
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE sessions SET is_active = 0 WHERE token_hash = ?
            """, (token_hash,))
            conn.commit()
    
    def invalidate_all_sessions(self, user_id: str) -> int:
        """
        Invalidate all sessions for a user (logout everywhere).
        
        Args:
            user_id: The user ID
        
        Returns:
            Number of sessions invalidated
        """
        with self._get_connection() as conn:
            result = conn.execute("""
                UPDATE sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1
            """, (user_id,))
            conn.commit()
            return result.rowcount
    
    def get_user_sessions(self, user_id: str, active_only: bool = True) -> List[Session]:
        """
        Get all sessions for a user.
        
        Args:
            user_id: The user ID
            active_only: Only return active, non-expired sessions
        
        Returns:
            List of Session objects
        """
        with self._get_connection() as conn:
            if active_only:
                now = datetime.now(timezone.utc).isoformat()
                rows = conn.execute("""
                    SELECT * FROM sessions
                    WHERE user_id = ? AND is_active = 1 AND expires_at > ?
                    ORDER BY last_activity DESC
                """, (user_id, now)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM sessions
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,)).fetchall()
            
            return [self._row_to_session(row) for row in rows]
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions from the database.
        
        Returns:
            Number of sessions cleaned up
        """
        with self._get_connection() as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            # First, mark expired sessions as inactive
            conn.execute("""
                UPDATE sessions SET is_active = 0
                WHERE is_active = 1 AND expires_at < ?
            """, (now,))
            
            # Delete sessions older than 30 days
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            result = conn.execute("""
                DELETE FROM sessions WHERE expires_at < ?
            """, (cutoff,))
            
            conn.commit()
            return result.rowcount
    
    def get_session_by_id(self, session_id: str) -> Optional[Session]:
        """Get a session by its ID."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM sessions WHERE id = ?
            """, (session_id,)).fetchone()
            
            if not row:
                return None
            
            return self._row_to_session(row)
    
    def _row_to_session(self, row: sqlite3.Row) -> Session:
        """Convert a database row to a Session object."""
        return Session(
            id=row["id"],
            user_id=row["user_id"],
            token_hash=row["token_hash"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            last_activity=datetime.fromisoformat(row["last_activity"]),
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
            is_active=bool(row["is_active"]),
        )
    
    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks."""
        return hmac.compare_digest(a.encode(), b.encode())
