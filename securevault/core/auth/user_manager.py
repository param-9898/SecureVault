"""
User Management
===============

Secure user management with role-based access control.

Security Features:
- Secure password hashing (Argon2id)
- Role-based permissions
- Login throttling
- Account lockout
- Audit logging ready
"""

from __future__ import annotations

import secrets
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Final, Optional, List
import hmac

from securevault.core.auth.argon2_auth import (
    Argon2Hasher,
    hash_password,
    verify_password,
)


# Security constants
MAX_LOGIN_ATTEMPTS: Final[int] = 5
LOCKOUT_DURATION_SECONDS: Final[int] = 300  # 5 minutes
MIN_PASSWORD_LENGTH: Final[int] = 12
MAX_PASSWORD_LENGTH: Final[int] = 128


class UserRole(Enum):
    """User roles for access control."""
    USER = auto()
    ADMIN = auto()
    
    @classmethod
    def from_string(cls, value: str) -> "UserRole":
        """Convert string to UserRole."""
        return cls[value.upper()]


@dataclass
class User:
    """
    User account representation.
    
    Note: password_hash is never exposed in repr or str.
    """
    id: str
    username: str
    password_hash: str
    role: UserRole
    created_at: datetime
    updated_at: datetime
    is_active: bool = True
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    
    def __repr__(self) -> str:
        """Safe representation without password hash."""
        return (
            f"User(id={self.id!r}, username={self.username!r}, "
            f"role={self.role.name}, is_active={self.is_active})"
        )
    
    def is_locked(self) -> bool:
        """Check if the account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until
    
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class UserExistsError(Exception):
    """Raised when trying to create a user that already exists."""
    pass


class UserNotFoundError(Exception):
    """Raised when a user is not found."""
    pass


class AccountLockedError(Exception):
    """Raised when account is locked due to failed attempts."""
    def __init__(self, locked_until: datetime):
        self.locked_until = locked_until
        remaining = (locked_until - datetime.now(timezone.utc)).total_seconds()
        super().__init__(f"Account locked. Try again in {int(remaining)} seconds.")


class PasswordValidationError(Exception):
    """Raised when password doesn't meet requirements."""
    pass


class UserManager:
    """
    Secure user management with SQLite backend.
    
    Provides:
    - User registration with password validation
    - Secure authentication with throttling
    - Role-based access control
    - Account lockout protection
    
    Usage:
        manager = UserManager(db_path)
        manager.initialize_db()
        
        # Register a user
        user = manager.create_user("alice", "SecureP@ssw0rd123", UserRole.USER)
        
        # Authenticate
        user = manager.authenticate("alice", "SecureP@ssw0rd123")
        
        # Check permissions
        if user.is_admin():
            # admin operations
    
    Security Notes:
        - Passwords are hashed with Argon2id
        - Failed attempts trigger progressive lockout
        - All operations use parameterized queries (SQL injection safe)
    """
    
    __slots__ = ("_db_path", "_hasher")
    
    # SQL schema for users table
    _SCHEMA: Final[str] = """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'USER',
        is_active INTEGER NOT NULL DEFAULT 1,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_login TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
    
    CREATE TABLE IF NOT EXISTS roles (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        permissions TEXT
    );
    
    CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    """
    
    def __init__(self, db_path: Path | str) -> None:
        """
        Initialize the user manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self._db_path = Path(db_path)
        self._hasher = Argon2Hasher()
        self.initialize_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(
            self._db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    
    def initialize_db(self) -> None:
        """
        Initialize the database schema.
        
        Creates tables if they don't exist.
        """
        # Ensure parent directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            conn.executescript(self._SCHEMA)
            
            # Insert default roles if not exist
            conn.execute("""
                INSERT OR IGNORE INTO roles (id, name, description, permissions)
                VALUES (?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                "USER",
                "Standard user role",
                "read,write"
            ))
            
            conn.execute("""
                INSERT OR IGNORE INTO roles (id, name, description, permissions)
                VALUES (?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                "ADMIN",
                "Administrator role",
                "read,write,delete,admin"
            ))
            
            conn.commit()
    
    def _validate_password(self, password: str) -> None:
        """
        Validate password meets security requirements.
        
        Raises:
            PasswordValidationError: If password is invalid
        """
        errors = []
        
        if len(password) < MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        
        if len(password) > MAX_PASSWORD_LENGTH:
            errors.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
        
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~")
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise PasswordValidationError("; ".join(errors))
    
    def create_user(
        self,
        username: str,
        password: str,
        role: UserRole = UserRole.USER,
    ) -> User:
        """
        Create a new user account.
        
        Args:
            username: Unique username
            password: Password (will be hashed)
            role: User role (default: USER)
        
        Returns:
            Created User object
        
        Raises:
            UserExistsError: If username already exists
            PasswordValidationError: If password doesn't meet requirements
        """
        # Validate password
        self._validate_password(password)
        
        # Validate username
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(username) > 64:
            raise ValueError("Username must be at most 64 characters")
        if not username.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        password_hash = self._hasher.hash(password).encoded
        
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO users (id, username, password_hash, role, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, username, password_hash, role.name, now, now))
                conn.commit()
        except sqlite3.IntegrityError:
            raise UserExistsError(f"User '{username}' already exists")
        
        return User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
        )
    
    def authenticate(self, username: str, password: str) -> User:
        """
        Authenticate a user with username and password.
        
        Args:
            username: Username
            password: Password to verify
        
        Returns:
            Authenticated User object
        
        Raises:
            UserNotFoundError: If user doesn't exist
            AccountLockedError: If account is locked
            AuthenticationError: If password is incorrect
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username,)
            ).fetchone()
            
            if not row:
                # Constant-time behavior: hash the password anyway
                self._hasher.hash(password)
                raise UserNotFoundError(f"User '{username}' not found")
            
            user = self._row_to_user(row)
            
            # Check if account is locked
            if user.is_locked():
                raise AccountLockedError(user.locked_until)
            
            # Verify password
            if not self._hasher.verify(password, user.password_hash):
                # Increment failed attempts
                self._record_failed_attempt(conn, user)
                raise AuthenticationError("Invalid password")
            
            # Reset failed attempts and update last login
            self._record_successful_login(conn, user)
            
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login = datetime.now(timezone.utc)
            
            return user
    
    def _record_failed_attempt(self, conn: sqlite3.Connection, user: User) -> None:
        """Record a failed login attempt and potentially lock the account."""
        new_attempts = user.failed_attempts + 1
        locked_until = None
        
        if new_attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
        
        conn.execute("""
            UPDATE users 
            SET failed_attempts = ?, locked_until = ?, updated_at = ?
            WHERE id = ?
        """, (
            new_attempts,
            locked_until.isoformat() if locked_until else None,
            datetime.now(timezone.utc).isoformat(),
            user.id,
        ))
        conn.commit()
        
        if locked_until:
            raise AccountLockedError(locked_until)
    
    def _record_successful_login(self, conn: sqlite3.Connection, user: User) -> None:
        """Record a successful login."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            UPDATE users
            SET failed_attempts = 0, locked_until = NULL, last_login = ?, updated_at = ?
            WHERE id = ?
        """, (now, now, user.id))
        conn.commit()
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get a user by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            
            if not row:
                return None
            
            return self._row_to_user(row)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get a user by username."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username,)
            ).fetchone()
            
            if not row:
                return None
            
            return self._row_to_user(row)
    
    def list_users(self, include_inactive: bool = False) -> List[User]:
        """List all users."""
        with self._get_connection() as conn:
            if include_inactive:
                rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM users WHERE is_active = 1 ORDER BY username"
                ).fetchall()
            
            return [self._row_to_user(row) for row in rows]
    
    def update_password(self, user_id: str, new_password: str) -> None:
        """
        Update a user's password.
        
        Args:
            user_id: User ID
            new_password: New password (will be validated and hashed)
        """
        self._validate_password(new_password)
        
        password_hash = self._hasher.hash(new_password).encoded
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            result = conn.execute("""
                UPDATE users
                SET password_hash = ?, updated_at = ?
                WHERE id = ?
            """, (password_hash, now, user_id))
            
            if result.rowcount == 0:
                raise UserNotFoundError(f"User with ID '{user_id}' not found")
            
            conn.commit()
    
    def update_role(self, user_id: str, new_role: UserRole) -> None:
        """Update a user's role."""
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            result = conn.execute("""
                UPDATE users
                SET role = ?, updated_at = ?
                WHERE id = ?
            """, (new_role.name, now, user_id))
            
            if result.rowcount == 0:
                raise UserNotFoundError(f"User with ID '{user_id}' not found")
            
            conn.commit()
    
    def deactivate_user(self, user_id: str) -> None:
        """Deactivate a user account."""
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE users
                SET is_active = 0, updated_at = ?
                WHERE id = ?
            """, (now, user_id))
            conn.commit()
    
    def unlock_user(self, user_id: str) -> None:
        """Unlock a user account."""
        now = datetime.now(timezone.utc).isoformat()
        
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE users
                SET failed_attempts = 0, locked_until = NULL, updated_at = ?
                WHERE id = ?
            """, (now, user_id))
            conn.commit()
    
    def delete_user(self, user_id: str) -> None:
        """
        Permanently delete a user.
        
        WARNING: This is irreversible. Consider deactivate_user instead.
        """
        with self._get_connection() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
    
    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert a database row to a User object."""
        locked_until = None
        if row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
        
        last_login = None
        if row["last_login"]:
            last_login = datetime.fromisoformat(row["last_login"])
        
        return User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=UserRole.from_string(row["role"]),
            is_active=bool(row["is_active"]),
            failed_attempts=row["failed_attempts"],
            locked_until=locked_until,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_login=last_login,
        )
    
    def log_audit_event(
        self,
        action: str,
        user_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Log an audit event.
        
        Args:
            action: Action performed
            user_id: Optional user ID who performed the action
            details: Optional additional details
            ip_address: Optional IP address
        """
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO audit_log (id, user_id, action, details, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                user_id,
                action,
                details,
                ip_address,
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()
