"""
Device Lock System
==================

Enforces device binding by verifying hardware fingerprint on every operation.

Security Properties:
- Hard failure on device mismatch (no bypass)
- Only fingerprint hashes stored
- Integration with auth layer
- Optional multi-device support with explicit registration

Usage Pattern:
1. On first setup: Register device fingerprint
2. On every decrypt: Verify current fingerprint matches
3. On mismatch: Hard failure, no data access

WARNING:
- Device changes (hardware upgrades) will block access
- Provide administrator recovery mechanisms
- VMs may have unstable fingerprints
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Optional, List

from securevault.core.device.hardware_fingerprint import (
    HardwareFingerprintCollector,
    HardwareFingerprint,
    FingerprintSource,
    DEFAULT_FINGERPRINT_SALT,
    MIN_FINGERPRINT_SOURCES,
)


# Device lock configuration
MAX_REGISTERED_DEVICES: Final[int] = 3
DEVICE_LOCK_ENABLED: Final[bool] = True


class DeviceMismatchError(Exception):
    """
    Raised when current device doesn't match registered device.
    
    This is a HARD FAILURE - no bypass is allowed.
    """
    def __init__(self, message: str = "Device fingerprint mismatch"):
        super().__init__(message)


class DeviceNotRegisteredError(Exception):
    """Raised when no device is registered for the user."""
    pass


class DeviceLimitExceededError(Exception):
    """Raised when user has too many registered devices."""
    pass


@dataclass
class RegisteredDevice:
    """
    Represents a registered device for a user.
    
    Note: fingerprint_hash is the only stored identifier.
    """
    id: str
    user_id: str
    fingerprint_hash: str
    device_name: str
    registered_at: datetime
    last_verified_at: Optional[datetime]
    is_active: bool = True
    
    def __repr__(self) -> str:
        """Safe representation."""
        return (
            f"RegisteredDevice(id={self.id!r}, name={self.device_name!r}, "
            f"active={self.is_active})"
        )


class DeviceLock:
    """
    Device binding and verification system.
    
    Provides:
    - Device registration (hash-only storage)
    - Device verification on every sensitive operation
    - Hard failure on mismatch
    - Multi-device support with limits
    
    Usage:
        lock = DeviceLock(db_path)
        lock.initialize_db()
        
        # Register current device
        lock.register_device(user_id, "My Laptop")
        
        # Verify before every decrypt
        try:
            lock.verify_device(user_id)
        except DeviceMismatchError:
            # HARD FAILURE - abort operation
            raise
    
    Security Notes:
        - NEVER bypass verification failures
        - Only hashes are stored, never raw hardware IDs
        - Verification is mandatory before any crypto operation
    """
    
    __slots__ = ("_db_path", "_collector", "_enabled")
    
    _SCHEMA: Final[str] = """
    CREATE TABLE IF NOT EXISTS registered_devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        fingerprint_hash TEXT NOT NULL,
        device_name TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        last_verified_at TEXT,
        is_active INTEGER NOT NULL DEFAULT 1
    );
    
    CREATE INDEX IF NOT EXISTS idx_devices_user ON registered_devices(user_id);
    CREATE INDEX IF NOT EXISTS idx_devices_hash ON registered_devices(fingerprint_hash);
    
    CREATE TABLE IF NOT EXISTS device_verification_log (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        user_id TEXT NOT NULL,
        success INTEGER NOT NULL,
        fingerprint_hash TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    
    CREATE INDEX IF NOT EXISTS idx_verify_log_user ON device_verification_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_verify_log_time ON device_verification_log(timestamp);
    """
    
    def __init__(
        self,
        db_path: Path | str,
        salt: bytes = DEFAULT_FINGERPRINT_SALT,
        enabled: bool = DEVICE_LOCK_ENABLED,
    ) -> None:
        """
        Initialize the device lock system.
        
        Args:
            db_path: Path to SQLite database
            salt: Salt for fingerprint hashing
            enabled: Whether device locking is enforced
        """
        self._db_path = Path(db_path)
        self._collector = HardwareFingerprintCollector(salt=salt)
        self._enabled = enabled
    
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
    
    @property
    def is_enabled(self) -> bool:
        """Check if device locking is enabled."""
        return self._enabled
    
    def get_current_fingerprint(self) -> HardwareFingerprint:
        """
        Get the current device's fingerprint.
        
        Returns:
            HardwareFingerprint for this device
        """
        return self._collector.collect()
    
    def register_device(
        self,
        user_id: str,
        device_name: str,
        fingerprint: Optional[HardwareFingerprint] = None,
    ) -> RegisteredDevice:
        """
        Register the current device for a user.
        
        Args:
            user_id: The user ID to register device for
            device_name: Human-readable device name
            fingerprint: Optional pre-collected fingerprint
        
        Returns:
            RegisteredDevice record
        
        Raises:
            DeviceLimitExceededError: If user has too many devices
        """
        if fingerprint is None:
            fingerprint = self._collector.collect()
        
        with self._get_connection() as conn:
            # Check device limit
            active_count = conn.execute("""
                SELECT COUNT(*) FROM registered_devices
                WHERE user_id = ? AND is_active = 1
            """, (user_id,)).fetchone()[0]
            
            if active_count >= MAX_REGISTERED_DEVICES:
                raise DeviceLimitExceededError(
                    f"Maximum of {MAX_REGISTERED_DEVICES} devices allowed"
                )
            
            # Check if device already registered
            existing = conn.execute("""
                SELECT id FROM registered_devices
                WHERE user_id = ? AND fingerprint_hash = ? AND is_active = 1
            """, (user_id, fingerprint.fingerprint_hash)).fetchone()
            
            if existing:
                # Update existing device
                now = datetime.now(timezone.utc).isoformat()
                conn.execute("""
                    UPDATE registered_devices
                    SET device_name = ?, last_verified_at = ?
                    WHERE id = ?
                """, (device_name, now, existing["id"]))
                conn.commit()
                
                return self._get_device_by_id(existing["id"])
            
            # Register new device
            device_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT INTO registered_devices
                (id, user_id, fingerprint_hash, device_name, registered_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                device_id,
                user_id,
                fingerprint.fingerprint_hash,
                device_name,
                now,
            ))
            conn.commit()
            
            return RegisteredDevice(
                id=device_id,
                user_id=user_id,
                fingerprint_hash=fingerprint.fingerprint_hash,
                device_name=device_name,
                registered_at=datetime.fromisoformat(now),
                last_verified_at=None,
            )
    
    def verify_device(
        self,
        user_id: str,
        fingerprint: Optional[HardwareFingerprint] = None,
    ) -> RegisteredDevice:
        """
        Verify the current device matches a registered device.
        
        THIS IS THE CRITICAL SECURITY FUNCTION.
        
        Args:
            user_id: The user ID to verify for
            fingerprint: Optional pre-collected fingerprint
        
        Returns:
            Matching RegisteredDevice if verified
        
        Raises:
            DeviceNotRegisteredError: If user has no registered devices
            DeviceMismatchError: If current device doesn't match (HARD FAILURE)
        """
        if not self._enabled:
            # If disabled, return a dummy device
            # This should only be used for testing/development
            import warnings
            warnings.warn(
                "Device lock is DISABLED. This is insecure!",
                SecurityWarning,
                stacklevel=2,
            )
            return RegisteredDevice(
                id="disabled",
                user_id=user_id,
                fingerprint_hash="",
                device_name="(Device lock disabled)",
                registered_at=datetime.now(timezone.utc),
                last_verified_at=datetime.now(timezone.utc),
            )
        
        if fingerprint is None:
            fingerprint = self._collector.collect()
        
        with self._get_connection() as conn:
            # Get all registered devices for user
            devices = conn.execute("""
                SELECT * FROM registered_devices
                WHERE user_id = ? AND is_active = 1
            """, (user_id,)).fetchall()
            
            if not devices:
                self._log_verification(conn, None, user_id, False, fingerprint)
                raise DeviceNotRegisteredError(
                    f"No devices registered for user {user_id}"
                )
            
            # Check against each registered device
            for device_row in devices:
                stored_hash = device_row["fingerprint_hash"]
                
                # Constant-time comparison
                if hmac.compare_digest(
                    fingerprint.fingerprint_hash.encode(),
                    stored_hash.encode()
                ):
                    # Match found - update last verified
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute("""
                        UPDATE registered_devices
                        SET last_verified_at = ?
                        WHERE id = ?
                    """, (now, device_row["id"]))
                    
                    self._log_verification(
                        conn, device_row["id"], user_id, True, fingerprint
                    )
                    conn.commit()
                    
                    return self._row_to_device(device_row)
            
            # NO MATCH - HARD FAILURE
            self._log_verification(conn, None, user_id, False, fingerprint)
            conn.commit()
            
            raise DeviceMismatchError(
                "Current device fingerprint does not match any registered device. "
                "Access denied."
            )
    
    def _log_verification(
        self,
        conn: sqlite3.Connection,
        device_id: Optional[str],
        user_id: str,
        success: bool,
        fingerprint: HardwareFingerprint,
    ) -> None:
        """Log a device verification attempt."""
        conn.execute("""
            INSERT INTO device_verification_log
            (id, device_id, user_id, success, fingerprint_hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            device_id,
            user_id,
            1 if success else 0,
            fingerprint.fingerprint_hash,
            datetime.now(timezone.utc).isoformat(),
        ))
    
    def get_user_devices(self, user_id: str, active_only: bool = True) -> List[RegisteredDevice]:
        """
        Get all registered devices for a user.
        
        Args:
            user_id: The user ID
            active_only: Only return active devices
        
        Returns:
            List of RegisteredDevice objects
        """
        with self._get_connection() as conn:
            if active_only:
                rows = conn.execute("""
                    SELECT * FROM registered_devices
                    WHERE user_id = ? AND is_active = 1
                    ORDER BY registered_at DESC
                """, (user_id,)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM registered_devices
                    WHERE user_id = ?
                    ORDER BY registered_at DESC
                """, (user_id,)).fetchall()
            
            return [self._row_to_device(row) for row in rows]
    
    def deactivate_device(self, device_id: str) -> None:
        """
        Deactivate a registered device.
        
        Args:
            device_id: The device ID to deactivate
        """
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE registered_devices
                SET is_active = 0
                WHERE id = ?
            """, (device_id,))
            conn.commit()
    
    def deactivate_all_devices(self, user_id: str) -> int:
        """
        Deactivate all devices for a user.
        
        Args:
            user_id: The user ID
        
        Returns:
            Number of devices deactivated
        """
        with self._get_connection() as conn:
            result = conn.execute("""
                UPDATE registered_devices
                SET is_active = 0
                WHERE user_id = ? AND is_active = 1
            """, (user_id,))
            conn.commit()
            return result.rowcount
    
    def is_device_registered(
        self,
        user_id: str,
        fingerprint: Optional[HardwareFingerprint] = None,
    ) -> bool:
        """
        Check if current device is registered (without raising on mismatch).
        
        Args:
            user_id: The user ID
            fingerprint: Optional pre-collected fingerprint
        
        Returns:
            True if device is registered, False otherwise
        """
        if fingerprint is None:
            try:
                fingerprint = self._collector.collect()
            except RuntimeError:
                return False
        
        with self._get_connection() as conn:
            result = conn.execute("""
                SELECT 1 FROM registered_devices
                WHERE user_id = ? AND fingerprint_hash = ? AND is_active = 1
            """, (user_id, fingerprint.fingerprint_hash)).fetchone()
            
            return result is not None
    
    def _get_device_by_id(self, device_id: str) -> Optional[RegisteredDevice]:
        """Get a device by its ID."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM registered_devices WHERE id = ?
            """, (device_id,)).fetchone()
            
            if not row:
                return None
            
            return self._row_to_device(row)
    
    def _row_to_device(self, row: sqlite3.Row) -> RegisteredDevice:
        """Convert a database row to RegisteredDevice."""
        last_verified = None
        if row["last_verified_at"]:
            last_verified = datetime.fromisoformat(row["last_verified_at"])
        
        return RegisteredDevice(
            id=row["id"],
            user_id=row["user_id"],
            fingerprint_hash=row["fingerprint_hash"],
            device_name=row["device_name"],
            registered_at=datetime.fromisoformat(row["registered_at"]),
            last_verified_at=last_verified,
            is_active=bool(row["is_active"]),
        )
    
    def get_verification_history(
        self,
        user_id: str,
        limit: int = 100,
    ) -> List[dict]:
        """
        Get verification history for a user.
        
        Args:
            user_id: The user ID
            limit: Maximum records to return
        
        Returns:
            List of verification records
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM device_verification_log
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (user_id, limit)).fetchall()
            
            return [
                {
                    "id": row["id"],
                    "device_id": row["device_id"],
                    "success": bool(row["success"]),
                    "timestamp": datetime.fromisoformat(row["timestamp"]),
                }
                for row in rows
            ]


class SecurityWarning(UserWarning):
    """Warning for security-related concerns."""
    pass
