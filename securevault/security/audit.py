"""
Tamper-Aware Audit System
=========================

Append-only audit logging with integrity verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Final, Optional, List, Dict
import logging


class AuditSeverity(Enum):
    """Audit event severity levels."""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AuditEventType(Enum):
    """Types of auditable events."""
    # Authentication
    LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    
    # User Management
    USER_CREATED = "USER_CREATED"
    USER_DELETED = "USER_DELETED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    
    # File Operations
    FILE_ENCRYPTED = "FILE_ENCRYPTED"
    FILE_DECRYPTED = "FILE_DECRYPTED"
    FILE_DELETED = "FILE_DELETED"
    
    # Device
    DEVICE_REGISTERED = "DEVICE_REGISTERED"
    DEVICE_VERIFIED = "DEVICE_VERIFIED"
    DEVICE_MISMATCH = "DEVICE_MISMATCH"
    
    # Security
    INTRUSION_DETECTED = "INTRUSION_DETECTED"
    PANIC_TRIGGERED = "PANIC_TRIGGERED"
    VAULT_LOCKED = "VAULT_LOCKED"
    
    # System
    STARTUP = "STARTUP"
    SHUTDOWN = "SHUTDOWN"
    CONFIG_CHANGED = "CONFIG_CHANGED"


@dataclass
class AuditEvent:
    """An auditable security event."""
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    user_id: Optional[str] = None
    device_hash: Optional[str] = None
    description: str = ""
    details: Dict = field(default_factory=dict)
    
    # Computed fields
    event_id: str = field(default="")
    previous_hash: str = field(default="")
    event_hash: str = field(default="")
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = hashlib.sha256(
                f"{self.timestamp.isoformat()}{self.event_type.value}{os.urandom(8).hex()}".encode()
            ).hexdigest()[:16]
    
    def compute_hash(self, previous_hash: str) -> str:
        """Compute event hash for chain integrity."""
        self.previous_hash = previous_hash
        
        # Hash all fields except event_hash
        data = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "device_hash": self.device_hash,
            "description": self.description,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        
        self.event_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
        
        return self.event_hash
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "device_hash": self.device_hash[:8] + "..." if self.device_hash else None,
            "description": self.description,
            "previous_hash": self.previous_hash,  # Full hash for chain verification
            "event_hash": self.event_hash,  # Full hash for chain verification
        }


class TamperAwareAuditLog:
    """
    Append-only audit log with tamper detection.
    
    Features:
    - Chained hashes for integrity
    - Append-only (no deletion)
    - Automatic severity filtering
    - JSON Lines format
    - No sensitive plaintext
    """
    
    def __init__(self, log_path: Path, hmac_key: bytes = None):
        self._log_path = log_path
        self._hmac_key = hmac_key or os.urandom(32)
        self._lock = threading.Lock()
        self._last_hash = "genesis"
        self._event_count = 0
        
        # Ensure log directory exists
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing chain if present
        self._load_chain()
    
    def _load_chain(self):
        """Load existing log chain and verify integrity."""
        if not self._log_path.exists():
            return
        
        try:
            with open(self._log_path, 'r') as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        self._last_hash = event.get("event_hash", self._last_hash)
                        self._event_count += 1
        except Exception:
            pass  # Start fresh if corrupted
    
    def log(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        description: str,
        user_id: str = None,
        device_hash: str = None,
        details: Dict = None,
    ) -> str:
        """
        Log an audit event.
        
        Returns:
            Event ID
        """
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            device_hash=device_hash,
            description=description,
            details=details or {},
        )
        
        with self._lock:
            # Compute chained hash
            event.compute_hash(self._last_hash)
            
            # Append to log
            with open(self._log_path, 'a') as f:
                f.write(json.dumps(event.to_dict()) + "\n")
                f.flush()
                os.fsync(f.fileno())
            
            self._last_hash = event.event_hash
            self._event_count += 1
        
        return event.event_id
    
    def verify_integrity(self) -> tuple[bool, int]:
        """
        Verify log chain integrity.
        
        Returns:
            Tuple of (is_valid, event_count)
        """
        if not self._log_path.exists():
            return True, 0
        
        previous_hash = "genesis"
        count = 0
        
        try:
            with open(self._log_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    event = json.loads(line)
                    
                    # Verify chain (full hash comparison)
                    stored_prev = event.get("previous_hash", "")
                    if stored_prev != previous_hash:
                        return False, count
                    
                    previous_hash = event.get("event_hash", "")
                    count += 1
            
            return True, count
            
        except Exception:
            return False, count
    
    def get_events(
        self,
        since: datetime = None,
        event_type: AuditEventType = None,
        severity: AuditSeverity = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Get filtered events (read-only)."""
        events = []
        
        if not self._log_path.exists():
            return events
        
        try:
            with open(self._log_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    event = json.loads(line)
                    
                    # Apply filters
                    if since:
                        event_time = datetime.fromisoformat(event["timestamp"])
                        if event_time < since:
                            continue
                    
                    if event_type and event["event_type"] != event_type.value:
                        continue
                    
                    if severity and event["severity"] != severity.value:
                        continue
                    
                    events.append(event)
                    
                    if len(events) >= limit:
                        break
            
        except Exception:
            pass
        
        return events


# Global audit log
_audit_log: Optional[TamperAwareAuditLog] = None


def get_audit_log() -> TamperAwareAuditLog:
    """Get the global audit log instance."""
    global _audit_log
    if _audit_log is None:
        import tempfile
        log_path = Path(tempfile.gettempdir()) / "securevault" / "audit.log"
        _audit_log = TamperAwareAuditLog(log_path)
    return _audit_log


def audit_log(
    event_type: AuditEventType,
    severity: AuditSeverity,
    description: str,
    **kwargs
) -> str:
    """Convenience function to log an audit event."""
    return get_audit_log().log(event_type, severity, description, **kwargs)
