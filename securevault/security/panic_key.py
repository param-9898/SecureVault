"""
Panic Key System
================

Provides emergency vault lock via keyboard or programmatic trigger.

Features:
- Configurable hotkey combinations
- Signal-based triggering
- Programmatic API
- Response actions: wipe memory, lock vault, secure shutdown

Usage:
    panic_system = PanicKeySystem()
    panic_system.register_hotkey(['Ctrl', 'Shift', 'Delete'])
    panic_system.start()
    
    # On panic (hotkey or programmatic):
    #   1. All memory wiped
    #   2. Vault locked
    #   3. Audit log written
    #   4. Optional: application exit

Security Notes:
    - Panic is IRREVERSIBLE
    - All sensitive data is wiped
    - Designed for emergency situations
"""

from __future__ import annotations

import atexit
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Final, Optional, Callable, List, Set


class PanicReason(Enum):
    """Reason for panic trigger."""
    HOTKEY = auto()
    SIGNAL = auto()
    PROGRAMMATIC = auto()
    IDS_THREAT = auto()
    TIMEOUT = auto()
    USER_REQUEST = auto()


@dataclass
class PanicEvent:
    """Records a panic event."""
    reason: PanicReason
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "reason": self.reason.name,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


class PanicKeySystem:
    """
    Emergency panic key system.
    
    Provides multiple ways to trigger emergency vault lock:
    1. Keyboard hotkey (requires GUI or keyboard hook)
    2. Unix signals (SIGUSR1, SIGTERM)
    3. Programmatic trigger
    
    Response Actions:
    1. Wipe all sensitive memory
    2. Lock the vault
    3. Write audit log
    4. Optional: terminate application
    
    Usage:
        panic = PanicKeySystem()
        
        # Add response callbacks
        panic.on_panic(close_ui)
        panic.on_panic(notify_admin)
        
        # Install signal handlers
        panic.install_signal_handlers()
        
        # Start hotkey monitoring (if available)
        panic.start()
        
        # Manual trigger
        panic.trigger(PanicReason.USER_REQUEST)
    """
    
    __slots__ = (
        "_callbacks", "_triggered", "_exit_on_panic",
        "_log", "_events", "_lock", "_hotkey_thread",
        "_running", "_hotkey_combo",
    )
    
    def __init__(
        self,
        exit_on_panic: bool = False,
    ) -> None:
        """
        Initialize the panic key system.
        
        Args:
            exit_on_panic: Whether to exit application after panic
        """
        self._callbacks: List[Callable[[PanicEvent], None]] = []
        self._triggered = False
        self._exit_on_panic = exit_on_panic
        self._log = logging.getLogger("securevault.panic")
        self._events: List[PanicEvent] = []
        self._lock = threading.Lock()
        self._hotkey_thread: Optional[threading.Thread] = None
        self._running = False
        self._hotkey_combo: List[str] = []
        
        # Register cleanup
        atexit.register(self._cleanup)
    
    def on_panic(self, callback: Callable[[PanicEvent], None]) -> None:
        """
        Register a callback for panic events.
        
        Callbacks are invoked in registration order after memory wipe.
        """
        self._callbacks.append(callback)
    
    def trigger(
        self,
        reason: PanicReason = PanicReason.USER_REQUEST,
        details: str = "",
    ) -> None:
        """
        Trigger a panic.
        
        This is the NUCLEAR OPTION:
        1. All sensitive memory is wiped
        2. Vault is locked
        3. Callbacks are invoked
        4. Application may exit
        
        Args:
            reason: Why panic was triggered
            details: Additional information
        """
        with self._lock:
            if self._triggered:
                return  # Already triggered
            
            self._triggered = True
        
        # Create event
        event = PanicEvent(reason=reason, details=details)
        self._events.append(event)
        
        # Log
        self._log.critical(
            f"PANIC TRIGGERED: {reason.name} - {details or 'No details'}"
        )
        
        # Step 1: Wipe memory
        self._wipe_memory()
        
        # Step 2: Lock vault
        self._lock_vault()
        
        # Step 3: Invoke callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                self._log.error(f"Panic callback error: {e}")
        
        # Step 4: Optional exit
        if self._exit_on_panic:
            self._log.critical("Panic: exiting application")
            sys.exit(1)
    
    def _wipe_memory(self) -> None:
        """Wipe all sensitive memory."""
        try:
            from securevault.core.memory.zeroization import trigger_panic as mem_panic
            mem_panic()
            self._log.info("Panic: memory wiped")
        except ImportError:
            self._log.warning("Panic: memory module not available")
        except Exception as e:
            self._log.error(f"Panic: memory wipe failed: {e}")
    
    def _lock_vault(self) -> None:
        """Lock the vault."""
        try:
            from securevault.core.memory.zeroization import VaultLock
            lock = VaultLock()
            if not lock.is_locked:
                lock._locked = True  # Mark as locked without re-triggering panic
            self._log.info("Panic: vault locked")
        except ImportError:
            self._log.warning("Panic: vault lock not available")
        except Exception as e:
            self._log.error(f"Panic: vault lock failed: {e}")
    
    def install_signal_handlers(self) -> None:
        """
        Install signal handlers for panic trigger.
        
        Handlers:
        - SIGTERM: Graceful termination (triggers panic)
        - SIGINT: Interrupt (Ctrl+C, triggers panic)
        - SIGUSR1: User signal (Unix, triggers panic)
        """
        def signal_handler(signum: int, frame) -> None:
            sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
            self.trigger(
                PanicReason.SIGNAL,
                details=f"Signal: {sig_name}",
            )
        
        try:
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            
            # Unix-specific
            if hasattr(signal, 'SIGUSR1'):
                signal.signal(signal.SIGUSR1, signal_handler)
            
            self._log.info("Panic signal handlers installed")
        except Exception as e:
            self._log.warning(f"Could not install signal handlers: {e}")
    
    def register_hotkey(self, keys: List[str]) -> None:
        """
        Register a hotkey combination for panic.
        
        Args:
            keys: List of key names, e.g. ['Ctrl', 'Shift', 'Delete']
        
        Note:
            Hotkey monitoring requires platform-specific implementation.
            On Windows, uses keyboard hooks.
            On Linux/macOS, may require additional libraries.
        """
        self._hotkey_combo = keys
        self._log.info(f"Panic hotkey registered: {'+'.join(keys)}")
    
    def start(self) -> None:
        """Start hotkey monitoring (if configured)."""
        if not self._hotkey_combo:
            self._log.warning("No hotkey configured, start() has no effect")
            return
        
        if self._running:
            return
        
        self._running = True
        # Note: Actual hotkey monitoring requires platform-specific
        # implementation (pynput, keyboard library, etc.)
        # This is a placeholder for the architecture
        self._log.info("Panic key system started")
    
    def stop(self) -> None:
        """Stop hotkey monitoring."""
        self._running = False
        if self._hotkey_thread:
            self._hotkey_thread.join(timeout=1.0)
            self._hotkey_thread = None
        self._log.info("Panic key system stopped")
    
    def _cleanup(self) -> None:
        """Cleanup on exit."""
        self.stop()
    
    def reset(self) -> None:
        """
        Reset the panic state.
        
        WARNING: This is for testing only. In production,
        panic is irreversible.
        """
        with self._lock:
            self._triggered = False
        self._events.clear()
    
    @property
    def is_triggered(self) -> bool:
        """Check if panic has been triggered."""
        return self._triggered
    
    @property
    def events(self) -> List[PanicEvent]:
        """Get panic event history."""
        return list(self._events)


# Convenience function
def trigger_emergency_panic(reason: str = "") -> None:
    """
    Trigger an emergency panic.
    
    This is the NUCLEAR OPTION for emergency situations.
    All sensitive data will be wiped immediately.
    
    Args:
        reason: Optional reason for the panic
    """
    panic = PanicKeySystem(exit_on_panic=True)
    panic.trigger(
        PanicReason.PROGRAMMATIC,
        details=reason or "Emergency panic triggered",
    )


class DuressDetector:
    """
    Detects duress (coercion) situations.
    
    Features:
    - Duress password (alternative password that triggers silent alarm)
    - Decoy vault (shows fake data while alerting)
    
    Usage:
        detector = DuressDetector()
        detector.set_duress_password(duress_hash)
        
        # During authentication
        if detector.is_duress_password(entered_password):
            # Show decoy vault, trigger silent alarm
            pass
    """
    
    __slots__ = ("_duress_password_hash", "_callbacks", "_log")
    
    def __init__(self) -> None:
        """Initialize duress detector."""
        self._duress_password_hash: Optional[str] = None
        self._callbacks: List[Callable[[], None]] = []
        self._log = logging.getLogger("securevault.duress")
    
    def set_duress_password_hash(self, password_hash: str) -> None:
        """
        Set the duress password hash.
        
        The duress password, when entered, triggers the duress response
        instead of normal vault access.
        
        Args:
            password_hash: Hash of the duress password
        """
        self._duress_password_hash = password_hash
    
    def check_duress(self, password_hash: str) -> bool:
        """
        Check if the entered password is the duress password.
        
        Args:
            password_hash: Hash of entered password
        
        Returns:
            True if this is the duress password
        """
        if not self._duress_password_hash:
            return False
        
        import hmac
        is_duress = hmac.compare_digest(
            password_hash.encode(),
            self._duress_password_hash.encode(),
        )
        
        if is_duress:
            self._trigger_duress()
        
        return is_duress
    
    def _trigger_duress(self) -> None:
        """Handle duress situation."""
        self._log.warning("DURESS DETECTED - silent alarm triggered")
        
        for callback in self._callbacks:
            try:
                callback()
            except Exception:
                pass
    
    def on_duress(self, callback: Callable[[], None]) -> None:
        """Register a callback for duress detection."""
        self._callbacks.append(callback)
