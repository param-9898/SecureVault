"""
Memory Zeroization Utilities
============================

Provides explicit memory zeroization and panic handling.

Security Properties:
- Explicit zeroization (no GC reliance)
- Exception-safe cleanup
- Panic key trigger
- Forced vault lock

Key Concepts:
- Zeroization: Overwriting memory with zeros/patterns
- Panic: Emergency wipe of all sensitive data
- Guard: Automatic cleanup on scope exit
"""

from __future__ import annotations

import ctypes
import gc
import functools
import signal
import sys
import threading
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Final, Optional, Callable, List, Set, Any, TypeVar, Iterator
import atexit


# Zeroization constants
WIPE_PASSES: Final[int] = 3


def secure_zero(data: bytearray | memoryview) -> None:
    """
    Securely zero a byte buffer.
    
    Uses ctypes for direct memory access where possible,
    with fallback to Python-level zeroing.
    
    Args:
        data: Mutable byte buffer to zero
    
    Security Notes:
        - This is best-effort; Python may have copies
        - Call immediately after use, before GC
        - Buffer must be mutable (bytearray, not bytes)
    """
    if len(data) == 0:
        return
    
    try:
        if isinstance(data, memoryview):
            # memoryview - zero directly
            for i in range(len(data)):
                data[i] = 0
        else:
            # bytearray - use ctypes
            addr = ctypes.addressof(
                (ctypes.c_char * len(data)).from_buffer(data)
            )
            
            # Multi-pass wipe
            ctypes.memset(addr, 0, len(data))
            ctypes.memset(addr, 0xFF, len(data))
            ctypes.memset(addr, 0, len(data))
            
    except Exception:
        # Fallback: Python-level zeroing
        for i in range(len(data)):
            if isinstance(data, memoryview):
                data[i] = 0
            else:
                data[i] = 0


def secure_zero_string(s: str) -> None:
    """
    Attempt to zero a string's internal buffer.
    
    WARNING: This is UNRELIABLE in Python due to:
    - String interning
    - Immutable string objects
    - Copy-on-reference semantics
    
    This function exists for completeness but provides
    minimal security guarantees.
    
    For sensitive strings, use SecureString instead.
    """
    # Python strings are immutable, so this is best-effort
    # We try to access the internal buffer but this may not work
    try:
        # This approach doesn't work reliably in Python
        # Included only to document the limitation
        pass
    except Exception:
        pass
    
    # The only reliable approach is to ensure string objects
    # go out of scope and hope GC collects them


T = TypeVar("T")


def zeroize_on_exception(
    *buffers: bytearray,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that zeroizes buffers on exception.
    
    Usage:
        key = bytearray(32)
        
        @zeroize_on_exception(key)
        def process():
            fill_key(key)
            use_key(key)
            # If exception here, key is zeroed
        
        process()
        secure_zero(key)  # Normal cleanup
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return func(*args, **kwargs)
            except Exception:
                # Zeroize all buffers on exception
                for buf in buffers:
                    secure_zero(buf)
                raise
        return wrapper
    return decorator


@contextmanager
def ZeroizeContext(*buffers: bytearray) -> Iterator[None]:
    """
    Context manager that zeroizes buffers on exit.
    
    Always zeroizes, whether exit is normal or exceptional.
    
    Usage:
        key = bytearray(32)
        nonce = bytearray(12)
        
        with ZeroizeContext(key, nonce):
            fill_key(key)
            fill_nonce(nonce)
            encrypt(data, key, nonce)
        # key and nonce are now zeroed
    """
    try:
        yield
    finally:
        for buf in buffers:
            try:
                secure_zero(buf)
            except Exception:
                pass


class PanicHandler:
    """
    Emergency panic handler for secure data wipe.
    
    Provides a centralized mechanism to immediately wipe
    all sensitive data when a panic is triggered.
    
    Use Cases:
    - User presses panic key combination
    - Intrusion detection triggers
    - Application shutdown
    - Lock timeout
    
    Usage:
        handler = PanicHandler()
        
        # Register sensitive buffers
        key = SecureBuffer(32)
        handler.register(key)
        
        # On panic (e.g., from keyboard shortcut):
        handler.trigger()  # Wipes all registered buffers
        
        # Or install signal handler:
        handler.install_signal_handlers()
    
    Security Notes:
        - Panic is irreversible
        - All registered data is wiped immediately
        - Application should lock/exit after panic
    """
    
    _instance: Optional["PanicHandler"] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> "PanicHandler":
        """Singleton pattern for global panic handler."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self) -> None:
        """Initialize the panic handler."""
        if getattr(self, "_initialized", False):
            return
        
        self._registered: Set[weakref.ref] = set()
        self._callbacks: List[Callable[[], None]] = []
        self._panic_triggered = False
        self._initialized = True
        
        # Register cleanup on exit
        atexit.register(self._cleanup_on_exit)
    
    def register(self, obj: Any) -> None:
        """
        Register an object for panic cleanup.
        
        The object must have a wipe() method.
        Uses weak reference to avoid preventing GC.
        """
        if hasattr(obj, "wipe"):
            ref = weakref.ref(obj)
            self._registered.add(ref)
    
    def unregister(self, obj: Any) -> None:
        """Unregister an object from panic cleanup."""
        # Find and remove the weak reference
        to_remove = None
        for ref in self._registered:
            if ref() is obj:
                to_remove = ref
                break
        
        if to_remove:
            self._registered.discard(to_remove)
    
    def add_callback(self, callback: Callable[[], None]) -> None:
        """
        Add a callback to invoke on panic.
        
        Callbacks are called after all objects are wiped.
        """
        self._callbacks.append(callback)
    
    def trigger(self) -> None:
        """
        Trigger a panic - wipe all registered objects.
        
        This is the NUCLEAR OPTION - all sensitive data is wiped.
        """
        if self._panic_triggered:
            return  # Already triggered
        
        self._panic_triggered = True
        
        # Wipe all registered objects
        for ref in list(self._registered):
            try:
                obj = ref()
                if obj is not None and hasattr(obj, "wipe"):
                    obj.wipe()
            except Exception:
                pass  # Best effort
        
        self._registered.clear()
        
        # Invoke callbacks
        for callback in self._callbacks:
            try:
                callback()
            except Exception:
                pass
        
        # Force garbage collection
        gc.collect()
    
    def reset(self) -> None:
        """
        Reset the panic state.
        
        Should only be used for testing.
        """
        self._panic_triggered = False
        self._registered.clear()
        self._callbacks.clear()
    
    @property
    def is_triggered(self) -> bool:
        """Check if panic has been triggered."""
        return self._panic_triggered
    
    def install_signal_handlers(self) -> None:
        """
        Install signal handlers for panic trigger.
        
        Installs handlers for:
        - SIGTERM: Graceful termination
        - SIGINT: Interrupt (Ctrl+C)
        - SIGUSR1: User-defined (Unix only)
        """
        def panic_signal_handler(signum: int, frame: Any) -> None:
            self.trigger()
            sys.exit(1)
        
        try:
            signal.signal(signal.SIGTERM, panic_signal_handler)
            signal.signal(signal.SIGINT, panic_signal_handler)
            
            # Unix-specific signals
            if hasattr(signal, "SIGUSR1"):
                signal.signal(signal.SIGUSR1, panic_signal_handler)
                
        except Exception:
            pass  # Signal handling may be restricted
    
    def _cleanup_on_exit(self) -> None:
        """Cleanup handler for normal exit."""
        if not self._panic_triggered:
            self.trigger()


def trigger_panic() -> None:
    """
    Trigger a global panic.
    
    Convenience function to trigger the singleton PanicHandler.
    """
    PanicHandler().trigger()


@dataclass
class VaultLock:
    """
    Forced vault lock mechanism.
    
    Provides a way to immediately lock the vault and wipe
    all decrypted data from memory.
    
    Usage:
        vault_lock = VaultLock()
        
        # User action or timeout triggers lock
        vault_lock.lock()
    """
    _locked: bool = False
    _lock_callbacks: list = None
    
    def __post_init__(self) -> None:
        if self._lock_callbacks is None:
            self._lock_callbacks = []
    
    def on_lock(self, callback: Callable[[], None]) -> None:
        """Register a callback to invoke on lock."""
        self._lock_callbacks.append(callback)
    
    def lock(self) -> None:
        """
        Lock the vault immediately.
        
        Triggers panic to wipe all sensitive data.
        """
        if self._locked:
            return
        
        self._locked = True
        
        # Trigger panic to wipe data
        trigger_panic()
        
        # Invoke lock callbacks
        for callback in self._lock_callbacks:
            try:
                callback()
            except Exception:
                pass
    
    def unlock(self) -> None:
        """
        Unlock the vault.
        
        Note: This doesn't restore wiped data - a fresh
        authentication is required.
        """
        self._locked = False
    
    @property
    def is_locked(self) -> bool:
        """Check if vault is locked."""
        return self._locked


class AutoLockTimer:
    """
    Automatic vault lock timer.
    
    Locks the vault after a period of inactivity.
    
    Usage:
        timer = AutoLockTimer(timeout_seconds=300)  # 5 minutes
        timer.start()
        
        # On user activity:
        timer.reset()
        
        # Timer will trigger lock after timeout
    """
    
    __slots__ = ("_timeout", "_timer", "_vault_lock", "_running")
    
    def __init__(
        self,
        timeout_seconds: int = 300,
        vault_lock: Optional[VaultLock] = None,
    ) -> None:
        """
        Initialize the auto-lock timer.
        
        Args:
            timeout_seconds: Inactivity timeout
            vault_lock: VaultLock instance to trigger
        """
        self._timeout = timeout_seconds
        self._vault_lock = vault_lock or VaultLock()
        self._timer: Optional[threading.Timer] = None
        self._running = False
    
    def start(self) -> None:
        """Start the auto-lock timer."""
        if self._running:
            return
        
        self._running = True
        self._start_timer()
    
    def stop(self) -> None:
        """Stop the auto-lock timer."""
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
    
    def reset(self) -> None:
        """Reset the timer (on user activity)."""
        if not self._running:
            return
        
        if self._timer:
            self._timer.cancel()
        
        self._start_timer()
    
    def _start_timer(self) -> None:
        """Internal: start the timer."""
        self._timer = threading.Timer(
            self._timeout,
            self._on_timeout,
        )
        self._timer.daemon = True
        self._timer.start()
    
    def _on_timeout(self) -> None:
        """Internal: handle timeout."""
        if self._running:
            self._vault_lock.lock()
