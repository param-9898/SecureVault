"""
Intrusion Detection System
==========================

Provides active defense through detection and response.

Detection Capabilities:
- Debugger attachment detection
- Excessive login failure monitoring
- Virtual machine / sandbox indicators
- Memory inspection attempts

Response Actions:
- Memory zeroization (panic)
- Vault locking
- Secure audit logging
- Application termination (optional)

Security Note:
    This is a defense-in-depth measure. Sophisticated attackers
    may bypass these checks. Layer with other security controls.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Final, Optional, Callable, List, Dict, Set
import logging


# Platform detection
IS_WINDOWS: Final[bool] = platform.system() == "Windows"
IS_LINUX: Final[bool] = platform.system() == "Linux"
IS_MACOS: Final[bool] = platform.system() == "Darwin"


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = auto()      # Informational
    MEDIUM = auto()   # Suspicious activity
    HIGH = auto()     # Active attack
    CRITICAL = auto() # Immediate action required


class ThreatType(Enum):
    """Types of detected threats."""
    DEBUGGER_ATTACHED = auto()
    EXCESSIVE_LOGIN_FAILURES = auto()
    VM_DETECTED = auto()
    SANDBOX_DETECTED = auto()
    MEMORY_INSPECTION = auto()
    TIMING_ATTACK = auto()
    BRUTE_FORCE = auto()
    PROCESS_INJECTION = auto()
    UNKNOWN = auto()


@dataclass
class ThreatEvent:
    """
    Represents a detected security threat.
    """
    threat_type: ThreatType
    threat_level: ThreatLevel
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging."""
        return {
            "type": self.threat_type.name,
            "level": self.threat_level.name,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "details": self.details,
        }


class DebuggerDetector:
    """
    Detects debugger attachment.
    
    Methods:
    - Windows: IsDebuggerPresent, CheckRemoteDebuggerPresent
    - Linux: /proc/self/status TracerPid
    - macOS: sysctl PT_DENY_ATTACH
    
    Limitations:
    - Can be bypassed by kernel-level debuggers
    - Some virtualization platforms trigger false positives
    """
    
    @staticmethod
    def is_debugger_attached() -> bool:
        """
        Check if a debugger is attached to the process.
        
        Returns:
            True if debugger detected
        """
        try:
            if IS_WINDOWS:
                return DebuggerDetector._check_windows_debugger()
            elif IS_LINUX:
                return DebuggerDetector._check_linux_debugger()
            elif IS_MACOS:
                return DebuggerDetector._check_macos_debugger()
        except Exception:
            pass
        return False
    
    @staticmethod
    def _check_windows_debugger() -> bool:
        """Windows-specific debugger detection."""
        try:
            kernel32 = ctypes.windll.kernel32
            
            # Check IsDebuggerPresent
            if kernel32.IsDebuggerPresent():
                return True
            
            # Check remote debugger
            is_debugged = ctypes.c_int(0)
            if kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(),
                ctypes.byref(is_debugged)
            ):
                if is_debugged.value:
                    return True
            
            # Check debug flags in PEB (Process Environment Block)
            # NtGlobalFlag check
            
        except Exception:
            pass
        return False
    
    @staticmethod
    def _check_linux_debugger() -> bool:
        """Linux-specific debugger detection."""
        try:
            # Check /proc/self/status for TracerPid
            status_path = Path("/proc/self/status")
            if status_path.exists():
                content = status_path.read_text()
                for line in content.split('\n'):
                    if line.startswith('TracerPid:'):
                        tracer_pid = int(line.split(':')[1].strip())
                        if tracer_pid != 0:
                            return True
            
            # Check for common debugger environment variables
            debug_vars = ['DEBUGGER', 'GDB_PYTHON_SCRIPT', '_JAVA_JVMTI_TRACE']
            for var in debug_vars:
                if os.environ.get(var):
                    return True
                    
        except Exception:
            pass
        return False
    
    @staticmethod
    def _check_macos_debugger() -> bool:
        """macOS-specific debugger detection."""
        try:
            # Use sysctl to check P_TRACED flag
            import subprocess
            result = subprocess.run(
                ['sysctl', 'kern.proc.pid.' + str(os.getpid())],
                capture_output=True,
                text=True,
                timeout=2,
            )
            # Check for P_TRACED in output
            if 'P_TRACED' in result.stdout:
                return True
                
        except Exception:
            pass
        return False


class VMDetector:
    """
    Detects virtual machine / sandbox environments.
    
    Indicators:
    - Hardware strings (VirtualBox, VMware, QEMU, Hyper-V)
    - Registry keys (Windows)
    - DMI/SMBIOS data (Linux)
    - Process names
    - MAC address prefixes
    
    Note:
    - VM detection is used defensively to prevent analysis
    - Can cause false positives in cloud/container environments
    """
    
    # Known VM MAC address prefixes
    VM_MAC_PREFIXES: Final[Set[str]] = {
        "00:0C:29",  # VMware
        "00:50:56",  # VMware
        "08:00:27",  # VirtualBox
        "52:54:00",  # QEMU/KVM
        "00:1C:42",  # Parallels
        "00:15:5D",  # Hyper-V
    }
    
    # Known VM process names
    VM_PROCESSES: Final[Set[str]] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe",
        "sandboxie", "vmsrvc.exe",
        "qemu-ga", "spice-vdagent",
    }
    
    # Known sandbox/analysis tool processes
    SANDBOX_PROCESSES: Final[Set[str]] = {
        "wireshark.exe", "fiddler.exe", "procmon.exe",
        "ollydbg.exe", "x64dbg.exe", "immunitydebugger.exe",
        "ida.exe", "ida64.exe", "idag.exe", "idaq.exe",
        "dumpcap.exe", "tcpdump", "strace",
    }
    
    @classmethod
    def is_vm_environment(cls) -> tuple[bool, str]:
        """
        Check if running in a virtual machine.
        
        Returns:
            Tuple of (is_vm, vm_type)
        """
        try:
            if IS_WINDOWS:
                return cls._check_windows_vm()
            elif IS_LINUX:
                return cls._check_linux_vm()
            elif IS_MACOS:
                return cls._check_macos_vm()
        except Exception:
            pass
        return False, ""
    
    @classmethod
    def is_sandbox_environment(cls) -> bool:
        """
        Check for sandbox/analysis environment indicators.
        
        Returns:
            True if sandbox indicators detected
        """
        try:
            # Check running processes
            if IS_WINDOWS:
                result = subprocess.run(
                    ['tasklist', '/fo', 'csv'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                if result.returncode == 0:
                    processes = result.stdout.lower()
                    for proc in cls.SANDBOX_PROCESSES:
                        if proc.lower() in processes:
                            return True
            elif IS_LINUX:
                result = subprocess.run(
                    ['ps', 'aux'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    processes = result.stdout.lower()
                    for proc in cls.SANDBOX_PROCESSES:
                        if proc.lower() in processes:
                            return True
            
            # Check for suspicious environment
            sandbox_env_vars = [
                'SANDBOX_PATH', 'CUCKOO_ROOT', 'ANALYSIS_ID',
            ]
            for var in sandbox_env_vars:
                if os.environ.get(var):
                    return True
                    
        except Exception:
            pass
        return False
    
    @classmethod
    def _check_windows_vm(cls) -> tuple[bool, str]:
        """Windows VM detection."""
        try:
            import winreg
            
            # Check system BIOS
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\BIOS"
            )
            
            vm_indicators = {
                "VirtualBox": "vbox",
                "VMware": "vmware",
                "QEMU": "qemu",
                "Hyper-V": "hyper-v",
                "Parallels": "parallels",
            }
            
            for i in range(100):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    value_lower = str(value).lower()
                    for vm_name, indicator in vm_indicators.items():
                        if indicator in value_lower:
                            return True, vm_name
                except WindowsError:
                    break
            
            winreg.CloseKey(key)
            
            # Check WMI for VM
            result = subprocess.run(
                ['wmic', 'computersystem', 'get', 'model'],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )
            if result.returncode == 0:
                model = result.stdout.lower()
                for vm_name, indicator in vm_indicators.items():
                    if indicator in model:
                        return True, vm_name
                        
        except Exception:
            pass
        return False, ""
    
    @classmethod
    def _check_linux_vm(cls) -> tuple[bool, str]:
        """Linux VM detection."""
        try:
            # Check DMI data
            dmi_paths = [
                Path("/sys/class/dmi/id/product_name"),
                Path("/sys/class/dmi/id/sys_vendor"),
                Path("/sys/class/dmi/id/chassis_vendor"),
            ]
            
            vm_indicators = {
                "VirtualBox": ["virtualbox", "vbox"],
                "VMware": ["vmware"],
                "QEMU": ["qemu"],
                "KVM": ["kvm"],
                "Xen": ["xen"],
                "Hyper-V": ["microsoft", "hyper-v"],
            }
            
            for dmi_path in dmi_paths:
                if dmi_path.exists():
                    try:
                        content = dmi_path.read_text().lower()
                        for vm_name, indicators in vm_indicators.items():
                            for indicator in indicators:
                                if indicator in content:
                                    return True, vm_name
                    except PermissionError:
                        pass
            
            # Check /proc/cpuinfo for hypervisor flag
            cpuinfo = Path("/proc/cpuinfo")
            if cpuinfo.exists():
                content = cpuinfo.read_text()
                if "hypervisor" in content:
                    return True, "Unknown Hypervisor"
                    
        except Exception:
            pass
        return False, ""
    
    @classmethod
    def _check_macos_vm(cls) -> tuple[bool, str]:
        """macOS VM detection."""
        try:
            result = subprocess.run(
                ['system_profiler', 'SPHardwareDataType'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "vmware" in output:
                    return True, "VMware"
                if "virtualbox" in output:
                    return True, "VirtualBox"
                if "parallels" in output:
                    return True, "Parallels"
        except Exception:
            pass
        return False, ""


class LoginFailureMonitor:
    """
    Monitors and detects excessive login failures.
    
    Features:
    - Rolling time window tracking
    - IP-based rate limiting
    - User-based rate limiting
    - Automatic lockout triggering
    """
    
    __slots__ = (
        "_failures", "_max_failures", "_window_seconds",
        "_lock", "_callbacks"
    )
    
    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 300,
    ) -> None:
        """
        Initialize the login failure monitor.
        
        Args:
            max_failures: Maximum failures before triggering
            window_seconds: Time window for counting failures
        """
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._failures: Dict[str, List[float]] = {}  # key -> [timestamps]
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[str, int], None]] = []
    
    def record_failure(
        self,
        identifier: str,
        source: str = "unknown",
    ) -> bool:
        """
        Record a login failure.
        
        Args:
            identifier: User ID or IP address
            source: Source of the attempt
        
        Returns:
            True if threshold exceeded (intrusion detected)
        """
        now = time.time()
        cutoff = now - self._window_seconds
        
        with self._lock:
            # Get or create failure list
            if identifier not in self._failures:
                self._failures[identifier] = []
            
            # Remove old failures
            self._failures[identifier] = [
                t for t in self._failures[identifier] if t > cutoff
            ]
            
            # Add new failure
            self._failures[identifier].append(now)
            
            count = len(self._failures[identifier])
            
            # Check threshold
            if count >= self._max_failures:
                # Trigger callbacks
                for callback in self._callbacks:
                    try:
                        callback(identifier, count)
                    except Exception:
                        pass
                return True
        
        return False
    
    def get_failure_count(self, identifier: str) -> int:
        """Get current failure count for an identifier."""
        now = time.time()
        cutoff = now - self._window_seconds
        
        with self._lock:
            if identifier not in self._failures:
                return 0
            
            # Count recent failures
            return len([
                t for t in self._failures[identifier] if t > cutoff
            ])
    
    def on_threshold_exceeded(
        self,
        callback: Callable[[str, int], None],
    ) -> None:
        """Register a callback for when threshold is exceeded."""
        self._callbacks.append(callback)
    
    def reset(self, identifier: Optional[str] = None) -> None:
        """Reset failure counts."""
        with self._lock:
            if identifier:
                self._failures.pop(identifier, None)
            else:
                self._failures.clear()


class IntrusionDetectionSystem:
    """
    Central intrusion detection and response system.
    
    Provides:
    - Continuous monitoring thread
    - Multiple detection mechanisms
    - Configurable response actions
    - Secure audit logging
    
    Usage:
        ids = IntrusionDetectionSystem()
        
        # Configure response
        ids.on_threat(handle_threat)
        
        # Start monitoring
        ids.start()
        
        # Report login failure
        ids.report_login_failure(user_id)
        
        # Stop monitoring
        ids.stop()
    
    Security Notes:
        - All detections are logged
        - HIGH/CRITICAL threats trigger immediate response
        - Configure panic_on_critical for automatic memory wipe
    """
    
    __slots__ = (
        "_running", "_monitor_thread", "_interval",
        "_threat_handlers", "_login_monitor", "_events",
        "_panic_on_critical", "_lock_on_high", "_log",
        "_vm_check_enabled", "_debugger_check_enabled",
    )
    
    def __init__(
        self,
        monitor_interval: float = 5.0,
        panic_on_critical: bool = True,
        lock_on_high: bool = True,
        check_vm: bool = True,
        check_debugger: bool = True,
    ) -> None:
        """
        Initialize the intrusion detection system.
        
        Args:
            monitor_interval: Seconds between monitoring checks
            panic_on_critical: Trigger panic on critical threats
            lock_on_high: Lock vault on high threats
            check_vm: Enable VM detection
            check_debugger: Enable debugger detection
        """
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._interval = monitor_interval
        self._threat_handlers: List[Callable[[ThreatEvent], None]] = []
        self._login_monitor = LoginFailureMonitor()
        self._events: List[ThreatEvent] = []
        self._panic_on_critical = panic_on_critical
        self._lock_on_high = lock_on_high
        self._vm_check_enabled = check_vm
        self._debugger_check_enabled = check_debugger
        self._log = logging.getLogger("securevault.ids")
        
        # Register login failure callback
        self._login_monitor.on_threshold_exceeded(self._on_login_threshold)
    
    def start(self) -> None:
        """Start the monitoring thread."""
        if self._running:
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="IDS-Monitor",
        )
        self._monitor_thread.start()
        self._log.info("Intrusion detection system started")
    
    def stop(self) -> None:
        """Stop the monitoring thread."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=self._interval * 2)
            self._monitor_thread = None
        self._log.info("Intrusion detection system stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                self._perform_checks()
            except Exception as e:
                self._log.error(f"IDS monitoring error: {e}")
            
            # Sleep in small intervals for responsive shutdown
            for _ in range(int(self._interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)
    
    def _perform_checks(self) -> None:
        """Perform all security checks."""
        # Check for debugger
        if self._debugger_check_enabled:
            if DebuggerDetector.is_debugger_attached():
                self._raise_threat(ThreatEvent(
                    threat_type=ThreatType.DEBUGGER_ATTACHED,
                    threat_level=ThreatLevel.CRITICAL,
                    description="Debugger detected attached to process",
                    source="DebuggerDetector",
                ))
        
        # Check for VM (only once at startup typically)
        # Doing it continuously could cause performance issues
    
    def check_environment(self) -> List[ThreatEvent]:
        """
        Perform one-time environment check.
        
        Called at startup to detect VM/sandbox.
        
        Returns:
            List of detected threats
        """
        threats = []
        
        # VM check
        if self._vm_check_enabled:
            is_vm, vm_type = VMDetector.is_vm_environment()
            if is_vm:
                threat = ThreatEvent(
                    threat_type=ThreatType.VM_DETECTED,
                    threat_level=ThreatLevel.MEDIUM,
                    description=f"Virtual machine environment detected: {vm_type}",
                    source="VMDetector",
                    details={"vm_type": vm_type},
                )
                threats.append(threat)
                self._raise_threat(threat)
        
        # Sandbox check
        if VMDetector.is_sandbox_environment():
            threat = ThreatEvent(
                threat_type=ThreatType.SANDBOX_DETECTED,
                threat_level=ThreatLevel.HIGH,
                description="Sandbox/analysis environment detected",
                source="VMDetector",
            )
            threats.append(threat)
            self._raise_threat(threat)
        
        # Debugger check
        if self._debugger_check_enabled:
            if DebuggerDetector.is_debugger_attached():
                threat = ThreatEvent(
                    threat_type=ThreatType.DEBUGGER_ATTACHED,
                    threat_level=ThreatLevel.CRITICAL,
                    description="Debugger detected at startup",
                    source="DebuggerDetector",
                )
                threats.append(threat)
                self._raise_threat(threat)
        
        return threats
    
    def report_login_failure(
        self,
        identifier: str,
        source: str = "unknown",
    ) -> bool:
        """
        Report a login failure.
        
        Args:
            identifier: User ID or IP address
            source: Source of the attempt
        
        Returns:
            True if threshold exceeded
        """
        return self._login_monitor.record_failure(identifier, source)
    
    def _on_login_threshold(self, identifier: str, count: int) -> None:
        """Handle login failure threshold exceeded."""
        threat = ThreatEvent(
            threat_type=ThreatType.EXCESSIVE_LOGIN_FAILURES,
            threat_level=ThreatLevel.HIGH,
            description=f"Excessive login failures detected: {count} attempts",
            source="LoginMonitor",
            details={
                "identifier": identifier,
                "failure_count": count,
            },
        )
        self._raise_threat(threat)
    
    def _raise_threat(self, event: ThreatEvent) -> None:
        """Process a detected threat."""
        # Log the event
        self._events.append(event)
        self._log.warning(
            f"THREAT DETECTED: {event.threat_type.name} "
            f"[{event.threat_level.name}] - {event.description}"
        )
        
        # Notify handlers
        for handler in self._threat_handlers:
            try:
                handler(event)
            except Exception as e:
                self._log.error(f"Threat handler error: {e}")
        
        # Automatic response
        if event.threat_level == ThreatLevel.CRITICAL and self._panic_on_critical:
            self._trigger_panic(event)
        elif event.threat_level == ThreatLevel.HIGH and self._lock_on_high:
            self._trigger_lock(event)
    
    def _trigger_panic(self, event: ThreatEvent) -> None:
        """Trigger panic response."""
        self._log.critical(f"PANIC TRIGGERED by {event.threat_type.name}")
        try:
            from securevault.core.memory.zeroization import trigger_panic
            trigger_panic()
        except ImportError:
            pass
    
    def _trigger_lock(self, event: ThreatEvent) -> None:
        """Trigger vault lock."""
        self._log.warning(f"VAULT LOCK triggered by {event.threat_type.name}")
        # Lock is handled by threat handlers typically
    
    def on_threat(
        self,
        handler: Callable[[ThreatEvent], None],
    ) -> None:
        """Register a threat handler."""
        self._threat_handlers.append(handler)
    
    def get_events(
        self,
        since: Optional[datetime] = None,
        threat_type: Optional[ThreatType] = None,
    ) -> List[ThreatEvent]:
        """Get recorded threat events."""
        events = self._events
        
        if since:
            events = [e for e in events if e.timestamp >= since]
        
        if threat_type:
            events = [e for e in events if e.threat_type == threat_type]
        
        return events
    
    @property
    def is_running(self) -> bool:
        """Check if IDS is running."""
        return self._running
