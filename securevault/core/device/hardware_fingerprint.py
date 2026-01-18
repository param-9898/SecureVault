"""
Hardware Fingerprinting
=======================

Collects and hashes hardware identifiers for device binding.

Security Properties:
- Multiple independent hardware sources
- Cryptographic hashing (no raw IDs stored)
- OS-aware implementation (Windows/Linux/macOS)
- Graceful degradation with minimum source requirement

Fingerprint Sources:
- Machine GUID (Windows) / Machine ID (Linux)
- CPU ID / Processor information
- Motherboard/System UUID
- TPM public key hash (if available)
- MAC addresses (optional, less stable)

WARNING:
- Hardware fingerprints can change with hardware upgrades
- Virtual machines may have unstable fingerprints
- Always provide recovery mechanisms for legitimate users
"""

from __future__ import annotations

import hashlib
import hmac
import platform
import subprocess
import uuid
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Final, Optional, Dict, List, Set
from pathlib import Path


# Minimum number of sources required for a valid fingerprint
MIN_FINGERPRINT_SOURCES: Final[int] = 2

# Salt for fingerprint hashing (can be customized per-installation)
DEFAULT_FINGERPRINT_SALT: Final[bytes] = b"SecureVault_DeviceBinding_v1"


class FingerprintSource(Enum):
    """Available hardware fingerprint sources."""
    MACHINE_GUID = auto()
    CPU_ID = auto()
    MOTHERBOARD_UUID = auto()
    TPM_KEY = auto()
    MAC_ADDRESS = auto()
    DISK_SERIAL = auto()
    BIOS_SERIAL = auto()


@dataclass(frozen=True, slots=True)
class HardwareFingerprint:
    """
    Immutable hardware fingerprint.
    
    Attributes:
        fingerprint_hash: SHA-256 hash of combined identifiers
        sources_used: Set of sources that contributed to fingerprint
        source_count: Number of sources used
        platform: Operating system platform
    """
    fingerprint_hash: str
    sources_used: frozenset[FingerprintSource]
    source_count: int
    platform: str
    
    def __repr__(self) -> str:
        """Safe representation without exposing hash."""
        return (
            f"HardwareFingerprint(sources={self.source_count}, "
            f"platform={self.platform})"
        )
    
    def matches(self, other: "HardwareFingerprint") -> bool:
        """
        Check if this fingerprint matches another.
        
        Uses constant-time comparison to prevent timing attacks.
        """
        return hmac.compare_digest(
            self.fingerprint_hash.encode(),
            other.fingerprint_hash.encode()
        )
    
    def matches_hash(self, hash_value: str) -> bool:
        """Check if this fingerprint matches a stored hash."""
        return hmac.compare_digest(
            self.fingerprint_hash.encode(),
            hash_value.encode()
        )


class HardwareFingerprintCollector:
    """
    Collects hardware identifiers from various sources.
    
    This class is OS-aware and will use appropriate methods
    for each platform.
    
    Usage:
        collector = HardwareFingerprintCollector()
        fingerprint = collector.collect()
        
        # Store only the hash
        store(fingerprint.fingerprint_hash)
        
        # Later, verify
        current = collector.collect()
        if not current.matches_hash(stored_hash):
            raise DeviceMismatchError()
    
    Security Notes:
        - Raw identifiers are never stored or returned
        - All identifiers are hashed together
        - Minimum source count prevents weak fingerprints
    """
    
    __slots__ = ("_salt", "_platform", "_collected_ids")
    
    def __init__(self, salt: bytes = DEFAULT_FINGERPRINT_SALT) -> None:
        """
        Initialize the fingerprint collector.
        
        Args:
            salt: Custom salt for hashing (default provided)
        """
        self._salt = salt
        self._platform = platform.system().lower()
        self._collected_ids: Dict[FingerprintSource, str] = {}
    
    def collect(
        self,
        required_sources: Optional[Set[FingerprintSource]] = None,
        min_sources: int = MIN_FINGERPRINT_SOURCES,
    ) -> HardwareFingerprint:
        """
        Collect hardware fingerprint from available sources.
        
        Args:
            required_sources: Optional set of required sources
            min_sources: Minimum number of sources needed
        
        Returns:
            HardwareFingerprint with hashed identifiers
        
        Raises:
            RuntimeError: If insufficient sources available
        """
        self._collected_ids.clear()
        
        # Collect from all available sources
        self._collect_machine_guid()
        self._collect_cpu_id()
        self._collect_motherboard_uuid()
        self._collect_tpm_info()
        self._collect_bios_serial()
        
        # Check minimum sources
        if len(self._collected_ids) < min_sources:
            raise RuntimeError(
                f"Insufficient hardware sources for fingerprint. "
                f"Found {len(self._collected_ids)}, need {min_sources}."
            )
        
        # Check required sources
        if required_sources:
            missing = required_sources - set(self._collected_ids.keys())
            if missing:
                raise RuntimeError(
                    f"Required fingerprint sources not available: {missing}"
                )
        
        # Combine and hash
        fingerprint_hash = self._compute_hash()
        
        return HardwareFingerprint(
            fingerprint_hash=fingerprint_hash,
            sources_used=frozenset(self._collected_ids.keys()),
            source_count=len(self._collected_ids),
            platform=self._platform,
        )
    
    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of all collected identifiers."""
        # Sort keys for deterministic ordering
        sorted_items = sorted(
            self._collected_ids.items(),
            key=lambda x: x[0].name
        )
        
        # Combine: SALT || SOURCE1:VALUE1 || SOURCE2:VALUE2 || ...
        hasher = hashlib.sha256(self._salt)
        for source, value in sorted_items:
            hasher.update(f"|{source.name}:{value}".encode())
        
        return hasher.hexdigest()
    
    def _collect_machine_guid(self) -> None:
        """Collect machine GUID/ID."""
        try:
            if self._platform == "windows":
                # Windows: Read from registry
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography"
                )
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                self._collected_ids[FingerprintSource.MACHINE_GUID] = machine_guid
                
            elif self._platform == "linux":
                # Linux: Read /etc/machine-id
                machine_id_path = Path("/etc/machine-id")
                if machine_id_path.exists():
                    machine_id = machine_id_path.read_text().strip()
                    self._collected_ids[FingerprintSource.MACHINE_GUID] = machine_id
                else:
                    # Fallback to /var/lib/dbus/machine-id
                    dbus_path = Path("/var/lib/dbus/machine-id")
                    if dbus_path.exists():
                        machine_id = dbus_path.read_text().strip()
                        self._collected_ids[FingerprintSource.MACHINE_GUID] = machine_id
                        
            elif self._platform == "darwin":
                # macOS: Use IOPlatformUUID
                result = subprocess.run(
                    ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    match = re.search(
                        r'"IOPlatformUUID"\s*=\s*"([^"]+)"',
                        result.stdout
                    )
                    if match:
                        self._collected_ids[FingerprintSource.MACHINE_GUID] = match.group(1)
                        
        except Exception:
            pass  # Source unavailable
    
    def _collect_cpu_id(self) -> None:
        """Collect CPU identifier."""
        try:
            if self._platform == "windows":
                # Windows: Use WMIC
                result = subprocess.run(
                    ["wmic", "cpu", "get", "ProcessorId"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                if result.returncode == 0:
                    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                    if len(lines) > 1:
                        cpu_id = lines[1]
                        if cpu_id and cpu_id != "ProcessorId":
                            self._collected_ids[FingerprintSource.CPU_ID] = cpu_id
                            
            elif self._platform == "linux":
                # Linux: Read /proc/cpuinfo
                cpuinfo_path = Path("/proc/cpuinfo")
                if cpuinfo_path.exists():
                    cpuinfo = cpuinfo_path.read_text()
                    # Look for serial or unique identifier
                    for line in cpuinfo.split('\n'):
                        if 'Serial' in line or 'serial' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                self._collected_ids[FingerprintSource.CPU_ID] = parts[1].strip()
                                break
                    else:
                        # Use model name + stepping as fallback (less unique but stable)
                        model = ""
                        for line in cpuinfo.split('\n'):
                            if 'model name' in line.lower():
                                parts = line.split(':')
                                if len(parts) > 1:
                                    model = parts[1].strip()
                                    break
                        if model:
                            # Hash the model to create a pseudo-ID
                            self._collected_ids[FingerprintSource.CPU_ID] = hashlib.md5(
                                model.encode()
                            ).hexdigest()
                            
            elif self._platform == "darwin":
                # macOS: Use sysctl
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    cpu_brand = result.stdout.strip()
                    if cpu_brand:
                        # Hash the brand string
                        self._collected_ids[FingerprintSource.CPU_ID] = hashlib.md5(
                            cpu_brand.encode()
                        ).hexdigest()
                        
        except Exception:
            pass
    
    def _collect_motherboard_uuid(self) -> None:
        """Collect motherboard/system UUID."""
        try:
            if self._platform == "windows":
                # Windows: Use WMIC
                result = subprocess.run(
                    ["wmic", "csproduct", "get", "UUID"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                if result.returncode == 0:
                    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                    if len(lines) > 1:
                        sys_uuid = lines[1]
                        # Filter out generic/empty UUIDs
                        if sys_uuid and sys_uuid != "UUID" and not sys_uuid.startswith("FFFF"):
                            self._collected_ids[FingerprintSource.MOTHERBOARD_UUID] = sys_uuid
                            
            elif self._platform == "linux":
                # Linux: Read from DMI
                dmi_paths = [
                    Path("/sys/class/dmi/id/product_uuid"),
                    Path("/sys/class/dmi/id/board_serial"),
                ]
                for dmi_path in dmi_paths:
                    if dmi_path.exists():
                        try:
                            sys_uuid = dmi_path.read_text().strip()
                            if sys_uuid and not sys_uuid.startswith("0000"):
                                self._collected_ids[FingerprintSource.MOTHERBOARD_UUID] = sys_uuid
                                break
                        except PermissionError:
                            continue
                            
            elif self._platform == "darwin":
                # macOS: Already covered by IOPlatformUUID in machine_guid
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    match = re.search(
                        r"Hardware UUID:\s*([A-F0-9-]+)",
                        result.stdout,
                        re.IGNORECASE
                    )
                    if match:
                        self._collected_ids[FingerprintSource.MOTHERBOARD_UUID] = match.group(1)
                        
        except Exception:
            pass
    
    def _collect_tpm_info(self) -> None:
        """Collect TPM information if available."""
        try:
            if self._platform == "windows":
                # Windows: Check TPM status
                result = subprocess.run(
                    ["powershell", "-Command", 
                     "(Get-Tpm).TpmPresent; (Get-Tpm).ManufacturerId"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if lines and lines[0].strip().lower() == "true":
                        # TPM is present, use manufacturer ID
                        if len(lines) > 1:
                            tpm_id = lines[1].strip()
                            if tpm_id:
                                self._collected_ids[FingerprintSource.TPM_KEY] = tpm_id
                                
            elif self._platform == "linux":
                # Linux: Check /sys/class/tpm
                tpm_path = Path("/sys/class/tpm/tpm0")
                if tpm_path.exists():
                    # Read TPM version/capabilities
                    caps_path = tpm_path / "caps"
                    if caps_path.exists():
                        caps = caps_path.read_text().strip()
                        self._collected_ids[FingerprintSource.TPM_KEY] = hashlib.md5(
                            caps.encode()
                        ).hexdigest()
                        
        except Exception:
            pass
    
    def _collect_bios_serial(self) -> None:
        """Collect BIOS serial number."""
        try:
            if self._platform == "windows":
                result = subprocess.run(
                    ["wmic", "bios", "get", "SerialNumber"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
                if result.returncode == 0:
                    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                    if len(lines) > 1:
                        serial = lines[1]
                        if serial and serial != "SerialNumber" and serial != "To be filled by O.E.M.":
                            self._collected_ids[FingerprintSource.BIOS_SERIAL] = serial
                            
            elif self._platform == "linux":
                bios_path = Path("/sys/class/dmi/id/bios_version")
                if bios_path.exists():
                    try:
                        bios_ver = bios_path.read_text().strip()
                        if bios_ver:
                            self._collected_ids[FingerprintSource.BIOS_SERIAL] = bios_ver
                    except PermissionError:
                        pass
                        
        except Exception:
            pass
    
    def get_available_sources(self) -> List[FingerprintSource]:
        """Get list of available fingerprint sources on this system."""
        # Collect without raising on insufficient sources
        self._collected_ids.clear()
        self._collect_machine_guid()
        self._collect_cpu_id()
        self._collect_motherboard_uuid()
        self._collect_tpm_info()
        self._collect_bios_serial()
        
        return list(self._collected_ids.keys())


def get_device_fingerprint(
    salt: bytes = DEFAULT_FINGERPRINT_SALT,
    min_sources: int = MIN_FINGERPRINT_SOURCES,
) -> HardwareFingerprint:
    """
    Get the current device's hardware fingerprint.
    
    Args:
        salt: Custom salt for hashing
        min_sources: Minimum required sources
    
    Returns:
        HardwareFingerprint for this device
    
    Convenience function for simple usage.
    """
    collector = HardwareFingerprintCollector(salt=salt)
    return collector.collect(min_sources=min_sources)
