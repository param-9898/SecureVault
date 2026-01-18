"""
Secure Configuration Module
===========================

Provides immutable, environment-aware configuration with security-first defaults.

Security Features:
- Immutable configuration after initialization
- Environment variable override support
- No secrets in default values
- Type-safe configuration access
- OS-aware path handling
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Mapping, Any, Optional
from functools import cached_property
import hashlib


# Security Constants
_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset({
    "password", "secret", "key", "token", "api_key", 
    "private", "credential", "auth", "salt"
})


def _is_sensitive_key(key: str) -> bool:
    """Check if a configuration key might contain sensitive data."""
    key_lower = key.lower()
    return any(sensitive in key_lower for sensitive in _SENSITIVE_KEYS)


def _get_default_data_dir() -> Path:
    """Get OS-appropriate default data directory."""
    system = platform.system().lower()
    
    if system == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif system == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:  # Linux and others
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    
    return base / "SecureVault"


def _get_default_config_dir() -> Path:
    """Get OS-appropriate default config directory."""
    system = platform.system().lower()
    
    if system == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif system == "darwin":
        base = Path.home() / "Library" / "Preferences"
    else:  # Linux and others
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    
    return base / "SecureVault"


def _get_default_log_dir() -> Path:
    """Get OS-appropriate default log directory."""
    system = platform.system().lower()
    
    if system == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "SecureVault" / "Logs"
    elif system == "darwin":
        return Path.home() / "Library" / "Logs" / "SecureVault"
    else:  # Linux and others
        return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "SecureVault" / "logs"


@dataclass(frozen=True, slots=True)
class PathConfig:
    """Immutable path configuration with OS-aware defaults."""
    
    data_dir: Path = field(default_factory=_get_default_data_dir)
    config_dir: Path = field(default_factory=_get_default_config_dir)
    log_dir: Path = field(default_factory=_get_default_log_dir)
    
    def __post_init__(self) -> None:
        """Validate paths after initialization."""
        # Ensure all paths are absolute
        for field_name in ["data_dir", "config_dir", "log_dir"]:
            path = getattr(self, field_name)
            if not path.is_absolute():
                raise ValueError(f"{field_name} must be an absolute path: {path}")


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Immutable security configuration."""
    
    # Encryption settings
    key_derivation_iterations: int = 600_000  # OWASP recommended for PBKDF2
    salt_length: int = 32
    key_length: int = 32  # 256 bits for AES-256
    
    # Session settings
    session_timeout_seconds: int = 900  # 15 minutes
    max_login_attempts: int = 5
    lockout_duration_seconds: int = 300  # 5 minutes
    
    # Memory security
    secure_memory_wipe: bool = True
    
    def __post_init__(self) -> None:
        """Validate security settings."""
        if self.key_derivation_iterations < 100_000:
            raise ValueError("Key derivation iterations must be at least 100,000")
        if self.salt_length < 16:
            raise ValueError("Salt length must be at least 16 bytes")
        if self.key_length < 16:
            raise ValueError("Key length must be at least 16 bytes")


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    """Immutable logging configuration."""
    
    level: str = "INFO"
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 5
    format: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    enable_console: bool = True
    enable_file: bool = True
    
    def __post_init__(self) -> None:
        """Validate logging settings."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {self.level}")


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Immutable application configuration."""
    
    app_name: str = "SecureVault"
    version: str = "0.1.0"
    debug_mode: bool = False  # Always False in production
    
    def __post_init__(self) -> None:
        """Validate and enforce security rules."""
        # SECURITY: Never allow debug mode to be accidentally enabled
        if self.debug_mode:
            import warnings
            warnings.warn(
                "Debug mode is enabled. This should NEVER be used in production.",
                SecurityWarning,
                stacklevel=2
            )


class SecureConfig:
    """
    Centralized, immutable configuration loader with environment override support.
    
    This class provides a secure way to manage application configuration with:
    - Immutable configuration after initialization
    - Environment variable overrides (prefixed with SECUREVAULT_)
    - Type-safe access to configuration values
    - OS-aware path defaults
    
    Usage:
        config = SecureConfig.load()
        log_dir = config.paths.log_dir
        iterations = config.security.key_derivation_iterations
    """
    
    __slots__ = ("_paths", "_security", "_logging", "_app", "_frozen", "_config_hash")
    
    _instance: Optional[SecureConfig] = None
    
    def __init__(
        self,
        paths: Optional[PathConfig] = None,
        security: Optional[SecurityConfig] = None,
        logging: Optional[LoggingConfig] = None,
        app: Optional[AppConfig] = None,
    ) -> None:
        """Initialize configuration. Use SecureConfig.load() for standard initialization."""
        # Use object.__setattr__ to bypass our immutability check during init
        object.__setattr__(self, "_frozen", False)
        object.__setattr__(self, "_paths", paths or PathConfig())
        object.__setattr__(self, "_security", security or SecurityConfig())
        object.__setattr__(self, "_logging", logging or LoggingConfig())
        object.__setattr__(self, "_app", app or AppConfig())
        object.__setattr__(self, "_config_hash", self._compute_hash())
        # Freeze the object after all attributes are set
        object.__setattr__(self, "_frozen", True)
    
    def _compute_hash(self) -> str:
        """Compute a hash of the configuration for integrity checking."""
        config_str = f"{self._paths}|{self._security}|{self._logging}|{self._app}"
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]
    
    @property
    def paths(self) -> PathConfig:
        """Get path configuration."""
        return self._paths
    
    @property
    def security(self) -> SecurityConfig:
        """Get security configuration."""
        return self._security
    
    @property
    def logging(self) -> LoggingConfig:
        """Get logging configuration."""
        return self._logging
    
    @property
    def app(self) -> AppConfig:
        """Get application configuration."""
        return self._app
    
    @property
    def config_hash(self) -> str:
        """Get configuration integrity hash."""
        return self._config_hash
    
    @classmethod
    def load(cls, env_prefix: str = "SECUREVAULT") -> SecureConfig:
        """
        Load configuration with environment variable overrides.
        
        Environment variables should be prefixed with SECUREVAULT_ and use
        double underscores for nested values.
        
        Examples:
            SECUREVAULT_LOG_LEVEL=DEBUG
            SECUREVAULT_SECURITY__SESSION_TIMEOUT_SECONDS=1800
            SECUREVAULT_PATHS__DATA_DIR=/custom/path
        
        Args:
            env_prefix: Prefix for environment variables (default: SECUREVAULT)
            
        Returns:
            Configured SecureConfig instance
        """
        # Parse environment overrides
        env_overrides = cls._parse_env_overrides(env_prefix)
        
        # Build path configuration
        paths_kwargs: dict[str, Any] = {}
        if "paths.data_dir" in env_overrides:
            paths_kwargs["data_dir"] = Path(env_overrides["paths.data_dir"])
        if "paths.config_dir" in env_overrides:
            paths_kwargs["config_dir"] = Path(env_overrides["paths.config_dir"])
        if "paths.log_dir" in env_overrides:
            paths_kwargs["log_dir"] = Path(env_overrides["paths.log_dir"])
        
        # Build security configuration
        security_kwargs: dict[str, Any] = {}
        if "security.key_derivation_iterations" in env_overrides:
            security_kwargs["key_derivation_iterations"] = int(
                env_overrides["security.key_derivation_iterations"]
            )
        if "security.session_timeout_seconds" in env_overrides:
            security_kwargs["session_timeout_seconds"] = int(
                env_overrides["security.session_timeout_seconds"]
            )
        
        # Build logging configuration
        logging_kwargs: dict[str, Any] = {}
        if "logging.level" in env_overrides:
            logging_kwargs["level"] = env_overrides["logging.level"]
        if "logging.enable_console" in env_overrides:
            logging_kwargs["enable_console"] = env_overrides["logging.enable_console"].lower() == "true"
        if "logging.enable_file" in env_overrides:
            logging_kwargs["enable_file"] = env_overrides["logging.enable_file"].lower() == "true"
        
        # Build app configuration (debug_mode cannot be overridden via env for security)
        app_kwargs: dict[str, Any] = {}
        
        return cls(
            paths=PathConfig(**paths_kwargs) if paths_kwargs else None,
            security=SecurityConfig(**security_kwargs) if security_kwargs else None,
            logging=LoggingConfig(**logging_kwargs) if logging_kwargs else None,
            app=AppConfig(**app_kwargs) if app_kwargs else None,
        )
    
    @staticmethod
    def _parse_env_overrides(prefix: str) -> dict[str, str]:
        """Parse environment variables with the given prefix."""
        overrides: dict[str, str] = {}
        prefix_upper = f"{prefix.upper()}_"
        
        for key, value in os.environ.items():
            if key.startswith(prefix_upper):
                # Convert SECUREVAULT_SECTION__KEY to section.key
                config_key = key[len(prefix_upper):].lower().replace("__", ".")
                
                # SECURITY: Skip sensitive keys from environment
                if _is_sensitive_key(config_key):
                    continue
                    
                overrides[config_key] = value
        
        return overrides
    
    @classmethod
    def get_instance(cls) -> SecureConfig:
        """
        Get or create the singleton configuration instance.
        
        Returns:
            The global SecureConfig instance
        """
        if cls._instance is None:
            cls._instance = cls.load()
        return cls._instance
    
    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance. Use only for testing."""
        cls._instance = None
    
    def ensure_directories(self) -> None:
        """Create all required directories with secure permissions."""
        import stat
        
        directories = [
            self._paths.data_dir,
            self._paths.config_dir,
            self._paths.log_dir,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            
            # Set restrictive permissions on Unix-like systems
            if platform.system().lower() != "windows":
                directory.chmod(stat.S_IRWXU)  # 700 - owner only
    
    def __repr__(self) -> str:
        """Safe string representation without sensitive data."""
        return f"SecureConfig(hash={self._config_hash}, app={self._app.app_name})"
    
    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent modification after initialization."""
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError("SecureConfig is immutable after initialization")
        super().__setattr__(name, value)


class SecurityWarning(UserWarning):
    """Warning for security-related configuration issues."""
    pass
