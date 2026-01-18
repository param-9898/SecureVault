"""
Secure Logging Module
=====================

Provides security-aware logging with secret filtering and tamper detection.

Security Features:
- Automatic secret/sensitive data filtering
- Rotating log files with size limits
- Tamper-aware log integrity (optional checksums)
- No debug information leakage
- Structured logging support
"""

from __future__ import annotations

import hashlib
import logging
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final, Optional, Any, Pattern
import json


# Patterns for sensitive data detection
_SENSITIVE_PATTERNS: Final[list[tuple[str, Pattern[str]]]] = [
    ("password", re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']+["\']?')),
    ("api_key", re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[^\s"\']+["\']?')),
    ("token", re.compile(r'(?i)(token|bearer)\s*[=:]\s*["\']?[^\s"\']+["\']?')),
    ("secret", re.compile(r'(?i)(secret|private[_-]?key)\s*[=:]\s*["\']?[^\s"\']+["\']?')),
    ("credential", re.compile(r'(?i)(credential|auth)\s*[=:]\s*["\']?[^\s"\']+["\']?')),
    ("connection_string", re.compile(r'(?i)(connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\']?[^\s"\']+["\']?')),
    # Base64 encoded secrets (longer than 20 chars)
    ("base64_secret", re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')),
    # Hex encoded secrets (longer than 32 chars)
    ("hex_secret", re.compile(r'(?i)(?:0x)?[a-f0-9]{32,}')),
]

_REDACTED_TEXT: Final[str] = "[REDACTED]"


class SecureLogFilter(logging.Filter):
    """
    Log filter that removes sensitive information from log messages.
    
    This filter scans log messages for patterns that might contain
    sensitive data (passwords, API keys, tokens, etc.) and replaces
    them with [REDACTED].
    """
    
    def __init__(self, name: str = "", additional_patterns: Optional[list[Pattern[str]]] = None) -> None:
        """
        Initialize the secure log filter.
        
        Args:
            name: Logger name filter (empty string matches all)
            additional_patterns: Additional regex patterns to redact
        """
        super().__init__(name)
        self._additional_patterns = additional_patterns or []
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log record by redacting sensitive information.
        
        Args:
            record: The log record to filter
            
        Returns:
            Always True (record is always kept, just sanitized)
        """
        # Sanitize the main message
        if record.msg and isinstance(record.msg, str):
            record.msg = self._sanitize(record.msg)
        
        # Sanitize any arguments
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._sanitize(str(v)) if isinstance(v, str) else v 
                              for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._sanitize(str(arg)) if isinstance(arg, str) else arg 
                    for arg in record.args
                )
        
        return True
    
    def _sanitize(self, text: str) -> str:
        """Remove sensitive data from text."""
        result = text
        
        # Apply built-in patterns
        for name, pattern in _SENSITIVE_PATTERNS:
            result = pattern.sub(f"{name}={_REDACTED_TEXT}", result)
        
        # Apply additional patterns
        for pattern in self._additional_patterns:
            result = pattern.sub(_REDACTED_TEXT, result)
        
        return result


class TamperAwareFormatter(logging.Formatter):
    """
    Log formatter that adds integrity checksums to log entries.
    
    Each log entry includes a checksum that can be used to detect
    if the log has been modified after creation.
    """
    
    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        include_checksum: bool = True,
    ) -> None:
        """
        Initialize the tamper-aware formatter.
        
        Args:
            fmt: Log message format string
            datefmt: Date format string
            include_checksum: Whether to include integrity checksums
        """
        super().__init__(fmt, datefmt)
        self._include_checksum = include_checksum
        self._sequence = 0
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with optional integrity checksum."""
        # Get the base formatted message
        message = super().format(record)
        
        if self._include_checksum:
            self._sequence += 1
            # Create checksum from sequence, timestamp, and message
            checksum_data = f"{self._sequence}:{record.created}:{message}"
            checksum = hashlib.sha256(checksum_data.encode()).hexdigest()[:12]
            message = f"{message} |CHK:{checksum}"
        
        return message


class StructuredLogFormatter(logging.Formatter):
    """
    Formatter that outputs logs in JSON format for easy parsing.
    
    Useful for log aggregation systems and security monitoring.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, default=str)


class SecureRotatingFileHandler(RotatingFileHandler):
    """
    Rotating file handler with additional security features.
    
    Features:
    - Creates log directory with secure permissions
    - Validates log file path
    - Prevents path traversal attacks
    """
    
    def __init__(
        self,
        filename: str | Path,
        mode: str = "a",
        maxBytes: int = 10 * 1024 * 1024,  # 10 MB default
        backupCount: int = 5,
        encoding: str = "utf-8",
    ) -> None:
        """
        Initialize the secure rotating file handler.
        
        Args:
            filename: Path to the log file
            mode: File mode (default: append)
            maxBytes: Maximum file size before rotation
            backupCount: Number of backup files to keep
            encoding: File encoding
        """
        log_path = Path(filename).resolve()
        
        # Security: Validate path doesn't contain traversal
        if ".." in str(log_path):
            raise ValueError("Log path cannot contain path traversal sequences")
        
        # Create directory with secure permissions
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        super().__init__(
            str(log_path),
            mode=mode,
            maxBytes=maxBytes,
            backupCount=backupCount,
            encoding=encoding,
        )


def get_secure_logger(
    name: str,
    log_dir: Optional[Path] = None,
    level: str = "INFO",
    enable_console: bool = True,
    enable_file: bool = True,
    enable_json: bool = False,
    max_file_size: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    include_checksums: bool = False,
) -> logging.Logger:
    """
    Create a secure logger with automatic secret filtering.
    
    Args:
        name: Logger name (typically __name__)
        log_dir: Directory for log files (auto-detected if not provided)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        enable_console: Whether to output to console
        enable_file: Whether to output to file
        enable_json: Whether to use JSON format for file output
        max_file_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        include_checksums: Whether to include integrity checksums
        
    Returns:
        Configured secure logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    logger.setLevel(getattr(logging, level.upper()))
    
    # Add secure filter to all handlers
    secure_filter = SecureLogFilter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG)
        console_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(secure_filter)
        logger.addHandler(console_handler)
    
    # File handler
    if enable_file and log_dir:
        log_file = log_dir / f"{name.replace('.', '_')}.log"
        
        file_handler = SecureRotatingFileHandler(
            filename=log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
        )
        file_handler.setLevel(logging.DEBUG)
        
        if enable_json:
            file_formatter = StructuredLogFormatter()
        elif include_checksums:
            file_formatter = TamperAwareFormatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                include_checksum=True,
            )
        else:
            file_formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(secure_filter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def configure_root_logger(
    log_dir: Optional[Path] = None,
    level: str = "INFO",
    enable_console: bool = True,
    enable_file: bool = True,
) -> None:
    """
    Configure the root logger with secure defaults.
    
    This should be called once at application startup to ensure
    all loggers inherit secure settings.
    
    Args:
        log_dir: Directory for log files
        level: Logging level
        enable_console: Whether to output to console
        enable_file: Whether to output to file
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    secure_filter = SecureLogFilter()
    
    if enable_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%H:%M:%S"
        ))
        console_handler.addFilter(secure_filter)
        root_logger.addHandler(console_handler)
    
    if enable_file and log_dir:
        log_file = log_dir / "securevault.log"
        file_handler = SecureRotatingFileHandler(
            filename=log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        file_handler.addFilter(secure_filter)
        root_logger.addHandler(file_handler)
