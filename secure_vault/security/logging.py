"""
Secure logging configuration and utilities
"""

import logging
import os
from pathlib import Path
import structlog
import json
from datetime import datetime
import stat
from typing import Dict, Any, Optional, Set

# Sensitive data patterns to be redacted
SENSITIVE_KEYS = {
    'password', 'key', 'token', 'secret', 'private', 
    'credentials', 'auth', 'jwt', 'signature'
}

def sanitize_log_data(record: logging.LogRecord) -> logging.LogRecord:
    """
    Sanitize sensitive data in log records before they're emitted.
    
    Args:
        record: The log record to sanitize
        
    Returns:
        The sanitized log record
    """
    # Skip if record doesn't have a message
    if not hasattr(record, 'msg') or not record.msg:
        return record
    
    # Patterns for sensitive data
    patterns = [
        # JWT tokens (base64 encoded strings with periods)
        (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', '[REDACTED_JWT]'),
        
        # Passwords in various formats
        (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'password=[REDACTED]'),
        (r'pass[wW]ord\s*[=:]\s*[^\s,;]+', 'password=[REDACTED]'),
        
        # API keys and tokens
        (r'api[-_]?key\s*[=:]\s*[^\s,;]+', 'api_key=[REDACTED]'),
        (r'token\s*[=:]\s*[^\s,;]+', 'token=[REDACTED]'),
        
        # Cookie values
        (r'cookie\s*[=:]\s*[^\s,;]+', 'cookie=[REDACTED]'),
        
        # Bearer token headers
        (r'Bearer\s+[A-Za-z0-9\._-]+', 'Bearer [REDACTED]'),
        
        # Basic auth headers
        (r'Basic\s+[A-Za-z0-9+/=]+', 'Basic [REDACTED]'),
    ]
    
    # Apply sanitization to the message string
    sanitized_msg = record.msg
    for pattern, replacement in patterns:
        sanitized_msg = re.sub(pattern, replacement, str(sanitized_msg))
    
    # Update the record with sanitized message
    record.msg = sanitized_msg
    
    # Also sanitize args if they exist
    if hasattr(record, 'args') and record.args:
        sanitized_args = []
        for arg in record.args:
            if isinstance(arg, str):
                for pattern, replacement in patterns:
                    arg = re.sub(pattern, replacement, arg)
            sanitized_args.append(arg)
        record.args = tuple(sanitized_args)
    
    return record

class SecureLogHandler:
    """
    Handles secure log file management with proper permissions
    """
    def __init__(self, log_dir: str, max_size_mb: int = 10, backup_count: int = 3):
        self.log_dir = Path(log_dir)
        self.max_size = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        
        # Create log directory with secure permissions
        self._ensure_secure_directory()
        
    def _ensure_secure_directory(self):
        """Ensure log directory exists with secure permissions"""
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True)
        
        # Set secure permissions on log directory
        if os.name == 'posix':
            os.chmod(self.log_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    
    def get_handler(self, log_name: str) -> logging.Handler:
        """Get a secure rotating file handler"""
        from logging.handlers import RotatingFileHandler
        
        log_file = self.log_dir / f"{log_name}.log"
        
        handler = RotatingFileHandler(
            log_file,
            maxBytes=self.max_size,
            backupCount=self.backup_count
        )
        
        # Set secure permissions for log file
        if os.name == 'posix' and log_file.exists():
            os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
        
        # Formatter for standard logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        return handler

class SecurityAuditLogger:
    """
    Specialized logger for security audit events
    """
    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / "security_audit.log"
        self._ensure_secure_directory()
        
    def _ensure_secure_directory(self):
        """Ensure log directory exists with secure permissions"""
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True)
        
        # Set secure permissions on log directory
        if os.name == 'posix':
            os.chmod(self.log_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], 
                          user: Optional[str] = None, success: bool = True):
        """Log a security-related event with proper sanitization"""
        # Create event data with timestamp
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'success': success,
            'user': user or 'unknown',
            'details': details
        }
        
        # Sanitize sensitive data
        sanitized_event = sanitize_log_data(None, None, event)
        
        # Write to log file with secure handling
        try:
            # Create file if doesn't exist
            if not self.log_file.exists() and os.name == 'posix':
                with open(self.log_file, 'w') as f:
                    pass
                os.chmod(self.log_file, stat.S_IRUSR | stat.S_IWUSR)
            
            # Append event to log
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(sanitized_event) + '\n')
                
        except Exception as e:
            # Fallback logging
            logging.error(f"Failed to write security audit log: {e}")

    def configure_logging(log_dir: str = './logs', 
                        console_level: int = logging.INFO,
                        file_level: int = logging.DEBUG):
        """
        Configure secure logging for the application with sensitive data sanitization
        """
        # Create secure log handler
        handler = SecureLogHandler(log_dir)
        
        # Add the sanitizer to the logging chain
        logging.setLogRecordFactory(sanitize_log_data)
        
        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                sanitize_log_data,  # Keep existing sanitizer too
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer()
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            cache_logger_on_first_use=True,
        )
        
        # Configure standard logging
        root_logger = logging.getLogger()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # File handler
        file_handler = handler.get_handler('app')
        file_handler.setLevel(file_level)
        
        # Configure root logger
        root_logger.handlers = []
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
        root_logger.setLevel(min(console_level, file_level))
        
        # Create security audit logger
        security_logger = SecurityAuditLogger(log_dir)
        
        return security_logger