"""
Secure error handling with sanitized messages
"""

import logging
import os
from typing import Dict, Any, Optional, Type, Tuple, List
import traceback
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class SecureError(Exception):
    """Base class for secure errors"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        self.error_id = self._generate_error_id()
        super().__init__(self.message)
    
    def _generate_error_id(self) -> str:
        """Generate a unique ID for this error for tracing"""
        timestamp = datetime.utcnow().isoformat()
        unique_data = f"{timestamp}:{self.message}:{id(self)}"
        return hashlib.sha256(unique_data.encode()).hexdigest()[:12]
    
    def log_error(self):
        """Log the error details securely"""
        # Sanitize any sensitive details
        safe_details = self._sanitize_details()
        
        # Log with error ID for tracing
        logger.error(
            f"Error {self.error_id}: {self.message}",
            extra={"error_details": safe_details}
        )
    
    def _sanitize_details(self) -> Dict[str, Any]:
        """Remove sensitive information from error details"""
        if not self.details:
            return {}
        
        # Deep copy to avoid modifying the original
        sanitized = dict(self.details)
        
        # Keys that might contain sensitive data
        sensitive_keys = {
            'password', 'key', 'token', 'secret', 'auth',
            'credential', 'private', 'signature'
        }
        
        # Sanitize nested dictionaries
        def sanitize_dict(d):
            for key in list(d.keys()):
                # Check if key contains sensitive information
                if any(pattern in key.lower() for pattern in sensitive_keys):
                    d[key] = '[REDACTED]'
                # Recurse into nested dicts
                elif isinstance(d[key], dict):
                    d[key] = sanitize_dict(d[key])
                # Sanitize lists that might contain dicts
                elif isinstance(d[key], list):
                    d[key] = [
                        sanitize_dict(item) if isinstance(item, dict) else item
                        for item in d[key]
                    ]
            return d
        
        return sanitize_dict(sanitized)
    
    def get_user_message(self) -> str:
        """Get a sanitized message suitable for user display"""
        return f"Error: {self.message}. Reference: {self.error_id}"

class AuthenticationError(SecureError):
    """Authentication-related errors"""
    def get_user_message(self) -> str:
        return "Authentication failed"

class PermissionError(SecureError):
    """Permission-related errors"""
    def get_user_message(self) -> str:
        return "Permission denied"

class ValidationError(SecureError):
    """Input validation errors"""
    def get_user_message(self) -> str:
        return "Invalid input provided"

class FileOperationError(SecureError):
    """File operation errors"""
    def get_user_message(self) -> str:
        return "File operation failed"

class CryptoError(SecureError):
    """Cryptography-related errors"""
    def get_user_message(self) -> str:
        return "Encryption operation failed"

class ConfigurationError(SecureError):
    """Configuration-related errors"""
    def get_user_message(self) -> str:
        return "System configuration error"

class ErrorHandler:
    """
    Central error handler for securely managing and reporting errors
    """
    def __init__(self, error_log_path: Optional[str] = None):
        self.error_log_path = Path(error_log_path) if error_log_path else None
        self._ensure_error_log_directory()
    
    def _ensure_error_log_directory(self):
        """Ensure error log directory exists with proper permissions"""
        if self.error_log_path:
            directory = self.error_log_path.parent
            if not directory.exists():
                directory.mkdir(parents=True)
                
                # Set secure permissions on Unix systems
                if os.name == 'posix':
                    import stat
                    os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    
    def handle_exception(self, exc: Exception, user_context: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        """
        Handle an exception securely
        
        Returns:
            Tuple of (user_message, error_id)
        """
        # Default user message for unknown errors
        user_message = "An unexpected error occurred"
        error_id = hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).hexdigest()[:12]
        
        try:
            # For our secure errors, use their built-in handling
            if isinstance(exc, SecureError):
                exc.log_error()
                return exc.get_user_message(), exc.error_id
            
            # For standard exceptions, create an appropriate wrapper
            mapped_error = self._map_exception(exc, user_context)
            mapped_error.log_error()
            return mapped_error.get_user_message(), mapped_error.error_id
            
        except Exception as e:
            # Last resort error handling
            logger.error(f"Error handler failed: {e}")
            return user_message, error_id
    
    def _map_exception(self, exc: Exception, context: Optional[Dict[str, Any]] = None) -> SecureError:
        """Map standard exceptions to our secure errors"""
        context = context or {}
        
        # Add exception info to context
        error_context = {
            'original_exception': exc.__class__.__name__,
            'traceback_hash': hashlib.sha256(
                str(traceback.format_exc()).encode()
            ).hexdigest()[:16],
            **context
        }
        
        # Map common exceptions to our secure types
        if isinstance(exc, (PermissionError, OSError)) and getattr(exc, 'errno', 0) in (13, 30):
            return PermissionError(str(exc), error_context)
        elif isinstance(exc, (FileNotFoundError, IsADirectoryError, NotADirectoryError)):
            return FileOperationError(str(exc), error_context)
        elif isinstance(exc, (ValueError, TypeError, AttributeError)):
            return ValidationError(str(exc), error_context)
        elif isinstance(exc, (ModuleNotFoundError, ImportError, KeyError)):
            return ConfigurationError(str(exc), error_context)
        else:
            # Generic secure error for unknown exceptions
            return SecureError(f"Unexpected error: {exc.__class__.__name__}", error_context)
    
    def log_detailed_error(self, error_id: str, exc: Exception, context: Dict[str, Any] = None):
        """Log detailed error information to a secure file"""
        if not self.error_log_path:
            return
        
        try:
            # Create error report
            context = context or {}
            error_report = {
                'error_id': error_id,
                'timestamp': datetime.utcnow().isoformat(),
                'exception_type': exc.__class__.__name__,
                'exception_message': str(exc),
                'python_version': sys.version,
                'traceback': traceback.format_exc(),
                'context': context
            }
            
            # Sanitize report
            self._sanitize_error_report(error_report)
            
            # Append to log file
            with open(self.error_log_path, 'a') as f:
                f.write(json.dumps(error_report) + '\n')
                
            # Set secure permissions on Unix systems
            if os.name == 'posix' and self.error_log_path.exists():
                import stat
                os.chmod(self.error_log_path, stat.S_IRUSR | stat.S_IWUSR)
                
        except Exception as e:
            logger.error(f"Failed to log detailed error: {e}")
    
    def _sanitize_error_report(self, report: Dict[str, Any]):
        """Remove sensitive information from error report"""
        # Keys that might contain sensitive data
        sensitive_keys = {
            'password', 'key', 'token', 'secret', 'auth',
            'credential', 'private', 'signature'
        }
        
        def sanitize_value(value):
            if isinstance(value, dict):
                return sanitize_dict(value)
            elif isinstance(value, list):
                return [sanitize_value(item) for item in value]
            elif isinstance(value, str):
                # Redact potential sensitive data in strings
                for key in sensitive_keys:
                    if key in value.lower():
                        parts = value.lower().split(key)
                        if len(parts) > 1:
                            return value[:len(parts[0]) + len(key)] + '[REDACTED]'
                return value
            else:
                return value
        
        def sanitize_dict(d):
            result = {}
            for key, value in d.items():
                if any(pattern in key.lower() for pattern in sensitive_keys):
                    result[key] = '[REDACTED]'
                else:
                    result[key] = sanitize_value(value)
            return result
        
        # Sanitize the entire report
        for key in list(report.keys()):
            report[key] = sanitize_value(report[key])
        
        # Always sanitize traceback specially
        if 'traceback' in report:
            # Remove potentially sensitive data from traceback
            lines = report['traceback'].split('\n')
            sanitized_lines = []
            for line in lines:
                sanitized_line = line
                for pattern in sensitive_keys:
                    if pattern in line.lower():
                        parts = line.lower().split(pattern)
                        if len(parts) > 1:
                            index = len(parts[0]) + len(pattern)
                            sanitized_line = line[:index] + '[REDACTED]'
                            break
                sanitized_lines.append(sanitized_line)
            report['traceback'] = '\n'.join(sanitized_lines)

# Global error handler instance
error_handler = ErrorHandler(error_log_path='./logs/detailed_errors.log')