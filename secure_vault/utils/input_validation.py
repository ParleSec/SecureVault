"""
Secure input validation for user data
"""

import os
import re
from pathlib import Path
from typing import Union, Optional, Dict, Any, List, Callable, TypeVar, Pattern, Tuple
import logging
import string
import hashlib
from ..security.errors import ValidationError

logger = logging.getLogger(__name__)

T = TypeVar('T')

class InputValidator:
    """Base validator for secure input validation"""
    def __init__(self, error_message: str = "Invalid input"):
        self.error_message = error_message
    
    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate input
        Returns (is_valid, error_message)
        """
        raise NotImplementedError("Subclasses must implement validate()")
    
    def __call__(self, value: Any) -> bool:
        """Make validator callable"""
        valid, _ = self.validate(value)
        return valid

class PathValidator(InputValidator):
    """Validate file paths for security"""
    def __init__(self, 
                base_dir: Optional[Path] = None,
                allow_create: bool = False,
                allow_symlinks: bool = False,
                allowed_extensions: Optional[List[str]] = None,
                error_message: str = "Invalid or insecure path"):
        super().__init__(error_message)
        self.base_dir = Path(base_dir) if base_dir else None
        self.allow_create = allow_create
        self.allow_symlinks = allow_symlinks
        self.allowed_extensions = allowed_extensions
    
    def validate(self, path: Union[str, Path]) -> Tuple[bool, Optional[str]]:
        """Validate a file path"""
        try:
            path = Path(path)
            
            # Check if path exists or creation is allowed
            if not path.exists() and not self.allow_create:
                return False, f"Path does not exist: {path}"
            
            # Handle symlinks
            if path.is_symlink() and not self.allow_symlinks:
                return False, f"Symlinks are not allowed: {path}"
            
            # Check base directory restriction
            if self.base_dir:
                try:
                    # Resolve to catch directory traversal attempts
                    resolved_path = path.resolve()
                    resolved_base = self.base_dir.resolve()
                    
                    if not str(resolved_path).startswith(str(resolved_base)):
                        return False, f"Path outside allowed directory: {path}"
                except (ValueError, RuntimeError):
                    return False, f"Invalid path resolution: {path}"
            
            # Check extensions if specified
            if self.allowed_extensions and path.suffix.lower() not in self.allowed_extensions:
                ext_list = ', '.join(self.allowed_extensions)
                return False, f"Extension not allowed. Must be one of: {ext_list}"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return False, self.error_message

class StringValidator(InputValidator):
    """Validate string input for security"""
    def __init__(self,
                min_length: int = 1,
                max_length: int = 255,
                allowed_pattern: Optional[Pattern] = None,
                disallowed_chars: Optional[str] = None,
                strip: bool = True,
                error_message: str = "Invalid string input"):
        super().__init__(error_message)
        self.min_length = min_length
        self.max_length = max_length
        self.allowed_pattern = allowed_pattern
        self.disallowed_chars = disallowed_chars
        self.strip = strip
    
    def validate(self, value: str) -> Tuple[bool, Optional[str]]:
        """Validate a string"""
        try:
            if not isinstance(value, str):
                return False, f"Value must be a string, got {type(value).__name__}"
            
            # Clean input if requested
            if self.strip:
                value = value.strip()
            
            # Check length
            if len(value) < self.min_length:
                return False, f"Input too short (minimum {self.min_length} characters)"
            
            if len(value) > self.max_length:
                return False, f"Input too long (maximum {self.max_length} characters)"
            
            # Check pattern if specified
            if self.allowed_pattern and not self.allowed_pattern.match(value):
                return False, f"Input does not match required pattern"
            
            # Check disallowed characters
            if self.disallowed_chars:
                for char in self.disallowed_chars:
                    if char in value:
                        return False, f"Input contains disallowed character: {char}"
            
            return True, None
            
        except Exception as e:
            logger.error(f"String validation error: {e}")
            return False, self.error_message

class PasswordValidator(InputValidator):
    """Validate password strength"""
    def __init__(self,
                min_length: int = 12,
                require_uppercase: bool = True,
                require_lowercase: bool = True,
                require_digits: bool = True,
                require_special: bool = True,
                disallow_common: bool = True,
                error_message: str = "Password does not meet security requirements"):
        super().__init__(error_message)
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digits = require_digits
        self.require_special = require_special
        self.disallow_common = disallow_common
        
        # Common password fragments to check against
        self.common_patterns = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'letmein', 'monkey', 'abc123', 'football', 'iloveyou',
            'access', 'master', 'shadow', 'diamond', 'secret',
            '1234', 'baseball', 'dragon', 'solo', 'princess'
        ]
    
    def validate(self, password: str) -> Tuple[bool, Optional[str]]:
        """Validate password strength"""
        try:
            # Check length
            if len(password) < self.min_length:
                return False, f"Password too short (minimum {self.min_length} characters)"
            
            # Check character requirements
            if self.require_uppercase and not any(c.isupper() for c in password):
                return False, "Password must contain at least one uppercase letter"
            
            if self.require_lowercase and not any(c.islower() for c in password):
                return False, "Password must contain at least one lowercase letter"
            
            if self.require_digits and not any(c.isdigit() for c in password):
                return False, "Password must contain at least one digit"
            
            if self.require_special:
                special_chars = set(string.punctuation)
                if not any(c in special_chars for c in password):
                    return False, "Password must contain at least one special character"
            
            # Check against common passwords
            if self.disallow_common:
                password_lower = password.lower()
                for pattern in self.common_patterns:
                    if pattern in password_lower:
                        return False, f"Password contains a common pattern"
            
            # Check password entropy
            entropy = self._calculate_entropy(password)
            if entropy < 50:  # Minimum recommended entropy
                return False, "Password not complex enough"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Password validation error: {e}")
            return False, self.error_message
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        # Count character classes used
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        # Calculate character pool size
        char_pool = 0
        if has_upper: char_pool += 26
        if has_lower: char_pool += 26
        if has_digit: char_pool += 10
        if has_special: char_pool += len(string.punctuation)
        
        # Calculate entropy: log2(char_pool) * length
        import math
        if char_pool == 0:
            return 0
        entropy = math.log2(char_pool) * len(password)
        return entropy

class ContentTypeValidator(InputValidator):
    """Validate content type/MIME type"""
    def __init__(self, 
                allowed_types: List[str],
                error_message: str = "Invalid or disallowed content type"):
        super().__init__(error_message)
        self.allowed_types = [t.lower() for t in allowed_types]
    
    def validate(self, content_type: str) -> Tuple[bool, Optional[str]]:
        """Validate content type string"""
        try:
            if not content_type or not isinstance(content_type, str):
                return False, "Content type must be a non-empty string"
            
            # Normalize and check
            content_type = content_type.lower().strip()
            
            # Extract main type for wildcard matching
            main_type = content_type.split('/')[0]
            
            for allowed in self.allowed_types:
                # Exact match
                if content_type == allowed:
                    return True, None
                
                # Wildcard match (e.g., "image/*")
                if allowed.endswith('/*') and main_type == allowed.split('/')[0]:
                    return True, None
            
            return False, f"Content type '{content_type}' not allowed"
            
        except Exception as e:
            logger.error(f"Content type validation error: {e}")
            return False, self.error_message

class SecurityValidator:
    """
    Validates input for security concerns like injection, XSS, etc.
    """
    def __init__(self):
        # Regex patterns for common attacks
        self.sql_injection_pattern = re.compile(
            r"(?:')|(?:--)|(?:;)|(?:/\*)|(?:\bORDER\b)|(?:\bUNION\b)|(?:\bSELECT\b)|"
            r"(?:\bDELETE\b)|(?:\bDROP\b)|(?:\bUPDATE\b)|(?:\bINSERT\b)",
            re.IGNORECASE
        )
        
        self.xss_pattern = re.compile(
            r"(?:<script.*?>)|(?:<.*?javascript:.*?>)|(?:<.*?onload=.*?>)|"
            r"(?:<.*?onclick=.*?>)|(?:<.*?onerror=.*?>)",
            re.IGNORECASE
        )
        
        self.path_traversal_pattern = re.compile(r"(?:\.\./)|(?:\.\.\\)")
        
        self.command_injection_pattern = re.compile(
            r"(?:;)|(?:\|)|(?:&&)|(?:\|\|)|(?:\`)|(?:\$\()",
            re.IGNORECASE
        )
    
    def check_sql_injection(self, value: str) -> Tuple[bool, Optional[str]]:
        """Check for SQL injection attempts"""
        if self.sql_injection_pattern.search(value):
            return False, "Potential SQL injection detected"
        return True, None
    
    def check_xss(self, value: str) -> Tuple[bool, Optional[str]]:
        """Check for XSS attempts"""
        if self.xss_pattern.search(value):
            return False, "Potential XSS attack detected"
        return True, None
    
    def check_path_traversal(self, value: str) -> Tuple[bool, Optional[str]]:
        """Check for path traversal attempts"""
        if self.path_traversal_pattern.search(value):
            return False, "Potential path traversal attack detected"
        return True, None
    
    def check_command_injection(self, value: str) -> Tuple[bool, Optional[str]]:
        """Check for command injection attempts"""
        if self.command_injection_pattern.search(value):
            return False, "Potential command injection detected"
        return True, None
    
    def validate_input(self, value: str, 
                      check_sql: bool = True,
                      check_xss: bool = True,
                      check_path: bool = True,
                      check_command: bool = True) -> Tuple[bool, Optional[str]]:
        """Validate input for all security concerns"""
        if not isinstance(value, str):
            return True, None  # Non-string inputs are validated elsewhere
        
        # Run all requested checks
        if check_sql:
            valid, error = self.check_sql_injection(value)
            if not valid:
                return False, error
        
        if check_xss:
            valid, error = self.check_xss(value)
            if not valid:
                return False, error
        
        if check_path:
            valid, error = self.check_path_traversal(value)
            if not valid:
                return False, error
        
        if check_command:
            valid, error = self.check_command_injection(value)
            if not valid:
                return False, error
        
        return True, None

def validate_or_raise(value: Any, validator: InputValidator, error_context: Dict[str, Any] = None):
    """
    Validate input or raise a validation error
    """
    valid, error = validator.validate(value)
    if not valid:
        raise ValidationError(error or validator.error_message, error_context)
    return value

# Create global security validator
security_validator = SecurityValidator()