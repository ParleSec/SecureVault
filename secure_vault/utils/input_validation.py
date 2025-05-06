"""
Secure input validation for user data
"""
import os
import re
from pathlib import Path
from typing import Union, Optional, Dict, Any, List, Callable, TypeVar, Pattern, Tuple
import logging
import string
import urllib.parse
import html
from ..security.errors import ValidationError

# Import third-party libraries if available
try:
    import bleach  # For HTML sanitization
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False

try:
    from sqlparse import parse as parse_sql  # For SQL parsing
    SQL_PARSE_AVAILABLE = True
except ImportError:
    SQL_PARSE_AVAILABLE = False

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
            
            # Normalize path to handle different representations
            try:
                normalized_path = path.resolve()
            except (ValueError, RuntimeError):
                return False, f"Invalid path resolution: {path}"
            
            # Check for path traversal attempts by looking for suspicious patterns
            path_str = str(path).replace('\\', '/')
            decoded_path = urllib.parse.unquote(path_str)
            
            # Check for different path traversal patterns
            traversal_patterns = [
                '../', '..\\', '%2e%2e/', '%2e%2e\\', '..%2f', '..%5c',
                '....///', '....\\\\\\'
            ]
            
            for pattern in traversal_patterns:
                if pattern in decoded_path:
                    return False, f"Path traversal attempt detected: {path}"
            
            # Check if path exists or creation is allowed
            if not path.exists() and not self.allow_create:
                return False, f"Path does not exist: {path}"
            
            # Handle symlinks
            if path.is_symlink() and not self.allow_symlinks:
                return False, f"Symlinks are not allowed: {path}"
            
            # Check base directory restriction
            if self.base_dir:
                resolved_base = self.base_dir.resolve()
                
                # Ensure path is within base directory
                if not str(normalized_path).startswith(str(resolved_base)):
                    return False, f"Path outside allowed directory: {path}"
            
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
        
        # Common password fragments to check against - expanded list
        self.common_patterns = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'letmein', 'monkey', 'abc123', 'football', 'iloveyou',
            'access', 'master', 'shadow', 'diamond', 'secret',
            '1234', 'baseball', 'dragon', 'solo', 'princess',
            'passw0rd', 'p@ssw0rd', 'admin123', 'welcome123',
            '123abc', '12345', 'trustno1', 'sunshine', '654321',
            'superman', 'qazwsx', 'michael', 'football1', 'jennifer',
            'jordan23', 'password1', 'hunter2'
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
            
            # Check against common passwords - with enhanced normalization
            if self.disallow_common:
                # Normalize password for pattern checking
                # Convert to lowercase and remove common substitutions
                normalized = password.lower()
                substitutions = {
                    '0': 'o', '1': 'i', '3': 'e', '4': 'a', 
                    '5': 's', '7': 't', '@': 'a', '$': 's'
                }
                
                for k, v in substitutions.items():
                    normalized = normalized.replace(k, v)
                
                for pattern in self.common_patterns:
                    if pattern in normalized:
                        return False, f"Password contains a common pattern"
            
            # Check password entropy
            entropy = self._calculate_entropy(password)
            if entropy < 60:  # Increased minimum recommended entropy
                return False, "Password not complex enough"
            
            # Check for repeated patterns (e.g., 'abcabc')
            for i in range(2, len(password) // 2 + 1):
                for j in range(len(password) - i * 2 + 1):
                    if password[j:j+i] == password[j+i:j+2*i]:
                        return False, "Password contains repeated patterns"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Password validation error: {e}")
            return False, self.error_message
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        import math
        
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
        
        # Calculate base entropy: log2(char_pool) * length
        if char_pool == 0:
            return 0
            
        base_entropy = math.log2(char_pool) * len(password)
        
        # Calculate character distribution entropy (penalize repetition)
        char_counts = {}
        for c in password:
            char_counts[c] = char_counts.get(c, 0) + 1
        
        distribution_entropy = 0
        for c, count in char_counts.items():
            p = count / len(password)
            distribution_entropy -= p * math.log2(p)
        
        # Combine both entropy calculations
        return base_entropy * 0.75 + (distribution_entropy * len(password) * 4)

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
            
            # Handle parameters in content type (e.g., text/plain; charset=utf-8)
            main_content_type = content_type.split(';')[0].strip()
            
            # Extract main type for wildcard matching
            main_type = main_content_type.split('/')[0]
            
            for allowed in self.allowed_types:
                # Exact match
                if main_content_type == allowed:
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
    Enhanced validator for security concerns like injection, XSS, etc.
    Uses multiple detection strategies beyond regex.
    """
    def __init__(self):
        # Enhanced regex patterns for common attacks
        
        # SQL Injection
        self.sql_injection_pattern = re.compile(
            # Basic SQL patterns
            r"(?:'(?:'')?)|"  # Single quotes (including SQL Server style escaping)
            r"(?:--(?:[ \t]|$))|"  # SQL comments
            r"(?:;(?:[ \t]|$))|"  # Statement terminator
            r"(?:/\*(?:.|[\r\n])*?\*/)|"  # Block comments
            r"(?:#(?:[ \t]|$))|"  # MySQL/PostgreSQL comment
            # SQL keywords that might indicate injection
            r"(?:\b(?:UNION(?:\s+ALL)?|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|"
            r"ALTER|CREATE|TRUNCATE|DECLARE|EXEC(?:UTE)?|CAST|OR|AND|XOR|"
            r"SLEEP|WAITFOR|BENCHMARK|HAVING|GROUP\s+BY|ORDER\s+BY|LIMIT)\b)",
            re.IGNORECASE | re.MULTILINE
        )
        
        # XSS
        self.xss_pattern = re.compile(
            # Script tags
            r"(?:<script[^>]*>.*?</script>)|"
            # Inline event handlers
            r"(?:<[^>]*\s+on(?:abort|blur|change|click|dblclick|dragdrop|error|focus|"
            r"keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|"
            r"mouseup|reset|resize|select|submit|unload)(?:\s*=|\s*:)\s*[\"']?[^>]*>)|"
            # JavaScript URLs
            r"(?:<[^>]*(?:href|src|style|formaction)\s*=\s*[\"']?\s*(?:javascript|vbscript|"
            r"data:text/html|data:application/javascript|data:application/x-javascript)[^>]*>)|"
            # CSS expressions
            r"(?:<[^>]*style\s*=\s*[\"']?\s*[^\"']*expression\s*\([^>]*>)|"
            # Other dangerous attributes
            r"(?:<[^>]*(?:fscommand|seeksegmenttime)[^>]*>)|"
            # SVG events
            r"(?:<svg[^>]*>[^<]*<(?:script|animate|set)[^>]*>)|"
            # Meta refresh/redirect
            r"(?:<meta[^>]*(?:http-equiv\s*=\s*[\"']?refresh[\"']?)[^>]*>)|"
            # Entity encoding
            r"(?:&#x[0-9a-f]{2,6};)|(?:&#[0-9]{2,6};)",
            re.IGNORECASE | re.DOTALL
        )
        
        # Path Traversal
        self.path_traversal_pattern = re.compile(
            r"(?:\.\./)|"  # Standard directory traversal
            r"(?:\.\.\\)|"  # Windows directory traversal
            r"(?:%2e%2e/)|"  # URL encoded directory traversal
            r"(?:%2e%2e\\)|"  # URL encoded Windows directory traversal
            r"(?:\.\.%2f)|"  # Mixed encoding
            r"(?:\.\.%5c)|"  # Mixed encoding Windows
            r"(?:\.\\\./)|"  # Obfuscated traversal
            r"(?:%252e%252e/)|"  # Double URL encoding
            r"(?:\.\.%c0%af)|"  # UTF-8 overlong encoding
            r"(?:\.\.%c1%9c)",  # UTF-8 overlong encoding
            re.IGNORECASE
        )
        
        # Command Injection
        self.command_injection_pattern = re.compile(
            r"(?:;[ \t]*(?:\w+[ \t]+)*[\w/\\]+)|"  # Command chaining with semicolon
            r"(?:\|[ \t]*(?:\w+[ \t]+)*[\w/\\]+)|"  # Pipe operator
            r"(?:\|\|[ \t]*(?:\w+[ \t]+)*[\w/\\]+)|"  # Logical OR operator
            r"(?:&[ \t]*(?:\w+[ \t]+)*[\w/\\]+)|"  # Background execution
            r"(?:&&[ \t]*(?:\w+[ \t]+)*[\w/\\]+)|"  # Logical AND operator
            r"(?:`[^`]*`)|"  # Backtick execution
            r"(?:\$\([^)]*\))|"  # Command substitution
            r"(?:\$\{[^}]*\})|"  # Variable substitution
            r"(?:\n[ \t]*(?:\w+[ \t]+)*[\w/\\]+)|"  # Newline injection
            r"(?:%0[ad](?:\w+[ \t]+)*[\w/\\]+)|"  # URL encoded newline
            r"(?:/bin/(?:ba)?sh)|"  # Direct shell execution
            r"(?:curl|wget|nc|python|perl|ruby|php)[ \t]",  # Common command names
            re.IGNORECASE | re.MULTILINE
        )
        
        # Common dangerous file extensions
        self.dangerous_extensions = [
            '.php', '.phtml', '.php3', '.php4', '.php5', '.pht',  # PHP
            '.asp', '.aspx', '.cshtml', '.vbhtml',  # ASP.NET
            '.jsp', '.jspx', '.jsw', '.jsv', '.jspf',  # Java
            '.pl', '.py', '.rb', '.cgi', '.sh', '.bash',  # Scripts
            '.exe', '.dll', '.so', '.bat', '.cmd',  # Executables
            '.htaccess', '.config', '.conf',  # Configuration files
            '.swf',  # Flash
        ]
    
    def check_sql_injection(self, value: str) -> Tuple[bool, Optional[str]]:
        """Advanced check for SQL injection attempts using multiple methods"""
        # Skip empty values
        if not value:
            return True, None
            
        # Method 1: Basic regex pattern detection
        if self.sql_injection_pattern.search(value):
            return False, "Potential SQL injection detected"
            
        # Method 2: Check for encoded attack patterns
        # Decode URL-encoded strings
        decoded_value = urllib.parse.unquote(value)
        if decoded_value != value and self.sql_injection_pattern.search(decoded_value):
            return False, "Potential SQL injection detected (URL encoded)"
            
        # Method 3: Use sqlparse to detect SQL structure if available
        if SQL_PARSE_AVAILABLE:
            try:
                # Try to parse as SQL and check for multiple statements
                parsed = parse_sql(value)
                if len(parsed) > 1:
                    return False, "Multiple SQL statements detected"
                    
                # Check for suspicious keywords in parsed SQL
                for statement in parsed:
                    stmt_str = str(statement).lower()
                    if any(keyword in stmt_str for keyword in [
                        'union', 'select', 'from', 'where', 'insert', 'update', 'delete',
                        'drop', 'alter', 'create', 'truncate'
                    ]):
                        return False, "SQL keywords detected in input"
            except Exception:
                # If parsing fails, continue with other checks
                pass
                
        # Method 4: Check for specific evasion techniques
        evasions = [
            # Character encoding
            "char(", "chr(", "ASCII(", "UNHEX(", 
            # String concatenation
            "||", "concat(", "+", 
            # Comments to break keywords
            "sel/**/ect", "un/**/ion", "1 /*! or 1=1 */",
            # Alternative whitespace
            "\t", "\n", "\r", "\x0b", "\x0c"
        ]
        
        for evasion in evasions:
            if evasion in value.lower():
                return False, f"Potential SQL injection evasion technique detected"
        
        return True, None
    
    def check_xss(self, value: str) -> Tuple[bool, Optional[str]]:
        """Advanced check for XSS attempts using multiple methods"""
        # Skip empty values
        if not value:
            return True, None
            
        # Method 1: Basic regex pattern detection
        if self.xss_pattern.search(value):
            return False, "Potential XSS attack detected"
            
        # Method 2: Check for encoded attack patterns
        # Decode HTML entities and URL-encoded strings
        decoded_value = html.unescape(urllib.parse.unquote(value))
        if decoded_value != value and self.xss_pattern.search(decoded_value):
            return False, "Potential XSS attack detected (encoded)"
            
        # Method 3: Use bleach to sanitize HTML if available
        if BLEACH_AVAILABLE:
            cleaned = bleach.clean(value)
            if cleaned != value:
                return False, "Potentially unsafe HTML detected"
                
        # Method 4: Check for specific evasion techniques
        evasions = [
            # Protocol handlers
            "javascript:", "vbscript:", "data:", "about:", 
            # Script obfuscation
            "\\x", "\\u", "%u", "&#", "\\74",
            # Event handlers not covered by regex
            "onactivate", "onbeforeactivate", "onbeforecopy", "onbeforecut", 
            "onbeforedeactivate", "onbeforepaste", "onbeforeprint", 
            "onbeforeunload", "onbegin", "onbounce", "oncellchange", 
            "oncontextmenu", "oncontrolselect", "oncopy", "oncut", 
            "ondataavailable", "ondatasetchanged", "ondatasetcomplete", 
            "ondeactivate", "ondrag", "ondragdrop", "ondragend", "ondragenter", 
            "ondragleave", "ondragover", "ondragstart", "ondrop", "onend", 
            "onerror", "onerrorupdate", "onfilterchange", "onfinish", 
            "onfocusin", "onfocusout", "onhelp", "onlayoutcomplete", 
            "onlosecapture", "onmouseenter", "onmouseleave", "onmousewheel", 
            "onmove", "onmoveend", "onmovestart", "onpaste", "onpropertychange", 
            "onreadystatechange", "onreset", "onresize", "onresizeend", 
            "onresizestart", "onrowenter", "onrowexit", "onrowsdelete", 
            "onrowsinserted", "onscroll", "onselect", "onselectionchange", 
            "onselectstart", "onstart", "onstop", "ontimeerror"
        ]
        
        for evasion in evasions:
            if evasion.lower() in value.lower():
                return False, f"Potential XSS evasion technique detected"
        
        return True, None
    
    def check_path_traversal(self, value: str) -> Tuple[bool, Optional[str]]:
        """Advanced check for path traversal attempts"""
        # Skip empty values
        if not value:
            return True, None
            
        # Method 1: Basic regex pattern detection
        if self.path_traversal_pattern.search(value):
            return False, "Potential path traversal attack detected"
            
        # Method 2: Check for encoded attack patterns
        # Decode repeatedly to catch multiple encoding layers
        decoded = value
        for _ in range(3):  # Try decoding up to 3 times
            new_decoded = urllib.parse.unquote(decoded)
            if new_decoded == decoded:  # No more decoding possible
                break
            decoded = new_decoded
            
            if self.path_traversal_pattern.search(decoded):
                return False, "Potential path traversal attack detected (encoded)"
                
        # Method 3: Check for normalized path traversal
        path_obj = None
        try:
            path_obj = Path(value).resolve()
            path_str = str(path_obj)
            
            # Look for suspicious sequences in the resolved path
            if ".." in path_str:
                return False, "Path contains traversal sequence after resolution"
        except Exception:
            # If path resolution fails, it might be a malicious path
            return False, "Invalid path format"
            
        # Method 4: Check for dangerous file extensions
        if path_obj:
            suffix = path_obj.suffix.lower()
            if suffix in self.dangerous_extensions:
                return False, f"Path contains potentially dangerous file extension: {suffix}"
        
        return True, None
    
    def check_command_injection(self, value: str) -> Tuple[bool, Optional[str]]:
        """Advanced check for command injection attempts"""
        # Skip empty values
        if not value:
            return True, None
            
        # Method 1: Basic regex pattern detection
        if self.command_injection_pattern.search(value):
            return False, "Potential command injection detected"
            
        # Method 2: Check for encoded attack patterns
        # Decode URL-encoded strings
        decoded_value = urllib.parse.unquote(value)
        if decoded_value != value and self.command_injection_pattern.search(decoded_value):
            return False, "Potential command injection detected (URL encoded)"
            
        # Method 3: Check for specific evasion techniques
        evasions = [
            # Command separators
            "`", "$", "&", "|", ";", "$(", "${", 
            # Whitespace alternatives
            "${IFS}", "$IFS", "{IFS}", 
            # Base64 execution
            "echo", "base64", "eval", "exec", 
            # Reverse shells
            "bash -i", "/dev/tcp", "netcat", "mkfifo", "socat",
            # Command substitution
            "$(", "`", "$((", "<<<", 
            # Null byte
            "\0", "%00"
        ]
        
        for evasion in evasions:
            if evasion in value:
                return False, f"Potential command injection evasion technique detected"
                
        # Method 4: Check for environment variable access
        env_vars = [
            "$PATH", "$HOME", "$USER", "$SHELL", "$PWD", 
            "$LANG", "$TZ", "$TERM", "$MAIL", "$PS1"
        ]
        
        for var in env_vars:
            if var in value:
                return False, f"Potential environment variable access detected"
        
        return True, None
    
    def validate_input(self, value: str, 
                      check_sql: bool = True,
                      check_xss: bool = True,
                      check_path: bool = True,
                      check_command: bool = True,
                      context: str = None) -> Tuple[bool, Optional[str]]:
        """
        Validate input for all security concerns with context awareness
        
        Args:
            value: The input string to validate
            check_sql: Whether to check for SQL injection
            check_xss: Whether to check for XSS
            check_path: Whether to check for path traversal
            check_command: Whether to check for command injection
            context: Optional context information to guide validation
                     (e.g., "sql", "html", "path", "command", "filename")
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(value, str):
            return True, None  # Non-string inputs are validated elsewhere
            
        # Adjust checks based on context if provided
        if context:
            context = context.lower()
            
            # Override default checks based on context
            if context == "sql":
                check_sql = True
                check_xss = False
                check_path = False
                check_command = False
            elif context in ("html", "xml", "markup"):
                check_sql = False
                check_xss = True
                check_path = False
                check_command = False
            elif context in ("path", "filename", "directory"):
                check_sql = False
                check_xss = False
                check_path = True
                check_command = False
            elif context in ("command", "shell", "exec"):
                check_sql = False
                check_xss = False
                check_path = False
                check_command = True
                
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

def validate_or_raise(value: Any, validator: InputValidator, 
                      error_context: Dict[str, Any] = None, 
                      context: str = None):
    """
    Validate input or raise a validation error with enhanced context awareness
    
    Args:
        value: Value to validate
        validator: Validator instance to use
        error_context: Additional context for the error
        context: Context hint for security validation
    
    Returns:
        Validated value if valid
        
    Raises:
        ValidationError if validation fails
    """
    # For string types, perform security validation first
    if isinstance(value, str) and isinstance(validator, (StringValidator, PathValidator)):
        security_validator = SecurityValidator()
        valid, error = security_validator.validate_input(value, context=context)
        if not valid:
            raise ValidationError(error, error_context)
    
    # Perform regular validation
    valid, error = validator.validate(value)
    if not valid:
        raise ValidationError(error or validator.error_message, error_context)
    
    return value

# Create global security validator
security_validator = SecurityValidator()