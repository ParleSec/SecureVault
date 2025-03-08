"""
Secure API implementation with enhanced security measures.
Provides endpoints for authentication, file listing, encryption,
decryption, and deletion.
"""

from flask import Flask, request, jsonify, send_file, Response, g, abort, redirect, current_app
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import tempfile
from pathlib import Path
import os
from dotenv import load_dotenv
import time
import secrets
import logging
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
import sys
from werkzeug.utils import secure_filename
import base64
import json
import traceback
import random
import urllib.parse
import sqlite3

# Import persistent token blocklist
from secure_vault.web.token_blocklist import is_token_revoked as global_is_token_revoked
from secure_vault.web.token_blocklist import TokenBlocklist

# Import user management for authentication
from secure_vault.users.user_manager import UserManager

# Configure Admin_Key
root_dir = Path(__file__).parent.absolute()
env_path = root_dir / '.env'
load_dotenv(dotenv_path=env_path)
admin_key = os.getenv('SECUREVAULT_ADMIN_KEY')

if admin_key:
    print(f"Admin key loaded (length: {len(admin_key)})")
else:
    print("WARNING: SECUREVAULT_ADMIN_KEY not found in environment variables")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('secure_api.log')
    ]
)
logger = logging.getLogger(__name__)


def validate_url_path():
    """
    Validate URL path for security concerns before processing the request.
    This catches URL path issues that might bypass endpoint-specific validation.
    """
    # Skip for certain paths that are known to be safe
    if request.path == '/' or request.path.startswith('/static/'):
        return None
    
    # Skip authorization and options requests
    if request.method == 'OPTIONS':
        return None
    
    # Get API instance from current app
    api_instance = getattr(current_app, '_secure_api_instance', None)
    if not api_instance:
        return None  # Can't validate without API instance
    
    # Validate each path segment
    path_segments = request.path.split('/')
    for segment in path_segments:
        if not segment:  # Skip empty segments
            continue
            
        # URL-decode segment to catch encoded attacks
        decoded_segment = urllib.parse.unquote(segment)
        
        # Try validating segments that look like filenames
        if '.' in segment or len(segment) > 3:
            try:
                valid, error = api_instance.validate_api_input(decoded_segment, 'path')
                if not valid:
                    logger.warning(f"URL path validation failed: {error} in '{decoded_segment}'")
                    return jsonify({'error': f'Invalid URL path: {error}'}), 400
            except Exception as e:
                logger.error(f"Error validating URL path: {e}")
                # Continue even if validation fails
                
    # Return None to continue with the request
    return None

def validate_origin():
    """
    Validate request origin for cross-site request protection.
    This adds an additional layer of security beyond CSRF tokens.
    """
    # Skip for OPTIONS requests (pre-flight CORS)
    if request.method == 'OPTIONS':
        return None
        
    # Skip for GET requests (read-only operations)
    if request.method == 'GET':
        return None
        
    # Only enforce on state-changing operations
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        origin = request.headers.get('Origin')
        
        # If origin is present, validate it
        if origin:
            # Allow the API server origin
            allowed_origins = [
                f'https://{request.host}',
                'https://localhost:5000'
            ]
            
            # Add additional allowed origins from environment
            env_origins = os.getenv('ALLOWED_ORIGINS', '')
            if env_origins:
                allowed_origins.extend(env_origins.split(','))
                
            # Check if origin is allowed
            if not any(origin.startswith(allowed) for allowed in allowed_origins):
                logger.warning(f"Invalid request origin: {origin}")
                return jsonify({'error': 'Cross-origin request forbidden'}), 403
    
    # Continue with the request
    return None

class SecureAPI:
    """
    Secure API implementation with security best practices.
    Provides endpoints for authentication, file listing, encryption, decryption,
    and deletion.
    """
    def __init__(self, vault, user_db_path=None):
        # Kill any existing processes on port 5000
        # I spent 6 hours rewriting code only to realise
        ## I had a residual Docker process Listening on port 5000
        port = int(os.getenv('PORT', 5000))
        self.kill_processes_on_port(port)

        self.app = Flask(__name__)
        self.vault = vault
        
        # Initialize user manager
        self.user_db_path = user_db_path or os.getenv('USER_DB_PATH', './secure_vault_data/users/users.db')
        
        # Log the user database path for debugging
        logger.info(f"Using user database at: {self.user_db_path}")
        
        # Ensure user database directory exists
        db_dir = os.path.dirname(self.user_db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")

        # Check if database file exists
        if not os.path.exists(self.user_db_path):
            logger.warning(f"Database file does not exist: {self.user_db_path}")
            logger.warning("The database will be created when the first user is added")
        else:
            logger.info(f"Found existing database at: {self.user_db_path}")
            
        # Initialize user manager
        self.user_manager = UserManager(self.user_db_path)

        # Path Validation
        self.app._secure_api_instance = self
        self.app.before_request(validate_url_path)
        
        # Origin Validation for additional security
        self.app.before_request(validate_origin)

        # Initialize token blocklist with the user database path
        self.token_blocklist = TokenBlocklist(self.user_db_path)
        logger.info("Initialized persistent token blocklist")
        
        # Apply proxy fix (useful if behind a reverse proxy)
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_proto=1, x_host=1)
        
        self.app.config.update({
            'CSRF_COOKIE_SAMESITE': 'Lax',  # Use 'Lax' for better compatibility
            'CSRF_COOKIE_HTTPONLY': False,   # False so JS can read it for AJAX requests
            'CSRF_COOKIE_SECURE': True,      # Only send over HTTPS
            #'CSRF_DISABLE': False,           # Ensure it's explicitly enabled
            'CSRF_HEADER_NAME': 'X-CSRFToken',    # Ensure header name matches what we send
            'CSRF_COOKIE_NAME': 'csrf_token' # Explicitly set cookie name
        })

        # Enable CSRF protection (only exempting authentication endpoint)
        self.csrf = SeaSurf(self.app)
        
        # Enforce HTTPS and add secure headers
        self.talisman = Talisman(
            self.app,
            force_https=True,
            strict_transport_security=True,
            session_cookie_secure=True,
            content_security_policy={
                'default-src': "'self'",
                'img-src': "'self' data:",
                'script-src': "'self'",
                'style-src': "'self'",
                'connect-src': "'self'",
            },
            referrer_policy='strict-origin-when-cross-origin'
        )
        
        # Rate limiting
        self.limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"]
        )
        self.limiter.init_app(self.app)
        
        # Application configuration - FIXED: Use dictionary instead of kwargs
        self.app.config.update({
            'SECRET_KEY': os.getenv('SECRET_KEY', secrets.token_hex(32)),
            'JWT_EXPIRATION_HOURS': 24,
            'UPLOAD_FOLDER': str(Path('./temp_uploads')),
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16 MB
        })
        
        # Ensure consistent SECRET_KEY
        if not self.app.config.get('SECRET_KEY'):
            # Use the module imported at the top
            self.app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
            logger.info(f"Generated new SECRET_KEY: {self.app.config['SECRET_KEY'][:10]}...")
        else:
            logger.info(f"Using existing SECRET_KEY: {self.app.config['SECRET_KEY'][:10]}...")
        
        # Ensure upload directory exists
        upload_folder = self.app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Initialize API routes (guard against duplicate registration)
        if not getattr(self.app, '_routes_initialized', False):
            self._initialize_routes()
            self.app._routes_initialized = True

        self.fix_token_blocklist_initialization()

    def kill_processes_on_port(self, port=5000):
        """
        Kill any processes listening on the specified port.
        This is useful to ensure the API server can start without port conflicts.
        
        Args:
            port: The port number to check (default: 5000)
        
        Returns:
            bool: True if processes were found and killed, False otherwise
        """
        import platform
        import subprocess
        import os
        import signal
        import logging
        
        logger = logging.getLogger(__name__)
        logger.info(f"Checking for processes on port {port}")
        
        system = platform.system()
        killed = False
        
        try:
            if system == "Windows":
                # Windows: use netstat to find the processes
                output = subprocess.check_output(
                    f'netstat -ano | findstr :{port}',
                    shell=True
                ).decode()
                
                # Extract PIDs
                pids = set()
                for line in output.splitlines():
                    if f":{port}" in line:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            pids.add(int(parts[4]))
                
                # Kill each process
                for pid in pids:
                    logger.info(f"Killing process PID {pid} on port {port}")
                    try:
                        subprocess.run(f'taskkill /F /PID {pid}', shell=True)
                        killed = True
                    except subprocess.SubprocessError as e:
                        logger.error(f"Failed to kill process {pid}: {e}")
            
            if killed:
                logger.info(f"Successfully killed processes on port {port}")
            else:
                logger.info(f"No processes found on port {port}")
            
            return killed
            
        except Exception as e:
            logger.error(f"Error checking for processes on port {port}: {e}")
            return False

    def fix_token_blocklist_initialization(self):
        """
        Ensure token_blocklist is properly initialized.
        This is a safety mechanism to make sure we don't have type confusion.
        """
        try:
            from secure_vault.web.token_blocklist import TokenBlocklist
            
            # Check if token_blocklist is not already a TokenBlocklist instance
            if not hasattr(self, 'token_blocklist') or not isinstance(self.token_blocklist, TokenBlocklist):
                logger.warning("Reinitializing token_blocklist as a proper TokenBlocklist instance")
                self.token_blocklist = TokenBlocklist(self.user_db_path)
                
                # Update module globals
                try:
                    from secure_vault.web.token_blocklist import _global_token_blocklist
                    # Reload global token blocklist from database
                    conn = sqlite3.connect(self.user_db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT token_signature FROM revoked_tokens")
                    signatures = [row[0] for row in cursor.fetchall()]
                    conn.close()
                    
                    # Update the global set
                    _global_token_blocklist.update(signatures)
                    logger.info(f"Reloaded {len(signatures)} tokens into global blocklist")
                except Exception as e:
                    logger.error(f"Failed to reload global token blocklist: {e}")
        except Exception as e:
            logger.error(f"Failed to fix token_blocklist initialization: {e}")
            # Ensure there's at least a set for blocklisted tokens if all else fails
            if not hasattr(self, 'token_blocklist'):
                self.token_blocklist = set()

    def validate_api_input(self, value, input_type, **kwargs):
        """
        Validate API input with appropriate context
        
        Args:
            value: The input value to validate
            input_type: Type of input ('filename', 'password', 'token', etc.)
            **kwargs: Additional validation parameters
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Import security validator for context-aware validation
        try:
            from secure_vault.utils.input_validation import security_validator
            
            # Skip validation for None values (will be handled separately)
            if value is None:
                return True, None
            
            # For backward compatibility: if security_validator doesn't have validate_input method,
            # use the old method based on input type
            if not hasattr(security_validator, 'validate_input'):
                self.logger.warning("Enhanced validation not available - using legacy validation")
                if input_type == 'username':
                    # No validation for username in old version
                    return True, None
                elif input_type == 'password':
                    # No validation for password in old version
                    return True, None
                elif input_type in ('filename', 'path'):
                    return security_validator.check_path_traversal(value)
                elif input_type == 'sql':
                    return security_validator.check_sql_injection(value)
                elif input_type in ('html', 'content'):
                    return security_validator.check_xss(value)
                elif input_type == 'command':
                    return security_validator.check_command_injection(value)
                else:
                    # Default to all checks
                    sql_valid, sql_error = security_validator.check_sql_injection(value)
                    if not sql_valid:
                        return sql_valid, sql_error
                    
                    xss_valid, xss_error = security_validator.check_xss(value)
                    if not xss_valid:
                        return xss_valid, xss_error
                    
                    return True, None
            
            # Map input types to validation contexts
            context_map = {
                'username': 'text',
                'password': 'text',
                'filename': 'filename',
                'path': 'path',
                'query': 'sql',
                'content': 'html',
                'command': 'command',
                'token': 'text',
                'email': 'text'
            }
            
            # Get appropriate context
            context = context_map.get(input_type, None)
            
            # Configure checks based on input type
            check_sql = input_type in ('username', 'query', 'content', 'email', 'text')
            check_xss = input_type in ('username', 'content', 'text', 'email')
            check_path = input_type in ('filename', 'path')
            check_command = input_type in ('command')
            
            # Override using kwargs if provided
            if 'check_sql' in kwargs:
                check_sql = kwargs['check_sql']
            if 'check_xss' in kwargs:
                check_xss = kwargs['check_xss']
            if 'check_path' in kwargs:
                check_path = kwargs['check_path']
            if 'check_command' in kwargs:
                check_command = kwargs['check_command']
            
            # Validate with security validator
            return security_validator.validate_input(
                value,
                check_sql=check_sql,
                check_xss=check_xss,
                check_path=check_path,
                check_command=check_command,
                context=context
            )
            
        except ImportError:
            self.logger.warning("Security validator module not found - skipping validation")
            return True, None
        except Exception as e:
            self.logger.error(f"Validation error: {e}")
            # Fall back to accepting the input to avoid blocking functionality
            return True, None


    def _initialize_routes(self):
        """Initialize API routes with security decorators."""
        # Store self reference for use in decorators
        api_instance = self
        
        def require_auth(f):
            """Decorator to require valid JWT authentication."""
            @wraps(f)
            def decorated(*args, **kwargs):
                # Extract token with better handling
                auth_header = request.headers.get('Authorization', '')
                logger.debug(f"Auth header received: {auth_header[:30]}...")
                
                # Check if header starts with 'Bearer ' prefix
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]  # Remove 'Bearer ' prefix
                else:
                    token = auth_header  # Use as-is for compatibility
                    
                if not token:
                    logger.warning("No authentication token provided")
                    return jsonify({'error': 'Missing authentication token'}), 401
                    
                try:
                    # Check if token is revoked - handle both global function and instance method
                    is_revoked = False
                    
                    # Try instance method first if available
                    if hasattr(self.token_blocklist, 'is_revoked'):
                        try:
                            is_revoked = self.token_blocklist.is_revoked(token)
                        except Exception as e:
                            logger.warning(f"Instance token check failed: {e}")
                            
                            # Fallback to global function
                            try:
                                token_parts = token.split('.')
                                if len(token_parts) == 3:
                                    token_signature = token_parts[2]
                                    
                                    # Check global blocklist directly
                                    from secure_vault.web.token_blocklist import _global_token_blocklist
                                    is_revoked = token_signature in _global_token_blocklist
                            except Exception as e2:
                                logger.warning(f"Global token check failed: {e2}")
                    
                    if is_revoked:
                        logger.warning(f"Token is blocklisted: {token[:10]}...")
                        raise JWTError("Token has been revoked")
                    
                    # Decode token
                    payload = jwt.decode(
                        token,
                        self.app.config['SECRET_KEY'],
                        algorithms=['HS256']
                    )
                    
                    # Store user info in Flask g object
                    g.user_id = payload['sub']
                    g.username = payload.get('username', 'unknown')
                    
                except jwt.ExpiredSignatureError as e:
                    logger.warning(f"Token expired: {e}")
                    return jsonify({'error': 'Token has expired'}), 401
                except JWTError as e:
                    logger.warning(f"Invalid token: {e}")
                    return jsonify({'error': f'Invalid token: {str(e)}'}), 401
                except Exception as e:
                    logger.error(f"Unexpected authentication error: {e}")
                    return jsonify({'error': f'Authentication error: {str(e)}'}), 401
                    
                return f(*args, **kwargs)
            return decorated

        @self.app.route('/api/debug/routes', methods=['GET'])
        def debug_routes():
            """Debug endpoint to list all registered routes and their CSRF exemption status"""
            if request.remote_addr not in ['127.0.0.1', 'localhost']:
                return jsonify({'error': 'Access denied'}), 403
                
            routes = []
            for rule in self.app.url_map.iter_rules():
                csrf_exempt = False
                if hasattr(self.csrf, '_exempt_views'):
                    view_function = self.app.view_functions.get(rule.endpoint)
                    if view_function:
                        csrf_exempt = view_function in self.csrf._exempt_views
                        
                routes.append({
                    'route': str(rule),
                    'endpoint': rule.endpoint,
                    'methods': list(rule.methods),
                    'csrf_exempt': csrf_exempt
                })
                
            return jsonify(routes)

        # Make sure it's CSRF exempt
        self.csrf.exempt(debug_routes)

        @self.app.route('/api/auth', methods=['POST'])
        @self.limiter.limit("25 per minute")
        def authenticate():
            """Secure authentication endpoint with enhanced validation."""
            # Get credentials from either Basic Auth or form data
            username = None
            password = None
            
            # Try to get credentials from Basic Auth
            if request.authorization:
                username = request.authorization.username
                password = request.authorization.password
            # Try to get credentials from form data
            elif request.form:
                username = request.form.get('username')
                password = request.form.get('password')
            # Try to get credentials from JSON data
            elif request.is_json:
                json_data = request.get_json()
                username = json_data.get('username')
                password = json_data.get('password')
            
            # Log attempt with available info
            logger.info(f"Authentication attempt received with method: {request.method}")

            # Validate inputs before checking if they're missing
            # This ensures we catch security violations even in partial credentials
            if username:
                # Enhanced validation for username
                valid, error = self.validate_api_input(username, 'username')
                if not valid:
                    logger.warning(f"Authentication failed: invalid username format - {error}")
                    return jsonify({'error': f'Invalid username format: {error}'}), 400
            
            if password:
                # Validate password
                valid, error = self.validate_api_input(password, 'password')
                if not valid:
                    logger.warning(f"Authentication failed: invalid password format - {error}")
                    return jsonify({'error': f'Invalid password format: {error}'}), 400
            
            # Now check if credentials are complete
            if not username or not password:
                logger.warning("Authentication attempt with missing credentials")
                return jsonify({'error': 'Missing credentials'}), 401
            
            # Log authentication attempt with debugging info
            logger.info(f"Authentication attempt for user: {username}, method: {request.method}")
            
            # Authenticate against user database with extra error handling
            try:
                success, user_info = self.user_manager.authenticate(username, password)
                
                # Debug log for authentication result
                logger.debug(f"Authentication result: success={success}, info={user_info}")
                
                if not success:
                    # Log failed attempt
                    logger.warning(f"Failed authentication attempt for user: {username}")
                    error_msg = user_info.get('error', 'Authentication failed')
                    return jsonify({'error': error_msg}), 401
                
                # Extract user ID from successfully authenticated user with explicit type handling
                user_id = user_info.get('id')
                logger.debug(f"Extracted user_id: {user_id}, type: {type(user_id)}")
                
                if user_id is None:
                    logger.error(f"User authenticated but no user ID provided: {username}")
                    return jsonify({'error': 'Authentication error: missing user ID'}), 500
                
                # Generate JWT token with explicit handling
                try:
                    logger.debug(f"Generating JWT token for user: {username} (ID: {user_id})")
                    # Ensure user_id is a string
                    user_id_str = str(user_id)
                    
                    # Current time in UTC
                    now = datetime.now(timezone.utc)
                    
                    # Create token payload
                    payload = {
                        'sub': user_id_str,  # Must be a string
                        'username': username,
                        'iat': now,
                        'exp': now + timedelta(hours=self.app.config['JWT_EXPIRATION_HOURS']),
                        'jti': secrets.token_hex(16)
                    }
                    
                    # Add optional email claim if available
                    if 'email' in user_info and user_info['email']:
                        payload['email'] = user_info['email']
                        
                    logger.debug(f"JWT payload: {payload}")
                    
                    # Ensure secret key is properly set
                    secret_key = self.app.config['SECRET_KEY']
                    if not secret_key:
                        # Use the module imported at the top
                        secret_key = secrets.token_hex(32)
                        self.app.config['SECRET_KEY'] = secret_key
                        logger.info(f"Generated new secret key: {secret_key[:10]}...")
                        
                    # Encode token with explicit algorithm
                    token = jwt.encode(
                        payload,
                        secret_key,
                        algorithm='HS256'
                    )
                    
                    logger.info(f"Generated JWT token for user {username} (token ID: {payload['jti']})")
                    
                    # Return successful authentication response
                    return jsonify({
                        'token': token,
                        'expires_in': self.app.config['JWT_EXPIRATION_HOURS'] * 3600,
                        'user': {
                            'id': user_id_str,
                            'username': username
                        }
                    })
                except Exception as e:
                    logger.exception(f"Token generation failed: {e}")
                    return jsonify({'error': f'Authentication error: token generation failed - {str(e)}'}), 500
                
            except Exception as e:
                logger.exception(f"Error during authentication for user {username}: {str(e)}")
                return jsonify({'error': 'Authentication system error'}), 500

        # Only exempt authentication from CSRF protection
        self.csrf.exempt(authenticate)

        @self.app.before_request
        def debug_csrf():
            """Debug CSRF token validation"""
            if request.method not in ['GET', 'HEAD', 'OPTIONS']:
                token_cookie = request.cookies.get('csrf_token')
                token_header = request.headers.get('X-CSRFToken')
                logger.info(f"CSRF Debug - Method: {request.method}, Path: {request.path}")
                logger.info(f"CSRF Cookie: {token_cookie[:10] + '...' if token_cookie else 'None'}")
                logger.info(f"CSRF Header: {token_header[:10] + '...' if token_header else 'None'}")

        @self.app.route('/api/files', methods=['GET'])
        @require_auth
        @self.limiter.limit("100 per hour")
        def list_files():
            """List encrypted files in the vault."""
            try:
                logger.info(f"User {g.username} requested file listing")
                files = self.vault.list_files()
                file_list = []
                for f in files:
                    stat = f.stat()
                    file_list.append({
                        'name': f.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                return jsonify(file_list)
            except Exception as e:
                logger.error(f"List files failed: {e}")
                return jsonify({'error': 'Failed to list files'}), 500
        
        # No CSRF exemption for list_files - but for GET requests, 
        # CSRF tokens are not validated anyway by default in most CSRF protection libraries

        @self.app.route('/api/files', methods=['POST'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def encrypt_file():
            """Securely encrypt and store an uploaded file using its original filename."""
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            file = request.files['file']
            password = request.form.get('password')
            
            # Check if password exists
            if not password:
                return jsonify({'error': 'No password provided'}), 400
            
            # Validate password for security violations
            valid, error = self.validate_api_input(password, 'password')
            if not valid:
                logger.warning(f"Encryption failed: invalid password format - {error}")
                return jsonify({'error': f'Invalid password format: {error}'}), 400
            
            # Get and validate filename
            original_filename = None
            if file.filename:
                # Sanitize and retrieve the original filename
                original_filename = secure_filename(file.filename)
            
            if not original_filename:
                return jsonify({'error': 'Invalid or missing filename'}), 400
            
            # Enhanced validation for filename
            valid, error = self.validate_api_input(original_filename, 'filename')
            if not valid:
                logger.warning(f"Encryption failed: invalid filename - {error}")
                return jsonify({'error': f'Invalid filename: {error}'}), 400

            # Save the uploaded file to a temporary location with its original name.
            temp_path = os.path.join(self.app.config['UPLOAD_FOLDER'], original_filename)
            try:
                file.save(temp_path)
                # The vault.encrypt_file method now uses file_path.name to preserve the original filename.
                encrypted_path = self.vault.encrypt_file(temp_path, password)
                return jsonify({
                    'message': 'File encrypted successfully',
                    'file': encrypted_path.name  # e.g., "document.pdf.vault"
                })
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
                return jsonify({'error': 'Encryption failed'}), 500
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception as e:
                        logger.error(f"Failed to remove temp file: {e}")
        
        # Do NOT exempt encrypt_file from CSRF protection

        @self.app.route('/api/files/<filename>', methods=['POST'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def decrypt_file(filename):
            """Securely decrypt and download a file."""
            # First validate filename for security violations
            valid, error = self.validate_api_input(filename, 'filename')
            if not valid:
                logger.warning(f"Decryption failed: invalid filename - {error}")
                return jsonify({'error': f'Invalid filename: {error}'}), 400
            
            # Get and validate password
            password = request.form.get('password')
            if not password:
                return jsonify({'error': 'No password provided'}), 400
            
            # Validate password for security concerns
            valid, error = self.validate_api_input(password, 'password')
            if not valid:
                logger.warning(f"Decryption failed: invalid password format - {error}")
                return jsonify({'error': f'Invalid password format: {error}'}), 400
            
            # Now check if the file exists (only after validation passes)
            encrypted_path = self.vault.vault_dir / filename
            if not encrypted_path.exists():
                return jsonify({'error': 'File not found'}), 404
            
            temp_path = None
            secure_temp_file = None
            
            try:
                # Use the SecureTempFile class for guaranteed secure deletion
                try:
                    from secure_vault.security.files import SecureTempFile
                    with SecureTempFile(suffix='.tmp', prefix='securevault_') as temp_path:
                        self.vault.decrypt_file(encrypted_path, temp_path, password)
                        
                        # Remove only the trailing '.vault' suffix to restore the original filename.
                        if filename.endswith('.vault'):
                            original_filename = filename[:-6]
                        else:
                            original_filename = filename
                            
                        response = send_file(
                            temp_path,
                            as_attachment=True,
                            download_name=original_filename,
                            max_age=0
                        )
                        response.headers['Content-Disposition'] = (
                            "attachment; filename=\"{0}\"; filename*=UTF-8''{0}".format(original_filename)
                        )
                        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                        response.headers['Pragma'] = 'no-cache'
                        response.headers['X-Content-Type-Options'] = 'nosniff'
                        
                        # Store temp_path for cleanup in after_request
                        if not hasattr(g, 'pending_temp_files'):
                            g.pending_temp_files = []
                        g.pending_temp_files.append(temp_path)
                        
                        return response
                except ImportError:
                    # Fallback if SecureTempFile isn't available
                    import tempfile
                    import os
                    
                    fd, temp_path = tempfile.mkstemp()
                    try:
                        os.close(fd)
                        self.vault.decrypt_file(encrypted_path, temp_path, password)
                        
                        # Remove only the trailing '.vault' suffix to restore the original filename.
                        if filename.endswith('.vault'):
                            original_filename = filename[:-6]
                        else:
                            original_filename = filename
                            
                        response = send_file(
                            temp_path,
                            as_attachment=True,
                            download_name=original_filename,
                            max_age=0
                        )
                        response.headers['Content-Disposition'] = (
                            "attachment; filename=\"{0}\"; filename*=UTF-8''{0}".format(original_filename)
                        )
                        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                        response.headers['Pragma'] = 'no-cache'
                        response.headers['X-Content-Type-Options'] = 'nosniff'
                        
                        # Add to pending files to be deleted
                        self.app.config['PENDING_TEMP_FILES'] = (
                            self.app.config.get('PENDING_TEMP_FILES', []) + [temp_path]
                        )
                        
                        return response
                    finally:
                        # Ensure immediate secure deletion if an error occurs
                        if temp_path and os.path.exists(temp_path):
                            try:
                                # Securely delete the file
                                file_size = os.path.getsize(temp_path)
                                with open(temp_path, 'wb') as f:
                                    # Pass 1: Random data
                                    f.write(os.urandom(file_size))
                                    f.flush()
                                    os.fsync(f.fileno())
                                    # Pass 2: Zeros
                                    f.seek(0)
                                    f.write(b'\x00' * file_size)
                                    f.flush()
                                    os.fsync(f.fileno())
                                    # Pass 3: Ones
                                    f.seek(0)
                                    f.write(b'\xFF' * file_size)
                                    f.flush()
                                    os.fsync(f.fileno())
                                # Remove the file
                                os.unlink(temp_path)
                            except Exception as e:
                                logger.error(f"Failed to securely delete temp file {temp_path}: {e}")
                                # Try simple delete as a last resort
                                try:
                                    os.unlink(temp_path)
                                except Exception:
                                    pass
                        
            except ValueError as e:
                # Handle validation/decryption errors
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return jsonify({'error': 'Decryption failed'}), 500
        
        # Do NOT exempt decrypt_file from CSRF protection

        @self.app.route('/api/files/<filename>', methods=['DELETE'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def delete_file(filename):
            """Securely delete an encrypted file."""
            # First validate filename for security violations
            valid, error = self.validate_api_input(filename, 'filename')
            if not valid:
                logger.warning(f"Deletion failed: invalid filename - {error}")
                return jsonify({'error': f'Invalid filename: {error}'}), 400
            
            # Only check if file exists after validation passes
            file_path = self.vault.vault_dir / filename
            if not file_path.exists():
                return jsonify({'error': 'File not found'}), 404
            
            # Attempt deletion
            try:
                os.remove(file_path)
                return jsonify({'message': 'File deleted successfully'})
            except Exception as e:
                logger.error(f"Delete failed: {e}")
                return jsonify({'error': 'Delete failed'}), 500
        
        # Do NOT exempt delete_file from CSRF protection


        @self.app.route('/api/auth/revoke', methods=['POST'])
        @require_auth
        def revoke_token():
            """Revoke the current authentication token."""
            # Add detailed CSRF debugging
            csrf_cookie = request.cookies.get('csrf_token')
            csrf_header = request.headers.get('X-CSRFToken')
            
            logger.info("CSRF Debug for token revocation:")
            logger.info(f"- Cookie exists: {csrf_cookie is not None}")
            logger.info(f"- Header exists: {csrf_header is not None}")
            if csrf_cookie and csrf_header:
                logger.info(f"- Cookie value: {csrf_cookie[:5]}...{csrf_cookie[-5:] if len(csrf_cookie) > 10 else ''}")
                logger.info(f"- Header value: {csrf_header[:5]}...{csrf_header[-5:] if len(csrf_header) > 10 else ''}")
                logger.info(f"- Values match: {csrf_cookie == csrf_header}")
            auth_header = request.headers.get('Authorization', '')
            
            # Extract the token properly
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
            else:
                token = auth_header
                
            try:
                # Log the revocation attempt
                logger.info(f"Token revocation attempt by user {g.username}")
                
                # Get token signature
                token_parts = token.split('.')
                if len(token_parts) != 3:
                    return jsonify({'error': 'Invalid token format'}), 400
                    
                token_signature = token_parts[2]
                
                # Decode the token to get its payload
                payload = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                
                # Attempt to revoke using proper TokenBlocklist instance if available
                success = False
                
                if hasattr(self.token_blocklist, 'add_token'):
                    # Try using the TokenBlocklist instance
                    try:
                        success = self.token_blocklist.add_token(token, payload)
                    except Exception as e:
                        logger.error(f"Failed to add token to TokenBlocklist: {e}")
                
                # Fallback: add to global blocklist directly if we're using a set
                if not success and isinstance(self.token_blocklist, set):
                    try:
                        # Get the global blocklist from the token_blocklist module
                        from secure_vault.web.token_blocklist import _global_token_blocklist
                        # Add the token signature to both the global set and the instance set
                        _global_token_blocklist.add(token_signature)
                        self.token_blocklist.add(token_signature)
                        success = True
                        logger.info(f"Added token to global blocklist directly")
                    except Exception as e:
                        logger.error(f"Failed to add token to global blocklist: {e}")
                
                if success:
                    logger.info(f"Token revoked successfully for user {g.username}")
                    return jsonify({'message': 'Token revoked successfully'})
                else:
                    # Last resort: try direct database storage
                    try:
                        conn = sqlite3.connect(self.user_db_path)
                        cursor = conn.cursor()
                        
                        # Extract necessary info from payload
                        jti = payload.get('jti', secrets.token_hex(16))
                        user_id = str(payload.get('sub', ''))
                        expires_at = datetime.fromtimestamp(payload.get('exp', 0), tz=timezone.utc)
                        
                        # Create the table if it doesn't exist
                        cursor.execute('''
                        CREATE TABLE IF NOT EXISTS revoked_tokens (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            jti TEXT UNIQUE NOT NULL,
                            token_signature TEXT UNIQUE NOT NULL,
                            user_id TEXT NOT NULL,
                            revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            expires_at TIMESTAMP NOT NULL,
                            metadata TEXT
                        )
                        ''')
                        
                        # Insert the token
                        cursor.execute(
                            '''
                            INSERT INTO revoked_tokens (jti, token_signature, user_id, expires_at, metadata)
                            VALUES (?, ?, ?, ?, ?)
                            ''', 
                            (jti, token_signature, user_id, expires_at.isoformat(), '{}')
                        )
                        conn.commit()
                        conn.close()
                        
                        # Add to global set
                        from secure_vault.web.token_blocklist import _global_token_blocklist
                        _global_token_blocklist.add(token_signature)
                        
                        logger.info(f"Token manually added to database and global set for user {g.username}")
                        return jsonify({'message': 'Token revoked successfully (manual method)'}), 200
                        
                    except Exception as e:
                        logger.error(f"All token revocation methods failed: {e}")
                        return jsonify({'error': 'Failed to revoke token'}), 500
            except jwt.InvalidTokenError as e:
                logger.error(f"Invalid token in revocation request: {e}")
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                logger.error(f"Error in token revocation: {e}")
                return jsonify({'error': f'Token revocation failed: {str(e)}'}), 500
        
        # Endpoint is exempt from CSRF due to compatability erros
        # Logout CSRF exemptions are low risk
        self.csrf.exempt(revoke_token)

        @self.app.route('/api/maintenance/cleanup-tokens', methods=['POST'])
        def cleanup_tokens():
            """Clean up expired tokens endpoint - admin access only."""
            # Verify admin key
            admin_key = request.headers.get('X-Admin-Key')
            expected_admin_key = os.getenv('SECUREVAULT_ADMIN_KEY')
            
            if not admin_key or admin_key != expected_admin_key:
                logger.warning("Unauthorized token cleanup attempt")
                return jsonify({'error': 'Unauthorized - Invalid or missing admin key'}), 403
            
            try:
                # Call the cleanup method on token_blocklist
                if hasattr(self.token_blocklist, 'cleanup_expired_tokens'):
                    removed = self.token_blocklist.cleanup_expired_tokens()
                    logger.info(f"Admin-triggered cleanup removed {removed} expired tokens")
                    return jsonify({
                        'message': 'Cleanup successful',
                        'tokens_removed': removed
                    })
                else:
                    # Fallback if the method doesn't exist (using a set)
                    logger.warning("Token blocklist doesn't support cleanup_expired_tokens method")
                    return jsonify({
                        'message': 'Cleanup not supported with current token blocklist implementation',
                        'tokens_removed': 0
                    })
            
            except Exception as e:
                logger.error(f"Error cleaning up expired tokens: {e}")
                return jsonify({'error': f'Cleanup failed: {str(e)}'}), 500
        
        # Still exempt admin cleanup_tokens
        self.csrf.exempt(cleanup_tokens)
        
        @self.app.route('/api/users/register', methods=['POST'])
        @self.limiter.limit("5 per hour")
        def register_user():
            """Register a new user with the system."""
            # Admin APIs should only be accessible from localhost
            if request.remote_addr not in ['127.0.0.1', 'localhost']:
                return jsonify({'error': 'Access denied'}), 403
                
            if not request.is_json:
                return jsonify({'error': 'Invalid request format'}), 400
                
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')
            admin_key = data.get('admin_key')
            
            # Verify admin key if creating first user or if other users exist
            expected_admin_key = os.getenv('SECUREVAULT_ADMIN_KEY')
            if self.user_manager.has_any_users() and admin_key != expected_admin_key:
                return jsonify({'error': 'Invalid admin key'}), 403
            
            if not username or not password:
                return jsonify({'error': 'Username and password are required'}), 400
                
            # Check if user already exists
            if self.user_manager.user_exists(username):
                return jsonify({'error': 'Username already exists'}), 409
                
            # Create user
            success = self.user_manager.create_user(username, password, email)
            
            if success:
                logger.info(f"New user registered: {username}")
                return jsonify({
                    'message': 'User registered successfully',
                    'username': username
                })
            else:
                return jsonify({'error': 'Failed to create user'}), 500
        
        # Do NOT exempt register_user from CSRF protection

        @self.app.route('/api/debug/jwt', methods=['GET'])
        def debug_jwt():
            """Debug endpoint for JWT token validation."""
            
            # Only allow access from localhost
            if request.remote_addr not in ['127.0.0.1', 'localhost']:
                return jsonify({'error': 'Access denied'}), 403
                
            # Get token from header
            auth_header = request.headers.get('Authorization', '')
            
            # Extract token properly
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
            else:
                token = auth_header
            
            if not token:
                return jsonify({
                    'error': 'No token provided',
                    'help': 'Send token in Authorization header: Bearer <token>'
                }), 400
            
            try:
                # Decode token without verification
                # Split the token into parts
                parts = token.split('.')
                if len(parts) != 3:
                    return jsonify({'error': f'Invalid token format. Expected 3 parts, got {len(parts)}'}), 400
                
                # Decode header
                header_part = parts[0]
                padding = len(header_part) % 4
                if padding:
                    header_part += '=' * (4 - padding)
                    
                header_json = base64.b64decode(header_part).decode('utf-8')
                header = json.loads(header_json)
                
                # Decode payload
                payload_part = parts[1]
                padding = len(payload_part) % 4
                if padding:
                    payload_part += '=' * (4 - padding)
                    
                payload_json = base64.b64decode(payload_part).decode('utf-8')
                payload = json.loads(payload_json)
                
                # Try to verify the token
                verification_result = {'verified': False, 'error': None}
                try:
                    decoded = jwt.decode(
                        token,
                        self.app.config['SECRET_KEY'],
                        algorithms=['HS256']
                    )
                    verification_result = {'verified': True, 'decoded': decoded}
                except Exception as e:
                    verification_result = {'verified': False, 'error': str(e)}
                
                # Check if token is revoked using the instance method, not the global function
                is_revoked = self.token_blocklist.is_revoked(token)
                
                return jsonify({
                    'token': token,
                    'header': header,
                    'payload': payload,
                    'verification': verification_result,
                    'is_revoked': is_revoked,
                    'app_config': {
                        'secret_key_length': len(self.app.config['SECRET_KEY']),
                        'jwt_expiration_hours': self.app.config['JWT_EXPIRATION_HOURS']
                    }
                })
            except Exception as e:
                return jsonify({'error': f'Error decoding token: {str(e)}'}), 400
        
        # Exempt debug endpoint only for localhost debugging purposes
        self.csrf.exempt(debug_jwt)

        # Add a helper route to get CSRF token for frontend
        @self.app.route('/api/csrf-token', methods=['GET'])
        @require_auth
        def get_csrf_token():
            """Return the current CSRF token for the frontend."""
            # This works with Flask-SeaSurf - it sets the cookie automatically
            # and we just need to return a success message
            return jsonify({
                'message': 'CSRF token cookie set',
                'instructions': 'Read the csrf_token cookie and include it in the X-CSRFToken header for all non-GET requests'
            })

        @self.app.errorhandler(413)
        def request_entity_too_large(error):
            """Handle file size exceeded error."""
            return jsonify({
                'error': 'File too large',
                'max_size': self.app.config['MAX_CONTENT_LENGTH']
            }), 413

        @self.app.errorhandler(429)
        def ratelimit_handler(error):
            """Handle rate limit exceeded error."""
            return jsonify({
                'error': 'Rate limit exceeded',
                'retry_after': error.description
            }), 429
            
        # Add a handler for CSRF errors
        @self.app.errorhandler(400)
        def handle_csrf_error(e):
            """Handle CSRF validation errors."""
            if 'CSRF' in str(e):
                logger.warning(f"CSRF validation failed: {str(e)}")
                return jsonify({
                    'error': 'CSRF validation failed. Please refresh the page and try again.',
                    'type': 'csrf_error'
                }), 400
            # Pass through other 400 errors
            return e

        @self.app.after_request
        def secure_cleanup_temp_files(response):
            """Securely clean up temporary files after each request."""
            # Check for pending files in Flask g object
            pending_g_files = getattr(g, 'pending_temp_files', [])
            for temp_path in pending_g_files:
                try:
                    if os.path.exists(temp_path):
                        # Get file size for secure overwrite
                        try:
                            file_size = os.path.getsize(temp_path)
                            
                            # Securely delete the file with multiple passes
                            with open(temp_path, 'wb') as f:
                                # Pass 1: Random data
                                f.write(os.urandom(file_size))
                                f.flush()
                                os.fsync(f.fileno())
                                
                                # Pass 2: Zeros
                                f.seek(0)
                                f.write(b'\x00' * file_size)
                                f.flush()
                                os.fsync(f.fileno())
                                
                                # Pass 3: Ones
                                f.seek(0)
                                f.write(b'\xFF' * file_size)
                                f.flush()
                                os.fsync(f.fileno())
                                
                            # Finally remove the file
                            os.unlink(temp_path)
                            logger.debug(f"Securely deleted temporary file: {temp_path}")
                            
                        except Exception as e:
                            logger.error(f"Error during secure deletion of {temp_path}: {e}")
                            # Fallback to standard deletion if secure deletion fails
                            try:
                                os.unlink(temp_path)
                                logger.warning(f"Used fallback standard deletion for {temp_path}")
                            except Exception as fallback_e:
                                logger.error(f"Fallback deletion also failed for {temp_path}: {fallback_e}")
                except Exception as e:
                    logger.error(f"Failed to clean up temporary file {temp_path}: {e}")
            
            # Also check old pending files in app config
            temp_files = self.app.config.pop('PENDING_TEMP_FILES', [])
            for temp_path in temp_files:
                try:
                    if os.path.exists(temp_path):
                        # Get file size for secure overwrite
                        try:
                            file_size = os.path.getsize(temp_path)
                            
                            # Securely delete the file with multiple passes
                            with open(temp_path, 'wb') as f:
                                # Pass 1: Random data
                                f.write(os.urandom(file_size))
                                f.flush()
                                os.fsync(f.fileno())
                                
                                # Pass 2: Zeros
                                f.seek(0)
                                f.write(b'\x00' * file_size)
                                f.flush()
                                os.fsync(f.fileno())
                                
                                # Pass 3: Ones
                                f.seek(0)
                                f.write(b'\xFF' * file_size)
                                f.flush()
                                os.fsync(f.fileno())
                                
                            # Finally remove the file
                            os.unlink(temp_path)
                            logger.debug(f"Securely deleted temporary file: {temp_path}")
                            
                        except Exception as e:
                            logger.error(f"Error during secure deletion of {temp_path}: {e}")
                            # Fallback to standard deletion if secure deletion fails
                            try:
                                os.unlink(temp_path)
                                logger.warning(f"Used fallback standard deletion for {temp_path}")
                            except Exception as fallback_e:
                                logger.error(f"Fallback deletion also failed for {temp_path}: {fallback_e}")
                except Exception as e:
                    logger.error(f"Failed to clean up temporary file {temp_path}: {e}")
            
            # Return the response to continue the request chain
            return response
        
        @self.app.before_request
        def cleanup_expired_tokens_periodically():
            """Periodically clean up expired tokens."""
            api_instance = self  # Store reference to self
            
            # Run cleanup approximately every 100 requests (to avoid doing it on every request)
            if random.randint(1, 100) == 1:
                try:
                    removed = api_instance.token_blocklist.cleanup_expired_tokens()
                    if removed > 0:
                        logger.info(f"Periodic cleanup: removed {removed} expired tokens")
                except Exception as e:
                    logger.error(f"Failed to clean up expired tokens: {e}")
        def validate_api_input(self, value, input_type, **kwargs):
            """
            Validate API input with appropriate context
            
            Args:
                value: The input value to validate
                input_type: Type of input ('filename', 'password', 'token', etc.)
                **kwargs: Additional validation parameters
            
            Returns:
                Tuple of (is_valid, error_message)
            """
            # Import security validator here to avoid circular imports
            from secure_vault.utils.input_validation import security_validator
            
            # Skip validation for None values (will be handled separately)
            if value is None:
                return True, None
            
            # Map input types to validation contexts
            context_map = {
                'username': 'text',
                'password': 'text',
                'filename': 'filename',
                'path': 'path',
                'query': 'sql',
                'content': 'html',
                'command': 'command',
                'token': 'text',
                'email': 'text'
            }
            
            # Get appropriate context
            context = context_map.get(input_type, None)
            
            # Configure checks based on input type
            check_sql = input_type in ('username', 'query', 'content', 'email', 'text')
            check_xss = input_type in ('username', 'content', 'text', 'email')
            check_path = input_type in ('filename', 'path')
            check_command = input_type in ('command')
            
            # Override using kwargs if provided
            if 'check_sql' in kwargs:
                check_sql = kwargs['check_sql']
            if 'check_xss' in kwargs:
                check_xss = kwargs['check_xss']
            if 'check_path' in kwargs:
                check_path = kwargs['check_path']
            if 'check_command' in kwargs:
                check_command = kwargs['check_command']
            
            # Validate with security validator
            return security_validator.validate_input(
                value,
                check_sql=check_sql,
                check_xss=check_xss,
                check_path=check_path,
                check_command=check_command,
                context=context
            )
        
        def validate_url_path(self):
            """
            Validate URL path for security concerns before processing the request.
            This catches URL path issues that might bypass endpoint-specific validation.
            """
            # Skip for certain paths that are known to be safe
            if request.path == '/' or request.path.startswith('/static/'):
                return
            
            # Skip authorization and options requests
            if request.method == 'OPTIONS':
                return
            
            # Validate each path segment
            path_segments = request.path.split('/')
            for segment in path_segments:
                if not segment:  # Skip empty segments
                    continue
                    
                # URL-decode segment to catch encoded attacks
                decoded_segment = urllib.parse.unquote(segment)
                
                # Try validating segments that look like filenames
                if '.' in segment or len(segment) > 3:
                    valid, error = self.validate_api_input(decoded_segment, 'path')
                    if not valid:
                        logger.warning(f"URL path validation failed: {error} in '{decoded_segment}'")
                        return jsonify({'error': f'Invalid URL path: {error}'}), 400
    
    def run(self, host='localhost', port=5000, ssl_context=None, **kwargs):
        """
        Run the secure API server with SSL support with enhanced security warnings.
        """
        if ssl_context:
            self.app.run(host=host, port=port, ssl_context=ssl_context, **kwargs)
        else:
            from secure_vault.web.https_config import ensure_valid_cert_exists, validate_certificate
            cert_path, key_path = ensure_valid_cert_exists()
            
            # Validate the certificate and show clear warnings
            is_valid, reason = validate_certificate(cert_path)
            if not is_valid:
                logger.critical(f"Invalid certificate: {reason}")
                raise ValueError(f"Cannot start server with invalid certificate: {reason}")
            
            # Show prominent warnings for self-signed certificates
            if "Self-signed" in reason:
                border = "!" * 80
                logger.warning(border)
                logger.warning("SECURITY WARNING: Using self-signed certificate")
                logger.warning("This is NOT SECURE for production use.")
                logger.warning("Clients will see certificate warnings.")
                logger.warning(border)
            
            self.app.run(host=host, port=port, ssl_context=(cert_path, key_path), **kwargs)

    def cleanup(self):
        """Cleanup temporary files and resources."""
        try:
            upload_dir = Path(self.app.config['UPLOAD_FOLDER'])
            if upload_dir.exists():
                for file in upload_dir.glob('*'):
                    try:
                        os.remove(file)
                    except Exception as e:
                        logger.error(f"Failed to delete temporary file {file}: {e}")
            # No need to clear token blocklist since it's persistent in the database
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def __del__(self):
        """Ensure cleanup on deletion."""
        self.cleanup()