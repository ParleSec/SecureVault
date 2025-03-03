"""
Secure API implementation with enhanced security measures.
Provides endpoints for authentication, file listing, encryption,
decryption, and deletion.
"""

from flask import Flask, request, jsonify, send_file, Response, g, abort, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import tempfile
from pathlib import Path
import os
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

# Import persistent token blocklist
from secure_vault.web.token_blocklist import TokenBlocklist, is_token_revoked

# Import user management for authentication
from secure_vault.users.user_manager import UserManager

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

class SecureAPI:
    """
    Secure API implementation with security best practices.
    Provides endpoints for authentication, file listing, encryption, decryption,
    and deletion.
    """
    def __init__(self, vault, user_db_path=None):
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

        # Initialize token blocklist with the user database path
        self.token_blocklist = TokenBlocklist(self.user_db_path)
        logger.info("Initialized persistent token blocklist")
        
        # Apply proxy fix (useful if behind a reverse proxy)
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_proto=1, x_host=1)
        
        # Enable CSRF protection (exempting API endpoints as needed)
        self.csrf = SeaSurf(self.app)
        self.csrf._exempt_xhr = True
        
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
        
        # Blocklist for revoked tokens
        self.token_blocklist = set()
        
        # Ensure upload directory exists
        upload_folder = self.app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Initialize API routes (guard against duplicate registration)
        if not getattr(self.app, '_routes_initialized', False):
            self._initialize_routes()
            self.app._routes_initialized = True

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
                    # Use the global function instead of instance method
                    if is_token_revoked(token):
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

        @self.app.route('/api/auth', methods=['POST'])
        @self.limiter.limit("5 per minute")
        def authenticate():
            """Secure authentication endpoint with user verification."""
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
                    
                    logger.info(f"Generated JWT token for user {username}: {token[:30]}...")
                    
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

        self.csrf.exempt(authenticate)

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

        @self.app.route('/api/files', methods=['POST'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def encrypt_file():
            """Securely encrypt and store an uploaded file using its original filename."""
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            file = request.files['file']
            password = request.form.get('password')
            if not password:
                return jsonify({'error': 'No password provided'}), 400

            # Sanitize and retrieve the original filename.
            original_filename = secure_filename(file.filename)
            if not original_filename:
                return jsonify({'error': 'Invalid filename'}), 400

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
        self.csrf.exempt(encrypt_file)

        @self.app.route('/api/files/<filename>', methods=['POST'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def decrypt_file(filename):
            """Securely decrypt and download a file."""
            password = request.form.get('password')
            if not password:
                return jsonify({'error': 'No password provided'}), 400
            
            encrypted_path = self.vault.vault_dir / filename
            if not encrypted_path.exists():
                return jsonify({'error': 'File not found'}), 404
            
            temp_path = None
            try:
                fd, temp_path = tempfile.mkstemp()
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
                return response
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return jsonify({'error': 'Decryption failed'}), 500
            finally:
                if temp_path and os.path.exists(temp_path):
                    self.app.config['PENDING_TEMP_FILES'] = (
                        self.app.config.get('PENDING_TEMP_FILES', []) + [temp_path]
                    )
        self.csrf.exempt(decrypt_file)

        @self.app.route('/api/files/<filename>', methods=['DELETE'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def delete_file(filename):
            """Securely delete an encrypted file."""
            try:
                file_path = self.vault.vault_dir / filename
                if not file_path.exists():
                    return jsonify({'error': 'File not found'}), 404
                os.remove(file_path)
                return jsonify({'message': 'File deleted successfully'})
            except Exception as e:
                logger.error(f"Delete failed: {e}")
                return jsonify({'error': 'Delete failed'}), 500
        self.csrf.exempt(delete_file)

        @self.app.route('/api/auth/revoke', methods=['POST'])
        @require_auth
        def revoke_token():
            """Revoke the current authentication token."""
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            try:
                # Decode the token to get its payload
                payload = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                
                # Add token to persistent blocklist - this updates both the DB and the in-memory set
                if self.token_blocklist.add_token(token, payload):
                    logger.info(f"Token revoked successfully for user {g.username}")
                    return jsonify({'message': 'Token revoked successfully'})
                else:
                    logger.error(f"Failed to revoke token for user {g.username}")
                    return jsonify({'error': 'Failed to revoke token'}), 500
            except JWTError as e:
                logger.error(f"Invalid token in revocation request: {e}")
                return jsonify({'error': 'Invalid token'}), 401
        self.csrf.exempt(revoke_token)
            
        @self.app.route('/api/maintenance/cleanup-tokens', methods=['POST'])
        def cleanup_tokens():
            """Cleanup expired tokens from the blocklist (admin only)."""
            # Only allow access from localhost
            if request.remote_addr not in ['127.0.0.1', 'localhost']:
                return jsonify({'error': 'Access denied'}), 403
                
            # Verify admin key
            admin_key = request.headers.get('X-Admin-Key')
            expected_admin_key = os.getenv('SECUREVAULT_ADMIN_KEY')
            
            if admin_key != expected_admin_key:
                return jsonify({'error': 'Invalid admin key'}), 403
                
            # Perform cleanup
            removed_count = self.token_blocklist.cleanup_expired_tokens()
            return jsonify({
                'message': 'Token cleanup completed',
                'tokens_removed': removed_count
            })
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
        self.csrf.exempt(register_user)

        @self.app.route('/api/debug/jwt', methods=['GET'])
        def debug_jwt():
            """Debug endpoint for JWT token validation."""
            api_instance = self  # Store reference to self
            
            # Only allow access from localhost
            if request.remote_addr not in ['127.0.0.1', 'localhost']:
                return jsonify({'error': 'Access denied'}), 403
                
            # Get token from header
            auth_header = request.headers.get('Authorization', '')
            token = auth_header.replace('Bearer ', '')
            
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
                        api_instance.app.config['SECRET_KEY'],
                        algorithms=['HS256']
                    )
                    verification_result = {'verified': True, 'decoded': decoded}
                except Exception as e:
                    verification_result = {'verified': False, 'error': str(e)}
                
                # Check if token is revoked
                is_revoked = api_instance.token_blocklist.is_revoked(token)
                
                return jsonify({
                    'token': token,
                    'header': header,
                    'payload': payload,
                    'verification': verification_result,
                    'is_revoked': is_revoked,
                    'app_config': {
                        'secret_key_length': len(api_instance.app.config['SECRET_KEY']),
                        'jwt_expiration_hours': api_instance.app.config['JWT_EXPIRATION_HOURS']
                    }
                })
            except Exception as e:
                return jsonify({'error': f'Error decoding token: {str(e)}'}), 400
        self.csrf.exempt(debug_jwt)

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

        @self.app.before_request
        def cleanup_temp_files():
            """Clean up temporary files before each request."""
            temp_files = self.app.config.pop('PENDING_TEMP_FILES', [])
            for temp_path in temp_files:
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception as e:
                    logger.error(f"Failed to remove temp file: {e}")
        
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


    def run(self, host='localhost', port=5000, ssl_context=None, **kwargs):
        """
        Run the secure API server with SSL support.
        If an SSL context is provided, it is used; otherwise, a self-signed
        certificate is generated for development.
        """
        # Log server start with database info
        user_count = 0
        try:
            import sqlite3
            conn = sqlite3.connect(self.user_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            conn.close()
        except Exception as e:
            logger.warning(f"Could not count users in database: {e}")
            
        logger.info(f"Starting API server with user database: {self.user_db_path} ({user_count} users)")
        
        if ssl_context:
            self.app.run(host=host, port=port, ssl_context=ssl_context, **kwargs)
        else:
            from secure_vault.web.https_config import ensure_valid_cert_exists
            cert_path, key_path = ensure_valid_cert_exists()
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