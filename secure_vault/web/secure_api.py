"""
Secure API implementation with enhanced security measures
"""

from flask import Flask, request, jsonify, send_file, Response, g
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import tempfile
from pathlib import Path
import os
import time
import secrets
import logging
from datetime import datetime, timedelta
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
import sys

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
    Secure API implementation with security best practices
    """
    def __init__(self, vault):
        self.app = Flask(__name__)
        self.vault = vault
        
        # Security middleware
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_proto=1, x_host=1)
        
        # CSRF protection with exemptions for API endpoints
        self.csrf = SeaSurf(self.app)
        self.csrf._exempt_xhr = True  # Allow XMLHttpRequest to bypass CSRF
        
        # Talisman for HTTPS and security headers
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
        
        # Session management
        self.app.config.update(
            SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
            JWT_EXPIRATION_HOURS=24,
            UPLOAD_FOLDER=Path('./temp_uploads'),
            MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
        )
        
        # Initialize routes
        self._initialize_routes()
        
        # Blacklist for revoked tokens
        self.token_blacklist = set()
        
        # Create upload directory if it doesn't exist
        os.makedirs(self.app.config['UPLOAD_FOLDER'], exist_ok=True)

    def _initialize_routes(self):
        """Initialize API routes with security decorators"""
        
        def require_auth(f):
            """Require valid JWT authentication"""
            @wraps(f)
            def decorated(*args, **kwargs):
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                
                if not token:
                    return jsonify({'error': 'Missing authentication token'}), 401
                    
                try:
                    if token in self.token_blacklist:
                        raise jwt.InvalidTokenError("Token has been revoked")
                        
                    payload = jwt.decode(
                        token,
                        self.app.config['SECRET_KEY'],
                        algorithms=['HS256']
                    )
                    g.user_id = payload['sub']
                except jwt.ExpiredSignatureError:
                    return jsonify({'error': 'Token has expired'}), 401
                except jwt.InvalidTokenError as e:
                    return jsonify({'error': str(e)}), 401
                    
                return f(*args, **kwargs)
            return decorated

        @self.app.route('/api/auth', methods=['POST'])
        @self.limiter.limit("5 per minute")
        def authenticate():
            """Secure authentication endpoint"""
            auth = request.authorization
            
            if not auth or not auth.username or not auth.password:
                return jsonify({'error': 'Missing credentials'}), 401
                
            # In production, validate against user database
            user_id = auth.username
            
            # Generate token
            now = datetime.utcnow()
            token = jwt.encode(
                {
                    'sub': user_id,
                    'iat': now,
                    'exp': now + timedelta(hours=self.app.config['JWT_EXPIRATION_HOURS']),
                    'jti': secrets.token_hex(16)  # Unique token ID
                },
                self.app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            
            return jsonify({
                'token': token,
                'expires_in': self.app.config['JWT_EXPIRATION_HOURS'] * 3600
            })
        
        # Exempt authentication from CSRF
        self.csrf.exempt(authenticate)

        @self.app.route('/api/files', methods=['GET'])
        @require_auth
        @self.limiter.limit("100 per hour")
        def list_files():
            """List encrypted files"""
            try:
                files = self.vault.list_files()
                return jsonify([
                    {
                        'name': f.name,
                        'size': f.stat().st_size,
                        'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                    }
                    for f in files
                ])
            except Exception as e:
                logger.error(f"List files failed: {e}")
                return jsonify({'error': 'Failed to list files'}), 500

        @self.app.route('/api/files', methods=['POST'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def encrypt_file():
            """Securely encrypt and store a file"""
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
                
            file = request.files['file']
            password = request.form.get('password')
            
            if not password:
                return jsonify({'error': 'No password provided'}), 400
            
            temp_path = None
            try:
                # Create secure temp file path
                temp_filename = secrets.token_hex(16)
                temp_path = os.path.join(self.app.config['UPLOAD_FOLDER'], temp_filename)
                
                # Save uploaded file
                file.save(temp_path)
                
                # Encrypt the file
                encrypted_path = self.vault.encrypt_file(temp_path, password)
                
                return jsonify({
                    'message': 'File encrypted successfully',
                    'file': encrypted_path.name
                })
                
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
                return jsonify({'error': 'Encryption failed'}), 500
            finally:
                # Clean up temp file
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception as e:
                        logger.error(f"Failed to remove temp file: {e}")
        
        # Exempt file upload from CSRF
        self.csrf.exempt(encrypt_file)

        @self.app.route('/api/files/<filename>', methods=['POST'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def decrypt_file(filename):
            """Securely decrypt and download a file"""
            password = request.form.get('password')
            if not password:
                return jsonify({'error': 'No password provided'}), 400
                
            encrypted_path = self.vault.vault_dir / filename
            if not encrypted_path.exists():
                return jsonify({'error': 'File not found'}), 404
            
            temp_path = None
            try:
                # Create temp file for decrypted content
                fd, temp_path = tempfile.mkstemp()
                os.close(fd)  # Close file descriptor immediately
                
                # Decrypt to temp file
                self.vault.decrypt_file(encrypted_path, temp_path, password)
                
                # Send file with security headers
                response = send_file(
                    temp_path,
                    as_attachment=True,
                    download_name=filename.replace('.vault', ''),
                    max_age=0
                )
                
                # Add security headers
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
                # Ensure temp file cleanup via before_request hook
                if temp_path and os.path.exists(temp_path):
                    self.app.config['PENDING_TEMP_FILES'] = self.app.config.get('PENDING_TEMP_FILES', []) + [temp_path]
        
        # Exempt file decryption from CSRF
        self.csrf.exempt(decrypt_file)

        @self.app.route('/api/files/<filename>', methods=['DELETE'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def delete_file(filename):
            """Securely delete a file"""
            try:
                file_path = self.vault.vault_dir / filename
                if not file_path.exists():
                    return jsonify({'error': 'File not found'}), 404
                
                # Securely delete file
                os.remove(file_path)
                
                return jsonify({'message': 'File deleted successfully'})
                
            except Exception as e:
                logger.error(f"Delete failed: {e}")
                return jsonify({'error': 'Delete failed'}), 500
        
        # Exempt file deletion from CSRF
        self.csrf.exempt(delete_file)

        @self.app.route('/api/auth/revoke', methods=['POST'])
        @require_auth
        def revoke_token():
            """Revoke current authentication token"""
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            try:
                payload = jwt.decode(
                    token,
                    self.app.config['SECRET_KEY'],
                    algorithms=['HS256']
                )
                self.token_blacklist.add(token)
                return jsonify({'message': 'Token revoked successfully'})
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
        
        # Exempt token revocation from CSRF
        self.csrf.exempt(revoke_token)

        @self.app.errorhandler(413)
        def request_entity_too_large(error):
            """Handle file size exceeded error"""
            return jsonify({
                'error': 'File too large',
                'max_size': self.app.config['MAX_CONTENT_LENGTH']
            }), 413

        @self.app.errorhandler(429)
        def ratelimit_handler(error):
            """Handle rate limit exceeded error"""
            return jsonify({
                'error': 'Rate limit exceeded',
                'retry_after': error.description
            }), 429
            
        @self.app.before_request
        def cleanup_temp_files():
            """Clean up temporary files before each request"""
            temp_files = self.app.config.pop('PENDING_TEMP_FILES', [])
            for temp_path in temp_files:
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception as e:
                    logger.error(f"Failed to remove temp file: {e}")

    def run(self, host='localhost', port=5000, ssl_context=None, **kwargs):
        """
        Run the secure API server with SSL support
        
        Args:
            host (str): Hostname to bind to
            port (int): Port to bind to
            ssl_context: SSL context or tuple of (cert_file, key_file)
            **kwargs: Additional arguments for app.run()
        """
        # Configure HTTPS if SSL context provided
        if ssl_context:
            self.app.run(host=host, port=port, ssl_context=ssl_context, **kwargs)
        else:
            # Auto-generate SSL certificate for development
            from secure_vault.web.https_config import ensure_valid_cert_exists
            cert_path, key_path = ensure_valid_cert_exists()
            self.app.run(host=host, port=port, ssl_context=(cert_path, key_path), **kwargs)

    def cleanup(self):
        """Cleanup temporary files and resources"""
        try:
            # Clean up upload folder
            upload_dir = Path(self.app.config['UPLOAD_FOLDER'])
            if upload_dir.exists():
                for file in upload_dir.glob('*'):
                    try:
                        os.remove(file)
                    except Exception as e:
                        logger.error(f"Failed to delete temporary file {file}: {e}")
                
            # Clear token blacklist
            self.token_blacklist.clear()
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def __del__(self):
        """Ensure cleanup on deletion"""
        self.cleanup()