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
from jose import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
import sys
from werkzeug.utils import secure_filename
import secrets

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
    def __init__(self, vault):
        self.app = Flask(__name__)
        self.vault = vault
        
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
        
        # Application configuration
        self.app.config.update(
            SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
            JWT_EXPIRATION_HOURS=24,
            UPLOAD_FOLDER=str(Path('./temp_uploads')),
            MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB
        )
        
        # Blacklist for revoked tokens
        self.token_blacklist = set()
        
        # Ensure upload directory exists
        os.makedirs(self.app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Initialize API routes (guard against duplicate registration)
        if not getattr(self.app, '_routes_initialized', False):
            self._initialize_routes()
            self.app._routes_initialized = True

    def _initialize_routes(self):
        """Initialize API routes with security decorators."""
        def require_auth(f):
            """Decorator to require valid JWT authentication."""
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
            """Secure authentication endpoint."""
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
                return jsonify({'error': 'Missing credentials'}), 401
            
            # Authentication logic
            user_id = username
            now = datetime.now(timezone.utc)
            token = jwt.encode(
                {
                    'sub': user_id,
                    'iat': now,
                    'exp': now + timedelta(hours=self.app.config['JWT_EXPIRATION_HOURS']),
                    'jti': secrets.token_hex(16)
                },
                self.app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            
            return jsonify({
                'token': token,
                'expires_in': self.app.config['JWT_EXPIRATION_HOURS'] * 3600
            })

        self.csrf.exempt(authenticate)


        @self.app.route('/api/files', methods=['GET'])
        @require_auth
        @self.limiter.limit("100 per hour")
        def list_files():
            """List encrypted files in the vault."""
            try:
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
                jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                self.token_blacklist.add(token)
                return jsonify({'message': 'Token revoked successfully'})
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
        self.csrf.exempt(revoke_token)

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

    def run(self, host='localhost', port=5000, ssl_context=None, **kwargs):
        """
        Run the secure API server with SSL support.
        If an SSL context is provided, it is used; otherwise, a self-signed
        certificate is generated for development.
        """
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
            self.token_blacklist.clear()
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def __del__(self):
        """Ensure cleanup on deletion."""
        self.cleanup()