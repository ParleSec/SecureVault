"""
Secure API implementation with enhanced security measures
"""

from flask import Flask, request, jsonify, send_file, Response
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import tempfile
from pathlib import Path
import os
import time
import secrets
from typing import Dict, Optional
import logging
from datetime import datetime, timedelta
import jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
from .secure_files import SecureFile, SecureTempFile
from .secure_memory import SecureString
from .vault import SecureVault

logger = logging.getLogger(__name__)

class SecureAPI:
    """
    Secure API implementation with security best practices
    """
    def __init__(self, vault: SecureVault):
        self.app = Flask(__name__)
        self.vault = vault
        
        # Security middleware
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_proto=1, x_host=1)
        self.csrf = SeaSurf(self.app)
        self.talisman = Talisman(
            self.app,
            force_https=True,
            strict_transport_security=True,
            session_cookie_secure=True,
            content_security_policy={
                'default-src': "'self'",
                'img-src': "'self'",
                'script-src': "'self'",
            }
        )
        
        # Rate limiting
        self.limiter = Limiter(
            self.app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"]
        )
        
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
                    request.user_id = payload['sub']
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
            
            # Secure password handling
            secure_password = SecureString(password)
            
            # Create temp directory if it doesn't exist
            os.makedirs(self.app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            try:
                # Use secure temporary file
                with SecureTempFile(suffix='.tmp') as temp_path:
                    # Save uploaded file
                    file.save(temp_path)
                    
                    # Encrypt the file
                    encrypted_path = self.vault.encrypt_file(temp_path, secure_password.value)
                    
                    return jsonify({
                        'message': 'File encrypted successfully',
                        'file': encrypted_path.name
                    })
                    
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
                return jsonify({'error': 'Encryption failed'}), 500

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
                
            # Secure password handling
            secure_password = SecureString(password)
            
            try:
                # Use secure temporary file for decrypted content
                with SecureTempFile(suffix='.tmp') as temp_path:
                    # Decrypt to temp file
                    self.vault.decrypt_file(encrypted_path, temp_path, secure_password.value)
                    
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

        @self.app.route('/api/files/<filename>', methods=['DELETE'])
        @require_auth
        @self.limiter.limit("20 per hour")
        def delete_file(filename):
            """Securely delete a file"""
            try:
                file_path = self.vault.vault_dir / filename
                if not file_path.exists():
                    return jsonify({'error': 'File not found'}), 404
                    
                # Use secure file deletion
                secure_file = SecureFile(file_path)
                secure_file.secure_delete()
                
                return jsonify({'message': 'File deleted successfully'})
                
            except Exception as e:
                logger.error(f"Delete failed: {e}")
                return jsonify({'error': 'Delete failed'}), 500

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

    def run(self, host='localhost', port=5000, **kwargs):
        """Run the secure API server"""
        self.app.run(host=host, port=port, **kwargs)

    def cleanup(self):
        """Cleanup temporary files and resources"""
        try:
            # Clean up upload folder
            upload_dir = Path(self.app.config['UPLOAD_FOLDER'])
            if upload_dir.exists():
                for file in upload_dir.glob('*'):
                    try:
                        SecureFile(file).secure_delete()
                    except Exception as e:
                        logger.error(f"Failed to delete temporary file {file}: {e}")
                upload_dir.rmdir()
                
            # Clear token blacklist
            self.token_blacklist.clear()
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def __del__(self):
        """Ensure cleanup on deletion"""
        self.cleanup()