from flask import Flask, request, jsonify, g
from jose import jwt
import secrets
import time
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from secure_vault.users.user_manager import UserManager
from pathlib import Path
import json
import os

logger = logging.getLogger(__name__)

class AuthenticationManager:
    """
    Enhanced authentication manager to properly handle GUI authentication
    """
    def __init__(self, app, user_db_path, token_expiration_minutes=30):
        """Initialize the authentication manager"""
        self.app = app
        self.user_manager = UserManager(user_db_path)
        self.token_expiration = token_expiration_minutes
        
        # Configure JWT settings - make sure secret key is consistent
        self.jwt_secret_key = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
        self.app.config['JWT_SECRET_KEY'] = self.jwt_secret_key
        self.app.config['JWT_ALGORITHM'] = 'HS256'
        
        # Token blocklist storage
        self.token_blocklist_dir = Path('./token_blocklist')
        self.token_blocklist_dir.mkdir(parents=True, exist_ok=True)
        self.token_blocklist_file = self.token_blocklist_dir / 'blocklist.json'
        self.token_blocklist = self._load_blocklist()
        
        logger.info(f"Authentication manager initialized with {len(self.token_blocklist)} blocklisted tokens")
    
    def _load_blocklist(self):
        """Load token blocklist from disk"""
        if not self.token_blocklist_file.exists():
            return {}
        
        try:
            with open(self.token_blocklist_file, 'r') as f:
                data = json.load(f)
                # Filter out expired blocklist entries
                now = time.time()
                return {token: exp for token, exp in data.items() if exp > now}
        except Exception as e:
            logger.error(f"Failed to load token blocklist: {e}")
            return {}
    
    def _save_blocklist(self):
        """Save token blocklist to disk"""
        try:
            with open(self.token_blocklist_file, 'w') as f:
                json.dump(self.token_blocklist, f)
        except Exception as e:
            logger.error(f"Failed to save token blocklist: {e}")
    
    def setup_auth_routes(self):
        """Set up authentication routes on the Flask app"""
        
def setup_auth_routes(self):
    """Set up authentication routes on the Flask app"""
    
    @self.app.route('/api/auth', methods=['POST'])
    def authenticate():
        """Authenticate a user and issue a token"""
        # Get credentials from various sources
        username = None
        password = None
        
        # Try to get from JSON first (GUI will use this)
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            logger.debug(f"Got credentials from JSON for user: {username}")
            
        # Then try other methods
        if not username or not password:
            if request.authorization:
                username = request.authorization.username
                password = request.authorization.password
                logger.debug(f"Got credentials from Authorization header for user: {username}")
            elif request.form:
                username = request.form.get('username')
                password = request.form.get('password')
                logger.debug(f"Got credentials from form data for user: {username}")
        
        if not username or not password:
            logger.warning("Authentication failed: Missing credentials")
            return jsonify({'error': 'Missing credentials'}), 401
        
        # Log authentication attempt
        logger.info(f"Authentication attempt for user: {username}")
        
        # Authenticate against user database
        success, result = self.user_manager.authenticate(username, password)
        
        if success:
            # Authentication successful
            logger.info(f"Authentication successful for user: {username}")
            
            # Generate token
            token_info = self.generate_token(result)
            
            # Return token information
            return jsonify(token_info)
        else:
            # Authentication failed
            error_msg = result.get('error', 'Authentication failed')
            logger.warning(f"Authentication failed for user {username}: {error_msg}")
            return jsonify({'error': error_msg}), 401
    
    # Exempt the authentication route from CSRF protection
    if hasattr(self.app, 'csrf'):
        self.app.csrf.exempt(authenticate)
    elif hasattr(self, 'csrf'):
        self.csrf.exempt(authenticate)
    else:
        logger.warning("No CSRF protection found to exempt authentication route")
        
        @self.app.route('/api/auth/verify', methods=['GET'])
        def verify_token():
            """Verify if a token is valid"""
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return jsonify({'error': 'Missing token'}), 401
            
            valid, result = self.validate_token(token)
            
            if valid:
                return jsonify({
                    'valid': True,
                    'username': result.get('sub'),
                    'expires': datetime.fromtimestamp(result.get('exp')).isoformat()
                })
            else:
                return jsonify({'valid': False, 'error': result}), 401
        
        @self.app.route('/api/auth/revoke', methods=['POST'])
        def revoke_token():
            """Revoke the current token"""
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return jsonify({'error': 'Missing token'}), 401
            
            if self.revoke_token(token):
                return jsonify({'message': 'Token revoked successfully'})
            else:
                return jsonify({'error': 'Failed to revoke token'}), 400
    
    def authenticate_user(self, username, password):
        """Authenticate a user against the user database"""
        logger.info(f"Authenticating user: {username}")
        
        # Use the UserManager to validate credentials
        success, result = self.user_manager.authenticate(username, password)
        
        # Log authentication result
        if success:
            logger.info(f"User authenticated: {username}")
        else:
            logger.warning(f"Failed authentication attempt: {username}")
        
        return success, result
    
    def generate_token(self, user_info):
        """Generate a JWT token for an authenticated user"""
        # Make sure we have all the required fields
        if isinstance(user_info, dict) and 'username' in user_info:
            # If 'id' is missing, use username as id
            if 'id' not in user_info:
                user_info['id'] = user_info['username']
                
            now = datetime.now(timezone.utc)
            expiration = now + timedelta(minutes=self.token_expiration)
            
            # Generate a unique token ID
            jti = secrets.token_hex(16)
            
            # Create token payload
            payload = {
                'sub': user_info['username'],
                'user_id': user_info['id'],
                'iat': now,
                'exp': expiration,
                'jti': jti
            }
            
            # Sign the token
            token = jwt.encode(
                payload,
                self.app.config['JWT_SECRET_KEY'],
                algorithm=self.app.config['JWT_ALGORITHM']
            )
            
            logger.info(f"Generated token for user: {user_info['username']}, expires in {self.token_expiration} minutes")
            
            return {
                'token': token,
                'expires_in': self.token_expiration * 60,  # seconds
                'token_type': 'Bearer'
            }
        else:
            logger.error(f"Invalid user info for token generation: {user_info}")
            return {'error': 'Invalid user information'}
    
    def validate_token(self, token):
        """Validate a JWT token"""
        # Debug mode - more verbose logging
        debug = os.environ.get('DEBUG', 'false').lower() == 'true'
        
        if debug:
            logger.debug(f"Validating token: {token[:10]}...")
        
        try:
            # Check if token is blocklisted
            if token in self.token_blocklist:
                logger.warning("Token is blocklisted")
                return False, "Token has been revoked"
            
            # Verify and decode the token
            payload = jwt.decode(
                token,
                self.app.config['JWT_SECRET_KEY'],
                algorithms=[self.app.config['JWT_ALGORITHM']]
            )
            
            if debug:
                logger.debug(f"Token validated successfully for user: {payload.get('sub')}")
            
            return True, payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return False, "Token has expired"
        except jwt.JWTError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return False, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return False, f"Token validation error: {str(e)}"
    
    def revoke_token(self, token):
        """Revoke a token by adding it to the blocklist"""
        try:
            # Decode without verification to get expiration
            payload = jwt.decode(
                token,
                self.app.config['JWT_SECRET_KEY'],
                algorithms=[self.app.config['JWT_ALGORITHM']],
                options={'verify_signature': False}
            )
            
            # Get expiration timestamp
            exp = payload.get('exp', time.time() + 86400)  # Default 24h if not found
            
            # Add to blocklist with expiration
            self.token_blocklist[token] = exp
            
            # Save blocklist
            self._save_blocklist()
            
            logger.info(f"Token revoked for user: {payload.get('sub', 'unknown')}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    def require_auth(self, f):
        """Decorator to require valid JWT authentication"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            
            # Log authentication attempt
            logger.debug(f"Auth Header: {auth_header[:20] if auth_header else 'None'}")
            
            token = auth_header.replace('Bearer ', '') if auth_header.startswith('Bearer ') else auth_header
            
            if not token:
                logger.warning("Missing authentication token")
                return jsonify({'error': 'Missing authentication token'}), 401
            
            valid, result = self.validate_token(token)
            
            if not valid:
                logger.warning(f"Invalid token: {result}")
                return jsonify({'error': result}), 401
            
            # Store user info in Flask g object for route handlers
            g.user = result
            
            return f(*args, **kwargs)
        return decorated
    
    def cleanup_blocklist(self):
        """Clean up expired tokens from the blocklist"""
        try:
            now = time.time()
            expired_tokens = [token for token, exp in self.token_blocklist.items() if exp <= now]
            
            for token in expired_tokens:
                del self.token_blocklist[token]
            
            if expired_tokens:
                self._save_blocklist()
                logger.info(f"Cleaned up {len(expired_tokens)} expired tokens from blocklist")
        except Exception as e:
            logger.error(f"Failed to clean up token blocklist: {e}")

# Create a more secure API authentication setup
def setup_authentication(app, user_db_path):
    """
    Set up enhanced authentication for the SecureAPI
    
    Args:
        app: Flask application
        user_db_path: Path to user database
        
    Returns:
        AuthenticationManager: The configured auth manager
    """
    # Set debug mode for more verbose logging
    os.environ['DEBUG'] = 'true'
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create the auth manager
    auth_manager = AuthenticationManager(app, user_db_path)
    auth_manager.setup_auth_routes()
    
    # Clean up expired blocklisted tokens periodically
    @app.before_request
    def cleanup_expired_tokens():
        # Clean up every ~100 requests (randomly)
        if secrets.randbelow(100) == 0:
            auth_manager.cleanup_blocklist()
    
    return auth_manager