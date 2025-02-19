"""
HTTPS enforcement and secure headers middleware
"""

from flask import Flask, request, redirect, abort, Response
import logging
from typing import Optional, Dict, Any, List, Callable, Union, Tuple
from functools import wraps
import re
import ssl
import os
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class HttpsEnforcer:
    """
    Middleware to enforce HTTPS and add security headers
    """
    def __init__(self, 
                app: Optional[Flask] = None,
                permanent: bool = True,
                hsts_age: int = 31536000,  # 1 year
                preload: bool = False,
                include_subdomains: bool = True,
                skip_paths: Optional[List[str]] = None):
        self.permanent = permanent
        self.hsts_age = hsts_age
        self.preload = preload
        self.include_subdomains = include_subdomains
        self.skip_paths = skip_paths or []
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize with a Flask app"""
        # Add security headers to all responses
        @app.after_request
        def add_security_headers(response: Response) -> Response:
            # HSTS header
            if self.hsts_age:
                hsts_directive = f"max-age={self.hsts_age}"
                if self.include_subdomains:
                    hsts_directive += "; includeSubdomains"
                if self.preload:
                    hsts_directive += "; preload"
                response.headers['Strict-Transport-Security'] = hsts_directive
            
            # Prevent content type sniffing
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # Prevent clickjacking
            response.headers['X-Frame-Options'] = 'DENY'
            
            # XSS protection (for legacy browsers)
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Referrer policy
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # Content security policy
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "block-all-mixed-content"
            )
            
            # Cache control for sensitive data
            if request.path.startswith('/api/'):
                response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'
            
            return response
        
        # Enforce HTTPS for all requests
        @app.before_request
        def enforce_https():
            # Skip for tests and specific paths
            if app.testing or any(re.match(pattern, request.path) for pattern in self.skip_paths):
                return
                
            # Check if already using HTTPS
            if request.url.startswith('https://'):
                return
                
            # Check for secure forwarding headers (behind proxy)
            is_secure = request.headers.get('X-Forwarded-Proto', '').lower() == 'https'
            
            if not is_secure:
                # Redirect to HTTPS
                url = request.url.replace('http://', 'https://', 1)
                response = redirect(url, 301 if self.permanent else 302)
                return response

class CsrfProtection:
    """
    CSRF protection middleware with secure token management
    """
    def __init__(self, 
                app: Optional[Flask] = None,
                token_header: str = 'X-CSRF-Token',
                cookie_name: str = 'csrf_token',
                cookie_secure: bool = True,
                cookie_httponly: bool = True,
                cookie_samesite: str = 'Lax',
                exempt_methods: Optional[List[str]] = None,
                exempt_paths: Optional[List[str]] = None):
        self.token_header = token_header
        self.cookie_name = cookie_name
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite
        self.exempt_methods = exempt_methods or ['GET', 'HEAD', 'OPTIONS', 'TRACE']
        self.exempt_paths = exempt_paths or []
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize with a Flask app"""
        # Generate CSRF token for all requests
        @app.before_request
        def generate_csrf_token():
            if self.is_exempt_request():
                return
                
            # Get or generate token
            csrf_token = request.cookies.get(self.cookie_name)
            if not csrf_token:
                # Generate new secure token
                from secrets import token_hex
                csrf_token = token_hex(32)
                
                # Store for later use in this request
                setattr(request, '_csrf_token', csrf_token)
        
        # Verify CSRF token for state-changing requests
        @app.before_request
        def verify_csrf_token():
            if self.is_exempt_request():
                return
                
            # Check token
            token = request.headers.get(self.token_header)
            cookie_token = request.cookies.get(self.cookie_name)
            
            if not token or not cookie_token or not self.tokens_match(token, cookie_token):
                logger.warning("CSRF verification failed", 
                             extra={"path": request.path, "method": request.method})
                return abort(403, "CSRF validation failed")
        
        # Set CSRF cookie on all responses
        @app.after_request
        def set_csrf_cookie(response: Response) -> Response:
            if hasattr(request, '_csrf_token'):
                response.set_cookie(
                    self.cookie_name,
                    getattr(request, '_csrf_token'),
                    secure=self.cookie_secure,
                    httponly=self.cookie_httponly,
                    samesite=self.cookie_samesite
                )
            return response
    
    def is_exempt_request(self) -> bool:
        """Check if request is exempt from CSRF protection"""
        # Exempt based on method
        if request.method in self.exempt_methods:
            return True
            
        # Exempt based on path
        if any(re.match(pattern, request.path) for pattern in self.exempt_paths):
            return True
            
        return False
    
    def tokens_match(self, token1: str, token2: str) -> bool:
        """Securely compare tokens"""
        if not token1 or not token2:
            return False
            
        # Use constant-time comparison to prevent timing attacks
        from hmac import compare_digest
        return compare_digest(token1, token2)
    
    def exempt(self, view_function):
        """Decorator to exempt a view from CSRF protection"""
        @wraps(view_function)
        def wrapped(*args, **kwargs):
            request._csrf_exempt = True
            return view_function(*args, **kwargs)
        return wrapped

class SecureSslContext:
    """
    Creates a secure SSL context for HTTPS
    """
    def __init__(self, 
                cert_file: str,
                key_file: str,
                password: Optional[str] = None,
                ciphers: Optional[str] = None):
        self.cert_file = cert_file
        self.key_file = key_file
        self.password = password
        
        # Strong cipher suite by default
        self.ciphers = ciphers or (
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
            'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
            'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256'
        )
    
    def create_context(self) -> ssl.SSLContext:
        """Create a secure SSL context"""
        try:
            # Create context with modern TLS
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load certificate and key
            context.load_cert_chain(
                certfile=self.cert_file,
                keyfile=self.key_file,
                password=self.password
            )
            
            # Set to TLS 1.2 & 1.3 only
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            
            # Set cipher suite
            context.set_ciphers(self.ciphers)
            
            # Disable compression (CRIME attack)
            context.options |= ssl.OP_NO_COMPRESSION
            
            # Add modern curves
            context.set_ecdh_curve('prime256v1')
            
            # Verify peer
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            raise

def setup_https(app: Flask, cert_file: str, key_file: str, password: Optional[str] = None) -> Flask:
    """
    Setup HTTPS for a Flask app
    """
    # Create HTTPS enforcer
    enforcer = HttpsEnforcer(permanent=True)
    enforcer.init_app(app)
    
    # Add CSRF protection
    csrf = CsrfProtection(
        token_header='X-CSRF-Token',
        cookie_secure=True
    )
    csrf.init_app(app)
    
    # Configure SSL context
    ssl_context = SecureSslContext(
        cert_file=cert_file,
        key_file=key_file,
        password=password
    ).create_context()
    
    # Store for later use
    app.config['SSL_CONTEXT'] = ssl_context
    
    return app

def generate_self_signed_cert(cert_path: str, key_path: str, days: int = 365) -> Tuple[str, str]:
    """
    Generate a self-signed certificate for development
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import datetime
    
    # Create directories if needed
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Vault Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Write private key
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    return cert_path, key_path