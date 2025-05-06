"""
HTTPS Configuration for SecureVault
Handles certificate generation and secure context creation
"""

import os
from pathlib import Path
import logging
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Tuple

logger = logging.getLogger(__name__)

def generate_self_signed_cert(cert_path, key_path, days_valid=365):
    """
    Generate a self-signed certificate for development or initial deployment
    
    Args:
        cert_path (str): Path where certificate will be saved
        key_path (str): Path where private key will be saved
        days_valid (int): Number of days certificate should be valid
        
    Returns:
        tuple: (cert_path, key_path) if successful, None otherwise
    """
    try:
        # Create directories if needed
        cert_dir = os.path.dirname(cert_path)
        key_dir = os.path.dirname(key_path)
        os.makedirs(cert_dir, exist_ok=True)
        os.makedirs(key_dir, exist_ok=True)
        
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVault Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        # Certificate validity period
        now = datetime.datetime.utcnow()
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1")
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        logger.info(f"Generated self-signed certificate valid for {days_valid} days")
        
        # Set appropriate permissions for key file
        try:
            if os.name == 'posix':  # Linux/Mac
                os.chmod(key_path, 0o600)  # Read/write for owner only
                logger.info(f"Set secure permissions on key file: {key_path}")
        except Exception as e:
            logger.warning(f"Could not set permissions on key file: {e}")
            
        return cert_path, key_path
        
    except Exception as e:
        logger.error(f"Failed to generate certificate: {e}")
        return None

def create_ssl_context(cert_path, key_path, password=None):
    """
    Create a secure SSL context for HTTPS
    
    Args:
        cert_path (str): Path to certificate file
        key_path (str): Path to private key file
        password (str, optional): Password for private key if encrypted
        
    Returns:
        ssl.SSLContext: Configured SSL context
    """
    import ssl
    
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path, password=password)
        
        # Modern security settings
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
        context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
        
        # Additional hardening
        context.options |= ssl.OP_NO_COMPRESSION  # Disable compression (CRIME attack)
        context.set_ecdh_curve('prime256v1')
        
        return context
        
    except Exception as e:
        logger.error(f"Failed to create SSL context: {e}")
        raise

def ensure_valid_cert_exists(cert_dir='./certs'):
    """
    Ensure valid certificates exist, generating new ones if needed
    
    Args:
        cert_dir (str): Directory to store certificates
        
    Returns:
        tuple: (cert_path, key_path) paths to certificate files
    """
    cert_dir = Path(cert_dir)
    cert_path = cert_dir / 'cert.pem'
    key_path = cert_dir / 'key.pem'
    
    # Create directory if it doesn't exist
    os.makedirs(cert_dir, exist_ok=True)
    
    needs_new_cert = False
    
    # Check if cert files exist
    if not cert_path.exists() or not key_path.exists():
        needs_new_cert = True
    else:
        # Check expiration if certificate exists
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                if cert.not_valid_after < datetime.datetime.utcnow():
                    logger.warning("Certificate has expired, generating new one")
                    needs_new_cert = True
        except Exception as e:
            logger.error(f"Error checking certificate expiration: {e}")
            needs_new_cert = True
    
    if needs_new_cert:
        logger.info("Generating new self-signed certificate")
        return generate_self_signed_cert(str(cert_path), str(key_path))
    
    return str(cert_path), str(key_path)


def validate_certificate(cert_path: str) -> Tuple[bool, str]:
    """
    Validate a certificate for security issues.
    
    Args:
        cert_path: Path to the certificate file
        
    Returns:
        Tuple of (is_valid, reason)
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from datetime import datetime, timedelta
        
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check if certificate is expired or about to expire
            now = datetime.utcnow()
            if cert.not_valid_after < now:
                return False, "Certificate has expired"
            
            # Check if certificate is about to expire (within 30 days)
            if cert.not_valid_after < (now + timedelta(days=30)):
                logger.warning(f"Certificate will expire soon: {cert.not_valid_after}")
            
            # Check if certificate is self-signed
            is_self_signed = (cert.issuer == cert.subject)
            
            # Check key size for RSA keys
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                if key_size < 2048:
                    return False, f"Certificate key size too small: {key_size} bits (minimum 2048 required)"
            
            # If self-signed, flag it but don't invalidate
            if is_self_signed:
                logger.warning("Certificate is self-signed and not suitable for production use")
            
            return True, "" if not is_self_signed else "Self-signed certificate"
            
    except Exception as e:
        logger.error(f"Certificate validation error: {e}")
        return False, f"Certificate validation error: {e}"