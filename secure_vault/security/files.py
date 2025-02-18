"""
Secure file handling utilities
"""

import os
from pathlib import Path
import shutil
import logging
import platform
from typing import Optional
import stat

if platform.system() == 'Windows':
    import win32security
    import ntsecuritycon as con

logger = logging.getLogger(__name__)

class SecureFile:
    """
    Secure file handling with proper permissions and secure deletion
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self._set_secure_permissions()

    def _set_secure_permissions(self):
        """Set secure file permissions"""
        try:
            if platform.system() == 'Windows':
                # Get file security
                security = win32security.GetFileSecurity(
                    str(self.path), 
                    win32security.DACL_SECURITY_INFORMATION
                )
                
                # Create DACL with owner-only permissions
                dacl = win32security.ACL()
                user_sid = win32security.GetTokenInformation(
                    win32security.OpenProcessToken(
                        win32security.GetCurrentProcess(),
                        win32security.TOKEN_QUERY
                    ),
                    win32security.TokenUser
                )[0]
                
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    con.FILE_ALL_ACCESS,
                    user_sid
                )
                
                # Set DACL
                security.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    str(self.path),
                    win32security.DACL_SECURITY_INFORMATION,
                    security
                )
            else:
                # Unix-like systems: set user read/write only
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logger.error(f"Failed to set secure permissions: {e}")

    def secure_delete(self):
        """Securely delete the file"""
        if not self.path.exists():
            return

        try:
            # Get file size
            size = self.path.stat().st_size

            # Multiple pass overwrite
            with open(self.path, 'wb') as f:
                # Pass 1: Random data
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())

                # Pass 2: Zeros
                f.seek(0)
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())

                # Pass 3: Ones
                f.seek(0)
                f.write(b'\xFF' * size)
                f.flush()
                os.fsync(f.fileno())

            # Finally delete
            self.path.unlink()
        except Exception as e:
            logger.error(f"Failed to securely delete file: {e}")

class SecureDirectory:
    """
    Secure directory handling
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self._set_secure_permissions()

    def _set_secure_permissions(self):
        """Set secure directory permissions"""
        try:
            if platform.system() == 'Windows':
                # Similar to file permissions but for directories
                security = win32security.GetFileSecurity(
                    str(self.path),
                    win32security.DACL_SECURITY_INFORMATION
                )
                
                dacl = win32security.ACL()
                user_sid = win32security.GetTokenInformation(
                    win32security.OpenProcessToken(
                        win32security.GetCurrentProcess(),
                        win32security.TOKEN_QUERY
                    ),
                    win32security.TokenUser
                )[0]
                
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    con.FILE_ALL_ACCESS,
                    user_sid
                )
                
                security.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    str(self.path),
                    win32security.DACL_SECURITY_INFORMATION,
                    security
                )
            else:
                # Unix-like systems: set user read/write/execute only
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except Exception as e:
            logger.error(f"Failed to set secure directory permissions: {e}")

    def secure_delete(self):
        """Securely delete the directory and its contents"""
        if not self.path.exists():
            return

        try:
            # First, securely delete all files
            for file_path in self.path.rglob('*'):
                if file_path.is_file():
                    SecureFile(file_path).secure_delete()

            # Then remove the directory
            shutil.rmtree(self.path, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to securely delete directory: {e}")

class SecureTempFile:
    """
    Secure temporary file that is automatically deleted
    """
    def __init__(self, prefix: Optional[str] = None, suffix: Optional[str] = None):
        self.path = None
        self.prefix = prefix
        self.suffix = suffix
        self._file = None

    def __enter__(self):
        import tempfile
        # Create temporary file
        fd, self.path = tempfile.mkstemp(prefix=self.prefix, suffix=self.suffix)
        os.close(fd)
        
        # Set secure permissions
        self._file = SecureFile(self.path)
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.secure_delete()

def validate_path(path: Path, base_dir: Path) -> bool:
    """
    Ensure path is within base directory
    """
    try:
        return base_dir.resolve() in path.resolve().parents
    except (ValueError, RuntimeError):
        return False

def secure_move(src: Path, dst: Path):
    """
    Securely move a file
    """
    try:
        # Copy with secure permissions
        shutil.copy2(src, dst)
        SecureFile(dst)._set_secure_permissions()
        
        # Securely delete source
        SecureFile(src).secure_delete()
    except Exception as e:
        logger.error(f"Failed to securely move file: {e}")
        raise