"""
Enhanced file permission management
"""

import os
import platform
import stat
import logging
import shutil
from pathlib import Path
from typing import Optional, Union, List

logger = logging.getLogger(__name__)

class FilePermissionManager:
    """
    Manages secure file permissions across different operating systems
    """
    def __init__(self):
        self.os_type = platform.system()
        
        # Initialize platform-specific handlers
        if self.os_type == 'Windows':
            try:
                import win32security
                import ntsecuritycon
                self._win_security = win32security
                self._win_seccon = ntsecuritycon
            except ImportError:
                logger.warning("Could not import win32security - limited Windows security will be used")
                self._win_security = None
    
    def secure_file(self, path: Union[str, Path]) -> bool:
        """
        Set secure permissions on a file
        Returns True if successful, False otherwise
        """
        path = Path(path)
        if not path.exists():
            logger.error(f"Cannot secure non-existent file: {path}")
            return False
            
        try:
            if self.os_type == 'Windows':
                return self._secure_file_windows(path)
            else:  # Unix/Linux/MacOS
                return self._secure_file_unix(path)
        except Exception as e:
            logger.error(f"Failed to secure file {path}: {e}")
            return False
    
    def _secure_file_unix(self, path: Path) -> bool:
        """Apply secure permissions on Unix-like systems"""
        try:
            # Owner read/write only (600)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            return True
        except Exception as e:
            logger.error(f"Failed to set Unix file permissions: {e}")
            return False
    
    def _secure_file_windows(self, path: Path) -> bool:
        """Apply secure permissions on Windows"""
        try:
            if self._win_security:
                # Get current user's SID
                user_sid = self._win_security.GetTokenInformation(
                    self._win_security.OpenProcessToken(
                        self._win_security.GetCurrentProcess(),
                        self._win_security.TOKEN_QUERY
                    ),
                    self._win_security.TokenUser
                )[0]
                
                # Get file security
                security = self._win_security.GetFileSecurity(
                    str(path),
                    self._win_security.DACL_SECURITY_INFORMATION
                )
                
                # Create a new DACL with owner-only permissions
                dacl = self._win_security.ACL()
                dacl.AddAccessAllowedAce(
                    self._win_security.ACL_REVISION,
                    self._win_seccon.FILE_ALL_ACCESS,
                    user_sid
                )
                
                # Set the new DACL
                security.SetSecurityDescriptorDacl(1, dacl, 0)
                self._win_security.SetFileSecurity(
                    str(path),
                    self._win_security.DACL_SECURITY_INFORMATION,
                    security
                )
            else:
                # Fallback when win32security is not available
                # Hide file attributes
                import subprocess
                subprocess.run(["attrib", "+H", str(path)], check=False)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to set Windows file permissions: {e}")
            return False
    
    def secure_directory(self, path: Union[str, Path], recursive: bool = False) -> bool:
        """
        Set secure permissions on a directory
        Returns True if successful, False otherwise
        """
        path = Path(path)
        if not path.exists() or not path.is_dir():
            logger.error(f"Cannot secure non-existent directory: {path}")
            return False
            
        try:
            success = True
            
            # Secure the directory itself
            if self.os_type == 'Windows':
                success = self._secure_directory_windows(path)
            else:  # Unix/Linux/MacOS
                success = self._secure_directory_unix(path)
            
            # Recursively secure contents if requested
            if recursive and success:
                for item in path.glob('**/*'):
                    if item.is_file():
                        success = success and self.secure_file(item)
                    elif item.is_dir():
                        if self.os_type == 'Windows':
                            success = success and self._secure_directory_windows(item)
                        else:
                            success = success and self._secure_directory_unix(item)
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to secure directory {path}: {e}")
            return False
    
    def _secure_directory_unix(self, path: Path) -> bool:
        """Apply secure permissions on Unix-like systems"""
        try:
            # Owner read/write/execute only (700)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            return True
        except Exception as e:
            logger.error(f"Failed to set Unix directory permissions: {e}")
            return False
    
    def _secure_directory_windows(self, path: Path) -> bool:
        """Apply secure permissions on Windows"""
        try:
            if self._win_security:
                # Similar to file permissions but for directories
                user_sid = self._win_security.GetTokenInformation(
                    self._win_security.OpenProcessToken(
                        self._win_security.GetCurrentProcess(),
                        self._win_security.TOKEN_QUERY
                    ),
                    self._win_security.TokenUser
                )[0]
                
                security = self._win_security.GetFileSecurity(
                    str(path),
                    self._win_security.DACL_SECURITY_INFORMATION
                )
                
                dacl = self._win_security.ACL()
                dacl.AddAccessAllowedAce(
                    self._win_security.ACL_REVISION,
                    self._win_seccon.FILE_ALL_ACCESS,
                    user_sid
                )
                
                security.SetSecurityDescriptorDacl(1, dacl, 0)
                self._win_security.SetFileSecurity(
                    str(path),
                    self._win_security.DACL_SECURITY_INFORMATION,
                    security
                )
            else:
                # Fallback when win32security is not available
                # Hide directory attributes
                import subprocess
                subprocess.run(["attrib", "+H", str(path)], check=False)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to set Windows directory permissions: {e}")
            return False
    
    def ensure_secure_path(self, path: Union[str, Path], create: bool = True) -> Optional[Path]:
        """
        Ensure a path exists with secure permissions
        If create is True, will create missing directories
        Returns the Path if successful, None otherwise
        """
        path = Path(path)
        
        try:
            # Create directory if it doesn't exist
            if not path.exists():
                if not create:
                    logger.error(f"Path does not exist and create=False: {path}")
                    return None
                    
                path.mkdir(parents=True)
            
            # Secure the path
            if path.is_dir():
                if not self.secure_directory(path):
                    return None
            else:
                if not self.secure_file(path):
                    return None
            
            return path
            
        except Exception as e:
            logger.error(f"Failed to create/secure path {path}: {e}")
            return None
    
    def check_path_permissions(self, path: Union[str, Path]) -> bool:
        """
        Check if a path has secure permissions
        Returns True if permissions are secure, False otherwise
        """
        path = Path(path)
        if not path.exists():
            return False
            
        try:
            if self.os_type == 'Windows':
                return self._check_windows_permissions(path)
            else:  # Unix/Linux/MacOS
                return self._check_unix_permissions(path)
                
        except Exception as e:
            logger.error(f"Failed to check permissions for {path}: {e}")
            return False
    
    def _check_unix_permissions(self, path: Path) -> bool:
        """Check Unix permissions for security"""
        mode = path.stat().st_mode
        
        if path.is_dir():
            # Check for 700 (owner rwx only)
            return (mode & 0o777) == 0o700
        else:
            # Check for 600 (owner rw only)
            return (mode & 0o777) == 0o600
    
    def _check_windows_permissions(self, path: Path) -> bool:
        """Check Windows permissions for security"""
        if not self._win_security:
            return True  # Can't verify without win32security
            
        try:
            # Get current user's SID
            user_sid = self._win_security.GetTokenInformation(
                self._win_security.OpenProcessToken(
                    self._win_security.GetCurrentProcess(),
                    self._win_security.TOKEN_QUERY
                ),
                self._win_security.TokenUser
            )[0]
            
            # Get file security
            security = self._win_security.GetFileSecurity(
                str(path),
                self._win_security.DACL_SECURITY_INFORMATION
            )
            
            # Get DACL
            dacl = security.GetSecurityDescriptorDacl()
            if dacl is None:
                return False
                
            # Check if only the owner has access
            ace_count = dacl.GetAceCount()
            if ace_count != 1:
                return False
                
            # Get the only ACE
            ace = dacl.GetAce(0)
            
            # Check if it's the owner and has full access
            return (ace[2] == user_sid)
            
        except Exception as e:
            logger.error(f"Failed to check Windows permissions: {e}")
            return False
    
    def secure_file_transfer(self, src: Union[str, Path], dest: Union[str, Path]) -> bool:
        """
        Securely transfer a file with proper permissions
        Returns True if successful, False otherwise
        """
        src, dest = Path(src), Path(dest)
        
        if not src.exists():
            logger.error(f"Source file does not exist: {src}")
            return False
            
        try:
            # Create directory if necessary
            dest_dir = dest.parent
            if not dest_dir.exists():
                dest_dir.mkdir(parents=True)
                self.secure_directory(dest_dir)
            
            # Copy the file securely
            shutil.copy2(src, dest)
            
            # Set secure permissions on destination
            return self.secure_file(dest)
            
        except Exception as e:
            logger.error(f"Secure file transfer failed from {src} to {dest}: {e}")
            return False

# Create a global instance
permission_manager = FilePermissionManager()