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
import secrets

if platform.system() == 'Windows':
    try:
        import win32security
        import win32api  # Added this import for GetCurrentProcess
        import ntsecuritycon as con
        WINDOWS_SECURITY_AVAILABLE = True
    except ImportError:
        WINDOWS_SECURITY_AVAILABLE = False
        logging.getLogger(__name__).warning("Windows security modules not available. Limited security will be applied.")

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
            if platform.system() == 'Windows' and WINDOWS_SECURITY_AVAILABLE:
                # Get file security
                security = win32security.GetFileSecurity(
                    str(self.path), 
                    win32security.DACL_SECURITY_INFORMATION
                )
                
                # Create DACL with owner-only permissions
                dacl = win32security.ACL()
                
                # Get current process token using win32api.GetCurrentProcess
                process_handle = win32api.GetCurrentProcess()
                token_handle = win32security.OpenProcessToken(
                    process_handle,
                    win32security.TOKEN_QUERY
                )
                user_sid = win32security.GetTokenInformation(
                    token_handle,
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
            elif platform.system() != 'Windows':
                # Unix-like systems: set user read/write only
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logger.error(f"Failed to set secure permissions: {e}")

    def secure_delete(self):
        """Securely delete the file"""
        if not self.path.exists():
            logger.debug(f"File {self.path} does not exist, nothing to delete")
            return
            
        temp_path = None
        try:
            # Get file size
            size = self.path.stat().st_size
            
            # Try to use a different name if file might be in use
            try:
                temp_path = str(self.path) + ".del" + secrets.token_hex(4)
                os.rename(self.path, temp_path)
                path_to_wipe = temp_path
            except (OSError, PermissionError):
                # Continue with original path if rename fails
                temp_path = None
                path_to_wipe = str(self.path)

            # Multiple pass overwrite - in a separate try block to ensure we continue
            # with deletion even if overwrite fails
            try:
                with open(path_to_wipe, 'wb') as f:
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
            except Exception as e:
                logger.error(f"Error during file wiping of {path_to_wipe}: {e}")
                # Continue to file deletion anyway

            # Finally delete the file
            try:
                os.unlink(path_to_wipe)
                logger.debug(f"Deleted file: {path_to_wipe}")
            except Exception as e:
                logger.error(f"Failed to delete file {path_to_wipe} after wiping: {e}")
                raise  # Re-raise to be caught by outer exception handler
                
        except Exception as e:
            logger.error(f"Failed to securely delete file {self.path}: {e}")
            
            # Last resort: try standard deletion without secure wipe
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                    logger.warning(f"Used fallback standard deletion for {temp_path}")
                except Exception as fallback_e:
                    logger.error(f"Fallback deletion also failed for {temp_path}: {fallback_e}")
            elif os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                    logger.warning(f"Used fallback standard deletion for {self.path}")
                except Exception as fallback_e:
                    logger.error(f"Fallback deletion also failed for {self.path}: {fallback_e}")

    def __enter__(self):
        """Support for with statement"""
        return self.path
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup when exiting context"""
        pass  # We don't delete the file when exiting the context

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
            if platform.system() == 'Windows' and WINDOWS_SECURITY_AVAILABLE:
                # Similar to file permissions but for directories
                security = win32security.GetFileSecurity(
                    str(self.path),
                    win32security.DACL_SECURITY_INFORMATION
                )
                
                dacl = win32security.ACL()
                
                # Get current process token using win32api.GetCurrentProcess
                process_handle = win32api.GetCurrentProcess()
                token_handle = win32security.OpenProcessToken(
                    process_handle,
                    win32security.TOKEN_QUERY
                )
                user_sid = win32security.GetTokenInformation(
                    token_handle,
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
            elif platform.system() != 'Windows':
                # Unix-like systems: set user read/write/execute only
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except Exception as e:
            logger.error(f"Failed to set secure directory permissions: {e}")

    def secure_delete(self):
        """Securely delete the directory and its contents"""
        if not self.path.exists():
            logger.debug(f"Directory {self.path} does not exist, nothing to delete")
            return

        try:
            # Create a list of all files to delete
            files_to_delete = list(self.path.rglob('*'))
            
            # Sort files so that deeper paths are deleted first
            files_to_delete.sort(key=lambda x: len(str(x).split(os.sep)), reverse=True)
            
            # Track failed files for fallback deletion
            failed_files = []
            
            # First, securely delete all files
            for file_path in files_to_delete:
                if file_path.is_file():
                    try:
                        secure_file = SecureFile(file_path)
                        secure_file.secure_delete()
                    except Exception as e:
                        logger.error(f"Failed to securely delete file {file_path}: {e}")
                        failed_files.append(file_path)
            
            # Try fallback deletion for any files that failed
            for file_path in failed_files:
                if file_path.exists():
                    try:
                        file_path.unlink()
                        logger.warning(f"Used fallback standard deletion for {file_path}")
                    except Exception as e:
                        logger.error(f"Fallback deletion also failed for {file_path}: {e}")
            
            # Now try to delete all empty directories
            dirs_to_delete = [p for p in files_to_delete if p.is_dir()]
            dirs_to_delete.sort(key=lambda x: len(str(x).split(os.sep)), reverse=True)
            
            for dir_path in dirs_to_delete:
                try:
                    dir_path.rmdir()  # Will only succeed if directory is empty
                except Exception as e:
                    logger.error(f"Failed to delete directory {dir_path}: {e}")
            
            # Finally try to delete the root directory
            try:
                self.path.rmdir()
            except Exception as e:
                logger.error(f"Failed to delete root directory {self.path}: {e}")
                
                # If the directory still exists, use shutil as a last resort
                if self.path.exists():
                    logger.warning(f"Using shutil.rmtree as fallback for {self.path}")
                    shutil.rmtree(self.path, ignore_errors=True)
                    
        except Exception as e:
            logger.error(f"Failed to securely delete directory {self.path}: {e}")
            
            # Fallback: use shutil.rmtree as a last resort
            try:
                if self.path.exists():
                    shutil.rmtree(self.path, ignore_errors=True)
                    logger.warning(f"Used fallback rmtree for {self.path}")
            except Exception as fallback_e:
                logger.error(f"Fallback rmtree also failed for {self.path}: {fallback_e}")

class SecureTempFile:
    """
    Secure temporary file that is automatically deleted
    """
    def __init__(self, prefix: Optional[str] = None, suffix: Optional[str] = None, dir: Optional[str] = None):
        self.path = None
        self.prefix = prefix
        self.suffix = suffix
        self.dir = dir
        self._file = None
        self._fd = None
        self._closed = False

    def __enter__(self):
        import tempfile
        # Create temporary file
        self._fd, self.path = tempfile.mkstemp(prefix=self.prefix, suffix=self.suffix, dir=self.dir)
        os.close(self._fd)
        self._fd = None
        
        # Set secure permissions
        self._file = SecureFile(self.path)
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure secure deletion on exit"""
        self.close()

    def close(self):
        """Explicitly close and securely delete the temporary file"""
        if not self._closed:
            # Close file descriptor if still open
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass  # Already closed
                self._fd = None
                
            # Delete the file securely
            if self.path and os.path.exists(self.path):
                try:
                    if self._file:
                        self._file.secure_delete()
                    else:
                        # Fallback if _file wasn't created properly
                        logger.warning(f"Using fallback secure deletion for {self.path}")
                        size = os.path.getsize(self.path)
                        
                        try:
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
                        except Exception as e:
                            logger.error(f"Error wiping temporary file {self.path}: {e}")
                            
                        # Finally delete the file
                        try:
                            os.unlink(self.path)
                        except Exception as e:
                            logger.error(f"Error deleting temporary file {self.path}: {e}")
                except Exception as e:
                    logger.error(f"Failed to securely delete temporary file {self.path}: {e}")
                    
                    # Last resort: try standard deletion
                    try:
                        if os.path.exists(self.path):
                            os.unlink(self.path)
                            logger.warning(f"Used fallback standard deletion for {self.path}")
                    except Exception as fallback_e:
                        logger.error(f"Fallback deletion failed for {self.path}: {fallback_e}")
            
            self._closed = True
    
    def __del__(self):
        """Ensure deletion during garbage collection"""
        self.close()

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
    Securely move a file with error handling to ensure deletion
    """
    src, dst = Path(src), Path(dst)
    temp_file = None
    
    if not src.exists():
        logger.error(f"Source file does not exist: {src}")
        return False
    
    try:
        # Create directory if necessary
        dest_dir = dst.parent
        if not dest_dir.exists():
            dest_dir.mkdir(parents=True)
            SecureDirectory(dest_dir)._set_secure_permissions()
        
        # Use temporary file for safer copying
        temp_file = str(dst) + ".tmp" + secrets.token_hex(4)
        
        # Copy to temporary location first
        shutil.copy2(src, temp_file)
        SecureFile(temp_file)._set_secure_permissions()
        
        # Rename to destination
        if os.path.exists(dst):
            # If destination exists, delete it first
            os.unlink(dst)
        os.rename(temp_file, dst)
        
        # Remove reference to temp_file since it's been renamed
        temp_file = None
        
        # Now securely delete the source
        SecureFile(src).secure_delete()
        
        return True
    except Exception as e:
        logger.error(f"Failed to securely move file: {e}")
        
        # Clean up temp file if it exists
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
                logger.info(f"Cleaned up temporary file {temp_file}")
            except Exception as cleanup_e:
                logger.error(f"Failed to clean up temporary file {temp_file}: {cleanup_e}")
        
        # Try to ensure source file is deleted even on error
        try:
            if src.exists():
                SecureFile(src).secure_delete()
                logger.info(f"Source file {src} securely deleted after move error")
        except Exception as del_e:
            logger.error(f"Failed to securely delete source file after move error: {del_e}")
        
        raise  # Re-raise the original exception