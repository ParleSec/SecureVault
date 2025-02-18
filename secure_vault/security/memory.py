"""
Secure memory handling utilities for sensitive data
"""

import ctypes
import platform
import os
from typing import Optional
import mmap
import logging

logger = logging.getLogger(__name__)

class SecureString:
    """
    A string that is securely erased from memory when no longer needed
    """
    def __init__(self, value: str):
        self._value = value.encode('utf-8')
        self._address = id(self._value)
        self._length = len(self._value)

    def __del__(self):
        try:
            self.secure_zero()
        except Exception as e:
            logger.error(f"Failed to securely erase string: {e}")

    def secure_zero(self):
        """Securely zero out the memory containing the string"""
        if platform.system() == 'Windows':
            # Windows implementation
            handle = ctypes.c_void_p(self._address)
            ctypes.memset(handle, 0, self._length)
        else:
            # Unix-like systems
            try:
                with open('/proc/self/mem', 'rb+') as f:
                    f.seek(self._address)
                    f.write(b'\x00' * self._length)
            except (IOError, PermissionError):
                # Fallback method
                ctypes.memset(id(self._value), 0, self._length)

    @property
    def value(self) -> str:
        """Get the string value (use sparingly)"""
        return self._value.decode('utf-8')

class SecureBytes:
    """
    Bytes that are securely erased from memory when no longer needed
    """
    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._address = id(self._data)
        self._length = len(self._data)

    def __del__(self):
        try:
            self.secure_zero()
        except Exception as e:
            logger.error(f"Failed to securely erase bytes: {e}")

    def secure_zero(self):
        """Securely zero out the memory containing the bytes"""
        # First overwrite with random data
        for _ in range(3):
            for i in range(self._length):
                self._data[i] = os.urandom(1)[0]
        
        # Then zero out
        ctypes.memset(self._address, 0, self._length)
        
        # Finally, clear the reference
        self._data.clear()

    @property
    def value(self) -> bytes:
        """Get the bytes value (use sparingly)"""
        return bytes(self._data)

class SecureMemoryHandler:
    """
    Handler for secure memory operations
    """
    @staticmethod
    def mlock(address: int, size: int) -> bool:
        """Lock memory to prevent swapping"""
        try:
            if platform.system() == 'Windows':
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                return kernel32.VirtualLock(address, size)
            else:
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                return libc.mlock(address, size) == 0
        except Exception as e:
            logger.error(f"Failed to lock memory: {e}")
            return False

    @staticmethod
    def munlock(address: int, size: int) -> bool:
        """Unlock previously locked memory"""
        try:
            if platform.system() == 'Windows':
                kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                return kernel32.VirtualUnlock(address, size)
            else:
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                return libc.munlock(address, size) == 0
        except Exception as e:
            logger.error(f"Failed to unlock memory: {e}")
            return False

class ProtectedMemory:
    """
    Context manager for protected memory operations
    """
    def __init__(self, size: int):
        self.size = size
        self.address = None
        self.buffer = None

    def __enter__(self):
        # Allocate memory
        self.buffer = mmap.mmap(-1, self.size, mmap.MAP_PRIVATE)
        self.address = id(self.buffer)
        
        # Lock memory
        SecureMemoryHandler.mlock(self.address, self.size)
        return self.buffer

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            # Zero out memory
            self.buffer.seek(0)
            self.buffer.write(b'\x00' * self.size)
            
            # Unlock memory
            SecureMemoryHandler.munlock(self.address, self.size)
            
            # Close and remove buffer
            self.buffer.close()
        except Exception as e:
            logger.error(f"Failed to cleanup protected memory: {e}")

def secure_clear_memory(address: int, size: int):
    """
    Securely clear a region of memory
    """
    try:
        # Multiple overwrites with different patterns
        patterns = [0x00, 0xFF, 0xAA, 0x55]
        for pattern in patterns:
            ctypes.memset(address, pattern, size)
        
        # Final overwrite with zeros
        ctypes.memset(address, 0, size)
    except Exception as e:
        logger.error(f"Failed to clear memory: {e}")

def secure_password_prompt(prompt: str = "Enter password: ") -> SecureString:
    """
    Securely prompt for a password
    """
    import getpass
    password = getpass.getpass(prompt)
    return SecureString(password)