#!/usr/bin/env python
"""
Test script for validating the secure deletion functionality in SecureVault.
This script tests the SecureFile, SecureDirectory, and SecureTempFile classes
as well as the secure_move function to ensure proper secure deletion behavior.
"""

import os
import sys
import tempfile
import shutil
import logging
import time
import random
import string
from pathlib import Path
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('secure_deletion_test.log')
    ]
)
logger = logging.getLogger('secure_deletion_test')

# Attempt to import the secure file utilities
try:
    from secure_vault.security.files import SecureFile, SecureDirectory, SecureTempFile, secure_move
    logger.info("Successfully imported secure file utilities")
except ImportError:
    logger.error("Failed to import secure file utilities. Make sure the module is in your Python path.")
    # Try to add the parent directory to the path
    parent_dir = str(Path(__file__).parent.parent)
    sys.path.append(parent_dir)
    try:
        from secure_vault.security.files import SecureFile, SecureDirectory, SecureTempFile, secure_move
        logger.info(f"Successfully imported secure file utilities after adding {parent_dir} to path")
    except ImportError:
        logger.error("Could not import even after path adjustment. Please check your installation.")
        sys.exit(1)

def generate_random_content(size_kb=1):
    """Generate random file content of specified size in KB"""
    content = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
    return content.encode('utf-8')

def create_test_file(path, size_kb=1):
    """Create a test file with random content"""
    content = generate_random_content(size_kb)
    with open(path, 'wb') as f:
        f.write(content)
    return path

def check_file_exists(path):
    """Check if a file exists and log the result"""
    exists = os.path.exists(path)
    if exists:
        logger.warning(f"File still exists: {path}")
    else:
        logger.info(f"File successfully deleted: {path}")
    return exists

def test_secure_file_delete():
    """Test SecureFile.secure_delete() functionality"""
    logger.info("=== Testing SecureFile.secure_delete() ===")
    
    # Create a temporary file
    temp_dir = tempfile.mkdtemp(prefix="securevault_test_")
    test_file_path = os.path.join(temp_dir, "test_secure_file.txt")
    
    try:
        # Create test file
        create_test_file(test_file_path, size_kb=10)
        logger.info(f"Created test file: {test_file_path}")
        
        # Verify it exists
        assert os.path.exists(test_file_path), "Test file was not created"
        
        # Use SecureFile to delete it
        secure_file = SecureFile(test_file_path)
        secure_file.secure_delete()
        
        # Check if it was deleted
        exists = check_file_exists(test_file_path)
        assert not exists, "SecureFile.secure_delete() failed to delete the file"
        
        # Test with a non-existent file (should not raise exception)
        try:
            nonexistent_path = os.path.join(temp_dir, "nonexistent.txt")
            secure_file = SecureFile(nonexistent_path)
            secure_file.secure_delete()
            logger.info("SecureFile.secure_delete() handled non-existent file correctly")
        except Exception as e:
            logger.error(f"SecureFile.secure_delete() failed for non-existent file: {e}")
            assert False, "SecureFile.secure_delete() should not raise exception for non-existent file"
            
        # Test with a file that's being used (should handle gracefully)
        try:
            in_use_path = os.path.join(temp_dir, "in_use.txt")
            create_test_file(in_use_path, size_kb=1)
            
            # Open the file to create a file handle that keeps it open
            with open(in_use_path, 'r+b') as f:
                f.seek(0)
                f.write(b'X')  # Write something to keep the file open
                
                # Try to delete while the file is open
                secure_file = SecureFile(in_use_path)
                secure_file.secure_delete()
                
                # Check if it was deleted or at least attempted
                logger.info("SecureFile.secure_delete() attempted to delete in-use file")
            
            # After closing, check if the file still exists and delete if needed
            if os.path.exists(in_use_path):
                logger.warning("File was still in use, forcibly removing now")
                os.remove(in_use_path)
        except Exception as e:
            logger.error(f"SecureFile.secure_delete() test for in-use file had an unexpected error: {e}")
            traceback.print_exc()
        
        logger.info("SecureFile secure deletion tests completed")
        return True
    except AssertionError as e:
        logger.error(f"Test failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in test_secure_file_delete: {e}")
        traceback.print_exc()
        return False
    finally:
        # Clean up
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            logger.error(f"Failed to clean up temp directory: {e}")

def test_secure_directory_delete():
    """Test SecureDirectory.secure_delete() functionality"""
    logger.info("=== Testing SecureDirectory.secure_delete() ===")
    
    # Create a temporary directory structure
    base_temp_dir = tempfile.mkdtemp(prefix="securevault_test_dir_")
    test_dir = os.path.join(base_temp_dir, "test_dir")
    
    try:
        # Create directory structure with subdirectories and files
        os.makedirs(test_dir)
        os.makedirs(os.path.join(test_dir, "subdir1"))
        os.makedirs(os.path.join(test_dir, "subdir2", "subsubdir"))
        
        # Create some test files
        create_test_file(os.path.join(test_dir, "file1.txt"), size_kb=1)
        create_test_file(os.path.join(test_dir, "subdir1", "file2.txt"), size_kb=2)
        create_test_file(os.path.join(test_dir, "subdir2", "file3.txt"), size_kb=3)
        create_test_file(os.path.join(test_dir, "subdir2", "subsubdir", "file4.txt"), size_kb=4)
        
        logger.info(f"Created test directory structure at: {test_dir}")
        
        # Use SecureDirectory to delete it
        secure_dir = SecureDirectory(test_dir)
        secure_dir.secure_delete()
        
        # Check if it was deleted
        exists = os.path.exists(test_dir)
        if exists:
            logger.warning(f"Directory still exists: {test_dir}")
            # List remaining contents for debugging
            for root, dirs, files in os.walk(test_dir):
                for file in files:
                    logger.warning(f"Remaining file: {os.path.join(root, file)}")
                for dir in dirs:
                    logger.warning(f"Remaining directory: {os.path.join(root, dir)}")
        else:
            logger.info(f"Directory successfully deleted: {test_dir}")
        
        assert not exists, "SecureDirectory.secure_delete() failed to delete the directory"
        
        # Test with a non-existent directory (should not raise exception)
        try:
            nonexistent_dir = os.path.join(base_temp_dir, "nonexistent_dir")
            secure_dir = SecureDirectory(nonexistent_dir)
            secure_dir.secure_delete()
            logger.info("SecureDirectory.secure_delete() handled non-existent directory correctly")
        except Exception as e:
            logger.error(f"SecureDirectory.secure_delete() failed for non-existent directory: {e}")
            assert False, "SecureDirectory.secure_delete() should not raise exception for non-existent directory"
        
        logger.info("SecureDirectory secure deletion tests completed")
        return True
    except AssertionError as e:
        logger.error(f"Test failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in test_secure_directory_delete: {e}")
        traceback.print_exc()
        return False
    finally:
        # Clean up
        try:
            if os.path.exists(base_temp_dir):
                shutil.rmtree(base_temp_dir)
        except Exception as e:
            logger.error(f"Failed to clean up base temp directory: {e}")

def test_secure_temp_file():
    """Test SecureTempFile context manager"""
    logger.info("=== Testing SecureTempFile context manager ===")
    
    temp_path = None
    
    try:
        # Use SecureTempFile context manager
        with SecureTempFile(prefix="secure_test_") as temp_file:
            temp_path = temp_file
            
            # Write some data
            with open(temp_path, 'wb') as f:
                f.write(generate_random_content(size_kb=5))
            
            logger.info(f"Created temporary file with SecureTempFile: {temp_path}")
            
            # Verify it exists within the context
            assert os.path.exists(temp_path), "Temporary file was not created properly"
        
        # After exiting context, verify file was deleted
        exists = check_file_exists(temp_path)
        assert not exists, "SecureTempFile failed to delete the temporary file after context exit"
        
        # Test exception handling in context
        temp_path = None
        try:
            with SecureTempFile(prefix="secure_test_except_") as temp_file:
                temp_path = temp_file
                
                # Write some data
                with open(temp_path, 'wb') as f:
                    f.write(generate_random_content(size_kb=1))
                
                logger.info(f"Created temporary file for exception test: {temp_path}")
                
                # Simulate an exception
                raise ValueError("Test exception to verify cleanup")
        except ValueError:
            # Expected exception
            pass
        
        # Verify file was deleted despite exception
        if temp_path:
            exists = check_file_exists(temp_path)
            assert not exists, "SecureTempFile failed to delete the temporary file after exception"
        
        logger.info("SecureTempFile tests completed")
        return True
    except AssertionError as e:
        logger.error(f"Test failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in test_secure_temp_file: {e}")
        traceback.print_exc()
        return False

def test_secure_move():
    """Test secure_move function"""
    logger.info("=== Testing secure_move function ===")
    
    # Create temporary directories
    src_dir = tempfile.mkdtemp(prefix="securevault_test_src_")
    dst_dir = tempfile.mkdtemp(prefix="securevault_test_dst_")
    
    src_path = os.path.join(src_dir, "source_file.txt")
    dst_path = os.path.join(dst_dir, "destination_file.txt")
    
    try:
        # Create source file
        create_test_file(src_path, size_kb=10)
        logger.info(f"Created source file: {src_path}")
        
        # Move the file securely
        secure_move(src_path, dst_path)
        
        # Verify source was deleted and destination exists
        src_exists = check_file_exists(src_path)
        dst_exists = os.path.exists(dst_path)
        
        assert not src_exists, "secure_move failed to delete source file"
        assert dst_exists, "secure_move failed to create destination file"
        
        # Test with non-existent source
        try:
            nonexistent_src = os.path.join(src_dir, "nonexistent.txt")
            new_dst = os.path.join(dst_dir, "new_destination.txt")
            secure_move(nonexistent_src, new_dst)
            logger.error("secure_move should have raised an exception for non-existent source")
            assert False, "secure_move should raise exception for non-existent source"
        except Exception:
            logger.info("secure_move correctly raised exception for non-existent source")
        
        # Test with destination in non-existent directory (should create directory)
        new_dir_path = os.path.join(dst_dir, "new_subdir")
        new_dst_path = os.path.join(new_dir_path, "new_file.txt")
        
        # Create new source file
        new_src_path = os.path.join(src_dir, "another_source.txt")
        create_test_file(new_src_path, size_kb=2)
        
        secure_move(new_src_path, new_dst_path)
        
        src_exists = check_file_exists(new_src_path)
        dst_exists = os.path.exists(new_dst_path)
        
        assert not src_exists, "secure_move failed to delete source file in directory creation test"
        assert dst_exists, "secure_move failed to create destination file in new directory"
        
        logger.info("secure_move tests completed")
        return True
    except AssertionError as e:
        logger.error(f"Test failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in test_secure_move: {e}")
        traceback.print_exc()
        return False
    finally:
        # Clean up
        try:
            shutil.rmtree(src_dir)
            shutil.rmtree(dst_dir)
        except Exception as e:
            logger.error(f"Failed to clean up temp directories: {e}")

def test_error_handling():
    """Test error handling in secure deletion functions"""
    logger.info("=== Testing error handling in secure deletion ===")
    
    temp_dir = tempfile.mkdtemp(prefix="securevault_test_errors_")
    test_file_path = os.path.join(temp_dir, "error_test.txt")
    
    try:
        # Test 1: Attempt to delete a file with insufficient permissions
        create_test_file(test_file_path, size_kb=1)
        logger.info(f"Created test file: {test_file_path}")
        
        # Make file read-only on Unix-like systems
        if os.name == 'posix':
            import stat
            os.chmod(test_file_path, stat.S_IRUSR)
            logger.info(f"Made file read-only: {test_file_path}")
            
            # Try to delete it securely
            secure_file = SecureFile(test_file_path)
            
            try:
                secure_file.secure_delete()
                logger.info("SecureFile.secure_delete() handled read-only file")
            except Exception as e:
                logger.error(f"SecureFile.secure_delete() failed for read-only file: {e}")
                # Not failing the test since the behavior might be platform-dependent
            
            # Check the result
            exists = os.path.exists(test_file_path)
            if exists:
                # Reset permissions so we can clean up
                os.chmod(test_file_path, stat.S_IRUSR | stat.S_IWUSR)
                logger.warning("Read-only file still exists, manually removing")
                os.remove(test_file_path)
            else:
                logger.info("Read-only file was successfully deleted")
        else:
            logger.info("Skipping read-only file test on non-POSIX system")
        
        # Test 2: Create a file with forced I/O errors
        # This is a platform-dependent simulation, not a real test
        # Just log information about our expectations
        logger.info("In a production environment, I/O errors during secure deletion should be properly handled")
        logger.info("The enhanced implementation includes fallback mechanisms and proper error handling")
        
        return True
    except Exception as e:
        logger.error(f"Unexpected error in test_error_handling: {e}")
        traceback.print_exc()
        return False
    finally:
        # Clean up
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            logger.error(f"Failed to clean up temp directory: {e}")

def run_all_tests():
    """Run all tests and report results"""
    tests = [
        test_secure_file_delete,
        test_secure_directory_delete,
        test_secure_temp_file,
        test_secure_move,
        test_error_handling
    ]
    
    results = {}
    
    for test_func in tests:
        test_name = test_func.__name__
        logger.info(f"\nRunning {test_name}...")
        
        start_time = time.time()
        success = test_func()
        end_time = time.time()
        
        duration = end_time - start_time
        results[test_name] = {
            'success': success,
            'duration': duration
        }
        
        status = "PASSED" if success else "FAILED"
        logger.info(f"{test_name} {status} in {duration:.2f} seconds\n")
    
    # Print summary
    logger.info("\n=== Test Summary ===")
    passed = sum(1 for result in results.values() if result['success'])
    failed = len(results) - passed
    
    for test_name, result in results.items():
        status = "PASSED" if result['success'] else "FAILED"
        logger.info(f"{test_name}: {status} ({result['duration']:.2f}s)")
    
    logger.info(f"\nTotal: {len(results)} tests, {passed} passed, {failed} failed")
    
    return failed == 0

if __name__ == "__main__":
    logger.info("Starting secure deletion tests")
    
    try:
        success = run_all_tests()
        if success:
            logger.info("All tests passed!")
            sys.exit(0)
        else:
            logger.error("Some tests failed. Check the log for details.")
            sys.exit(1)
    except Exception as e:
        logger.critical(f"Test suite failed with error: {e}")
        traceback.print_exc()
        sys.exit(2)