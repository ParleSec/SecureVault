#!/usr/bin/env python
"""
SecureVault Encryption Test Script
Use this script to test SecureVault's encryption functionality.
"""

import os
import sys
import time
import random
import hashlib
from pathlib import Path

# Try to import SecureVault components
try:
    from secure_vault.core.crypto import CryptoManager
    from secure_vault.core.vault import SecureVault
    SECUREVAULT_IMPORTED = True
except ImportError:
    SECUREVAULT_IMPORTED = False
    print("Warning: Running in standalone mode. Testing file operations only.")

def generate_test_file(filename, size_kb):
    """Generate a test file of specified size with random content"""
    print(f"Generating {size_kb}KB test file: {filename}")
    
    # Create a file with random content
    with open(filename, 'wb') as f:
        # Generate blocks of 1KB
        for _ in range(size_kb):
            f.write(os.urandom(1024))
    
    # Calculate and return file hash
    file_hash = calculate_file_hash(filename)
    print(f"✓ File generated with SHA256: {file_hash[:16]}...")
    return file_hash

def calculate_file_hash(filename):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        # Read in 1MB chunks
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def test_file_encryption(vault_dir, test_files):
    """Test encrypting and decrypting files"""
    print("\n" + "=" * 60)
    print("SECUREVAULT ENCRYPTION TEST")
    print("=" * 60)
    
    if SECUREVAULT_IMPORTED:
        # Use actual SecureVault
        vault = SecureVault(vault_dir)
        crypto = CryptoManager()
    else:
        print("SecureVault modules not available. Simulating encryption/decryption.")
        # Skip actual tests in standalone mode
        for file_info in test_files:
            print(f"Would encrypt: {file_info['name']} ({file_info['size']}KB)")
        return
    
    results = []
    
    # Process each test file
    for file_info in test_files:
        filename = file_info['name']
        size_kb = file_info['size']
        password = file_info['password']
        
        print(f"\nTesting with file: {filename} ({size_kb}KB)")
        original_hash = generate_test_file(filename, size_kb)
        
        try:
            # Encrypt the file
            print(f"Encrypting file with password: {password[:2]}{'*' * (len(password)-4)}{password[-2:]}")
            start_time = time.time()
            encrypted_path = vault.encrypt_file(filename, password)
            encrypt_time = time.time() - start_time
            print(f"✓ File encrypted in {encrypt_time:.2f} seconds: {encrypted_path}")
            
            # Get encrypted file size
            encrypted_size = os.path.getsize(encrypted_path) / 1024  # KB
            
            # Decrypt the file
            decrypted_filename = f"decrypted_{filename}"
            print(f"Decrypting file to: {decrypted_filename}")
            start_time = time.time()
            decrypted_path = vault.decrypt_file(encrypted_path, decrypted_filename, password)
            decrypt_time = time.time() - start_time
            print(f"✓ File decrypted in {decrypt_time:.2f} seconds: {decrypted_path}")
            
            # Verify decrypted content
            decrypted_hash = calculate_file_hash(decrypted_filename)
            hashes_match = original_hash == decrypted_hash
            
            if hashes_match:
                print(f"✓ Verification successful - file integrity maintained")
            else:
                print(f"✗ Verification failed - hashes don't match!")
                print(f"  Original: {original_hash}")
                print(f"  Decrypted: {decrypted_hash}")
            
            # Record results
            results.append({
                'filename': filename,
                'size_kb': size_kb,
                'encrypted_size_kb': encrypted_size,
                'encrypt_time': encrypt_time,
                'decrypt_time': decrypt_time,
                'integrity_preserved': hashes_match,
                'original_hash': original_hash,
                'decrypted_hash': decrypted_hash
            })
            
        except Exception as e:
            print(f"✗ Test failed: {e}")
            results.append({
                'filename': filename,
                'size_kb': size_kb,
                'error': str(e)
            })
            
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    success_count = sum(1 for r in results if r.get('integrity_preserved', False))
    print(f"Tests completed: {len(results)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {len(results) - success_count}")
    
    if success_count > 0:
        # Calculate averages for successful tests
        avg_encrypt_time = sum(r['encrypt_time'] for r in results if 'encrypt_time' in r) / success_count
        avg_decrypt_time = sum(r['decrypt_time'] for r in results if 'decrypt_time' in r) / success_count
        avg_size_increase = sum((r['encrypted_size_kb'] - r['size_kb']) / r['size_kb'] * 100 
                                for r in results if 'encrypted_size_kb' in r) / success_count
        
        print(f"\nAverage encryption time: {avg_encrypt_time:.2f} seconds")
        print(f"Average decryption time: {avg_decrypt_time:.2f} seconds")
        print(f"Average size increase: {avg_size_increase:.1f}%")
    
    # Cleanup
    cleanup_test_files([f['name'] for f in test_files] + 
                      [f"decrypted_{f['name']}" for f in test_files])

def cleanup_test_files(filenames):
    """Clean up test files"""
    print("\nCleaning up test files...")
    for filename in filenames:
        if os.path.exists(filename):
            try:
                os.remove(filename)
                print(f"✓ Removed: {filename}")
            except Exception as e:
                print(f"✗ Failed to remove {filename}: {e}")

def main():
    # Configure test parameters
    vault_dir = "./test_vault"
    os.makedirs(vault_dir, exist_ok=True)
    
    # Define test files of different sizes
    test_files = [
        {'name': 'small_text.txt', 'size': 10, 'password': 'SmallTestFile@2025!'},
        {'name': 'medium_document.doc', 'size': 500, 'password': 'MediumSecure$File2025'},
        {'name': 'large_presentation.pptx', 'size': 2000, 'password': 'LargePresentation@2025!'},
        {'name': 'huge_video.mp4', 'size': 5000, 'password': 'HugeVideoFile$2025!'}
    ]
    
    # Run encryption tests
    test_file_encryption(vault_dir, test_files)
    
    # Clean up test vault
    if os.path.exists(vault_dir):
        import shutil
        shutil.rmtree(vault_dir)
        print(f"✓ Removed test vault: {vault_dir}")

if __name__ == "__main__":
    main()