import pytest
from secure_vault.core.crypto import CryptoManager, EncryptedData

def test_encryption_decryption():
    crypto = CryptoManager()
    test_data = b"Hello, World!"
    password = "test_password"
    
    # Test encryption
    encrypted_data = crypto.encrypt(test_data, password)
    assert isinstance(encrypted_data, EncryptedData)
    
    # Test decryption
    decrypted_data = crypto.decrypt(encrypted_data, password)
    assert decrypted_data == test_data

def test_invalid_password():
    crypto = CryptoManager()
    test_data = b"Hello, World!"
    
    encrypted_data = crypto.encrypt(test_data, "correct_password")
    
    with pytest.raises(ValueError):
        crypto.decrypt(encrypted_data, "wrong_password")