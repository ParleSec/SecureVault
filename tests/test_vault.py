import pytest
from pathlib import Path
from secure_vault.core.vault import SecureVault

@pytest.fixture
def temp_vault(tmp_path):
    return SecureVault(str(tmp_path))

@pytest.fixture
def test_file(tmp_path):
    file_path = tmp_path / "test.txt"
    file_path.write_text("Hello, World!")
    return file_path

def test_encrypt_decrypt_file(temp_vault, test_file):
    password = "test_password"
    
    # Test encryption
    encrypted_path = temp_vault.encrypt_file(str(test_file), password)
    assert encrypted_path.exists()
    assert encrypted_path.suffix == ".vault"
    
    # Test decryption
    output_path = test_file.parent / "decrypted.txt"
    decrypted_path = temp_vault.decrypt_file(encrypted_path, output_path, password)
    assert decrypted_path.exists()
    assert decrypted_path.read_text() == "Hello, World!"

def test_list_files(temp_vault, test_file):
    password = "test_password"
    
    # Encrypt a file
    temp_vault.encrypt_file(str(test_file), password)
    
    # Test listing files
    files = temp_vault.list_files()
    assert len(files) == 1
    assert files[0].suffix == ".vault"