import pytest
from secure_vault.web_api import create_app
import jwt
import json
import os
from pathlib import Path
import tempfile

@pytest.fixture
def app():
    """Create application for testing"""
    app = create_app(testing=True)
    return app

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def auth_token(app):
    """Create authentication token"""
    token = jwt.encode(
        {'sub': 'test_user'},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

@pytest.fixture
def auth_headers(auth_token):
    """Create headers with authentication"""
    return {'Authorization': f'Bearer {auth_token}'}

def test_authentication(client):
    """Test authentication endpoint"""
    response = client.post('/api/auth', auth=('test_user', 'password'))
    assert response.status_code == 200
    assert 'token' in response.json

def test_list_files_unauthorized(client):
    """Test list files without authentication"""
    response = client.get('/api/files')
    assert response.status_code == 401

def test_list_files(client, auth_headers):
    """Test list files with authentication"""
    response = client.get('/api/files', headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json, list)

def test_encrypt_file(client, auth_headers):
    """Test file encryption"""
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('test content')
        test_file = f.name

    try:
        with open(test_file, 'rb') as f:
            response = client.post(
                '/api/files',
                data={
                    'file': (f, 'test.txt'),
                    'password': 'test_password'
                },
                headers=auth_headers
            )
        
        assert response.status_code == 200
        assert 'file' in response.json
        
    finally:
        # Clean up
        os.unlink(test_file)

def test_decrypt_file(client, auth_headers):
    """Test file decryption"""
    # First encrypt a file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('test content')
        test_file = f.name

    try:
        # Encrypt
        with open(test_file, 'rb') as f:
            response = client.post(
                '/api/files',
                data={
                    'file': (f, 'test.txt'),
                    'password': 'test_password'
                },
                headers=auth_headers
            )
        
        encrypted_file = response.json['file']
        
        # Now decrypt
        response = client.post(
            f'/api/files/{encrypted_file}',
            data={'password': 'test_password'},
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert response.data.decode() == 'test content'
        
    finally:
        # Clean up
        os.unlink(test_file)

def test_delete_file(client, auth_headers):
    """Test file deletion"""
    # First encrypt a file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write('test content')
        test_file = f.name

    try:
        # Encrypt
        with open(test_file, 'rb') as f:
            response = client.post(
                '/api/files',
                data={
                    'file': (f, 'test.txt'),
                    'password': 'test_password'
                },
                headers=auth_headers
            )
        
        encrypted_file = response.json['file']
        
        # Delete the file
        response = client.delete(
            f'/api/files/{encrypted_file}',
            headers=auth_headers
        )
        
        assert response.status_code == 200
        
        # Verify file is gone
        response = client.get('/api/files', headers=auth_headers)
        assert encrypted_file not in [f['name'] for f in response.json]
        
    finally:
        # Clean up
        os.unlink(test_file)

def test_rate_limiting(client, auth_headers):
    """Test rate limiting"""
    # Make many requests
    for _ in range(101):  # One more than limit
        response = client.get('/api/files', headers=auth_headers)
    
    assert response.status_code == 429
    assert 'Rate limit exceeded' in response.json['error']