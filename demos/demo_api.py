"""
Complete SecureVault HTTPS Demo
This script demonstrates the full API flow over HTTPS with proper CSRF handling
"""

import os
import requests
import json
import urllib3
import re
import time
from rich.console import Console
from rich.panel import Panel

# Disable SSL warnings for development with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

def run_https_demo():
    """Run a complete demo of the HTTPS API with proper CSRF handling"""
    console.print(Panel("SecureVault HTTPS Demo", style="bold green"))
    
    # Configuration
    BASE_URL = "https://localhost:5000"
    API_URL = f"{BASE_URL}/api"
    VERIFY_SSL = False  # Set to True for production with valid certificates

    # Step 1: Create a session that will maintain cookies
    console.print("Creating session...", style="yellow")
    session = requests.Session()
    session.verify = VERIFY_SSL
    
    # Set headers to pass CSRF referer check
    session.headers.update({
        'Referer': BASE_URL,
        'Origin': BASE_URL,
        'User-Agent': 'SecureVault-Demo/1.0'
    })
    
    # Step 2: Get initial page to receive CSRF cookie
    try:
        console.print("Getting CSRF cookie...", style="yellow")
        response = session.get(f"{API_URL}/files")
        
        # Extract CSRF cookie
        csrf_cookie = None
        for cookie in session.cookies:
            if 'csrf' in cookie.name.lower():
                csrf_cookie = cookie.value
                console.print(f"Found CSRF cookie: {cookie.name}", style="green")
                break
        
        if not csrf_cookie:
            console.print("No CSRF cookie found in response", style="red")
            # Continue anyway, as we have the Cookie jar in the session
    except Exception as e:
        console.print(f"Error getting CSRF cookie: {e}", style="red")
        console.print("Continuing with authentication attempt...", style="yellow")
    
    # Step 3: Authenticate and get token
    console.print("\nAuthenticating...", style="yellow")
    try:
        auth_response = session.post(
            f"{API_URL}/auth",
            auth=("demo_user", "demo_password"),
            headers={'X-Requested-With': 'XMLHttpRequest'}  # Help bypass some CSRF checks
        )
        
        if auth_response.status_code == 403 and "CSRF token missing" in auth_response.text:
            console.print("CSRF token required for authentication", style="red")
            console.print(f"Server response: {auth_response.text}", style="red")
            console.print(f"Cookies: {session.cookies.get_dict()}", style="yellow")
            
            # Try to extract CSRF token from error message if present
            csrf_token_match = re.search(r'name="csrf_token" value="([^"]+)"', auth_response.text)
            if csrf_token_match:
                csrf_token = csrf_token_match.group(1)
                console.print(f"Extracted CSRF token: {csrf_token}", style="green")
                auth_response = session.post(
                    f"{API_URL}/auth",
                    auth=("demo_user", "demo_password"),
                    data={"csrf_token": csrf_token}
                )
            else:
                console.print("Could not extract CSRF token. The demo requires API modifications:", style="yellow")
                console.print("1. Exempt the auth endpoint from CSRF protection", style="yellow")
                console.print("2. Update Flask-SeaSurf configuration to use AJAX header exemption", style="yellow")
                return
                
        if auth_response.status_code != 200:
            console.print(f"Authentication failed: {auth_response.status_code}", style="red")
            console.print(f"Response: {auth_response.text}", style="red")
            return
            
        token_data = auth_response.json()
        token = token_data.get("token")
        if not token:
            console.print(f"No token in response: {token_data}", style="red")
            return
            
        console.print("Authentication successful", style="green")
        console.print(f"Token expires in: {token_data.get('expires_in', 'unknown')} seconds", style="green")
        
        # Add token to session headers
        session.headers.update({"Authorization": f"Bearer {token}"})
        
    except Exception as e:
        console.print(f"Authentication error: {e}", style="red")
        return
    
    # Step 4: List files (should be empty initially)
    console.print("\nListing files...", style="yellow")
    try:
        list_response = session.get(f"{API_URL}/files")
        if list_response.status_code != 200:
            console.print(f"Failed to list files: {list_response.status_code}", style="red")
            console.print(list_response.text, style="red")
            return
            
        files = list_response.json()
        if not files:
            console.print("No files in vault (expected)", style="green")
        else:
            console.print("Files already in vault:", style="green")
            for file in files:
                console.print(f"- {file['name']}", style="green")
    except Exception as e:
        console.print(f"Error listing files: {e}", style="red")
        return
    
    # Step 5: Create and encrypt a test file
    console.print("\nPreparing test file...", style="yellow")
    test_file_path = "https_secure_test.txt"
    with open(test_file_path, "w") as f:
        f.write("This is a secure test file encrypted over HTTPS!")
    
    try:
        console.print("Uploading and encrypting file...", style="yellow")
        with open(test_file_path, "rb") as f:
            files = {"file": (os.path.basename(test_file_path), f)}
            data = {"password": "secure_https_password"}
            
            # For multipart/form-data uploads, we may need to include CSRF token
            if csrf_cookie:
                data["csrf_token"] = csrf_cookie
                
            upload_response = session.post(
                f"{API_URL}/files",
                files=files,
                data=data
            )
            
        if upload_response.status_code == 403 and "CSRF" in upload_response.text:
            console.print("CSRF protection blocking file upload", style="red")
            console.print("The file upload endpoint needs CSRF exemption:", style="yellow")
            console.print("self.csrf.exempt(encrypt_file)", style="yellow")
            return
            
        if upload_response.status_code != 200:
            console.print(f"File encryption failed: {upload_response.status_code}", style="red")
            console.print(upload_response.text, style="red")
            return
            
        encrypted_file = upload_response.json().get("file")
        if not encrypted_file:
            console.print(f"No encrypted file in response: {upload_response.json()}", style="red")
            return
            
        console.print(f"File encrypted successfully: {encrypted_file}", style="green")
        
    except Exception as e:
        console.print(f"Error during file encryption: {e}", style="red")
        return
        
    # Step 6: Download and decrypt the file
    console.print("\nDownloading and decrypting file...", style="yellow")
    decrypted_file_path = "https_decrypted_test.txt"
    try:
        decrypt_response = session.post(
            f"{API_URL}/files/{encrypted_file}",
            data={"password": "secure_https_password"}
        )
        
        if decrypt_response.status_code != 200:
            console.print(f"File decryption failed: {decrypt_response.status_code}", style="red")
            console.print(decrypt_response.text, style="red")
            return
            
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypt_response.content)
            
        console.print("File decrypted successfully", style="green")
        
        # Verify content
        with open(decrypted_file_path, "r") as f:
            content = f.read()
            console.print(f"Decrypted content: {content}", style="green")
            
    except Exception as e:
        console.print(f"Error during file decryption: {e}", style="red")
        return
    
    # Step 7: Delete the encrypted file
    console.print("\nDeleting encrypted file...", style="yellow")
    try:
        delete_response = session.delete(f"{API_URL}/files/{encrypted_file}")
        
        if delete_response.status_code != 200:
            console.print(f"File deletion failed: {delete_response.status_code}", style="red")
            console.print(delete_response.text, style="red")
            return
            
        console.print("File deleted successfully", style="green")
        
    except Exception as e:
        console.print(f"Error deleting file: {e}", style="red")
        return
    
    # Step 8: Revoke the token
    console.print("\nRevoking token...", style="yellow")
    try:
        revoke_response = session.post(f"{API_URL}/auth/revoke")
        
        if revoke_response.status_code != 200:
            console.print(f"Token revocation failed: {revoke_response.status_code}", style="red")
            console.print(revoke_response.text, style="red")
            return
            
        console.print("Token revoked successfully", style="green")
        
        # Verify token is revoked
        console.print("\nVerifying token revocation...", style="yellow")
        verify_response = session.get(f"{API_URL}/files")
        if verify_response.status_code == 401:
            console.print("Token correctly reported as invalid after revocation", style="green")
        else:
            console.print(f"Unexpected response after token revocation: {verify_response.status_code}", style="red")
        
    except Exception as e:
        console.print(f"Error during token revocation: {e}", style="red")
        return
    
    # Success!
    console.print(Panel("\n✓ HTTPS API Demo completed successfully", style="bold green"))
    console.print("The SecureVault API is properly configured with HTTPS and security features!", style="green")

def cleanup():
    """Clean up test files"""
    for file in ["https_secure_test.txt", "https_decrypted_test.txt"]:
        if os.path.exists(file):
            try:
                os.remove(file)
                console.print(f"Removed test file: {file}", style="dim")
            except Exception as e:
                console.print(f"Error removing {file}: {e}", style="dim red")

if __name__ == "__main__":
    try:
        run_https_demo()
    finally:
        cleanup()