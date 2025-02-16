"""
Secure Vault API Demo
This script demonstrates various ways to use the Secure Vault API
"""

import os
from pathlib import Path
import requests
import json
from secure_vault import SecureVault, CryptoManager
from rich.console import Console
from rich.panel import Panel

console = Console()

def demo_python_api():
    """Demonstrate direct Python API usage"""
    console.print(Panel("Python API Demo", style="bold blue"))
    
    # Initialize vault
    vault = SecureVault("./demo_vault")
    
    # Create a test file
    with open("test_file.txt", "w") as f:
        f.write("This is a secret message for encryption!")
    
    try:
        # Encrypt the file
        console.print("Encrypting file...", style="yellow")
        encrypted_path = vault.encrypt_file("test_file.txt", "demo_password")
        console.print(f"File encrypted: {encrypted_path}", style="green")
        
        # List encrypted files
        console.print("\nListing encrypted files:", style="yellow")
        files = vault.list_files()
        for file in files:
            console.print(f"- {file.name}", style="green")
        
        # Decrypt the file
        console.print("\nDecrypting file...", style="yellow")
        decrypted_path = vault.decrypt_file(
            encrypted_path,
            "decrypted_file.txt",
            "demo_password"
        )
        console.print(f"File decrypted: {decrypted_path}", style="green")
        
        # Verify content
        with open(decrypted_path, "r") as f:
            content = f.read()
            console.print(f"\nDecrypted content: {content}", style="green")
            
        # Try with wrong password
        console.print("\nTrying with wrong password...", style="yellow")
        try:
            vault.decrypt_file(encrypted_path, "wrong.txt", "wrong_password")
        except ValueError as e:
            console.print(f"Expected error: {e}", style="red")
            
    finally:
        # Cleanup
        console.print("\nCleaning up...", style="yellow")
        for file in ["test_file.txt", "decrypted_file.txt"]:
            if os.path.exists(file):
                os.remove(file)
                console.print(f"Removed: {file}", style="green")

def demo_web_api():
    """Demonstrate Web API usage"""
    console.print(Panel("\nWeb API Demo", style="bold blue"))
    
    # Start the Flask server separately with:
    # export FLASK_APP=secure_vault.web_api
    # flask run
    
    BASE_URL = "http://localhost:5000/api"
    
    # Get authentication token
    console.print("Getting authentication token...", style="yellow")
    auth_response = requests.post(
        f"{BASE_URL}/auth",
        auth=("demo_user", "demo_password")
    )
    
    if auth_response.status_code != 200:
        console.print("Authentication failed!", style="red")
        return
        
    token = auth_response.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    console.print("Got authentication token", style="green")
    
    # Create test file
    with open("web_test.txt", "w") as f:
        f.write("This is a test for the web API!")
    
    try:
        # List files
        console.print("\nListing files...", style="yellow")
        list_response = requests.get(f"{BASE_URL}/files", headers=headers)
        files = list_response.json()
        for file in files:
            console.print(f"- {file['name']}", style="green")
        
        # Encrypt file
        console.print("\nEncrypting file...", style="yellow")
        with open("web_test.txt", "rb") as f:
            files = {"file": f}
            data = {"password": "web_password"}
            response = requests.post(
                f"{BASE_URL}/files",
                headers=headers,
                files=files,
                data=data
            )
            
        if response.status_code == 200:
            encrypted_file = response.json()["file"]
            console.print(f"File encrypted: {encrypted_file}", style="green")
            
            # Decrypt file
            console.print("\nDecrypting file...", style="yellow")
            response = requests.post(
                f"{BASE_URL}/files/{encrypted_file}",
                headers=headers,
                data={"password": "web_password"}
            )
            
            if response.status_code == 200:
                with open("web_decrypted.txt", "wb") as f:
                    f.write(response.content)
                console.print("File decrypted successfully", style="green")
                
                # Verify content
                with open("web_decrypted.txt", "r") as f:
                    content = f.read()
                    console.print(f"\nDecrypted content: {content}", style="green")
            
            # Try wrong password
            console.print("\nTrying with wrong password...", style="yellow")
            response = requests.post(
                f"{BASE_URL}/files/{encrypted_file}",
                headers=headers,
                data={"password": "wrong_password"}
            )
            console.print(f"Expected error: {response.json()['error']}", style="red")
            
            # Delete file
            console.print("\nDeleting encrypted file...", style="yellow")
            response = requests.delete(
                f"{BASE_URL}/files/{encrypted_file}",
                headers=headers
            )
            if response.status_code == 200:
                console.print("File deleted successfully", style="green")
                
    finally:
        # Cleanup
        console.print("\nCleaning up...", style="yellow")
        for file in ["web_test.txt", "web_decrypted.txt"]:
            if os.path.exists(file):
                os.remove(file)
                console.print(f"Removed: {file}", style="green")

def demo_crypto_manager():
    """Demonstrate low-level cryptographic operations"""
    console.print(Panel("\nCryptoManager Demo", style="bold blue"))
    
    crypto = CryptoManager()
    
    # Example data
    data = b"This is sensitive data to be encrypted"
    password = "crypto_demo_password"
    
    try:
        # Encrypt data
        console.print("Encrypting data...", style="yellow")
        encrypted_data = crypto.encrypt(data, password)
        console.print("Data encrypted successfully", style="green")
        console.print("\nEncrypted data object:", style="yellow")
        console.print(f"Nonce: {encrypted_data.nonce}", style="green")
        console.print(f"Salt: {encrypted_data.salt}", style="green")
        console.print(f"Signature: {encrypted_data.signature[:32]}...", style="green")
        
        # Decrypt data
        console.print("\nDecrypting data...", style="yellow")
        decrypted_data = crypto.decrypt(encrypted_data, password)
        console.print(f"Decrypted: {decrypted_data.decode()}", style="green")
        
        # Try wrong password
        console.print("\nTrying with wrong password...", style="yellow")
        try:
            crypto.decrypt(encrypted_data, "wrong_password")
        except ValueError as e:
            console.print(f"Expected error: {e}", style="red")
            
    except Exception as e:
        console.print(f"Error: {e}", style="red")

if __name__ == "__main__":
    # Create demo directory
    os.makedirs("demo_vault", exist_ok=True)
    
    try:
        # Run demos
        demo_python_api()
        demo_web_api()
        demo_crypto_manager()
        
    finally:
        # Cleanup demo directory
        import shutil
        if os.path.exists("demo_vault"):
            shutil.rmtree("demo_vault")
            console.print("\nRemoved demo vault directory", style="green")