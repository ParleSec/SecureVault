"""
Demo script showing how to use the Secure Vault CLI
"""

import os
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
import subprocess
import sys

console = Console()

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.absolute()
# Create directories for test files and vault
TEST_DIR = SCRIPT_DIR / "test_files"
VAULT_DIR = SCRIPT_DIR / "vault"

def run_command(command):
    """Run a CLI command and return its output"""
    # Use python -m syntax for Windows compatibility
    full_command = f'{sys.executable} -m secure_vault.cli --vault-dir "{VAULT_DIR}" {command}'
    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr

def create_test_files():
    """Create some test files for demonstration"""
    # Create a directory for test files
    os.makedirs(TEST_DIR, exist_ok=True)
    os.makedirs(VAULT_DIR, exist_ok=True)
    
    # Create test files of different sizes
    files = {
        "small.txt": "This is a small test file for encryption.",
        "medium.txt": "Medium sized content\n" * 100,
        "large.txt": "Large content for testing\n" * 1000
    }
    
    created_files = []
    for filename, content in files.items():
        path = TEST_DIR / filename
        with open(path, "w") as f:
            f.write(content)
            created_files.append(path)
            
    return created_files

def cleanup_files():
    """Clean up test files and artifacts"""
    # Remove test files directory
    if TEST_DIR.exists():
        for file in TEST_DIR.glob("*"):
            try:
                file.unlink()
            except Exception as e:
                console.print(f"Warning: Could not delete {file}: {e}", style="yellow")
        try:
            TEST_DIR.rmdir()
        except Exception as e:
            console.print(f"Warning: Could not remove test directory: {e}", style="yellow")
    
    # Remove vault directory
    if VAULT_DIR.exists():
        for file in VAULT_DIR.glob("*"):
            try:
                file.unlink()
            except Exception as e:
                console.print(f"Warning: Could not delete {file}: {e}", style="yellow")
        try:
            VAULT_DIR.rmdir()
        except Exception as e:
            console.print(f"Warning: Could not remove vault directory: {e}", style="yellow")
    
    # Remove decrypted files
    for file in SCRIPT_DIR.glob("decrypted_*"):
        try:
            file.unlink()
        except Exception as e:
            console.print(f"Warning: Could not delete {file}: {e}", style="yellow")

def demo_cli():
    """Demonstrate CLI functionality"""
    try:
        # Create test files
        console.print(Panel("Creating test files...", style="bold blue"))
        test_files = create_test_files()
        
        # Show help
        console.print("\n[bold blue]Showing help command:[/bold blue]")
        help_output, _ = run_command("--help")
        console.print(help_output)
        
        # Encrypt files
        console.print("\n[bold blue]Encrypting files:[/bold blue]")
        encrypted_files = []
        with Progress() as progress:
            task = progress.add_task("Encrypting...", total=len(test_files))
            
            for filepath in test_files:
                console.print(f"\nEncrypting {filepath}...")
                
                output, error = run_command(
                    f'encrypt "{filepath}" --password "test123"'
                )
                
                if error:
                    console.print(f"Error: {error}", style="bold red")
                else:
                    console.print(output, style="green")
                    # Store the full path of encrypted file
                    encrypted_files.append(VAULT_DIR / f"{filepath.stem}.vault")
                
                progress.advance(task)
        
        # List files
        console.print("\n[bold blue]Listing encrypted files:[/bold blue]")
        output, error = run_command("list")
        if error:
            console.print(f"Error: {error}", style="bold red")
        else:
            console.print(output, style="green")
        
        # Decrypt files
        console.print("\n[bold blue]Decrypting files:[/bold blue]")
        decrypted_files = []
        with Progress() as progress:
            task = progress.add_task("Decrypting...", total=len(encrypted_files))
            
            for encrypted_path in encrypted_files:
                console.print(f"\nDecrypting {encrypted_path}...")
                # Remove .vault extension and add decrypted_ prefix
                decrypted_path = SCRIPT_DIR / f"decrypted_{encrypted_path.stem}"
                
                output, error = run_command(
                    f'decrypt "{encrypted_path}" "{decrypted_path}" --password "test123"'
                )
                
                if error:
                    console.print(f"Error: {error}", style="bold red")
                else:
                    console.print(output, style="green")
                    decrypted_files.append(decrypted_path)
                
                progress.advance(task)
        
        # Verify decrypted content
        console.print("\n[bold blue]Verifying decrypted files:[/bold blue]")
        for original_path in test_files:
            decrypted_path = SCRIPT_DIR / f"decrypted_{original_path.stem}"
            
            if decrypted_path.exists():
                with open(original_path, 'r') as f1, open(decrypted_path, 'r') as f2:
                    if f1.read() == f2.read():
                        console.print(f"✓ {original_path.name} verified successfully", style="green")
                    else:
                        console.print(f"✗ {original_path.name} content mismatch", style="red")
            else:
                console.print(f"✗ {original_path.name} decryption failed", style="red")
        
        # Test wrong password
        console.print("\n[bold blue]Testing wrong password:[/bold blue]")
        test_file = encrypted_files[0]
        wrong_output_path = SCRIPT_DIR / "wrong.txt"
        output, error = run_command(
            f'decrypt "{test_file}" "{wrong_output_path}" --password "wrong_password"'
        )
        
        # Check if decryption failed with wrong password
        if "Invalid password" in error or "Invalid password" in output:
            console.print("✓ Wrong password correctly rejected", style="green")
        else:
            console.print("✗ Wrong password handling failed", style="red")
            if error:
                console.print(f"Error message: {error}", style="yellow")
            if output:
                console.print(f"Output message: {output}", style="yellow")
        
    finally:
        # Clean up
        console.print("\n[bold blue]Cleaning up...[/bold blue]")
        cleanup_files()
        console.print("✓ Cleanup completed", style="green")

if __name__ == "__main__":
    console.print(Panel("Secure Vault CLI Demo", style="bold blue"))
    console.print("This demo will show various CLI operations with the Secure Vault\n")
    
    try:
        demo_cli()
    except Exception as e:
        console.print(f"\nDemo failed: {str(e)}", style="bold red")
        console.print("Cleaning up...", style="yellow")
        cleanup_files()
    
    console.print("\nDemo completed!", style="bold green")