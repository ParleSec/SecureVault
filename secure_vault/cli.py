import click
from pathlib import Path
from secure_vault.core.vault import SecureVault
import os
import getpass

@click.group()
@click.option('--vault-dir', type=click.Path(), help='Vault directory location')
@click.option('--master-password', help='Master password for key encryption (NOT recommended via command line)')
@click.pass_context
def cli(ctx, vault_dir, master_password):
    """SecureVault - Encrypted File Storage System"""
    ctx.ensure_object(dict)
    
    # Get master password securely if not provided
    if not master_password:
        master_password = os.getenv('VAULT_MASTER_PASSWORD')
        
        # If still no password and there's no password file, prompt for it
        password_file = Path('./secure_vault/.master_password')
        if not master_password and not password_file.exists():
            master_password = getpass.getpass("Enter master password (or press Enter to generate one): ")
            if not master_password:
                click.echo("Generating secure master password...")
    
    # Initialize vault with master password  
    ctx.obj['vault'] = SecureVault(vault_dir, master_password)

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.password_option()
@click.pass_context
def encrypt(ctx, file_path, password):
    """Encrypt a file and store it in the vault"""
    try:
        encrypted_path = ctx.obj['vault'].encrypt_file(file_path, password)
        click.echo(f"File encrypted successfully: {encrypted_path}")
    except Exception as e:
        click.echo(f"Encryption failed: {str(e)}", err=True)
        exit(1)

@cli.command()
@click.argument('encrypted_file', type=click.Path(exists=True))
@click.argument('output_path', type=click.Path())
@click.password_option()
@click.pass_context
def decrypt(ctx, encrypted_file, output_path, password):
    """Decrypt a file from the vault"""
    try:
        decrypted_path = ctx.obj['vault'].decrypt_file(encrypted_file, output_path, password)
        click.echo(f"File decrypted successfully: {decrypted_path}")
    except Exception as e:
        click.echo(f"Decryption failed: {str(e)}", err=True)
        exit(1)

@cli.command()
@click.pass_context
def list(ctx):
    """List all encrypted files in the vault"""
    files = ctx.obj['vault'].list_files()
    if not files:
        click.echo("Vault is empty")
        return
    
    click.echo("Encrypted files in vault:")
    for file in files:
        click.echo(f"  - {file.name}")

@cli.command()
@click.pass_context
def change_master_password(ctx):
    """Change the master password for the vault"""
    current_password = getpass.getpass("Enter current master password: ")
    new_password = getpass.getpass("Enter new master password: ")
    confirm_password = getpass.getpass("Confirm new master password: ")
    
    if new_password != confirm_password:
        click.echo("Passwords do not match", err=True)
        exit(1)
        
    try:
        success = ctx.obj['vault'].change_master_password(current_password, new_password)
        if success:
            click.echo("Master password changed successfully")
        else:
            click.echo("Failed to change master password - current password may be incorrect", err=True)
            exit(1)
    except Exception as e:
        click.echo(f"Error changing master password: {str(e)}", err=True)
        exit(1)

def main():
    cli(obj={})

if __name__ == '__main__':
    main()