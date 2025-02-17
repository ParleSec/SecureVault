import click
from pathlib import Path
from .vault import SecureVault

@click.group()
@click.option('--vault-dir', type=click.Path(), help='Vault directory location')
@click.pass_context
def cli(ctx, vault_dir):
    """Secure File Vault - Encrypted File Storage System"""
    ctx.ensure_object(dict)
    ctx.obj['vault'] = SecureVault(vault_dir)

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

def main():
    cli(obj={})

if __name__ == '__main__':
    main()