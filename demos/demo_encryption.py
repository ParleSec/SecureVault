from secure_vault import SecureVault
import os

def main():
    # Create a test file
    with open("secret.txt", "w") as f:
        f.write("This is a secret message that needs to be encrypted!")

    # Initialize vault
    vault = SecureVault("./encrypted_vault")

    try:
        # Encrypt the file
        print("Encrypting file...")
        encrypted_path = vault.encrypt_file("secret.txt", "mysecretpassword")
        print(f"File encrypted and saved to: {encrypted_path}")

        # List encrypted files
        print("\nFiles in vault:")
        for file in vault.list_files():
            print(f"- {file.name}")

        # Decrypt the file
        print("\nDecrypting file...")
        decrypted_path = vault.decrypt_file(
            encrypted_path,
            "decrypted_secret.txt",
            "mysecretpassword"
        )
        print(f"File decrypted and saved to: {decrypted_path}")

        # Verify content
        with open("decrypted_secret.txt", "r") as f:
            content = f.read()
            print(f"\nDecrypted content: {content}")

        # Try with wrong password (should fail)
        print("\nTrying with wrong password...")
        try:
            vault.decrypt_file(
                encrypted_path,
                "should_fail.txt",
                "wrongpassword"
            )
        except ValueError as e:
            print(f"Decryption failed as expected: {e}")

    finally:
        # Clean up test files
        print("\nCleaning up test files...")
        for file in ["secret.txt", "decrypted_secret.txt"]:
            if os.path.exists(file):
                os.remove(file)
                print(f"Removed: {file}")

if __name__ == "__main__":
    main()