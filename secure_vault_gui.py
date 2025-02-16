import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from secure_vault import SecureVault
import os
from pathlib import Path

class SecureVaultGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure Vault")
        self.window.geometry("600x400")
        
        # Initialize the vault
        self.vault = SecureVault("./encrypted_vault")
        
        self.create_widgets()
        self.refresh_file_list()
        
    def create_widgets(self):
        # Create main container
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create left panel (file list)
        left_frame = ttk.LabelFrame(main_frame, text="Encrypted Files", padding="5")
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        # File listbox
        self.file_listbox = tk.Listbox(left_frame, width=30)
        self.file_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for listbox
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.file_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Create right panel (actions)
        right_frame = ttk.Frame(main_frame, padding="5")
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5)
        
        # Encrypt section
        encrypt_frame = ttk.LabelFrame(right_frame, text="Encrypt File", padding="5")
        encrypt_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(encrypt_frame, text="Select File", command=self.encrypt_file).grid(row=0, column=0, pady=5)
        
        # Decrypt section
        decrypt_frame = ttk.LabelFrame(right_frame, text="Decrypt File", padding="5")
        decrypt_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(decrypt_frame, text="Decrypt Selected", command=self.decrypt_file).grid(row=0, column=0, pady=5)
        
        # Refresh button
        ttk.Button(right_frame, text="Refresh List", command=self.refresh_file_list).grid(row=2, column=0, pady=20)
        
    def encrypt_file(self):
        # Select file to encrypt
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
            
        # Get password
        password = self.password_dialog("Enter encryption password")
        if not password:
            return
            
        try:
            # Encrypt the file
            self.vault.encrypt_file(file_path, password)
            messagebox.showinfo("Success", "File encrypted successfully!")
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            
    def decrypt_file(self):
        # Get selected file
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to decrypt")
            return
            
        file_name = self.file_listbox.get(selection[0])
        encrypted_path = self.vault.vault_dir / file_name
        
        # Get password
        password = self.password_dialog("Enter decryption password")
        if not password:
            return
            
        # Select output location
        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File",
            initialfile=file_name.replace('.vault', '')
        )
        if not output_path:
            return
            
        try:
            # Decrypt the file
            self.vault.decrypt_file(encrypted_path, output_path, password)
            messagebox.showinfo("Success", "File decrypted successfully!")
        except ValueError as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            
    def password_dialog(self, prompt):
        dialog = tk.Toplevel(self.window)
        dialog.title(prompt)
        dialog.geometry("300x150")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ttk.Label(dialog, text=prompt).pack(pady=10)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, show="*", textvariable=password_var)
        password_entry.pack(pady=10)
        
        result = [None]  # Use list to store result
        
        def on_ok():
            result[0] = password_var.get()
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
            
        ttk.Button(dialog, text="OK", command=on_ok).pack(side=tk.LEFT, padx=20)
        ttk.Button(dialog, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=20)
        
        dialog.wait_window()
        return result[0]
        
    def refresh_file_list(self):
        # Clear current list
        self.file_listbox.delete(0, tk.END)
        
        # Add all vault files
        for file_path in self.vault.list_files():
            self.file_listbox.insert(tk.END, file_path.name)
            
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = SecureVaultGUI()
    app.run()