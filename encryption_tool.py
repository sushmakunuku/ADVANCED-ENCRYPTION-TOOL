from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import tkinter as tk
from tkinter import filedialog, messagebox

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(input_path, output_path, password):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

def decrypt_file(input_path, output_path, password):
    with open(input_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    key = derive_key(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(plaintext)

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Encryption Tool")

        tk.Label(root, text="Select File:").grid(row=0, column=0, padx=10, pady=10)
        self.file_entry = tk.Entry(root, width=50)
        self.file_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(root, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=10, pady=10)

        tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = tk.Entry(root, show="*", width=50)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Button(root, text="Encrypt", command=self.encrypt).grid(row=2, column=1, sticky="w", padx=10, pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt).grid(row=2, column=1, sticky="e", padx=10, pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def encrypt(self):
        input_path = self.file_entry.get()
        password = self.password_entry.get()
        if not input_path or not password:
            messagebox.showerror("Error", "Please provide both file and password.")
            return
        output_path = input_path + ".enc"
        try:
            encrypt_file(input_path, output_path, password)
            messagebox.showinfo("Success", f"File encrypted successfully:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        input_path = self.file_entry.get()
        password = self.password_entry.get()
        if not input_path or not password:
            messagebox.showerror("Error", "Please provide both file and password.")
            return
        if input_path.endswith(".enc"):
            output_path = input_path[:-4] + ".dec"
        else:
            output_path = input_path + ".dec"
        try:
            decrypt_file(input_path, output_path, password)
            messagebox.showinfo("Success", f"File decrypted successfully:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
