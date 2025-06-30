# ADVANCED-ENCRYPTION-TOOL

This is a simple Python application that provides AES-256 encryption and decryption for files using a password-based key derivation function (PBKDF2). The application features a graphical user interface (GUI) built with Tkinter for easy file selection and password input.

## Features

- AES-256 encryption in CFB mode
- Password-based key derivation using PBKDF2 with SHA-256
- Random salt and IV generation for each encryption
- Simple GUI for file selection, encryption, and decryption
- Saves encrypted files with `.enc` extension and decrypted files with `.dec` extension

## Requirements

- Python 3.6+
- `cryptography` library
- Tkinter (usually included with Python)

Install the cryptography library if you don't have it:

```bash
pip install cryptography
