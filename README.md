# EncryptVault

EncryptVault is a Python-based tool designed to securely encrypt and decrypt files and folders using AES encryption and SHA-512 hashing. Originally developed as an educational demonstration of encryption techniques used in ransomware attacks, it now serves as a robust mechanism for securing sensitive data.

## Features

- **File Encryption/Decryption**: Encrypt or decrypt individual files using a password.
- **Folder Encryption/Decryption**: Encrypt or decrypt all files within a specified folder.
- **SHA-512 Hashing**: Generate SHA-512 hashes for encrypted files to verify integrity.
- **Executable Version**: Use the precompiled `.exe` file for ease of use without needing Python installed.

---

## Prerequisites (for Python Script)

- Python 3.x
- `cryptography` library

Install the required library using pip:

```bash
pip install cryptography
```

---

## Usage

### 1. **Using the Python Script**

1. **Clone the repository**:

   ```bash
   git clone https://github.com/sftp-nik/EncryptVault.git
   cd EncryptVault
   ```

2. **Run the script**:

   ```bash
   python3 main.py
   ```

3. **Follow the prompts**:

   - Choose whether to encrypt (E) or decrypt (D) files or folders.
   - Enter the file or folder path.
   - Enter the password.

### 2. **Using the Executable File**

1. Download the `EncryptVault.exe` file from the [releases](https://github.com/sftp-nik/EncryptVault/releases) section.
2. Double-click the `.exe` file to launch the application.
3. Follow the on-screen prompts just like in the Python script.

---

## Key Functions

- **Derive Key**: Uses the Scrypt key derivation function to derive a cryptographic key from the password and salt.
- **Encrypt Data**: Encrypts data using AES in CBC mode with PKCS7 padding.
- **Decrypt Data**: Decrypts AES-encrypted data in CBC mode.
- **Generate SHA-512 Hash**: Verifies the integrity of encrypted files.
- **Encrypt/Decrypt Files and Folders**: Handles encryption and decryption of specified files or entire directories.

---

## Example Commands (Python Script)

### To encrypt a file:

```bash
python3 main.py
Do you want to (E)ncrypt or (D)ecrypt? E
Enter the file or folder path: path/to/your/file.txt
Enter the password: your_password
```

### To decrypt a file:

```bash
python3 main.py
Do you want to (E)ncrypt or (D)ecrypt? D
Enter the file or folder path: path/to/your/file.txt.enc
Enter the password: your_password
```

---

## Notes

- Keep your password safe—it's required for both encryption and decryption.
- Use the executable file for convenience if Python isn't installed on your system.
- Always verify SHA-512 hashes to ensure data integrity.
- Deleting original files after encryption enhances security.

---

## Disclaimer

This tool is developed for educational purposes only. Use it responsibly. If the password is lost, encrypted data cannot be recovered.

---

## Developed By

- **Nikhil Kulkarni (Nik)**
- Follow on LinkedIn: [https://www.linkedin.com/in/thenikkulkarni/](https://www.linkedin.com/in/thenikkulkarni/)

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

