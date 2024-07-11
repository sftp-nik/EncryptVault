# EncryptVault
File and Folder Encryption/Decryption Tool
This project is a Python-based tool for encrypting and decrypting files and folders using AES encryption with SHA-512 hashing. It allows you to securely protect your sensitive data and files.

Features
File Encryption/Decryption: Encrypt or decrypt individual files using a password.
Folder Encryption/Decryption: Encrypt or decrypt all files within a specified folder.
SHA-512 Hashing: Generate SHA-512 hash for encrypted files to verify integrity.
Prerequisites
Python 3.x
cryptography library
You can install the required library using pip:

bash
Copy code
pip install cryptography
Usage
Clone the repository:
bash
Copy code
git clone https://github.com/sftp-nik/encryption-tool.git
cd encryption-tool
Run the script:
bash

python encrypt_decrypt.py
Follow the prompts:
Choose whether to encrypt (E) or decrypt (D) files or folders.
Enter the file or folder path.
Enter the password.
Functions
Derive Key
Derives a cryptographic key from the given password and salt using the Scrypt key derivation function.

Encrypt Data
Encrypts the given data using AES encryption in CBC mode with PKCS7 padding.

Decrypt Data
Decrypts the given encrypted data using AES decryption in CBC mode with PKCS7 padding.

Generate SHA-512 Hash
Generates a SHA-512 hash of the specified file for integrity verification.

Encrypt File
Encrypts a specified file and deletes the original file.

Decrypt File
Decrypts a specified encrypted file and deletes the encrypted file.

Encrypt Folder
Encrypts all files in a specified folder.

Decrypt Folder
Decrypts all encrypted files in a specified folder.

Example
To encrypt a file:

bash
Copy code
python encrypt_decrypt.py
Do you want to (E)ncrypt or (D)ecrypt? E
Enter the file or folder path: path/to/your/file.txt
Enter the password: your_password
To decrypt a file:

```bash

 python encrypt_decrypt.py
 Do you want to (E)ncrypt or (D)ecrypt? D
 Enter the file or folder path: path/to/your/file.txt.enc
 Enter the password: your_password


Note
Ensure to keep your password safe as it is required for both encryption and decryption.
Deleting the original files after encryption enhances security.
Always verify the SHA-512 hash of the encrypted files to ensure data integrity.
Developed by
Nik

License
This project is licensed under the MIT License - see the LICENSE file for details.

