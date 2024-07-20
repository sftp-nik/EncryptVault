# EncryptVault

### File and Folder Encryption/Decryption Tool

This project is a Python-based tool for encrypting and decrypting files and folders using AES encryption with SHA-512 hashing. It allows you to securely protect your sensitive data and files. Which further after some changes you can use as Ransomware, I've one. If you want then message me!

![Screenshot 2024-07-12 114316](https://github.com/user-attachments/assets/e71faf5c-5525-4bdc-a93c-7b05a47d237b)


## Features

- **File Encryption/Decryption**: Encrypt or decrypt individual files using a password.
- **Folder Encryption/Decryption**: Encrypt or decrypt all files within a specified folder.
- **SHA-512 Hashing**: Generate SHA-512 hash for encrypted files to verify integrity.

## Prerequisites

- Python 3.x
- `cryptography` library

You can install the required library using pip:

```bash
pip install cryptography
```

## Usage

1. Clone the repository:

```bash
git clone https://github.com/sftp-nik/EncryptVault.git
cd EncryptVault
```

2. Run the script:

```bash
python main.py
```

3. Follow the prompts:

- Choose whether to encrypt (E) or decrypt (D) files or folders.
- Enter the file or folder path.
- Enter the password.

## Functions

### Derive Key

Derives a cryptographic key from the given password and salt using the Scrypt key derivation function.

### Encrypt Data

Encrypts the given data using AES encryption in CBC mode with PKCS7 padding.

### Decrypt Data

Decrypts the given encrypted data using AES decryption in CBC mode with PKCS7 padding.

### Generate SHA-512 Hash

Generates a SHA-512 hash of the specified file for integrity verification.

### Encrypt File

Encrypts a specified file and deletes the original file.

### Decrypt File

Decrypts a specified encrypted file and deletes the encrypted file.

### Encrypt Folder

Encrypts all files in a specified folder.

### Decrypt Folder

Decrypts all encrypted files in a specified folder.

## Example

To encrypt a file:

```bash
python script.py
Do you want to (E)ncrypt or (D)ecrypt? E
Enter the file or folder path: path/to/your/file.txt
Enter the password: your_password
```

To decrypt a file:

```bash
python script.py
Do you want to (E)ncrypt or (D)ecrypt? D
Enter the file or folder path: path/to/your/file.txt.enc
Enter the password: your_password
```

## Note

- Ensure to keep your password safe as it is required for both encryption and decryption.
- Deleting the original files after encryption enhances security.
- Always verify the SHA-512 hash of the encrypted files to ensure data integrity.
- This is just a demo of Ransomware, if you want fully functional reach me out!

## Disclaimer 
This is developed only for educational purpose only, use this on your own risk! Remember your password, if you lost then you'll also lost your data!

## Developed by

- Nikhil Kulkarni (Nik)
- Follow me on LikedIn: https://www.linkedin.com/in/thenikkulkarni/

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
