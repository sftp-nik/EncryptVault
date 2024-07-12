import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted_data

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data[32:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def generate_sha512_hash(file_path: str) -> str:
    sha512 = hashlib.sha512()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha512.update(chunk)
    return sha512.hexdigest()

def encrypt_file(file_path: str, password: str) -> None:
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = encrypt_data(file_data, password)
    with open(file_path + ".enc", "wb") as f:
        f.write(encrypted_data)
    os.remove(file_path)
    print(f"Encrypted and deleted {file_path} -> {file_path}.enc")

def decrypt_file(file_path: str, password: str) -> None:
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    data = decrypt_data(encrypted_data, password)
    decrypted_path = file_path.replace(".enc", "")
    with open(decrypted_path, "wb") as f:
        f.write(data)
    os.remove(file_path)
    print(f"Decrypted and deleted {file_path} -> {decrypted_path}")

def encrypt_folder(folder_path: str, password: str) -> None:
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, password)

def decrypt_folder(folder_path: str, password: str) -> None:
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".enc"):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, password)

if __name__ == "__main__":
    action = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().upper()
    target = input("Enter the file or folder path: ").strip()
    password = getpass.getpass("Enter the password: ")

    if action == "E":
        if os.path.isfile(target):
            encrypt_file(target, password)
            hash_value = generate_sha512_hash(target + ".enc")
            print(f"SHA-512 hash of encrypted file: {hash_value}")
        elif os.path.isdir(target):
            encrypt_folder(target, password)
            print(f"Encrypted all files in {target}")
    elif action == "D":
        if os.path.isfile(target):
            decrypt_file(target, password)
        elif os.path.isdir(target):
            decrypt_folder(target, password)
    else:
        print("Invalid action. Please choose 'E' for encrypt or 'D' for decrypt.")

    print("Developed by Nik!")
    print("GitHub repo: https://github.com/sftp-nik")
