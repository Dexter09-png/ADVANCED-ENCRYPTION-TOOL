     
import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def confirm_password() -> str:
    while True:
        pw1 = getpass("Enter password: ")
        pw2 = getpass("Re-enter password: ")
        if pw1 == pw2:
            return pw1
        print("Passwords did not match. Please try again.\n")


def prompt_output_path(default_path: str) -> str:
    path = input(f"Enter output file path: ").strip()
    path = path if path else default_path

    if os.path.exists(path):
        confirm = input("File exists. Overwrite? (y/N): ").strip().lower()
        if confirm != "y":
            print("Operation cancelled.")
            sys.exit()
    return path

def encrypt_file(password: str, input_path: str, output_path: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(input_path, 'rb') as f:
        data = f.read()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print(f"File encrypted successfully and saved to: {output_path}")


def decrypt_file(password: str, input_path: str, output_path: str):
    """Decrypt an AES-256 encrypted file."""
    with open(input_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        data = unpadder.update(padded_data) + unpadder.finalize()
    except Exception:
        raise ValueError("Decryption failed. Incorrect password or corrupted file.")

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"File decrypted successfully and saved to: {output_path}")


def main():
    print("\n *** AES-256 FILE ENCRYPTION TOOL ***")
    print("1.  Encrypt a file")
    print("2.  Decrypt a file")
    print("3.  Exit")
    print("=======================================\n")

    choice = input("Enter your choice (1/2/3): ").strip()

    if choice == '3':
        print("Exiting the tool.")
        sys.exit()
    elif choice not in ['1', '2']:
        print("Invalid option. Exiting.")
        sys.exit()

    input_file = input("Enter input file path: ").strip()
    if not os.path.isfile(input_file):
        print("Error: File not found.")
        sys.exit()

    if choice == '1':
        default_out = input_file + ".aes"
        output_file = prompt_output_path(default_out)
        password = confirm_password()
        try:
            encrypt_file(password, input_file, output_file)
        except Exception as e:
            print(f"Encryption failed: {e}")

    elif choice == '2':
        default_out = os.path.splitext(input_file)[0] + ".decrypted"
        output_file = prompt_output_path(default_out)
        password = getpass("Enter password: ")
        try:
            decrypt_file(password, input_file, output_file)
        except Exception as e:
            print(f"{e}")


if __name__ == "__main__":
    main()

