import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm
import secrets

def generate_random_word(min_length=6, max_length=11):
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    length = secrets.randbelow(max_length - min_length + 1) + min_length
    return ''.join(secrets.choice(letters) for _ in range(length))

def generate_passphrase(word_count=20):
    return ' '.join(generate_random_word() for _ in range(word_count))

def shuffle_passphrase(passphrase, shuffle_count):
    words = passphrase.split()
    for _ in tqdm(range(shuffle_count), desc="Shuffling passphrase"):
        secrets.SystemRandom().shuffle(words)
    return ' '.join(words)

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(key: bytes, plaintext: bytes, salt: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)

def decrypt_data(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def main():
    choice = input("Choose an option (1 for encrypt, 2 for decrypt): ")
    
    if choice == '1':
        vault_name = input("Enter a name for your vault (this will be used as the filename): ")
        shuffle_count = int(input("Enter a shuffle count (1-399): "))
        passphrase = generate_passphrase()
        passphrase = shuffle_passphrase(passphrase, shuffle_count)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(passphrase, salt)
        text_to_encrypt = input("Enter the text to encrypt: ").encode()
        encrypted_data = encrypt_data(key, text_to_encrypt, salt, nonce)
        vault_path = os.path.join("..", "vaults", f"{vault_name}.val")
        with open(vault_path, "wb") as f:
            f.write(salt + nonce + encrypted_data)
        print(f"Data encrypted and stored in {vault_path}")
        print(f"Your passphrase (use it for decryption): {passphrase}")
        print("Please type 'exit' to securely close the terminal session.")
    elif choice == '2':
        file_path = input("Enter the Vault name stored in /vaults: ")
        full_path = os.path.join("..", "vaults", file_path)
        passphrase = getpass.getpass("Enter your passphrase: ")
        try:
            with open(full_path, "rb") as f:
                encrypted_data = f.read()
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            key = derive_key(passphrase, salt)
            decrypted_data = decrypt_data(key, ciphertext, nonce)
            print("Decrypted text:", decrypted_data.decode())
        except Exception as e:
            print("Error during decryption:", e)
        print("Please type 'exit' to securely close the terminal session.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
