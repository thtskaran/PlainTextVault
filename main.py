import os
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm

# Function to generate a random word of length between min_length and max_length
def generate_random_word(min_length=6, max_length=11):
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    length = secrets.randbelow(max_length - min_length + 1) + min_length
    return ''.join(secrets.choice(letters) for _ in range(length))

# Function to generate a passphrase consisting of 20 random words
def generate_passphrase(word_count=20):
    return ' '.join(generate_random_word() for _ in range(word_count))

# Function to shuffle the passphrase
def shuffle_passphrase(passphrase, shuffle_count):
    words = passphrase.split()
    for _ in tqdm(range(shuffle_count), desc="Shuffling passphrase"):
        secrets.SystemRandom().shuffle(words)
    return ' '.join(words)

# Function to derive a key from the passphrase
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Function to encrypt data
def encrypt_data(key: bytes, plaintext: bytes, salt: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return salt + nonce + aesgcm.encrypt(nonce, plaintext, None)

# Function to decrypt data
def decrypt_data(key: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    salt = ciphertext[:16]
    nonce = ciphertext[16:28]
    return aesgcm.decrypt(nonce, ciphertext[28:], None)

# Main function to handle user input and perform encryption/decryption
def main():
    choice = input("Choose an option (1 for encrypt, 2 for decrypt): ")
    
    if choice == '1':
        shuffle_count = int(input("Enter a shuffle count (1-399): "))
        passphrase = generate_passphrase()
        passphrase = shuffle_passphrase(passphrase, shuffle_count)
        salt = os.urandom(16)
        key = derive_key(passphrase, salt)
        text_to_encrypt = input("Enter the text to encrypt: ")
        encrypted_data = encrypt_data(key, text_to_encrypt.encode(), salt)
        with open("vault.val", "wb") as f:
            f.write(encrypted_data)
        print("Data encrypted and stored in vault.val")
        print(f"Your passphrase (use it for decryption): {passphrase}")
        print("Please type 'exit' to securely close the terminal session.")
    elif choice == '2':
        file_path = input("Enter the path to the encrypted file: ")
        passphrase = input("Enter your passphrase: ")
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
            salt = encrypted_data[:16]
            key = derive_key(passphrase, salt)
            decrypted_data = decrypt_data(key, encrypted_data)
            print("Decrypted text:", decrypted_data.decode())
        except Exception as e:
            print("Error during decryption:", e)
        print("Please type 'exit' to securely close the terminal session.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
