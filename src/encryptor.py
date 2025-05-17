from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom


class TextEncryptor:
    def __init__(self, password: str):
        self.backend = default_backend()
        self.salt = urandom(16)
        self.key = self.derive_key(password)

    def derive_key(self, password: str):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100_000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: str):
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return urlsafe_b64encode(self.salt + iv + ciphertext).decode()

    def decrypt(self, token: str, password: str):
        decoded = urlsafe_b64decode(token.encode())
        salt = decoded[:16]
        iv = decoded[16:32]
        ciphertext = decoded[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=self.backend
        )
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# Example usage
if __name__ == "__main__":
    password = input("Enter password: ").strip()
    mode = input("Encrypt (e) or Decrypt (d)? ").strip().lower()

    if mode == 'e':
        text = input("Enter text to encrypt: ")
        enc = TextEncryptor(password)
        encrypted = enc.encrypt(text)
        print(f"Encrypted:\n{encrypted}")
    elif mode == 'd':
        token = input("Enter encrypted text: ")
        enc = TextEncryptor(password)  # dummy instance just to access decrypt
        try:
            decrypted = enc.decrypt(token, password)
            print(f"Decrypted:\n{decrypted}")
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        print("Invalid option.")