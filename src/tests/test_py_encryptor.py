import sys
import os
import pytest
import base64

# Add the src directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.setup import TextEncryptor  # Import TextEncryptor from the setup module

# Helper function to extract salt from the encrypted token
def extract_salt(token):
    decoded = base64.urlsafe_b64decode(token.encode())
    return decoded[:16]

@pytest.fixture
def password():
    return "strong_password_123"

@pytest.fixture
def plaintext():
    return "This is a secret message."

def test_encrypt_returns_base64_string(password, plaintext):
    encryptor = TextEncryptor(password)
    encrypted = encryptor.encrypt(plaintext)

    # Should be a valid base64 string
    try:
        decoded = base64.urlsafe_b64decode(encrypted.encode())
        assert len(decoded) > 32  # Must include salt + IV + ciphertext
    except Exception:
        pytest.fail("Encryption did not return valid base64.")

def test_decrypt_recovers_original_text(password, plaintext):
    encryptor = TextEncryptor(password)
    encrypted = encryptor.encrypt(plaintext)
    
    # Use the decrypt method with original password
    decrypted = encryptor.decrypt(encrypted, password)
    assert decrypted == plaintext

def test_decrypt_with_wrong_password_fails(password, plaintext):
    encryptor = TextEncryptor(password)
    encrypted = encryptor.encrypt(plaintext)
    
    wrong_password = "wrong_password"
    wrong_encryptor = TextEncryptor(wrong_password)

    with pytest.raises(Exception):
        wrong_encryptor.decrypt(encrypted, wrong_password)

def test_encryption_uses_different_salt_each_time(password, plaintext):
    encryptor1 = TextEncryptor(password)
    encryptor2 = TextEncryptor(password)
    
    token1 = encryptor1.encrypt(plaintext)
    token2 = encryptor2.encrypt(plaintext)

    # Different salts -> different tokens
    assert token1 != token2
    assert extract_salt(token1) != extract_salt(token2)

def test_encrypt_decrypt_multiple_messages(password):
    messages = ["alpha", "beta", "123456", "!@#$%^&*", "🔥 Unicode 🔐"]
    for msg in messages:
        enc = TextEncryptor(password)
        encrypted = enc.encrypt(msg)
        decrypted = enc.decrypt(encrypted, password)
        assert decrypted == msg
