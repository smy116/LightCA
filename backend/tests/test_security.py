import pytest
from app.security import (
    encrypt_data,
    decrypt_data,
    hash_password,
    verify_password,
    is_bcrypt_hash,
    create_access_token,
    decode_access_token,
    encrypt_key_password,
    decrypt_key_password,
    encrypt_private_key,
    decrypt_private_key,
    calculate_fingerprint,
)


class TestEncryption:
    """Test AES-256-GCM encryption/decryption"""

    def test_encrypt_decrypt_simple_text(self):
        plaintext = "Hello, World!"
        key = "test_key_32_characters_minimum_length"

        encrypted = encrypt_data(plaintext, key)
        assert encrypted != plaintext
        assert isinstance(encrypted, str)

        decrypted = decrypt_data(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        plaintext = "Hello 世界! 🌍"
        key = "test_key_32_characters_minimum_length"

        encrypted = encrypt_data(plaintext, key)
        decrypted = decrypt_data(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_string(self):
        plaintext = ""
        key = "test_key_32_characters_minimum_length"

        encrypted = encrypt_data(plaintext, key)
        decrypted = decrypt_data(encrypted, key)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_key_fails(self):
        plaintext = "Secret message"
        key1 = "test_key_32_characters_minimum_length"
        key2 = "another_key_32_characters_minimum"

        encrypted = encrypt_data(plaintext, key1)

        with pytest.raises(Exception):
            decrypt_data(encrypted, key2)


class TestPasswordHashing:
    """Test bcrypt password hashing"""

    def test_hash_password(self):
        password = "my_secure_password"
        hashed = hash_password(password)

        assert isinstance(hashed, str)
        assert hashed != password
        assert is_bcrypt_hash(hashed)

    def test_verify_password_correct(self):
        password = "my_secure_password"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        password = "my_secure_password"
        wrong_password = "wrong_password"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) is False

    def test_is_bcrypt_hash_detection(self):
        password = "my_password"
        hashed = hash_password(password)

        assert is_bcrypt_hash(hashed) is True
        assert is_bcrypt_hash("not_a_hash") is False
        assert is_bcrypt_hash("$2a$") is False


class TestJWT:
    """Test JWT token generation and verification"""

    def test_create_and_decode_token(self):
        data = {"sub": "admin", "role": "user"}

        token = create_access_token(data)
        assert isinstance(token, str)

        decoded = decode_access_token(token)
        assert decoded is not None
        assert decoded["sub"] == "admin"
        assert decoded["role"] == "user"

    def test_decode_invalid_token(self):
        invalid_token = "invalid.token.here"

        decoded = decode_access_token(invalid_token)
        assert decoded is None


class TestKeyPasswordEncryption:
    """Test key password encryption/decryption"""

    def test_key_password_roundtrip(self):
        password = "my_key_password"

        encrypted = encrypt_key_password(password)
        decrypted = decrypt_key_password(encrypted)

        assert decrypted == password

    def test_key_password_empty_string(self):
        password = ""

        encrypted = encrypt_key_password(password)
        decrypted = decrypt_key_password(encrypted)

        assert decrypted == password


class TestPrivateKeyEncryption:
    """Test private key PEM encryption/decryption"""

    def test_private_key_encryption_without_password(self):
        private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VtUtUz8QKQK
-----END PRIVATE KEY-----"""

        encrypted = encrypt_private_key(private_key_pem)
        assert encrypted != private_key_pem

        decrypted = decrypt_private_key(encrypted)
        assert decrypted == private_key_pem

    def test_private_key_encryption_with_password(self):
        private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VtUtUz8QKQK
-----END PRIVATE KEY-----"""
        password = "key_password"

        encrypted = encrypt_private_key(private_key_pem, password)
        decrypted = decrypt_private_key(encrypted, password)

        assert decrypted == private_key_pem

    def test_private_key_decryption_wrong_password(self):
        private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VtUtUz8QKQK
-----END PRIVATE KEY-----"""

        encrypted = encrypt_private_key(private_key_pem, "correct_password")

        with pytest.raises(Exception):
            decrypt_private_key(encrypted, "wrong_password")


class TestFingerprint:
    """Test SHA-256 fingerprint calculation"""

    def test_calculate_fingerprint(self):
        data = b"Hello, World!"
        fingerprint = calculate_fingerprint(data)

        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in fingerprint)

    def test_fingerprint_consistency(self):
        data = b"Test data"
        fp1 = calculate_fingerprint(data)
        fp2 = calculate_fingerprint(data)

        assert fp1 == fp2

    def test_fingerprint_uniqueness(self):
        data1 = b"Data 1"
        data2 = b"Data 2"

        fp1 = calculate_fingerprint(data1)
        fp2 = calculate_fingerprint(data2)

        assert fp1 != fp2
