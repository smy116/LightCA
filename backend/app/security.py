import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from jose import JWTError, jwt

from app.config import settings


# ============================================
# AES-256-GCM Encryption/Decryption
# ============================================


def encrypt_data(plaintext: str, key: str) -> str:
    """Encrypt data using AES-256-GCM"""
    # Derive a 256-bit key from the master key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"lightca_salt",  # Fixed salt for simplicity
        iterations=100000,
        backend=default_backend(),
    )
    derived_key = kdf.derive(key.encode())

    # Generate a random IV
    iv = secrets.token_bytes(12)

    # Encrypt
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Return base64 encoded (iv + tag + ciphertext)
    encrypted_data = iv + encryptor.tag + ciphertext
    return base64.b64encode(encrypted_data).decode()


def decrypt_data(ciphertext: str, key: str) -> str:
    """Decrypt data using AES-256-GCM"""
    # Derive a 256-bit key from the master key

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"lightca_salt",
        iterations=100000,
        backend=default_backend(),
    )
    derived_key = kdf.derive(key.encode())

    # Decode base64
    encrypted_data = base64.b64decode(ciphertext)

    # Extract IV, tag, and ciphertext
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    actual_ciphertext = encrypted_data[28:]

    # Decrypt
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    return plaintext.decode()


# ============================================
# Password Hashing (bcrypt)
# ============================================


def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a bcrypt hash"""
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def is_bcrypt_hash(password: str) -> bool:
    """Check if a string is a bcrypt hash"""
    if not isinstance(password, str):
        return False
    if not (password.startswith("$2b$") or password.startswith("$2a$")):
        return False
    return len(password) >= 60


# ============================================
# JWT Token Management
# ============================================


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.MASTER_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT access token"""
    try:
        payload = jwt.decode(token, settings.MASTER_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


# ============================================
# Key Password Encryption
# ============================================


def encrypt_key_password(password: str) -> str:
    """Encrypt a key password using the master key"""
    return encrypt_data(password, settings.MASTER_KEY)


def decrypt_key_password(encrypted_password: str) -> str:
    """Decrypt a key password using the master key"""
    return decrypt_data(encrypted_password, settings.MASTER_KEY)


# ============================================
# Private Key Encryption
# ============================================


def encrypt_private_key(private_key_pem: str, password: Optional[str] = None) -> str:
    """Encrypt a private key PEM using the master key"""
    if password:
        # Encrypt the private key with the provided password first
        return encrypt_data(private_key_pem, settings.MASTER_KEY + password)
    else:
        # Encrypt directly with the master key
        return encrypt_data(private_key_pem, settings.MASTER_KEY)


def decrypt_private_key(encrypted_key: str, password: Optional[str] = None) -> str:
    """Decrypt a private key PEM"""
    if password:
        return decrypt_data(encrypted_key, settings.MASTER_KEY + password)
    else:
        return decrypt_data(encrypted_key, settings.MASTER_KEY)


# ============================================
# Fingerprint Calculation
# ============================================


def calculate_fingerprint(data: bytes) -> str:
    """Calculate SHA-256 fingerprint of data"""
    return hashlib.sha256(data).hexdigest()
