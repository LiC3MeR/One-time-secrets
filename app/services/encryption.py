import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from app.core.config import settings


def derive_key(passphrase: str = None) -> bytes:
    if passphrase:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(passphrase.encode())
        return digest.finalize()
    else:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(settings.SECRET_KEY.encode())
        return digest.finalize()


def encrypt_secret(secret: str, passphrase: str = None) -> tuple:
    key = derive_key(passphrase)
    iv = os.urandom(16)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    
    padded_secret = secret.encode()
    padding_length = 16 - (len(padded_secret) % 16)
    padded_secret += bytes([padding_length]) * padding_length
    
    encrypted_data = encryptor.update(padded_secret) + encryptor.finalize()
    
    return (
        base64.b64encode(encrypted_data).decode(),
        base64.b64encode(iv).decode()
    )


def decrypt_secret(encrypted_data: str, iv: str, passphrase: str = None) -> str:
    key = derive_key(passphrase)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(base64.b64decode(iv)),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
    
    padding_length = decrypted_data[-1]
    unpadded_data = decrypted_data[:-padding_length]
    
    return unpadded_data.decode()


def hash_passphrase(passphrase: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(passphrase.encode())
    return base64.b64encode(digest.finalize()).decode()
