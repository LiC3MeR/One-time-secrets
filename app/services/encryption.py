import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Tuple

from app.core.config import settings

# Функция для шифрования данных
def encrypt_data(data: str) -> Tuple[str, str]:
    # Генерируем случайный вектор инициализации
    iv = os.urandom(16)
    
    # Создаем ключ шифрования из секретного ключа приложения
    # Используем SHA-256 для получения ключа нужной длины (32 байта)
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    
    # Создаем шифр
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Шифруем данные
    encryptor = cipher.encryptor()
    # Дополняем данные до размера, кратного 16 байтам (блок AES)
    padded_data = data.encode() + b'\0' * (16 - len(data.encode()) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Кодируем в base64 для хранения в базе данных
    encrypted_data_b64 = base64.b64encode(encrypted_data).decode()
    iv_b64 = base64.b64encode(iv).decode()
    
    return encrypted_data_b64, iv_b64

# Функция для дешифрования данных
def decrypt_data(encrypted_data_b64: str, iv_b64: str) -> str:
    # Декодируем из base64
    encrypted_data = base64.b64decode(encrypted_data_b64)
    iv = base64.b64decode(iv_b64)
    
    # Создаем ключ шифрования из секретного ключа приложения
    # Используем SHA-256 для получения ключа нужной длины (32 байта)
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    
    # Создаем шифр
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    # Дешифруем данные
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Удаляем дополнение
    decrypted_data = decrypted_data.rstrip(b'\0')
    
    return decrypted_data.decode()
