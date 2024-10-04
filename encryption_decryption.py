import hashlib
import hmac
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pad(data):
    block_size = algorithms.AES.block_size // 8
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


# Function to unpad the data
def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_payload(payload, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_payload = pad(payload.encode())
    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()
    return iv + encrypted_payload  # Prepend IV for decryption


# Function to decrypt the message payload
def decrypt_payload(encrypted_payload, key):
    iv = encrypted_payload[:16]  # Extract IV (first 16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_payload = decryptor.update(encrypted_payload[16:]) + decryptor.finalize()
    return unpad(decrypted_payload).decode()


# Function to sign the message
def sign_message(message, key):
    message_json = json.dumps(message).encode()
    signature = hmac.new(key, message_json, hashlib.sha256).hexdigest()
    return signature


# Function to verify the message
def verify_message(message, signature, key):
    expected_signature = sign_message(message, key)
    return hmac.compare_digest(expected_signature, signature)
