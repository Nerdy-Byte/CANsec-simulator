import base64
import hashlib
import hmac
# import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# from cryptography.fernet import Fernet


def calculate_ick(payload, key):
    message_content = f"{payload}".encode()
    icv = hmac.new(key, message_content, hashlib.sha256).digest()
    return base64.b64encode(icv).decode()


def calculate_icv(payload, sectag, key):
    """
    Calculate the Integrity Check Value (ICV) based on the payload and SECTAG using HMAC.

    Args:
        payload (str): The payload data to be included in the ICV calculation.
        sectag (dict): The SECTAG containing relevant security information.
        key (bytes): The key used for HMAC calculation.

    Returns:
        str: Base64-encoded ICV.
    """
    message_content = f"{payload}{sectag}".encode('utf-8')
    icv = hmac.new(key, message_content, hashlib.sha256).digest()
    return base64.b64encode(icv).decode()


def derive_kek_and_ick(sz_k):
    """
    Derive the KEK (Key Encryption Key) and ICK (Integrity Check Key) from the SZK (Secure Zone Key).

    Args:
        sz_k (str): The shared Secure Zone Key (SZK).

    Returns:
        tuple: The derived KEK and ICK.
    """
    kek = hashlib.sha256(f"{sz_k}KEK".encode('utf-8')).digest()  # Derive KEK from SZK
    ick = hashlib.sha256(f"{sz_k}ICK".encode('utf-8')).digest()  # Derive ICK from SZK

    return kek, ick


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


# # Function to sign the message
# def sign_message(message, key):
#     message_json = json.dumps(message).encode()
#     signature = hmac.new(key, message_json, hashlib.sha256).hexdigest()
#     return signature


# Function to verify the message
# def verify_message(message, signature, key):
#     expected_signature = sign_message(message, key)
#     return hmac.compare_digest(expected_signature, signature)


# Generate a key for encryption
# def generate_key():
#     return Fernet.generate_key()


# Encrypt a dictionary
def encrypt_dict(input_dict, kek):
    """Encrypts the dictionary using the KEK and returns a Base64-encoded string."""
    return input_dict


def decrypt_dict(encrypted_str, kek):
    """Decrypts the Base64-encoded string back to a dictionary."""
    return encrypted_str
