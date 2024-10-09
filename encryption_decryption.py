import base64
import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


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
        tuple: The derived KEK (Fernet key) and ICK (binary).
    """
    # Derive KEK from SZK
    kek_raw = hashlib.sha256(f"{sz_k}KEK".encode('utf-8')).digest()  # 32 bytes
    kek = base64.urlsafe_b64encode(kek_raw)  # Encode to Base64 for Fernet

    # Derive ICK from SZK
    ick = hashlib.sha256(f"{sz_k}ICK".encode('utf-8')).digest()  # 32 bytes

    return kek.decode('utf-8'), ick  # Return KEK as string, ICK as bytes


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


def encrypt_dict(input_dict, kek):
    """
    Encrypts the dictionary values by first converting them into bytes and then encrypting.
    Returns the dictionary with encrypted (Base64-encoded) values.
    """
    f = Fernet(kek)
    for key, values in input_dict.items():
        input_dict[key] = f.encrypt(values)

    return input_dict


def decrypt_dict(input_dict, kek):
    """
    Decrypts the dictionary values by first converting Base64-encoded strings into bytes,
    then decrypting them, and converting the result back into strings.
    """
    f = Fernet(kek)
    for key, values in input_dict.items():
        input_dict[key] = f.decrypt(values)

    return input_dict
