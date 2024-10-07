import hashlib
import hmac
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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


# Function to sign the message
def sign_message(message, key):
    message_json = json.dumps(message).encode()
    signature = hmac.new(key, message_json, hashlib.sha256).hexdigest()
    return signature


# Function to verify the message
def verify_message(message, signature, key):
    expected_signature = sign_message(message, key)
    return hmac.compare_digest(expected_signature, signature)


def process_key_distribution(data):
    """
    Process the key distribution message received from the key server.

    Args:
        data (dict): The received key distribution data.
    """
    encrypted_key = data['encrypted_key']
    icv = data['ICV']
    supp_id = data['supp_id']
    received_channel_id = data['channel_id']

    # Step 1: Derive KEK and ICK from the SZK
    kek, ick = derive_kek_and_ick(SZK)  # Use the same SZK

    # Step 2: Verify the ICV
    calculated_icv = calculate_icv(encrypted_key, supp_id, ick)
    if calculated_icv != icv:
        logging.warning("Supplicant: ICV verification failed.")
        return

    # Step 3: Decrypt the association key using KEK
    association_key = decrypt_payload(encrypted_key, kek)

    # Step 4: Store the association key
    add_key(received_channel_id, association_key)
    logging.info("Supplicant: Association key stored successfully.")
