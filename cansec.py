import can
import os
import time
import logging
import yaml
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes

# Load keys from the YAML file
with open('cansec_data.yml') as file:
    data = yaml.safe_load(file)

CAK = bytes.fromhex(data['CAK'])  # 128-bit key for encryption and decryption
SAK = bytes.fromhex(data['SAK'])  # 128-bit key for HMAC authentication

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('CANsec')

def encrypt_message(plaintext, key):
    # Pad the plaintext to be a multiple of block size (AES 128-bit)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Generate a random IV for encryption
    iv = os.urandom(16)

    # AES CBC mode encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # Return IV + Ciphertext

def decrypt_message(ciphertext, key):
    # Split the IV and the actual ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # AES CBC mode decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

def generate_hmac(data, key):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac(data, received_hmac, key):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(received_hmac)
        return True
    except:
        return False

# CANsec message structure: [IV + Ciphertext + HMAC]

def send_secure_can_message(bus, message_id, plaintext):
    # Encrypt the message
    encrypted_message = encrypt_message(plaintext, CAK)

    # Generate HMAC for the encrypted message
    hmac = generate_hmac(encrypted_message, SAK)

    # Construct the CAN payload with encrypted message + HMAC
    can_payload = encrypted_message + hmac

    # Split payload into CAN frames (max 8 bytes per frame)
    frames = [can_payload[i:i+8] for i in range(0, len(can_payload), 8)]

    for frame_data in frames:
        # Create and send CAN message
        msg = can.Message(arbitration_id=message_id, data=frame_data, is_extended_id=False)
        bus.send(msg)
        logger.info(f"Sent CAN frame: {msg}")

def receive_secure_can_message(bus, message_id, expected_length):
    frames = []
    total_length = 0

    while total_length < expected_length:
        msg = bus.recv()
        if msg.arbitration_id == message_id:
            frames.append(msg.data)
            total_length += len(msg.data)

    # Reconstruct the payload from received frames
    received_payload = b''.join(frames)

    # Split into encrypted message and HMAC
    encrypted_message = received_payload[:-32]  # Exclude the last 32 bytes for HMAC
    received_hmac = received_payload[-32:]

    # Verify HMAC
    if not verify_hmac(encrypted_message, received_hmac, SAK):
        logger.error("HMAC verification failed! Message may be tampered.")
        return None

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, CAK)
    logger.info(f"Received and decrypted CAN message: {decrypted_message}")
    return decrypted_message

# Main CANsec communication loop
def main():
    # Setup CAN bus (socketcan example)
    bus = can.interface.Bus(channel='vcan0', interface='virtual')


    # Example of sending a secure message
    send_secure_can_message(bus, 0x123, b'Hello CANsec')

    # Example of receiving a secure message (expecting 48 bytes in total)
    receive_secure_can_message(bus, 0x123, 48)

if __name__ == "__main__":
    main()
