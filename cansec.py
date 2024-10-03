import hashlib
import hmac
import random
import string
import json
import os
import base64
import threading
import queue
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# Constants
CAN_ID = 0x123  # Example CAN ID
KEY_ROTATION_INTERVAL = timedelta(seconds=30)  # Key rotation interval
KEY_SIZE = 32  # AES key size (256 bits)
MAX_PACKET_NUMBER = 100  # Maximum packet number before key rotation
SECURE_ZONE_KEY_SIZE = 32  # Secure Zone Key size

# Function to generate a random payload
def generate_payload(size=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

# Function to create a new encryption key
def generate_key():
    return os.urandom(KEY_SIZE)

# Function to create a secure zone key
def generate_secure_zone_key():
    return os.urandom(SECURE_ZONE_KEY_SIZE)

# Function to pad the data
def pad(data):
    block_size = algorithms.AES.block_size // 8
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

# Function to unpad the data
def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# Function to encrypt the message payload
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

# Security Association class for secure channels
class SecurityAssociation:
    def __init__(self):
        self.secure_zone_key = generate_secure_zone_key()
        self.channels = {}  # Dictionary to hold session keys for each channel
        self.packet_counts = {}  # Dictionary to hold packet counts for each channel

    def create_channel(self, channel_id):
        # Create a new secure channel with a new session key and initialize packet count
        self.channels[channel_id] = generate_key()
        self.packet_counts[channel_id] = 0  # Initialize packet count for the channel

    def get_session_key(self, channel_id):
        return self.channels.get(channel_id)

    def increment_packet_count(self, channel_id):
        self.packet_counts[channel_id] += 1
        return self.packet_counts[channel_id]

    def reset_packet_count(self, channel_id):
        self.packet_counts[channel_id] = 0

# Node class to represent each CANsec node
class CANsecNode(threading.Thread):
    def __init__(self, node_id, message_queue):
        super().__init__()
        self.node_id = node_id
        self.security_association = SecurityAssociation()  # Each node has its own SA
        self.key_rotation_time = datetime.now() + KEY_ROTATION_INTERVAL
        self.message_queue = message_queue
        # Create secure channels
        for channel_id in range(3):  # Create 3 secure channels per node
            self.security_association.create_channel(channel_id)

    def run(self):
        while True:
            # Create a CANsec message
            channel_id = random.choice(list(self.security_association.channels.keys()))  # Randomly select a channel
            message = self.create_cansec_message(channel_id)
            print(f"Node {self.node_id} created message for channel {channel_id}:", message)

            # Check if we need to rotate keys for the specific channel
            if self.security_association.packet_counts[channel_id] >= MAX_PACKET_NUMBER:
                # Rotate keys in a separate thread to allow simultaneous processing
                key_rotation_thread = threading.Thread(target=self.rotate_key_for_channel, args=(channel_id,))
                key_rotation_thread.start()

            # Get the current session key for the selected channel
            current_key = self.security_association.get_session_key(channel_id)
            # Encrypt the message payload
            encrypted_payload = encrypt_payload(message['payload'], current_key)
            message['payload'] = base64.b64encode(encrypted_payload).decode()  # Store encrypted payload as base64
            signature = sign_message(message, current_key)
            print(f"Node {self.node_id} message signature:", signature)

            # Simulate sending the message to the queue
            self.message_queue.put((message, signature, channel_id))

            # Increment the packet count for the channel
            self.security_association.increment_packet_count(channel_id)

            # Simulate receiving messages from other nodes
            while not self.message_queue.empty():
                received_message, received_signature, received_channel_id = self.message_queue.get()
                self.receive_message(received_message, received_signature, received_channel_id)

    def create_cansec_message(self, channel_id):
        payload = generate_payload()
        message = {
            'id': CAN_ID,
            'payload': payload,
            'channel_id': channel_id  # Include channel ID in the message
        }
        return message

    def rotate_key_for_channel(self, channel_id):
        # Print old key before rotation
        print(f"Node {self.node_id} rotating key for channel {channel_id}:")
        old_key = self.security_association.get_session_key(channel_id)
        print(f" - Old key for channel {channel_id}: {base64.b64encode(old_key).decode()}")

        # Rotate session key for the specific channel
        self.security_association.channels[channel_id] = generate_key()

        # Print new key after rotation
        new_key = self.security_association.get_session_key(channel_id)
        print(f" - New key for channel {channel_id}: {base64.b64encode(new_key).decode()}")

        # Reset the packet count for the channel after key rotation
        self.security_association.reset_packet_count(channel_id)

    def receive_message(self, message, signature, channel_id):
        # Verify the received message using the appropriate session key
        current_key = self.security_association.get_session_key(channel_id)
        if verify_message(message, signature, current_key):
            print(f"Node {self.node_id} message verification successful for channel {channel_id}!")
            decrypted_payload = decrypt_payload(base64.b64decode(message['payload']), current_key)
            print(f"Node {self.node_id} decrypted payload:", decrypted_payload)
        else:
            print(f"Node {self.node_id} message verification failed for channel {channel_id}!")

# Main function to simulate multiple nodes
def main():
    message_queue = queue.Queue()  # Shared queue for message passing

    # Create and start multiple nodes
    nodes = [CANsecNode(node_id=i, message_queue=message_queue) for i in range(3)]
    for node in nodes:
        node.start()

if __name__ == "__main__":
    main()
