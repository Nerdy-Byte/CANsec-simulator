import string
import base64
import random
import hmac
import hashlib
from encryption_decryption import *

CAN_ID = 0x123  # Example CAN ID for the CANsec frame


def generate_payload(size=16):
    """Generate a random payload of specified size."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


class CANsecFrame:
    def __init__(self, node_id, channel_id, session_key, freshness_value, version_number=1, cipher_mode=1,
                 channel_identifier=0x001, an=0, sckey=None):
        """
        Initialize a CANsecFrame instance.

        Args:
            node_id (int): The ID of the node creating the frame.
            channel_id (int): The ID of the channel for this frame.
            session_key (bytes): The session key for encrypting the frame.
            freshness_value (int): The freshness value (64-bit) for preventing replay attacks.
            version_number (int): The version number for the CANsec protocol.
            cipher_mode (int): The cipher mode (0 for Authentication mode, 1 for AEAD).
            channel_identifier (int): The CAN Secure Channel Identifier.
        """
        self.node_id = node_id  # Initialize node_id
        self.channel_id = channel_id  # Initialize channel_id
        self.session_key = session_key  # Session key for encryption
        self.freshness_value = freshness_value  # Freshness value to prevent replay attacks
        self.payload = generate_payload()  # Generate a random payload
        self.encrypted_payload = None  # Placeholder for the encrypted payload

        # Security Tag (SECTAG)
        self.sectag = {
            'CCI': {
                'VN': version_number,  # CANsec Version Number
                'CM': cipher_mode,  # Cipher Mode
                'res': 0,  # Reserved bits (set to 0)
            },
            'SCI': channel_identifier,  # CAN Secure Channel Identifier
            'AN': an,  # Association Number (1-bit, set to 0 for now)
            'FV': self.freshness_value,  # Freshness Value
        }
        message_content = f"{self.payload}{self.sectag}".encode('utf-8')
        self.icv = hmac.new(sckey, message_content, hashlib.sha256).digest()  # Initialize ICV

    def encrypt(self):
        """Encrypt the payload using the provided session key."""
        self.encrypted_payload = encrypt_payload(self.payload, self.session_key)  # Encrypt the payload
        self.icv = self.calculate_icv(self.session_key)  # Calculate ICV after encryption

    def decrypt(self):
        """Decrypt the encrypted payload using the provided session key."""
        return decrypt_payload(self.encrypted_payload, self.session_key)  # Return the decrypted payload

    def verify_icv(self, key):
        """Verify the integrity and authenticity of the message using the provided session key."""
        # Verify the ICV for message authentication
        calculated_icv = self.calculate_icv(key)
        return self.icv == calculated_icv  # Compare ICVs for authenticity

    def calculate_icv(self, key):
        """Calculate the Integrity Check Value (ICV) based on the encrypted payload and SECTAG using HMAC.

        Args:
            key (bytes): The key used for HMAC calculation.

        Returns:
            str: Base64-encoded ICV.
        """
        # Create a message content combining the payload and sectag
        message_content = f"{self.payload}{self.sectag}".encode('utf-8')

        # Calculate HMAC using SHA256 as the hash function
        icv = hmac.new(key, message_content, hashlib.sha256).digest()  # ICV calculation

        # Return base64-encoded ICV
        return base64.b64encode(icv).decode()

    def replay_check(self, packet_number):
        """Check for replay attacks by comparing freshness value with the packet number."""
        if self.freshness_value >= packet_number:
            print("Replay attack detected!")
            return True  # Replay attack detected
        print("No replay attack detected.")
        return False  # No replay attack

    def get_association_number(self):
        return self.sectag['AN']

    def get_channel_id(self):
        return self.sectag['SCI']
