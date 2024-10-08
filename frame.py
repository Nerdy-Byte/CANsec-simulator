import string
import base64
import random
from encryption_decryption import *
from key_cache import *

CAN_ID = 0x123  # Example CAN ID for the CANsec frame


def generate_payload(size=16):
    """Generate a random payload of specified size."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


class CANsecFrame:
    def __init__(self, channel_id: bytes, freshness_value, version_number=1, cipher_mode=1, an=0):
        """
        Initialize a CANsecFrame instance.

        Args:
            channel_id (int): The ID of the channel for this frame.
            freshness_value (int): The freshness value (64-bit) for preventing replay attacks.
            version_number (int): The version number for the CANsec protocol.
            cipher_mode (int): The cipher mode (0 for Authentication mode, 1 for AEAD).
        """
        self.channel_id = channel_id  # Initialize channel_id
        self.freshness_value = freshness_value  # Freshness value to prevent replay attacks

        # Security Tag (SECTAG)
        self.sectag = {
            'CCI': {
                'VN': version_number,  # CANsec Version Number
                'CM': cipher_mode,  # Cipher Mode
                'res': 0,  # Reserved bits (set to 0)
            },
            'SCI': channel_id,  # CAN Secure Channel Identifier
            'AN': an,  # Association Number (1-bit, set to 0 for now)
            'FV': self.freshness_value,  # Freshness Value
        }
        sak = get_key(self.sectag['AN'], self.channel_id)
        print(f"inside can frame: {sak}")
        self.payload = encrypt_payload(generate_payload(), sak)
        # message_content = f"{self.payload}{self.sectag}".encode('utf-8')
        self.icv = calculate_icv(self.payload, self.sectag, sak)

    def extract(self):
        """Extract SCI, AN, Payload, and ICV from the frame."""

        payload = self.payload
        icv = self.icv
        sectag = self.sectag

        return {
            'Payload': payload,
            'ICV': icv,
            'Sectag': sectag
        }


class keyRequest:
    def __init__(self, lable, sci, association_key_name, keys=None, icv=None):
        self.lable = lable
        self.sci = sci
        self.association_key_name = association_key_name
        self.keys = keys
        self.icv = icv

    def get_lable(self):
        return self.lable

    def extract_data(self):
        return self.association_key_name, self.sci

    def get_keys(self):
        return self.keys

    def get_icv(self):
        return self.icv
