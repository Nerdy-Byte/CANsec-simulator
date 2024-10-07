import socket
import pickle
from frame import CANsecFrame
from key_cache import *
from encryption_decryption import *
import hmac
import hashlib
import base64
import os

# Constants
HOST = '127.0.0.1'  # Localhost
PORT_SUPP1 = 5050  # Port for Supplicant 1 (receiver port)
PORT_SUPP2 = 5051  # Port for Supplicant 2 (sender port)

# Supplicant parameters
NODE_ID_SUPP2 = 2
CHANNEL_ID = 2
ASSOCIATION_KEY = os.urandom(32)
FRESHNESS_VALUE_SUPP2 = 1


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


def receive_frame_from_supplicant1():
    # Create a socket to listen for Supplicant 1's frame
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow reuse of address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT_SUPP2))  # Supplicant 2 listens on its own port
        s.listen()
        print("Supplicant 2 is listening for a frame from Supplicant 1...")

        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)  # Receive the serialized frame
            received_frame = pickle.loads(data)  # Deserialize the frame

            # Extract data from received CANsecFrame
            frame_data = received_frame.extract()  # Ensure this method is correctly implemented
            sectag = frame_data['Sectag']
            icv = frame_data['ICV']
            payload = frame_data['Payload']

            # Retrieve the key
            key = get_key(sectag['AN'], sectag['SCI'])

            if key is None:
                print(f"Supplicant 2: No key found for Association Number {sectag['AN']}, Channel ID {sectag['SCI']}.")
                return

            calculated_icv = calculate_icv(payload, sectag, key)

            if icv == calculated_icv:
                print("Supplicant 2: ICV verified successfully.")
                decrypted_payload = decrypt_payload(payload, key)  # Use the correct decryption function
                print("Supplicant 2: Decrypted Payload:", decrypted_payload)
            else:
                print("Supplicant 2: ICV verification failed!")


def send_frame_to_supplicant1():
    # Create a CANsecFrame for Supplicant 2
    an = 0  # Example Association Number, adjust as needed
    sci = CHANNEL_ID  # Use the correct Channel ID or SCI

    # Retrieve the key for encryption
    key = get_key(an, sci)

    # Check if the key exists
    if key is None:
        print(f"Error: No key found for Association Number {an}, Channel ID {sci}.")
        return  # Stop execution if no key is found

    # Continue with CANsec frame creation
    can_frame = CANsecFrame(node_id=NODE_ID_SUPP2, channel_id=CHANNEL_ID,
                            freshness_value=FRESHNESS_VALUE_SUPP2)

    # Serialize the CANsecFrame
    serialized_frame = pickle.dumps(can_frame)

    # Send the frame to Supplicant 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT_SUPP1))  # Connect to Supplicant 1's port
            s.sendall(serialized_frame)
            print(f"Supplicant 2 sent CANsec frame to Supplicant 1: {can_frame}")
        except ConnectionRefusedError:
            print("Supplicant 2: Failed to send frame to Supplicant 1 - Connection refused.")


if __name__ == "__main__":
    # Supplicant 2 first listens for a frame and then sends a response
    print(ASSOCIATION_KEY)
    add_key(CHANNEL_ID, ASSOCIATION_KEY)  # Add key to cache for channel
    send_frame_to_supplicant1()
    receive_frame_from_supplicant1()
