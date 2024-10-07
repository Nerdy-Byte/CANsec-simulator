import socket
import pickle
import logging
from frame import CANsecFrame
from key_cache import *
from encryption_decryption import decrypt_payload
import hmac
import hashlib
import base64
import os

# its assumed that supplicant 1 will act as the key server when new supplicant joins the network and
# also when pkt numbers are exhausted

# Setup logging
logging.basicConfig(level=logging.INFO)

# Constants
HOST = '127.0.0.1'  # Localhost
PORT_SUPP1 = 5050  # Port for Supplicant 1
PORT_SUPP2 = 5051  # Port for Supplicant 2

# Supplicant parameters
NODE_ID_SUPP1 = 1
CHANNEL_ID = os.urandom(16)
ASSOCIATION_NUMBER = 0  # Assuming you want to start with Association Number 0
ASSOCIATION_KEY = os.urandom(32)
FRESHNESS_VALUE_SUPP1 = 1
SZK = '38d541f6210132720bb608d8e721c8b7039a7fbf12ac4e27c5e1d1dd1af6b8b8'


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


def send_frame_to_supplicant2():
    # Create a CANsecFrame for Supplicant 1
    can_frame = CANsecFrame(node_id=NODE_ID_SUPP1, channel_id=CHANNEL_ID,
                            freshness_value=FRESHNESS_VALUE_SUPP1)

    # Serialize the CANsecFrame
    serialized_frame = pickle.dumps(can_frame)

    # Send the frame to Supplicant 2
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT_SUPP2))
            s.sendall(serialized_frame)
            logging.info(f"Supplicant 1 sent CANsec frame to Supplicant 2: {can_frame}")
    except Exception as e:
        logging.error(f"Failed to send frame to Supplicant 2: {e}")


def receive_frame_from_supplicant2():
    # Create a socket to listen for Supplicant 2's response
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_SUPP1))
        s.listen()
        logging.info("Supplicant 1 is listening for a response from Supplicant 2...")

        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)  # Receive the serialized frame
            try:
                received_frame = pickle.loads(data)  # Deserialize the frame
            except Exception as e:
                logging.error(f"Failed to deserialize the frame: {e}")
                return

            # Extract data from received CANsecFrame
            data = received_frame.extract()  # Ensure this method is correctly implemented
            sectag = data['Sectag']
            icv = data['ICV']
            payload = data['Payload']

            key = get_key(sectag['AN'], sectag['SCI'])  # Retrieve the key
            if key is None:
                print(print_all_keys())
                logging.error(f"No key found for Association Number {sectag['AN']}, Channel ID {sectag['SCI']}.")
                return

            calculated_icv = calculate_icv(payload, sectag, key)

            if icv == calculated_icv:
                logging.info("Supplicant 1: ICV verified successfully.")
                decrypted_payload = decrypt_payload(payload, key)  # Use the correct decryption function
                logging.info("Supplicant 1: Decrypted Payload: %s", decrypted_payload)
            else:
                logging.warning("Supplicant 1: ICV verification failed!")


def keyserver():
    # gets called as soon as new node joins
    # request the SZK-name from the client and verify it
    # Broadcast instruction to generate KEK and ICK
    # generates the association keys for all the sc and broadcast them after encryption via KEK and adding ICK

    pass


if __name__ == "__main__":
    # Supplicant 1 first adds a key, sends a frame, and then listens for a response
    add_key(CHANNEL_ID, ASSOCIATION_KEY)  # Ensure association number is properly managed
    send_frame_to_supplicant2()
    receive_frame_from_supplicant2()
