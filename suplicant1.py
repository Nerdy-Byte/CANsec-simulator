import socket
import pickle
import logging
from frame import *
from key_cache import *
from encryption_decryption import *
import hmac
import hashlib
import base64
import os

# its assumed that supplicant 1 will act as the key server when new supplicant joins the network and
# also when pkt numbers are exhausted

# Setup logging
# logging.basicConfig(level=logging.INFO)

# Constants
HOST = '127.0.0.1'  # Localhost
PORT_SUPP1 = 5052  # Port for Supplicant 1
PORT_SUPP2 = 5051  # Port for Supplicant 2
SUPPLICANTS = []
# Supplicant parameters
# NODE_ID_SUPP1 = 1
CHANNEL_ID = os.urandom(8)
ASSOCIATION_NUMBER = 1  # Assuming you want to start with Association Number 0
ASSOCIATION_KEY = os.urandom(32)
FRESHNESS_VALUE_SUPP1 = 1
SZK = '38d541f6210132720bb608d8e721c8b7039a7fbf12ac4e27c5e1d1dd1af6b8b8'
SZK_NAME = '89d541f6210132720bb608d8e721c8b7039a7fbf12ac4e27c5e1d1dd1af6b8a2'


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
        # logging.warning("Supplicant: ICV verification failed.")
        print("Supplicant: ICV verification failed.")
        return

    # Step 3: Decrypt the association key using KEK
    association_key = decrypt_payload(encrypted_key, kek)
    # Step 4: Store the association key
    add_key(ASSOCIATION_NUMBER, received_channel_id, association_key)
    print("Supplicant: Association key stored successfully.")



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


def handle_key_request_from_supplicant2(received_frame):
    """
    Supplicant 1 listens for a key request from Supplicant 2 and responds with the requested keys.
    """
    global ASSOCIATION_NUMBER
    ASSOCIATION_NUMBER = 1 - ASSOCIATION_NUMBER
    keyname, sci = received_frame.extract_data()

    if keyname != SZK_NAME:
        print("Invalid Key name Request Declined!")
        return

    kek, ick = derive_kek_and_ick(SZK_NAME)
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    add_key(ASSOCIATION_NUMBER, CHANNEL_ID, key1)
    add_key(ASSOCIATION_NUMBER, sci, key2)
    keys = {CHANNEL_ID: key1, sci: key2}
    enc_keys = encrypt_dict(keys, kek)
    icv = calculate_ick(enc_keys, ick)
    key_frame = keyRequest(lable="KEYS", sci=CHANNEL_ID, association_key_name=SZK_NAME, keys=enc_keys, icv=icv,
                           an=ASSOCIATION_NUMBER)
    serialized_frame = pickle.dumps(key_frame)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT_SUPP2))
            s.sendall(serialized_frame)
            print(f"Supplicant 1 sent CANsec frame to Supplicant 2: {key_frame}")
    except Exception as e:
        print(f"Failed to send frame to Supplicant 2: {e}")


def send_frame_to_supplicant2():
    # Create a CANsecFrame for Supplicant 1
    # channel_id_int = int.from_bytes(CHANNEL_ID, byteorder='big')
    can_frame = CANsecFrame(channel_id=CHANNEL_ID, freshness_value=FRESHNESS_VALUE_SUPP1)

    # Serialize the CANsecFrame
    serialized_frame = pickle.dumps(can_frame)

    # Send the frame to Supplicant 2
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT_SUPP2))
            s.sendall(serialized_frame)
            print(f"Supplicant 1 sent CANsec frame to Supplicant 2: {can_frame}")
    except Exception as e:
        logging.error(f"Failed to send frame to Supplicant 2: {e}")


def receive_frame_from_supplicant2():
    # Create a socket to listen for Supplicant 2's response
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reusing the address
        s.bind((HOST, PORT_SUPP1))
        s.listen()
        print("Supplicant 1 is listening for a response from Supplicant 2...")

        while True:  # Keep listening for incoming connections
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)  # Receive the serialized frame
                if not data:
                    break  # No more data, exit the loop
                try:
                    received_frame = pickle.loads(data)  # Deserialize the frame
                except Exception as e:
                    print(f"Failed to deserialize the frame: {e}")
                    return

                if isinstance(received_frame, keyRequest):
                    handle_key_request_from_supplicant2(received_frame)
                    continue

                # Extract data from received CANsecFrame
                data = received_frame.extract()  # Ensure this method is correctly implemented
                sectag = data['Sectag']
                icv = data['ICV']
                payload = data['Payload']
                print(f"ICV::{icv}")
                key = get_key(sectag['AN'], sectag['SCI'])  # Retrieve the key
                calculated_icv = calculate_icv(payload, sectag, key)
                print(f"ICV::{calculated_icv}")

                if icv == calculated_icv:
                    print("Supplicant 1: ICV verified successfully.")
                    decrypted_payload = decrypt_payload(payload, key)  # Use the correct decryption function
                    print("Supplicant 1: Decrypted Payload: %s", decrypted_payload)
                else:
                    print("Supplicant 1: ICV verification failed!")


if __name__ == "__main__":
    try:
        receive_frame_from_supplicant2()
    except KeyboardInterrupt:
        print("Shutting down Supplicant 1.")
    except Exception as e:
        print(f"Unexpected error: {e}")
