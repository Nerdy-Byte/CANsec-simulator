import socket
import pickle
from frame import *
from key_cache import *
from encryption_decryption import *
import hmac
import hashlib
import base64
import os
import time

# Constants
HOST = '127.0.0.1'  # Localhost
PORT_SUPP1 = 5052  # Port for Supplicant 1 (receiver port)
PORT_SUPP2 = 5051  # Port for Supplicant 2 (sender port)

# Supplicant parameters
CHANNEL_ID = os.urandom(8)
MAX_PN_LIMIT = 10
SZK = '38d541f6210132720bb608d8e721c8b7039a7fbf12ac4e27c5e1d1dd1af6b8b8'
SZK_NAME = '89d541f6210132720bb608d8e721c8b7039a7fbf12ac4e27c5e1d1dd1af6b8a2'
PACKET_NUMBER = 1
FRESHNESS_VALUE_SUPP1 = 0


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


def getKeys():
    key_pkt = keyRequest(lable="JOIN_REQUEST", sci=CHANNEL_ID, association_key_name=SZK_NAME, icv=None)
    serialized_frame = pickle.dumps(key_pkt)

    # Send the frame to Supplicant 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT_SUPP1))  # Connect to Supplicant 1's port
            s.sendall(serialized_frame)
            print(f"Supplicant 2 sent join request frame to Supplicant 1: {key_pkt}")
        except ConnectionRefusedError:
            print("Supplicant 2: Failed to send frame to Supplicant 1 - Connection refused.")


def receive_keys_from_supplicant1(key_frame):
    """
    Receives keys from Supplicant 1, decrypts and stores them for Supplicant 2.
    """
    global FRESHNESS_VALUE_SUPP1
    kek, ick = derive_kek_and_ick(SZK_NAME)
    keys_data = key_frame.get_keys()
    calc_icv = calculate_ick(keys_data, ick)

    if key_frame.get_icv() != calc_icv:
        print("ICV Mismatch!")
        return

    keys = decrypt_dict(keys_data, kek)
    # calculated_icv = calculate_icv(keys_data, CHANNEL_ID, ick)
    an = key_frame.get_association_number()
    for key, value in keys.items():
        add_key(an, key, value)

    FRESHNESS_VALUE_SUPP1 = 0


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

            if isinstance(received_frame, keyRequest):
                if received_frame.get_lable() == "SEND-SCI":
                    getKeys()
                else:
                    receive_keys_from_supplicant1(received_frame)
                    return

            # Extract data from received CANsecFrame
            frame_data = received_frame.extract()
            sectag = frame_data['Sectag']
            icv = frame_data['ICV']
            payload = frame_data['Payload']

            # Retrieve the key
            key = get_key(sectag['AN'], sectag['SCI'])

            if key is None:
                print(f"Supplicant 2: No key found for Association Number {sectag['AN']}, Channel ID {sectag['SCI']}.")
                return

            calculated_icv = calculate_icv(payload, sectag, key)
            global FRESHNESS_VALUE_SUPP1
            if FRESHNESS_VALUE_SUPP1 <= received_frame.get_freshness_value():
                print("Old frame Dropping the packet!")
                return
            if icv == calculated_icv:
                print("Supplicant 2: ICV verified successfully.")
                decrypted_payload = decrypt_payload(payload, key)  # Use the correct decryption function
                FRESHNESS_VALUE_SUPP1 = received_frame.get_freshness_value()
                print("Supplicant 2: Decrypted Payload:", decrypted_payload)
            else:
                print("Supplicant 2: ICV verification failed!")


def send_frame_to_supplicant1():

    global PACKET_NUMBER, MAX_PN_LIMIT
    if PACKET_NUMBER >= MAX_PN_LIMIT:
        getKeys()
        PACKET_NUMBER = 1
        receive_frame_from_supplicant1()
        return

    # channel_id_int = int.from_bytes(CHANNEL_ID, byteorder='big')
    can_frame = CANsecFrame(channel_id=CHANNEL_ID, freshness_value=PACKET_NUMBER)
    PACKET_NUMBER = PACKET_NUMBER + 1

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
    getKeys()
    receive_frame_from_supplicant1()
    while True:
        send_frame_to_supplicant1()
        time.sleep(2)
