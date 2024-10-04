import socket
import pickle
import random
from frame import CANsecFrame

# Constants
HOST = '127.0.0.1'  # Localhost
PORT_SUPP1 = 65432  # Port for Supplicant 1
PORT_SUPP2 = 65433  # Port for Supplicant 2

# Supplicant parameters
NODE_ID_SUPP2 = 2
CHANNEL_ID = 2
SESSION_KEY = b'secretkey123456'
FRESHNESS_VALUE_SUPP2 = 1


def receive_frame_from_supplicant1():
    # Create a socket to listen for Supplicant 1's frame
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_SUPP2))
        s.listen()
        print("Supplicant 2 is listening for a frame from Supplicant 1...")

        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)  # Receive the serialized frame
            received_frame = pickle.loads(data)  # Deserialize the frame

            # Verify and decrypt the received frame
            if received_frame.verify_icv(received_frame.session_key):
                print("Supplicant 2: ICV verified successfully.")
                decrypted_payload = received_frame.decrypt()
                print("Supplicant 2: Decrypted Payload:", decrypted_payload)
            else:
                print("Supplicant 2: ICV verification failed!")

    return received_frame


def send_frame_to_supplicant1():
    # Create a CANsecFrame for Supplicant 2
    can_frame = CANsecFrame(node_id=NODE_ID_SUPP2, channel_id=CHANNEL_ID, session_key=SESSION_KEY,
                            freshness_value=FRESHNESS_VALUE_SUPP2)
    can_frame.encrypt()  # Encrypt the frame

    # Serialize the CANsecFrame
    serialized_frame = pickle.dumps(can_frame)

    # Send the frame to Supplicant 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_SUPP1))
        s.sendall(serialized_frame)
        print(f"Supplicant 2 sent CANsec frame to Supplicant 1: {can_frame}")


if __name__ == "__main__":
    # Supplicant 2 first listens for a frame and then sends a response
    receive_frame_from_supplicant1()
    send_frame_to_supplicant1()
