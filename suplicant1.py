import socket
import pickle
import random
from frame import CANsecFrame

# Constants
HOST = '127.0.0.1'  # Localhost
PORT_SUPP1 = 65432  # Port for Supplicant 1
PORT_SUPP2 = 65433  # Port for Supplicant 2

# Supplicant parameters
NODE_ID_SUPP1 = 1
CHANNEL_ID = 1
SESSION_KEY = b'secretkey123456'
FRESHNESS_VALUE_SUPP1 = 1


def send_frame_to_supplicant2():
    # Create a CANsecFrame for Supplicant 1
    can_frame = CANsecFrame(node_id=NODE_ID_SUPP1, channel_id=CHANNEL_ID, session_key=SESSION_KEY,
                            freshness_value=FRESHNESS_VALUE_SUPP1)
    can_frame.encrypt()  # Encrypt the frame

    # Serialize the CANsecFrame
    serialized_frame = pickle.dumps(can_frame)

    # Send the frame to Supplicant 2
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_SUPP2))
        s.sendall(serialized_frame)
        print(f"Supplicant 1 sent CANsec frame to Supplicant 2: {can_frame}")


def receive_frame_from_supplicant2():
    # Create a socket to listen for Supplicant 2's response
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT_SUPP1))
        s.listen()
        print("Supplicant 1 is listening for a response from Supplicant 2...")

        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)  # Receive the serialized frame
            received_frame = pickle.loads(data)  # Deserialize the frame

            # Verify and decrypt the received frame
            if received_frame.verify_icv(received_frame.session_key):
                print("Supplicant 1: ICV verified successfully.")
                decrypted_payload = received_frame.decrypt()
                print("Supplicant 1: Decrypted Payload:", decrypted_payload)
            else:
                print("Supplicant 1: ICV verification failed!")


if __name__ == "__main__":
    # Supplicant 1 first sends a frame and then listens for a response
    send_frame_to_supplicant2()
    receive_frame_from_supplicant2()
