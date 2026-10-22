
import threading
import socket

from cipher import (
    generatePrivateAndPublicKey,
    loadReceiverPublicKey,
    encryptMessage,
    decryptMessage
)

# Generate public and private key
my_public_key = generatePrivateAndPublicKey()

# Initialize peer public key
peer_public_key = None


# Receive exactly the peer's public key
def receive_public_key(conn):
    data = b""
    ending = b"-----END PUBLIC KEY-----"

    while ending not in data:
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed during key exchange")
        data += chunk

        if len(data) > 4096:
            raise ValueError("Public key is too large")

    return data


# Send message to other PC
def send_message(conn):
    global peer_public_key

    try:
        # Send public key first
        conn.sendall(my_public_key)
        print("Public key sent")

        while True:
            message = input("You: ")

            if message.lower() == "/quit":
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                break

            # Wait for peer public key
            if peer_public_key:
                encrypted_message = encryptMessage(
                    message.encode("utf-8"),
                    peer_public_key
                )

                # RSA-2048 ciphertext is 256 bytes
                conn.sendall(encrypted_message)
            else:
                print("Waiting for peer's public key...")

    except (ConnectionError, OSError, ValueError) as e:
        print(f"Error sending message: {e}")


# Receive message from other PC
def receive_message(conn):
    global peer_public_key

    try:
        # Receive peer public key first
        peer_public_key_data = receive_public_key(conn)

        peer_public_key = loadReceiverPublicKey(
            peer_public_key_data
        )

        print("Peer's public key received!")

        while True:
            encrypted_message = b""

            # Receive complete RSA ciphertext
            while len(encrypted_message) < 256:
                chunk = conn.recv(256 - len(encrypted_message))

                if not chunk:
                    print("Connection closed by peer.")
                    return

                encrypted_message += chunk

            # Decrypt message
            decrypted_message = decryptMessage(encrypted_message)

            print(f"\nPeer: {decrypted_message.decode('utf-8')}")

    except (ConnectionError, OSError, ValueError) as e:
        print(f"Error receiving message: {e}")
    except Exception as e:
        print(f"Message processing error: {e}")


# Start client mode
def start_client_mode(server_ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"Connecting to {server_ip}:{port}")
            s.connect((server_ip, port))
            print("Connected!")

            receive_thread = threading.Thread(
                target=receive_message,
                args=(s,),
                daemon=True
            )
            send_thread = threading.Thread(
                target=send_message,
                args=(s,),
                daemon=True
            )

            receive_thread.start()
            send_thread.start()

            send_thread.join()

        except (ConnectionRefusedError, OSError) as e:
            print(f"Failed to connect to server: {e}")


# Start server mode
def start_server_mode(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        s.bind((host, port))
        s.listen(1)

        print(f"Waiting for connection on {host}:{port}")

        conn, addr = s.accept()
        print(f"Connected by {addr}")

        with conn:
            receive_thread = threading.Thread(
                target=receive_message,
                args=(conn,),
                daemon=True
            )
            send_thread = threading.Thread(
                target=send_message,
                args=(conn,),
                daemon=True
            )

            receive_thread.start()
            send_thread.start()

            send_thread.join()
