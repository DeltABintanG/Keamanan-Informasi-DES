import socket
import threading

from des import encrypt, decrypt


HOST = "0.0.0.0"
PORT = 5000

# Key diasumsikan salih tahu
KEY = b"ISDESKEY"


def receive_messages(conn):
    while True:
        try:
            length_data = conn.recv(4)

            if not length_data:
                print("\nDevice A disconnected.")
                break

            if len(length_data) < 4:
                print("\nHeader tidak lengkap.")
                break

            message_length = int.from_bytes(length_data, "big")

            ciphertext = b""

            while len(ciphertext) < message_length:
                chunk = conn.recv(
                    message_length - len(ciphertext)
                )

                if not chunk:
                    print("\nConnection closed.")
                    return

                ciphertext += chunk

            print("\n--- DECRYPTION ---")

            print("Length :", len(ciphertext), "bytes")
            print("HEX    :", ciphertext.hex())

            plaintext = decrypt(ciphertext, KEY)

            print("PLAINTEXT:", plaintext.decode("utf-8"))


        except Exception as e:
            print("\n[ERROR RECEIVER]", e)
            break


def send_message(conn):
    while True:
        try:
            message = input("\nWSL -> Win : ")

            if message.lower() == "exit":
                print("Closing connection...")
                conn.close()
                break

            # Manual DES encryption
            ciphertext = encrypt(message, KEY)

            print("\n--- ENCRYPTION ---")
            print("Plaintext :", message)
            print("Ciphertext:", ciphertext.hex())

            # Kirim panjang ciphertext terlebih dahulu
            length = len(ciphertext)

            conn.sendall(
                length.to_bytes(4, "big")
            )

            # Kirim ciphertext
            conn.sendall(ciphertext)

        except Exception as e:
            print("\n[ERROR SENDER]", e)
            break


def main():
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen(1)

    print("WSL")
    print("=" * 60)
    print(f"Listening on {HOST}:{PORT}")
    print("Waiting...")

    conn, address = server.accept()

    print("\n[CONNECTED]")
    print("Windows :", address)

    receiver_thread = threading.Thread(
        target=receive_messages,
        args=(conn,),
        daemon=True
    )

    receiver_thread.start()

    send_message(conn)

    server.close()


if __name__ == "__main__":
    main()
