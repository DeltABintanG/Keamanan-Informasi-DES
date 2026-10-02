import socket
import threading

from des import encrypt, decrypt


# GANTI dengan IP WSL kamu
SERVER_IP = "172.22.26.107"

SERVER_PORT = 5000

# Key diasumsikan saling tahu
KEY = b"ISDESKEY"


def receive_messages(sock):
    while True:
        try:
            length_data = sock.recv(4)

            if not length_data:
                print("\nWSL disconnected.")
                break

            if len(length_data) < 4:
                print("\nHeader tidak lengkap.")
                break

            message_length = int.from_bytes(
                length_data,
                "big"
            )

            # Terima ciphertext sesuai panjang
            ciphertext = b""

            while len(ciphertext) < message_length:
                chunk = sock.recv(
                    message_length - len(ciphertext)
                )

                if not chunk:
                    print("\nConnection closed.")
                    return

                ciphertext += chunk

            print("\n")
            print("--- DECRYPTION ---")

            print("Length :", len(ciphertext), "bytes")
            print("HEX    :", ciphertext.hex())

            # Manual DES decryption
            plaintext = decrypt(ciphertext, KEY)

            print("PLAINTEXT:", plaintext.decode("utf-8"))

        except Exception as e:
            print("\n[ERROR RECEIVER]", e)
            break


def send_message(sock):
    while True:
        try:
            message = input("\nWin -> WSL : ")

            if message.lower() == "exit":
                print("Closing connection...")
                sock.close()
                break

            # Manual DES encryption
            ciphertext = encrypt(message, KEY)

            print("\n--- ENCRYPTION ---")
            print("Plaintext :", message)
            print("Ciphertext:", ciphertext.hex())

            # Kirim panjang ciphertext
            length = len(ciphertext)

            sock.sendall(
                length.to_bytes(4, "big")
            )

            # Kirim ciphertext
            sock.sendall(ciphertext)

        except Exception as e:
            print("\n[ERROR SENDER]", e)
            break


def main():
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    print("WINDOWS")
    print("=" * 60)

    print(
        f"Connecting to {SERVER_IP}:{SERVER_PORT}..."
    )

    try:
        sock.connect(
            (SERVER_IP, SERVER_PORT)
        )

    except Exception as e:
        print("\nTidak dapat terhubung.")
        print(e)
        return

    print("Terhubung ke WSL.")

    # Thread untuk menerima pesan
    receiver_thread = threading.Thread(
        target=receive_messages,
        args=(sock,),
        daemon=True
    )

    receiver_thread.start()

    # Main thread digunakan untuk mengirim
    send_message(sock)


if __name__ == "__main__":
    main()