#------------------------------------------------------------------------------------------
# Server.py (with decryption for day_end.csv)
#------------------------------------------------------------------------------------------
import hashlib
import hmac
from threading import Thread
import socket
import datetime
import sys
import traceback
import time
from Crypto.Cipher import AES

host = socket.gethostname()
port = 8888

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"

SECRET_KEY = b"#B5Gh6eEwl$Me7"  # HMAC
AES_GCM_KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes = AES-256


def process_connection(conn, ip_addr, MAX_BUFFER_SIZE):
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp", "w")  # temp file, can be ignored

    while net_bytes != b"":
        if blk_count == 0:  # 1st block
            if net_bytes.startswith(b"GET_MENU"):
                usr_cmd = "GET_MENU"
            elif net_bytes.startswith(b"CLOSING"):
                usr_cmd = "CLOSING"
            else:
                print("Unknown command received")
                return

            if usr_cmd == cmd_GET_MENU:  # send menu
                try:
                    src_file = open(default_menu, "rb")
                except FileNotFoundError:
                    print("file not found : " + default_menu)
                    sys.exit(0)

                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b"":
                        break
                    menu_hmac = hmac.new(SECRET_KEY, read_bytes, hashlib.sha256).hexdigest().encode()
                    conn.send(read_bytes + b"|" + menu_hmac)

                src_file.close()
                print("Processed SENDING menu")
                return

            elif usr_cmd == cmd_END_DAY:  # receive encrypted sales data
                now = datetime.datetime.now()
                filename = default_save_base + ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")

                # Collect all encrypted bytes after "CLOSING"
                encrypted_payload = net_bytes[len(cmd_END_DAY):]

                while True:
                    chunk = conn.recv(MAX_BUFFER_SIZE)
                    if chunk == b"":
                        break
                    encrypted_payload += chunk

                # Parse: nonce (12) + tag (16) + ciphertext
                if len(encrypted_payload) < 28:
                    raise ValueError("Encrypted payload is incomplete")

                nonce = encrypted_payload[:12]
                tag = encrypted_payload[12:28]
                ciphertext = encrypted_payload[28:]

                # Decrypt and verify
                decipher = AES.new(AES_GCM_KEY, AES.MODE_GCM, nonce=nonce)
                plaintext = decipher.decrypt_and_verify(ciphertext, tag)
                print("Encrypted data received:", ciphertext.hex())
                print("Decrypted sales data:", plaintext.decode("utf-8"))

                # Save decrypted sales data
                with open(filename, "wb") as f:
                    f.write(plaintext)

                print("saving decrypted file as " + filename)
                time.sleep(3)
                print("Processed CLOSING done")
                return

        else:  # subsequent blocks (not used in this simple version)
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)

    dest_file.close()
    print("saving file as " + filename)
    time.sleep(3)
    print("Processed CLOSING done")
    return


def client_thread(conn, ip, port, MAX_BUFFER_SIZE=4096):
    process_connection(conn, ip, MAX_BUFFER_SIZE)
    conn.close()
    print("Connection " + ip + ":" + port + " ended")
    return


def start_server():
    global host, port
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    try:
        soc.bind((host, port))
        print("Socket bind complete")
    except socket.error as msg:
        print("Bind failed. Error : " + str(sys.exc_info()))
        print(msg.with_traceback())
        sys.exit()

    soc.listen(10)
    print("Socket now listening")

    try:
        while True:
            conn, addr = soc.accept()
            ip, port = str(addr[0]), str(addr[1])
            print("Accepting connection from " + ip + ":" + port)
            try:
                Thread(target=client_thread, args=(conn, ip, port)).start()
            except Exception:
                print("Terrible error!")
                traceback.print_exc()
    except Exception:
        pass
    soc.close()
    return


start_server()