#------------------------------------------------------------------------------------------
# Client.py (with encryption for day_end.csv)
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client

import datetime
import hmac
import hashlib
import sys
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

host = socket.gethostname()
port = 8888
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

SECRET_KEY = b"#B5Gh6eEwl$Me7"  # HMAC
AES_GCM_KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes = AES-256

# --- GET MENU (unchanged, still with HMAC) ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU)
    data = my_socket.recv(4096)

    menu_data, menu_hmac = data.split(b"|")
    current_hmac = hmac.new(SECRET_KEY, menu_data, hashlib.sha256).hexdigest().encode()
    print("Current HMAC:", current_hmac.decode())
    print("Received HMAC:", menu_hmac.decode())

    if current_hmac == menu_hmac:
        print("HMAC verified successfully.")
    else:
        print("HMAC verification failed.")

    print("\n" + menu_data.decode() + "\n")

    with open(menu_file, "wb") as f:
        f.write(menu_data)

# --- SEND day_end.csv (ENCRYPTED with AES-GCM) ---
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))

    # Read the whole file
    with open(return_file, "rb") as out_file:
        plaintext = out_file.read()

    # Encrypt with AES-GCM
    nonce = get_random_bytes(12)
    cipher = AES.new(AES_GCM_KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    print("Original sales data:", plaintext)
    print("Encrypted sales data:", ciphertext.hex())
    print("Nonce:", nonce.hex())
    print("Authentication tag:", tag.hex())

    # Send: CLOSING + nonce + tag + ciphertext
    my_socket.sendall(cmd_END_DAY + nonce + tag + ciphertext)

    print("Sales data encrypted and sent to server.")