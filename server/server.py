#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
import hashlib
import hmac
import os
from threading import Thread    # for handling task in separate jobs we need threading
import socket           # tcp protocol
import datetime         # for composing date/time stamp
import sys              # handle system error
import traceback        # for print_exc function
import time             # for delay purpose
import ssl
from dotenv import load_dotenv
from pathlib import Path
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15 
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
global host, port

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"

client_rsa_public_key_file = "client_rsa_public_key.pem"

host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server

##Stores the secret keys in environment variables and loads them using dotenv for security purposes. 
##This avoids hardcoding sensitive information in the code. (Steven)
BASE_DIR = Path(__file__).resolve().parent  ##Get the folder path
load_dotenv(BASE_DIR / ".env") ##Load .env file from this folder

SECRET_KEY = os.getenv("HMAC_PRESHARED_KEY", "").encode("utf-8") ##Fetch the HMAC_PRESHARED_KEY from the .env file and encode it to bytes

AES_GCM_KEY = os.getenv("AES_GCM_KEY", "").encode("utf-8") ##Fetch the AES_GCM_KEY from the .env file and encode it to bytes
print("AES_GCM_KEY:", AES_GCM_KEY.decode())  ##Print the AES_GCM_KEY for debugging purposes

##------------------------------------------------------------------------------------------------


def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd: # ask for menu
                try:
                    src_file = open(default_menu,"rb")
                except:
                    print("file not found : " + default_menu)
                    sys.exit(0)
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b'':
                        break
                    #hints: you may apply a scheme (hashing/encryption) to read_bytes before sending to client.
                    ##Hmac integrity check for the menu file sent to client, encryption not requried (Steven)
                    menu_hmac = hmac.new(SECRET_KEY, read_bytes, hashlib.sha256).hexdigest().encode() #generate hmac
                    conn.send(read_bytes + b"|" + menu_hmac) #send the menu bytes and hmac together to client
                    ##-------------------------------------------------------------------------------------
                src_file.close()
                print("Processed SENDING menu") 
                return
            
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)
                payload = net_bytes[len(cmd_END_DAY):]  # remove "CLOSING"
                while b"|" not in payload:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    payload += chunk

                if b"|" not in payload:
                    raise ValueError("No signature separator in payload")

                content, signature = payload.split(b"|", 1)

                ##Fetch the client public key to generate the signature and verify(Steven)
                pub_key = RSA.import_key(open(client_rsa_public_key_file, "rb").read())
                digest = SHA256.new(content)
                verifier = pkcs1_15.new(pub_key)

                try:
                    verifier.verify(digest, signature)
                    print("The signature is valid")
                except:
                    print("The signature is not valid")

                dest_file.write(content)   # save only file content
                print("wrote content to file")

                blk_count += 1
                # dest_file.write( net_bytes[ len(cmd_END_DAY): ] ) # remove the CLOSING header    
                # blk_count = blk_count + 1
        else:  # write subsequent blocks of END_DAY message block
            # Hints: net_bytes may be an encrypted block of message.
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    dest_file.close()
    print("saving file as " + filename)
    time.sleep(3)
    print("Processed CLOSING done") 
    return

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + "ended")
    return

def start_server():
    global host, port
    # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')
    
    try:
        soc.bind((host, port))
        print('Socket bind complete')
    except socket.error as msg:
        
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket and can accept 10 connection
    soc.listen(10)
    print('Socket now listening')

    # this will make an infinite loop needed for 
    # not reseting server for every client
    try:
        while True:
            conn, addr = soc.accept()
            # assign ip and port
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port)

            ##TLS wrap the connection socket to secure the com between client and server(Steven)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
            conn = context.wrap_socket(conn, server_side=True)

            TLS_info = conn.cipher()
            print(TLS_info)
            ##-----------------------------------------------------------------------

            try:
                Thread(target=client_thread, args=(conn, ip, port)).start()
            except:
                print("Terrible error!")
                traceback.print_exc()
    except:
        pass
    soc.close()
    return

start_server()  
