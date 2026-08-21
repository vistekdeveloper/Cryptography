#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client
 
import datetime
import hmac
import hashlib
import sys              # handle system error
import socket
import time
import ssl
global host, port

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

SECRET_KEY = b"#B5Gh6eEwl$Me7" #HMAC

##Set up TLS context and wrap the socket for secure communication--------
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_socket:
    ##create a TLS socket and wrap the raw socket with it (Steven)
    with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
        tls_socket.connect((host, port)) ##Connect to the server using the TLS socket
    
        tls_socket.sendall(cmd_GET_MENU) 
        data = tls_socket.recv(4096)
        #hints : need to apply a scheme to verify the integrity of data.  
        ##HMAC Verification for the menu file received from server (Steven)
        menu_data, menu_hmac = data.split(b"|") #split the received data into menu and hmac
        current_hmac = hmac.new(SECRET_KEY, menu_data, hashlib.sha256).hexdigest().encode() #generate hmac for received menu
        print("Current HMAC:", current_hmac.decode())
        print("Received HMAC:", menu_hmac.decode())

        if current_hmac == menu_hmac: ##compare the hmacs
            print("HMAC verified successfully.")
        else:
            print("HMAC verification failed.")

        print("\n" + menu_data.decode() + "\n")

        with open(menu_file,"wb") as f:
            f.write(menu_data)
        tls_socket.close()

# print('Menu today received from server')
#print('Received', repr(data))  # for debugging use
raw_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    with context.wrap_socket(my_socket, server_hostname=host) as tls_socket:
        tls_socket.connect((host, port)) ##TLS socket connect to the server

        tls_socket.sendall(cmd_END_DAY) 
        ##-----------------------------------------------------------------------


        # try:
        #     out_file = open(return_file,"rb")
        # except:
        #     print("file not found : " + return_file)
        #     sys.exit(0)
        # file_bytes = out_file.read(1024)
        # sent_bytes=b''
        # while file_bytes != b'':
        #     # hints: need to protect the file_bytes in a way before sending out.
        #     tls_socket.send(file_bytes)
        #     sent_bytes+=file_bytes
        #     file_bytes = out_file.read(1024) # read next block from file
        # out_file.close()
        # tls_socket.close()

        try:
            with open(return_file, "rb") as out_file:
                content = out_file.read()
        except FileNotFoundError:
            print("file not found : " + return_file)
            sys.exit(0)

        tls_socket.sendall(content) ##Send the whole content of the file to the server
        tls_socket.shutdown(socket.SHUT_WR) ##Inform server that client is done writing

print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
