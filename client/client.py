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
global host, port

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

SECRET_KEY = b"#B5Gh6eEwl$Me7" #HMAC


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU )
    data = my_socket.recv(4096)
    #hints : need to apply a scheme to verify the integrity of data.  
    menu_data, menu_hmac = data.split(b"|") #split the received data into menu and hmac
    current_hmac = hmac.new(SECRET_KEY, menu_data, hashlib.sha256).hexdigest().encode() #generate hmac for received menu
    print("Current HMAC:", current_hmac.decode())
    print("Received HMAC:", menu_hmac.decode())

    if current_hmac == menu_hmac: #compare the hmacs
        print("HMAC verified successfully.")
    else:
        print("HMAC verification failed.")

    print("\n" + menu_data.decode() + "\n")

    menu_file = open(menu_file,"wb")
    menu_file.write(menu_data)
    menu_file.close()
    my_socket.close()

# print('Menu today received from server')
#print('Received', repr(data))  # for debugging use
my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
        out_file = open(return_file,"rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    file_bytes = out_file.read(1024)
    sent_bytes=b''
    while file_bytes != b'':
        # hints: need to protect the file_bytes in a way before sending out.
        my_socket.send(file_bytes)
        sent_bytes+=file_bytes
        file_bytes = out_file.read(1024) # read next block from file
    out_file.close()
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
