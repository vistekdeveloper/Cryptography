from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"1234567890abcdef"   # 16 bytes = AES-128

with open("server/menu_today.txt", "rb") as f:
    data = f.read()

menu = pad(data, AES.block_size) ##pad the data to 16bytes block size
print("Padded:", menu.hex(), "\n")

cipher = AES.new(KEY, AES.MODE_ECB) ##create a new AES cipher object in ECB mode
print("Cipher:", cipher, "\n")

encrypted_data = cipher.encrypt(menu) ##encrypt the padded data using the cipher object
print("Encrypted:", encrypted_data.hex(), "\n")

decipher = AES.new(KEY, AES.MODE_ECB) ##create a new AES cipher object in ECB mode for decryption
print("Decipher:", decipher, "\n")

decrypted = decipher.decrypt(encrypted_data) ##decrypt the encrypted data
print("Decrypted:", decrypted.hex(), "\n")

unpadded_data = unpad(decrypted, AES.block_size) ##unpad the decrypted data to get the original data
print("Original data:", unpadded_data.decode())