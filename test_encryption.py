from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"1234567890abcdef"   # 16 bytes = AES-128

with open("server/menu_today.txt", "rb") as f:
    data = f.read()

menu = pad(data, AES.block_size)
print("Padded:", menu.hex())

cipher = AES.new(KEY, AES.MODE_ECB)
print("Cipher:", cipher)
encrypted_data = cipher.encrypt(menu)
print("Encrypted:", encrypted_data.hex())

decipher = AES.new(KEY, AES.MODE_ECB)
decrypted = unpad(decipher.decrypt(encrypted_data), AES.block_size)

print("Recovered:", decrypted.decode("utf-8", errors="replace"))