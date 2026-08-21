from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes = AES-256 key

plaintext = b"apple,5\nbanana,3\nmilk,2\n"

nonce = get_random_bytes(12)

cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

print("Plaintext:", plaintext)
print("Nonce:", nonce.hex())
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())

decipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
recovered = decipher.decrypt_and_verify(ciphertext, tag)

print("Recovered:", recovered)

modified_ciphertext = bytearray(ciphertext)
modified_ciphertext[0] ^= 0xFF

try:
    tamper_cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    tamper_cipher.decrypt_and_verify(bytes(modified_ciphertext), tag)
    print("Tampering was not detected!")
except ValueError:
    print("Tampering detected correctly: invalid authentication tag.")
