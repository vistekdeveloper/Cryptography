#!/usr/bin/env python3
# IT8084 - ACG Practical - myDsStud.py (Extended with File Saving/Loading)

import os
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15 
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

RSA_PRIVATE_KEY_FILE = "rsa_private_key.pem"
RSA_PUBLIC_KEY_FILE = "rsa_public_key.pem"

header="A Simple Program using RSA to sign and verify a sha256 hashed message."
print(header)
message = input("Type in a phrase please =>")
print("Generating an RSA key pair...")
rsakey_pair=RSA.generate(2048)  
print("Done generating the key pair.")

# Export Private Key to PEM file
with open(RSA_PRIVATE_KEY_FILE, "wb") as f:
    f.write(rsakey_pair.export_key(format="PEM"))

# Export Public Key to PEM file
with open(RSA_PUBLIC_KEY_FILE, "wb") as f:
    f.write(rsakey_pair.publickey().export_key(format="PEM"))

print(f"Keys saved to {RSA_PRIVATE_KEY_FILE} and {RSA_PUBLIC_KEY_FILE}\n")

print("Signing the sha256 digest of the phrase with the private key of the RSA key pair")
digest=SHA256.new(message.encode())
print("digest:")
# print digest

for b in digest.digest():
    print("{0:02x}".format(b),end="")
print("\n")
signer = pkcs1_15.new(rsakey_pair)
signature=signer.sign(digest)
print("Signature:")
for b in signature:
    print("{0:02x}".format(b),end="")
print("\n")

print("Verifying the Signature of the phrase with the public key of the RSA key pair")
verifier = pkcs1_15.new(rsakey_pair.publickey())
# release the line below to trigger a invalid signature case.
# digest=SHA256.new("wrongmess".encode())
try:
    verifier.verify(digest,signature)
    print("The signature is valid")
except:
    print("The signature is not valid")