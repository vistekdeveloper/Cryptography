from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

EDDSA_PRIVATE_KEY_FILE = "eddsa_private_key.pem"
EDDSA_PUBLIC_KEY_FILE = "eddsa_public_key.pem"

def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Export Private Key to PEM file
    with open(EDDSA_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.export_key(format="PEM"))

    # Export Public Key to PEM file
    with open(EDDSA_PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key().export_key(format="PEM"))

    print(f"Keys saved to {EDDSA_PRIVATE_KEY_FILE} and {EDDSA_PUBLIC_KEY_FILE}\n")
    


def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


generate_keypair()


# if __name__ == "__main__":
#     message = b"closing report for today: total sales = 1500"

#     private_key, public_key = generate_keypair()
#     signature = sign_message(private_key, message)

#     print("Signature generated:", signature.hex())
#     print("Signature valid:", verify_signature(public_key, message, signature))

#     tampered = b"closing report for today: total sales = 9999"
#     print("Tampered message valid:", verify_signature(public_key, tampered, signature))

