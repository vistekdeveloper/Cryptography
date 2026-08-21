from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    message = b"closing report for today: total sales = 1500"

    private_key, public_key = generate_keypair()
    signature = sign_message(private_key, message)

    print("Signature generated:", signature.hex())
    print("Signature valid:", verify_signature(public_key, message, signature))

    tampered = b"closing report for today: total sales = 9999"
    print("Tampered message valid:", verify_signature(public_key, tampered, signature))