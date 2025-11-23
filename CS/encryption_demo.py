"""
encryption_demo.py

Demonstrates:
- Symmetric encryption (Fernet/AES under the hood)
- Asymmetric encryption (RSA public/private key pair)

Requirements:
    pip install cryptography
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def symmetric_demo(message: bytes):
    print("=" * 60)
    print("SYMMETRIC ENCRYPTION DEMO (Fernet / AES)")
    print("=" * 60)

    # Generate a random symmetric key (same key encrypts & decrypts)
    symmetric_key = Fernet.generate_key()
    cipher = Fernet(symmetric_key)

    # Encrypt and decrypt
    ciphertext = cipher.encrypt(message)
    decrypted = cipher.decrypt(ciphertext)

    print(f"Plaintext input:      {message.decode('utf-8')}")
    print(f"Symmetric key (base64): {symmetric_key.decode('utf-8')}")
    print(f"Ciphertext (base64): {ciphertext.decode('utf-8')}")
    print(f"Decrypted output:    {decrypted.decode('utf-8')}")
    print()


def asymmetric_demo(message: bytes):
    print("=" * 60)
    print("ASYMMETRIC ENCRYPTION DEMO (RSA)")
    print("=" * 60)

    # Generate RSA private/public key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048 bits is common for RSA
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format so they’re human-readable for the assignment
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # no password for demo
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Encrypt with PUBLIC key, decrypt with PRIVATE key
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    print("Plaintext input:", message.decode("utf-8"))
    print("\nPublic key (PEM):")
    print(public_pem)
    print("Private key (PEM):")
    print(private_pem)

    print("Ciphertext (hex):")
    print(ciphertext.hex())
    print("\nDecrypted output:", decrypted.decode("utf-8"))
    print()


def main():
    # Short message required by the assignment
    message = b"Security lab: symmetric vs asymmetric encryption"

    symmetric_demo(message)
    asymmetric_demo(message)


if __name__ == "__main__":
    main()
