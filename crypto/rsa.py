from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


def encrypt_aes_key(public_key, aes_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def decrypt_aes_key(private_key, encrypted_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key

from cryptography.hazmat.primitives import serialization
from pathlib import Path


KEYS_DIR = Path("keys")


def save_rsa_keys(private_key, public_key):
    KEYS_DIR.mkdir(exist_ok=True)

    private_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    (KEYS_DIR / "private_key.pem").write_bytes(private_data)
    (KEYS_DIR / "public_key.pem").write_bytes(public_data)

def load_rsa_keys():
    private_data = (KEYS_DIR / "private_key.pem").read_bytes()
    public_data = (KEYS_DIR / "public_key.pem").read_bytes()

    private_key = serialization.load_pem_private_key(
        private_data,
        password=None
    )

    public_key = serialization.load_pem_public_key(
        public_data
    )

    return private_key, public_key