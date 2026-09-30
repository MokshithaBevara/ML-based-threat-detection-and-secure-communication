import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key():
    """Generate a 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(message, key):
    """Encrypt a message using AES-256-GCM."""
    aes = AESGCM(key)

    # 12-byte nonce recommended for GCM
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


def decrypt_message(nonce, ciphertext, key):
    """Decrypt and authenticate an AES-256-GCM message."""
    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")