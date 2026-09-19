from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(key, message):
    aes = AESGCM(key)

    nonce = os.urandom(12)

    encrypted = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    return nonce, ciphertext, tag


def decrypt_message(key, nonce, ciphertext, tag):
    aes = AESGCM(key)

    encrypted = ciphertext + tag

    plaintext = aes.decrypt(
        nonce,
        encrypted,
        None
    )

    return plaintext.decode()