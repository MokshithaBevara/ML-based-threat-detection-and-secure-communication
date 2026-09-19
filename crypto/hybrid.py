from crypto.aes import generate_key, encrypt_message, decrypt_message
from crypto.rsa import (
    generate_rsa_keys,
    encrypt_aes_key,
    decrypt_aes_key
)


def hybrid_encrypt(message, public_key):
    # 1. Generate a new AES-256 key
    aes_key = generate_key()

    # 2. Encrypt the message using AES-256-GCM
    nonce, ciphertext, tag = encrypt_message(
        aes_key,
        message
    )

    # 3. Encrypt the AES key using RSA-OAEP
    encrypted_aes_key = encrypt_aes_key(
        public_key,
        aes_key
    )

    return encrypted_aes_key, nonce, ciphertext, tag


def hybrid_decrypt(
    encrypted_aes_key,
    nonce,
    ciphertext,
    tag,
    private_key
):
    # 1. Recover the AES key using RSA private key
    aes_key = decrypt_aes_key(
        private_key,
        encrypted_aes_key
    )

    # 2. Decrypt and authenticate the message using AES-GCM
    message = decrypt_message(
        aes_key,
        nonce,
        ciphertext,
        tag
    )

    return message