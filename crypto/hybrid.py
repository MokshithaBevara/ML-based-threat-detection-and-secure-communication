from crypto.aes import (
    generate_aes_key,
    encrypt_message,
    decrypt_message
)

from crypto.rsa import (
    encrypt_aes_key,
    decrypt_aes_key
)


def encrypt_data(message, public_key):
    """
    Hybrid encryption:
    1. Generate AES-256 key
    2. Encrypt message using AES-256-GCM
    3. Encrypt AES key using RSA-2048-OAEP
    """

    # Generate AES key
    aes_key = generate_aes_key()

    # Encrypt message
    nonce, ciphertext = encrypt_message(message, aes_key)

    # Protect AES key using RSA
    encrypted_aes_key = encrypt_aes_key(
        aes_key,
        public_key
    )

    return encrypted_aes_key, nonce, ciphertext


def decrypt_data(
    encrypted_aes_key,
    nonce,
    ciphertext,
    private_key
):
    """
    Hybrid decryption:
    1. Recover AES key using RSA
    2. Decrypt message using AES-GCM
    """

    # Recover AES key
    aes_key = decrypt_aes_key(
        encrypted_aes_key,
        private_key
    )

    # Decrypt message
    message = decrypt_message(
        nonce,
        ciphertext,
        aes_key
    )

    return message