# CipherBridge 🔐

Secure Communication System using Hybrid Encryption.

## Technologies Used

- Python
- Streamlit
- AES-256-GCM
- RSA-OAEP
- Cryptography Library

## How It Works

CipherBridge uses hybrid encryption:

1. AES-256-GCM encrypts the message.
2. RSA-OAEP encrypts the AES session key.
3. The receiver uses the RSA private key to recover the AES key.
4. AES-GCM decrypts and verifies the message.
5. Any modification to the encrypted message is detected.

## Project Structure

```text
CipherBridge/
│
├── app.py
├── requirements.txt
├── .gitignore
│
├── crypto/
│   ├── aes.py
│   ├── rsa.py
│   └── hybrid.py
│
└── keys/
    ├── private_key.pem
    └── public_key.pem