import streamlit as st
from crypto.rsa import generate_rsa_keys, save_rsa_keys, load_rsa_keys
from crypto.hybrid import hybrid_encrypt, hybrid_decrypt

if "rsa_keys" not in st.session_state:
    from pathlib import Path

    if (
        Path("keys/private_key.pem").exists()
        and Path("keys/public_key.pem").exists()
    ):
        st.session_state.rsa_keys = load_rsa_keys()
    else:
        st.session_state.rsa_keys = generate_rsa_keys()
        save_rsa_keys(*st.session_state.rsa_keys)

if "encrypted_data" not in st.session_state:
    st.session_state.encrypted_data = None

st.set_page_config(
    page_title="CipherBridge",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 CipherBridge")
st.info(
    "Hybrid Encryption: AES-256-GCM encrypts the message, "
    "while RSA-OAEP protects the AES session key."
)
st.subheader("Secure Communication Using Hybrid Encryption")

st.write(
    "AES-256-GCM + RSA-OAEP"
)

st.divider()

st.header("📤 Sender")

message = st.text_area(
    "Enter your message",
    placeholder="Type a secret message..."
)

encrypt_button = st.button("🔒 Encrypt Message")

if encrypt_button:
    if not message:
        st.warning("Please enter a message.")
    else:
        private_key, public_key = st.session_state.rsa_keys

        encrypted_aes_key, nonce, ciphertext, tag = hybrid_encrypt(
            message,
            public_key
        )

        st.success("🔒 Message encrypted successfully!")

        with st.expander("🔐 View Encrypted Data"):
            st.write("Encrypted AES Key")
            st.code(encrypted_aes_key.hex())

            st.write("Nonce")
            st.code(nonce.hex())

            st.write("Ciphertext")
            st.code(ciphertext.hex())

            st.write("Authentication Tag")
            st.code(tag.hex())

        st.session_state.encrypted_data = (
            encrypted_aes_key,
            nonce,
            ciphertext,
            tag,
            private_key
        )
st.divider()

st.header("📥 Receiver")

decrypt_button = st.button("🔓 Decrypt Message")

if decrypt_button:
    if st.session_state.encrypted_data is None:
        st.warning("Please encrypt a message first.")
    else:
        (
            encrypted_aes_key,
            nonce,
            ciphertext,
            tag,
            private_key
        ) = st.session_state.encrypted_data

        try:
            from crypto.hybrid import hybrid_decrypt

            decrypted_message = hybrid_decrypt(
                encrypted_aes_key,
                nonce,
                ciphertext,
                tag,
                private_key
            )

            st.success("🔓 Message decrypted successfully!")

            st.write("💬 Original Message")
            st.code(decrypted_message)

        except Exception:
            st.error("❌ Decryption failed. The message may have been modified.")

st.divider()

st.header("🛡️ Security Test")

tamper_button = st.button("⚠️ Simulate Tampering")

if tamper_button:
    if st.session_state.encrypted_data is None:
        st.warning("Please encrypt a message first.")
    else:
        (
            encrypted_aes_key,
            nonce,
            ciphertext,
            tag,
            private_key
        ) = st.session_state.encrypted_data

        # Modify one byte of the ciphertext
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 1
        tampered_ciphertext = bytes(tampered_ciphertext)

        try:
            from crypto.hybrid import hybrid_decrypt

            hybrid_decrypt(
                encrypted_aes_key,
                nonce,
                tampered_ciphertext,
                tag,
                private_key
            )

            st.error("⚠️ Tampering was not detected.")

        except Exception:
            st.success(
                "🛡️ Tampering detected! "
                "AES-GCM rejected the modified message."
            )