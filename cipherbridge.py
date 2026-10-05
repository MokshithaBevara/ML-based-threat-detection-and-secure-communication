import os
import json

from ml.predict import detect_attack
from crypto.rsa import generate_rsa_keys
from crypto.hybrid import encrypt_data, decrypt_data


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(
    os.path.join(BASE_DIR, "ml", "evaluation.json")
) as f:
    evaluation = json.load(f)


def main():

    print("\n" + "=" * 60)
    print("                  🔐 CIPHER GUARD")
    print("          Secure Communication & Threat Detection")
    print("=" * 60)

    # ========================================================
    # 1. ML SECURITY CHECK
    # ========================================================

    print("\n[1] ML SECURITY CHECK")
    print("-" * 60)

    print(
        f"Model Accuracy : "
        f"{evaluation['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision      : "
        f"{evaluation['precision'] * 100:.2f}%"
    )

    print(
        f"Recall         : "
        f"{evaluation['recall'] * 100:.2f}%"
    )

    print(
        f"F1-score       : "
        f"{evaluation['f1_score'] * 100:.2f}%"
    )

    print("\nConfusion Matrix:")
    print(evaluation["confusion_matrix"])

    # ========================================================
    # 2. SESSION SECURITY CHECK
    # ========================================================

    print("\n[2] SESSION SECURITY CHECK")
    print("-" * 60)

    print("Enter current session details:\n")

    network_packet_size = float(
        input("Network packet size: ")
    )

    protocol_type = input(
        "Protocol type: "
    )

    login_attempts = int(
        input("Login attempts: ")
    )

    session_duration = float(
        input("Session duration: ")
    )

    encryption_used = input(
        "Encryption used: "
    )

    ip_reputation_score = float(
        input("IP reputation score: ")
    )

    failed_logins = int(
        input("Failed logins: ")
    )

    browser_type = input(
        "Browser type: "
    )

    unusual_time_access = int(
        input("Unusual time access (0/1): ")
    )

    print("\nAnalysing session...")

    result = detect_attack(
        network_packet_size,
        protocol_type,
        login_attempts,
        session_duration,
        encryption_used,
        ip_reputation_score,
        failed_logins,
        browser_type,
        unusual_time_access
    )

    print(f"\nML Prediction : {result}")

    # ========================================================
    # 3. BLOCK SUSPICIOUS SESSION
    # ========================================================

    if result == "Attack":

        print("\n" + "!" * 60)
        print("🚨 SUSPICIOUS SESSION DETECTED")
        print("ACCESS DENIED")
        print("MESSAGE TRANSFER BLOCKED")
        print("!" * 60)

        return

    # ========================================================
    # 4. ALLOW NORMAL SESSION
    # ========================================================

    print("\n✓ ACCESS GRANTED")
    print("✓ Secure communication channel opened.")

    # ========================================================
    # 5. KEY GENERATION
    # ========================================================

    print("\n[3] KEY GENERATION")
    print("-" * 60)

    private_key, public_key = generate_rsa_keys()

    print("✓ RSA-2048 key pair generated")

    # ========================================================
    # 6. SECURE MESSAGE
    # ========================================================

    print("\n[4] SECURE MESSAGE")
    print("-" * 60)

    message = input("Enter message: ")

    encrypted_aes_key, nonce, ciphertext = encrypt_data(
        message,
        public_key
    )

    print("\n✓ AES-256 session key generated")
    print("✓ Message encrypted using AES-256-GCM")
    print("✓ AES key protected using RSA-2048-OAEP")

    # ========================================================
    # 7. RECEIVER
    # ========================================================

    print("\n[5] RECEIVER")
    print("-" * 60)

    decrypted_message = decrypt_data(
        encrypted_aes_key,
        nonce,
        ciphertext,
        private_key
    )

    print("✓ AES key recovered using RSA")
    print("✓ Message decrypted and authenticated using AES-GCM")

    # ========================================================
    # 8. VERIFICATION
    # ========================================================

    print("\n[6] VERIFICATION")
    print("-" * 60)

    print(f"Original  : {message}")
    print(f"Decrypted : {decrypted_message}")

    if message == decrypted_message:

        print("\n✓ Messages match")
        print("🔒 END-TO-END SECURITY VERIFIED")

    else:

        print("\n✗ Verification failed.")


if __name__ == "__main__":
    main()