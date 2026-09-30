import os
import joblib
import pandas as pd


# Find project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load trained model
MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "cipherbridge_ml_model.pkl"
)

model = joblib.load(MODEL_PATH)


def detect_attack(
    network_packet_size,
    protocol_type,
    login_attempts,
    session_duration,
    encryption_used,
    ip_reputation_score,
    failed_logins,
    browser_type,
    unusual_time_access
):
    """
    Predict whether a network/session activity
    is normal or an attack.
    """

    data = pd.DataFrame([{
        "network_packet_size": network_packet_size,
        "protocol_type": protocol_type,
        "login_attempts": login_attempts,
        "session_duration": session_duration,
        "encryption_used": encryption_used,
        "ip_reputation_score": ip_reputation_score,
        "failed_logins": failed_logins,
        "browser_type": browser_type,
        "unusual_time_access": unusual_time_access
    }])

    prediction = model.predict(data)[0]

    if prediction == 1:
        return "Attack"
    else:
        return "Normal"