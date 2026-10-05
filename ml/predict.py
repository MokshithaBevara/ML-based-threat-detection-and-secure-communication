import os
import joblib
import pandas as pd


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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

    # Feature engineering
    data["login_failure_ratio"] = (
        data["failed_logins"] /
        (data["login_attempts"] + 1)
    )

    data["auth_pressure"] = (
        data["login_attempts"] +
        data["failed_logins"]
    )

    data["login_failure_interaction"] = (
        data["login_attempts"] *
        data["failed_logins"]
    )

    data["risk_auth_interaction"] = (
        data["ip_reputation_score"] *
        data["failed_logins"]
    )

    data["session_login_interaction"] = (
        data["session_duration"] *
        data["login_attempts"]
    )

    # ML prediction
    prediction = model.predict(data)[0]

    # High-risk security safeguard
    high_risk = (
        login_attempts >= 10
        and failed_logins >= 5
        and ip_reputation_score >= 0.8
        and unusual_time_access == 1
    )

    if prediction == 1 or high_risk:
        return "Attack"

    return "Normal"