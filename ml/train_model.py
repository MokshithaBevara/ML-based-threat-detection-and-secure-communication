import os
import json
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import (
    OneHotEncoder,
    StandardScaler,
    PolynomialFeatures
)
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)


# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(
    BASE_DIR, "data", "cybersecurity_intrusion_data.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR, "ml", "cipherbridge_ml_model.pkl"
)

EVALUATION_PATH = os.path.join(
    BASE_DIR, "ml", "evaluation.json"
)

CONFUSION_PATH = os.path.join(
    BASE_DIR, "ml", "confusion_matrix.png"
)


# 1. Load dataset
df = pd.read_csv(DATA_PATH)

# Existing engineered features
df["login_failure_ratio"] = (
    df["failed_logins"] / (df["login_attempts"] + 1)
)

df["auth_pressure"] = (
    df["login_attempts"] + df["failed_logins"]
)

# Interaction features
df["login_failure_interaction"] = (
    df["login_attempts"] * df["failed_logins"]
)

df["risk_auth_interaction"] = (
    df["ip_reputation_score"] * df["failed_logins"]
)

df["session_login_interaction"] = (
    df["session_duration"] * df["login_attempts"]
)

print("Dataset loaded successfully!")
print("Dataset shape:", df.shape)


# 2. Prepare data
df = df.drop(columns=["session_id"])

X = df.drop(columns=["attack_detected"])
y = df["attack_detected"]


# 3. Features
numerical_features = [
    "network_packet_size",
    "login_attempts",
    "session_duration",
    "ip_reputation_score",
    "failed_logins",
    "unusual_time_access",

    # Engineered features
    "login_failure_ratio",
    "auth_pressure",
    "login_failure_interaction",
    "risk_auth_interaction",
    "session_login_interaction"
]

categorical_features = [
    "protocol_type",
    "encryption_used",
    "browser_type"
]


# 4. Numerical preprocessing
numerical_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("polynomial", PolynomialFeatures(
        degree=2,
        include_bias=False
    )),
    ("scaler", StandardScaler())
])


# 5. Categorical preprocessing
categorical_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("encoder", OneHotEncoder(handle_unknown="ignore"))
])


# 6. Combine preprocessing
preprocessor = ColumnTransformer([
    ("num", numerical_pipeline, numerical_features),
    ("cat", categorical_pipeline, categorical_features)
])


# 7. Logistic Regression
model = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", LogisticRegression(
        max_iter=2000,
        C=100
    ))
])


# 8. Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# 9. Train
print("\nTraining Logistic Regression...")
model.fit(X_train, y_train)
print("Training completed!")


# 10. Save model
joblib.dump(model, MODEL_PATH)
print("ML model saved successfully!")


# 11. Evaluate
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)


print("\n========== ML EVALUATION ==========")
print(f"Accuracy : {accuracy * 100:.2f}%")
print(f"Precision: {precision * 100:.2f}%")
print(f"Recall   : {recall * 100:.2f}%")
print(f"F1-score : {f1 * 100:.2f}%")

print("\nConfusion Matrix:")
print(cm)


# 12. Save evaluation results
evaluation = {
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1,
    "confusion_matrix": cm.tolist()
}

with open(EVALUATION_PATH, "w") as file:
    json.dump(evaluation, file, indent=4)

print("\nEvaluation results saved!")


# 13. Save confusion matrix image
plt.figure(figsize=(6, 5))

plt.imshow(cm, interpolation="nearest")

plt.title("CipherBridge - ML Confusion Matrix")
plt.colorbar()

plt.xticks(
    [0, 1],
    ["Normal", "Attack"]
)

plt.yticks(
    [0, 1],
    ["Normal", "Attack"]
)

plt.xlabel("Predicted")
plt.ylabel("Actual")

for i in range(2):
    for j in range(2):
        plt.text(
            j,
            i,
            cm[i, j],
            ha="center",
            va="center"
        )

plt.tight_layout()

plt.savefig(
    CONFUSION_PATH,
    dpi=300
)

plt.close()

print("Confusion matrix saved!")
print("===================================")