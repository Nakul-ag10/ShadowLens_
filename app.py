from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import joblib

# -----------------------------
# Load model & scaler
# -----------------------------
iforest = joblib.load(r"\tls_iforest.pkl")
scaler = joblib.load(r"ls_scaler.pkl")

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(
    title="TLS MITM Anomaly Detection API",
    description="Detects TLS MITM attacks using protocol-aware anomaly detection",
    version="1.0"
)

# Add CORS middleware to allow requests from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Input schema
# -----------------------------
class TLSInput(BaseModel):
    handshake_time_ms: float
    ja4_client_stability: float
    ja4_server_stability: float
    cert_reuse_score: float
    ca_rarity_score: float

# -----------------------------
# Feature engineering
# -----------------------------
def engineer_features(x: TLSInput):
    log_handshake_time = np.log1p(x.handshake_time_ms)

    client_instability = 1.0 - x.ja4_client_stability
    server_instability = 1.0 - x.ja4_server_stability

    cert_risk = (
        0.6 * x.cert_reuse_score +
        0.4 * x.ca_rarity_score
    )

    tls_trust_score = (
        x.ja4_client_stability *
        x.ja4_server_stability *
        (1.0 - cert_risk)
    )

    latency_trust_ratio = (
        log_handshake_time / (tls_trust_score + 1e-6)
    )

    return np.array([[
        log_handshake_time,
        client_instability,
        server_instability,
        x.cert_reuse_score,
        x.ca_rarity_score,
        cert_risk,
        tls_trust_score,
        latency_trust_ratio
    ]])

# -----------------------------
# Prediction endpoint
# -----------------------------
@app.post("/predict")
def predict(input_data: TLSInput):
    features = engineer_features(input_data)
    features_scaled = scaler.transform(features)

    anomaly_score = -iforest.decision_function(features_scaled)[0]

    # Threshold (same logic as training)
    threshold = np.percentile(scores[y == 0], 95)

    prediction = "MITM_ATTACK" if anomaly_score > threshold else "NORMAL"

    return {
        "prediction": prediction,
        "anomaly_score": round(float(anomaly_score), 4),
        "threshold": threshold,
        "explanation": {
            "high_latency": input_data.handshake_time_ms > 30,
            "low_tls_stability": (
                input_data.ja4_client_stability < 0.5 or
                input_data.ja4_server_stabilitnvy < 0.5
            ),
            "certificate_risk": (
                input_data.cert_reuse_score > 0.7 or
                input_data.ca_rarity_score > 0.7
            )
        }
    }

# -----------------------------
# Health check
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}
