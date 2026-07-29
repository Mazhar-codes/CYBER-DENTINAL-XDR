import pandas as pd
import joblib
import logging
import os
import numpy as np

logging.basicConfig(level=logging.INFO)

# ==== PATHS ====
BASE_DIR = r"D:\Cyber Sentinal\Network model"
MODEL_PATH = os.path.join(BASE_DIR, "network_model_isolation.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "network_scaler.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "network_encoders.pkl")
SAMPLE_EVE_JSON = os.path.join(BASE_DIR, "sample_eve.json")


def load_eve_json(path: str) -> pd.DataFrame:
    """Load and parse a Suricata eve.json sample for offline model testing."""
    if not os.path.exists(path):
        raise FileNotFoundError("eve.json sample not found.")

    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "flow":
                continue

            flow = ev.get("flow", {})
            rows.append({
                "ts": ev.get("timestamp", ""),
                "source_ip": ev.get("src_ip", ""),
                "destination_ip": ev.get("dest_ip", ""),
                "source_port": ev.get("src_port", 0),
                "destination_port": ev.get("dest_port", 0),
                "network_transport": ev.get("proto", "").lower(),
                "bytes_sent": flow.get("bytes_toserver", 0),
                "bytes_received": flow.get("bytes_toclient", 0),
                "packets_sent": flow.get("pkts_toserver", 0),
                "packets_received": flow.get("pkts_toclient", 0),
                "connection_duration": flow.get("age", 0),
                "connection_count": 1,
                "unique_dst_ips": 1,
                "unique_dst_ports": 1,
                "failed_connection_ratio": 0.0,
                "inter_arrival_variance": 0.0,
                "periodicity_score": 0.0,
                "dns_nxdomain_ratio": 0.0,
                "domain_entropy": 0.0,
                "ja3_rarity_score": 0.5,
                "tls_version": "NONE",
                "cipher_rarity": 0.5,
            })

    df = pd.DataFrame(rows)
    logging.info(f"Loaded Suricata eve.json sample: {df.shape}")
    return df


def preprocess(df, scaler, encoders):
    """Mirror backend preprocessing for offline testing."""
    from backend import preprocess as backend_preprocess  # reuse logic

    X_scaled, meta = backend_preprocess(df)
    return X_scaled, meta[["source_ip", "destination_ip"]]


def main():
    logging.info("Starting Network Model Testing")

    # Load Suricata eve.json sample
    df = load_eve_json(SAMPLE_EVE_JSON)

    # Load model, scaler, encoders
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    encoders = joblib.load(ENCODER_PATH)

    # Preprocess the data
    X_scaled, meta = preprocess(df, scaler, encoders)

    # Run predictions
    scores = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)
    threshold = 0  # tune if needed

    # Print results
    for i in range(len(meta)):
        score = scores[i]
        pred = "🚨 ANOMALY" if score < threshold else "✅ NORMAL"

        print("\n====================================")
        print(f"Source IP      : {meta.iloc[i]['source_ip']}")
        print(f"Destination IP : {meta.iloc[i]['destination_ip']}")
        print(f"Anomaly Score  : {round(score, 5)*100:.2f}%")
        print(f"Prediction     : {pred}")
        print("====================================")


if __name__ == "__main__":
    main()
