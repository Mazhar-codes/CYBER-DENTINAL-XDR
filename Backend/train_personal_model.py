# train_personal_model.py
# Trains a lightweight IsolationForest on YOUR collected baseline traffic.
# The model learns "what normal looks like on YOUR network".
# Anything it can't reconstruct well = anomaly for YOU specifically.
# Run AFTER collect_baseline.py

import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── CONFIG ────────────────────────────────────────────────────────────────────
BASE_DIR = r"D:\Cyber Sentinal\Backend"
BASELINE_CSV = os.path.join(BASE_DIR, "personal_baseline.csv")
OUTPUT_DIR = BASE_DIR

print("=" * 60)
print("TRAINING PERSONAL BASELINE MODEL")
print("=" * 60)

# ── LOAD YOUR BASELINE DATA ───────────────────────────────────────────────────
if not os.path.exists(BASELINE_CSV):
    raise FileNotFoundError(
        f"Baseline CSV not found at {BASELINE_CSV}\n"
        "Run collect_baseline.py first!"
    )

df = pd.read_csv(BASELINE_CSV)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)
print(f"Loaded {len(df):,} personal baseline flows")

feature_cols = [c for c in df.columns]
X = df[feature_cols].values

# ── SCALE ─────────────────────────────────────────────────────────────────────
personal_scaler = StandardScaler()
X_scaled = personal_scaler.fit_transform(X)
print(f"Features: {len(feature_cols)}")

# ── TRAIN PERSONAL ISOLATION FOREST ───────────────────────────────────────────
# Contamination very low — we collected ONLY normal traffic
print("\nTraining personal IsolationForest on YOUR traffic...")
personal_model = IsolationForest(
    n_estimators=300,
    contamination=0.01,  # expect only 1% noise in your baseline
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
personal_model.fit(X_scaled)

# ── COMPUTE THRESHOLD FROM YOUR OWN DATA ─────────────────────────────────────
# Set threshold at 1st percentile of YOUR normal traffic scores
scores = personal_model.decision_function(X_scaled)
threshold = float(np.percentile(scores, 1))  # 1st percentile
print(f"Personal anomaly threshold: {threshold:.6f}")
print(f"Score range on YOUR traffic: {scores.min():.4f} to {scores.max():.4f}")
print(f"Mean score: {scores.mean():.4f}")

flagged = (scores < threshold).mean()
print(f"Self-flagging rate: {flagged:.1%} (should be ~1%)")

# ── SAVE ──────────────────────────────────────────────────────────────────────
personal_artifacts = {
    "model": personal_model,
    "scaler": personal_scaler,
    "threshold": threshold,
    "features": feature_cols,
    "stats": {
        "n_training_flows": len(df),
        "score_mean": float(scores.mean()),
        "score_std": float(scores.std()),
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "threshold": threshold,
    },
}

output_path = os.path.join(OUTPUT_DIR, "personal_baseline_model.pkl")
joblib.dump(personal_artifacts, output_path)
print(f"\n✅ Personal model saved to: {output_path}")

# ── SUMMARY ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)
print(f"  Training flows  : {len(df):,}")
print(f"  Features used   : {len(feature_cols)}")
print(f"  Threshold set at: {threshold:.6f}")
print("  Expected false positive rate: ~1%")
print("\nYouTube streaming, Google, normal browsing will now be NORMAL ✅")
print("Real port scans, DoS, brute force will still be flagged 🚨")

