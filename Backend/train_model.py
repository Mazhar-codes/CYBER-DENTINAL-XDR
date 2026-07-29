# train_model.py
import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── CONFIG ──────────────────────────────────────────────
DATASET_DIR = r"D:\Cyber Sentinal\CICDS_dataset"
OUTPUT_DIR  = r"D:\Cyber Sentinal\Network model"

# CIC-IDS2017 columns to use
SELECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# ── LOAD DATA ────────────────────────────────────────────
print("Loading CIC-IDS2017 CSVs from", DATASET_DIR)
dfs = []
for fname in os.listdir(DATASET_DIR):
    if fname.endswith(".csv"):
        path = os.path.join(DATASET_DIR, fname)
        print(f"  Reading {fname}...")
        df = pd.read_csv(path, encoding="utf-8", low_memory=False)
        df.columns = df.columns.str.strip()  # remove whitespace from headers
        dfs.append(df)

if not dfs:
    raise RuntimeError("No CSV files found in DATASET_DIR")

df_all = pd.concat(dfs, ignore_index=True)
print(f"Total rows loaded: {len(df_all):,}")

# CIC-IDS2017 label column is usually "Label" or " Label"
label_col = "Label" if "Label" in df_all.columns else " Label"
df_all.rename(columns={label_col: "Label"}, inplace=True)
print(f"Label distribution:\n{df_all['Label'].value_counts().head()}")

# ── KEEP FEATURES ────────────────────────────────────────
missing = [c for c in SELECTED_FEATURES if c not in df_all.columns]
if missing:
    print("Warning – missing columns:", missing)
    SELECTED_FEATURES = [c for c in SELECTED_FEATURES if c in df_all.columns]

df_all = df_all[SELECTED_FEATURES + ["Label"]].copy()

# ── NUMERIC CLEANUP (do NOT drop all NaNs) ─────────────────
# Keep label as string, clean only feature columns
labels = df_all["Label"].astype(str).str.strip()

features = df_all[SELECTED_FEATURES].apply(pd.to_numeric, errors="coerce")
features.replace([np.inf, -np.inf], np.nan, inplace=True)
features.fillna(0, inplace=True)

df_all = features.copy()
df_all["Label"] = labels.values
print(f"Dataset shape after cleaning: {df_all.shape}")

# ── NORMAL vs ATTACK ─────────────────────────────────────
# CIC-IDS2017 uses "BENIGN" vs attack names
df_normal = df_all[df_all["Label"] == "BENIGN"]
df_attack = df_all[df_all["Label"] != "BENIGN"]

print(f"Normal flows : {len(df_normal):,}")
print(f"Attack flows : {len(df_attack):,}")

df_normal_sample = df_normal.sample(min(100_000, len(df_normal)), random_state=42)
df_attack_sample = df_attack.sample(min(20_000,  len(df_attack)),  random_state=42)

X_normal = df_normal_sample[SELECTED_FEATURES]
X_attack = df_attack_sample[SELECTED_FEATURES]

# ── SCALE ────────────────────────────────────────────────
print("Fitting scaler on normal traffic...")
scaler = StandardScaler()
X_normal_scaled = scaler.fit_transform(X_normal)
X_attack_scaled = scaler.transform(X_attack)

# ── TRAIN ────────────────────────────────────────────────
print("Training IsolationForest...")
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
    verbose=1,
)
model.fit(X_normal_scaled)

# ── QUICK EVAL ───────────────────────────────────────────
y_normal_pred = model.predict(X_normal_scaled)
y_attack_pred = model.predict(X_attack_scaled)

normal_accuracy = (y_normal_pred == 1).mean()
attack_detection = (y_attack_pred == -1).mean()
print(f"Normal traffic correctly classified : {normal_accuracy:.1%}")
print(f"Attacks correctly detected          : {attack_detection:.1%}")

# ── SAVE ─────────────────────────────────────────────────
joblib.dump(model,  os.path.join(OUTPUT_DIR, "network_model_isolation.pkl"))
joblib.dump(scaler, os.path.join(OUTPUT_DIR, "network_scaler.pkl"))
joblib.dump(SELECTED_FEATURES, os.path.join(OUTPUT_DIR, "network_features.pkl"))

print("\n✅ Saved:")
print("  network_model_isolation.pkl")
print("  network_scaler.pkl")
print("  network_features.pkl")