# train_classifier.py
# Trains a multi-class RandomForest classifier on CIC-IDS2017
# Output: network_classifier.pkl, network_label_encoder.pkl

import os
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

warnings.filterwarnings("ignore")

# ── CONFIG ──────────────────────────────────────────────────────────────────
DATASET_DIR = r"D:\Cyber Sentinal\Network Behavior\CICDS_dataset"
OUTPUT_DIR = r"D:\Cyber Sentinal\Backend"

# Reuse the SAME features as the IsolationForest pipeline
FEATURE_LIST_PATH = os.path.join(OUTPUT_DIR, "network_features.pkl")
if not os.path.exists(FEATURE_LIST_PATH):
    raise FileNotFoundError(
        f"Expected feature list at {FEATURE_LIST_PATH}. "
        "Run train_model.py first to create network_features.pkl."
    )

SELECTED_FEATURES = joblib.load(FEATURE_LIST_PATH)

# Attack type grouping — maps raw CIC labels → clean category names
ATTACK_GROUP_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "Heartbleed",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack \x96 XSS": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Infiltration": "Infiltration",
    "Bot": "Botnet",
}


def main() -> None:
    # ── STEP 1: Load CIC-IDS2017 ───────────────────────────────────────────
    print("=" * 60)
    print("STEP 1: Loading CIC-IDS2017 dataset...")
    print("=" * 60)

    dfs = []
    for fname in sorted(os.listdir(DATASET_DIR)):
        if not fname.endswith(".csv"):
            continue
        path = os.path.join(DATASET_DIR, fname)
        print(f"  Reading {fname}...")
        try:
            df = pd.read_csv(path, encoding="utf-8", low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
        except Exception as e:  # noqa: BLE001
            print(f"  ⚠️  Skipped {fname}: {e}")

    if not dfs:
        raise RuntimeError("No CSV files loaded from DATASET_DIR")

    df_all = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal rows loaded: {len(df_all):,}")

    # ── STEP 2: Standardise label column ──────────────────────────────────
    for col in df_all.columns:
        if "label" in col.lower():
            df_all.rename(columns={col: "Label"}, inplace=True)
            break

    df_all["Label"] = df_all["Label"].astype(str).str.strip()
    print("\nRaw label distribution:")
    print(df_all["Label"].value_counts().to_string())

    # ── STEP 3: Map to grouped attack types ───────────────────────────────
    df_all["AttackType"] = df_all["Label"].map(ATTACK_GROUP_MAP)
    unmapped = df_all["AttackType"].isna().sum()
    if unmapped > 0:
        print(f"\n⚠️  {unmapped} rows with unmapped labels:")
        print(df_all[df_all["AttackType"].isna()]["Label"].value_counts())
        df_all["AttackType"].fillna("Unknown", inplace=True)

    print("\nGrouped attack type distribution:")
    print(df_all["AttackType"].value_counts().to_string())

    # ── STEP 4: Select and clean features ─────────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 2: Cleaning features...")
    print("=" * 60)

    available = [c for c in SELECTED_FEATURES if c in df_all.columns]
    missing = [c for c in SELECTED_FEATURES if c not in df_all.columns]
    if missing:
        print(f"⚠️  Missing columns (will be zeroed later): {missing}")

    df_model = df_all[available + ["AttackType"]].copy()
    df_model = df_model.apply(
        lambda c: pd.to_numeric(c, errors="coerce") if c.name != "AttackType" else c
    )
    df_model.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_model.dropna(inplace=True)

    # Add any missing feature columns as zeros
    for col in SELECTED_FEATURES:
        if col not in df_model.columns:
            df_model[col] = 0.0

    df_model = df_model[SELECTED_FEATURES + ["AttackType"]]
    print(f"Rows after cleaning: {len(df_model):,}")

    # ── STEP 5: Balance classes ───────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 3: Balancing classes...")
    print("=" * 60)

    BENIGN_CAP = 100_000
    ATTACK_CAP = 15_000

    balanced_dfs = []
    for label, group in df_model.groupby("AttackType"):
        cap = BENIGN_CAP if label == "BENIGN" else ATTACK_CAP
        sampled = group.sample(min(len(group), cap), random_state=42)
        balanced_dfs.append(sampled)
        print(f"  {label:<20} {len(sampled):>8,} rows")

    df_balanced = pd.concat(balanced_dfs, ignore_index=True).sample(
        frac=1, random_state=42
    )
    print(f"\nTotal training rows: {len(df_balanced):,}")

    # ── STEP 6: Encode labels ─────────────────────────────────────────────
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df_balanced["AttackType"])
    X = df_balanced[SELECTED_FEATURES]
    print(f"\nClasses: {list(label_encoder.classes_)}")

    # ── STEP 7: Scale using EXISTING scaler from IsolationForest ──────────
    print("\n" + "=" * 60)
    print("STEP 4: Scaling features with existing network_scaler.pkl...")
    print("=" * 60)

    scaler_path = os.path.join(OUTPUT_DIR, "network_scaler.pkl")
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(
            f"Expected scaler at {scaler_path}. Run train_model.py first."
        )

    scaler = joblib.load(scaler_path)
    X_scaled = scaler.transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── STEP 8: Train RandomForest classifier ─────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 5: Training RandomForest classifier...")
    print("=" * 60)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=10,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        verbose=1,
    )
    clf.fit(X_train, y_train)

    # ── STEP 9: Evaluate ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 6: Evaluation")
    print("=" * 60)

    y_pred = clf.predict(X_test)
    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0,
        )
    )

    overall_acc = (y_pred == y_test).mean()
    print(f"Overall Accuracy: {overall_acc:.1%}")

    # ── STEP 10: Save artifacts ───────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 7: Saving model artifacts...")
    print("=" * 60)

    joblib.dump(clf, os.path.join(OUTPUT_DIR, "network_classifier.pkl"))
    joblib.dump(label_encoder, os.path.join(OUTPUT_DIR, "network_label_encoder.pkl"))

    print("✅ Saved network_classifier.pkl")
    print("✅ Saved network_label_encoder.pkl")
    print("\n🎉 Training complete!")


if __name__ == "__main__":
    main()

