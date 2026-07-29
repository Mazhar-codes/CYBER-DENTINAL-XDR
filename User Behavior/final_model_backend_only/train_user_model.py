"""
train_user_model.py
====================
Retrains the User Behavior anomaly detection model using the CERT r4.2 dataset.

What this script does
---------------------
1. Loads logon.csv, device.csv, file.csv, email.csv, psychometric.csv from
   Dataset/r4.2/r4.2/.
2. Aggregates per-user per-day feature vectors (14 behavioral features).
3. Labels each (user, day) pair as ANOMALY (1) or NORMAL (0) using answers.csv.
4. Trains an IsolationForest on NORMAL data with contamination=0.05, then
   calibrates the decision boundary threshold so that bulk-file sessions
   (file_ops_count > 500 in a day) score as ANOMALY.
5. Saves the new artifacts next to this script:
       user_model.pkl
       user_scaler.pkl
       feature_columns.json
       model_threshold.json

Run:
    python train_user_model.py

Requirements: pandas, numpy, scikit-learn, joblib
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).parent
DATASET_DIR = HERE / "Dataset" / "r4.2" / "r4.2"
ANSWERS_PATH = HERE / "answers.csv"
MODEL_OUT = HERE / "user_model.pkl"
SCALER_OUT = HERE / "user_scaler.pkl"
FEATURES_OUT = HERE / "feature_columns.json"
THRESHOLD_OUT = HERE / "model_threshold.json"

# ---------------------------------------------------------------------------
# Feature list — must stay in sync with xdr_runtime.py
# ---------------------------------------------------------------------------
FEATURE_COLUMNS = [
    "file_ops_count",
    "file_write_count",
    "file_read_count",
    "unique_files_accessed",
    "file_ops_rate",
    "logon_count",
    "logoff_count",
    "failed_logon_count",
    "after_hours_activity",
    "device_connects",
    "device_disconnects",
    "device_events",
    "emails_sent",
    "unique_recipients",
    "O", "C", "E", "A", "N",
]

# Bulk-file fast-path threshold (kept in sync with xdr_runtime.py)
BULK_FILE_THRESHOLD = 300


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_date_col(series: pd.Series) -> pd.Series:
    """Parse heterogeneous date strings; return a date (not datetime) Series."""
    parsed = pd.to_datetime(series, errors="coerce")
    return parsed.dt.date


def hour_of_day(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, errors="coerce")
    return parsed.dt.hour


# ---------------------------------------------------------------------------
# Load raw tables
# ---------------------------------------------------------------------------

def load_tables() -> dict:
    """Load CSV tables. Large files are aggregated in chunks to avoid OOM."""
    print("Loading CERT r4.2 CSV files …")
    tables = {}

    # These three fit in memory (~500 MB each max)
    for name in ("logon", "device", "file"):
        path = DATASET_DIR / f"{name}.csv"
        if not path.exists():
            print(f"  WARNING: {path} not found — skipping.")
            tables[name] = pd.DataFrame()
        else:
            tables[name] = pd.read_csv(path, low_memory=False)
            print(f"  {name}.csv  {len(tables[name]):>9,} rows")

    # email.csv is ~2.6 M rows — aggregate per user×day in chunks to stay within RAM
    email_path = DATASET_DIR / "email.csv"
    if not email_path.exists():
        print("  WARNING: email.csv not found — skipping.")
        tables["email"] = pd.DataFrame()
    else:
        print("  email.csv  — chunked aggregation …", end="", flush=True)
        chunk_frames = []
        chunk_size = 200_000
        for chunk in pd.read_csv(email_path, low_memory=False, chunksize=chunk_size):
            chunk["_date"] = parse_date_col(chunk["date"])
            chunk["_hour"] = hour_of_day(chunk["date"])
            chunk["_after_hours"] = ((chunk["_hour"] < 9) | (chunk["_hour"] >= 18)).astype(int)

            # Count unique recipients from 'to' column (semicolon-separated)
            def _count_recip(val):
                if pd.isna(val):
                    return 0
                return len([a for a in str(val).split(";") if a.strip()])

            chunk["_n_recip"] = chunk["to"].apply(_count_recip) if "to" in chunk.columns else 0

            agg = chunk.groupby(["user", "_date"]).agg(
                emails_sent=("id", "count"),
                after_hours_email=("_after_hours", "sum"),
                unique_recipients=("_n_recip", "sum"),
            ).reset_index().rename(columns={"_date": "date"})
            chunk_frames.append(agg)
            print(".", end="", flush=True)

        # Merge all chunk-level aggregates
        email_agg = pd.concat(chunk_frames, ignore_index=True)
        email_agg = email_agg.groupby(["user", "date"]).agg(
            emails_sent=("emails_sent", "sum"),
            after_hours_email=("after_hours_email", "sum"),
            unique_recipients=("unique_recipients", "sum"),
        ).reset_index()
        print(f" {len(email_agg):,} user×day rows")
        tables["email"] = email_agg

    psych_path = DATASET_DIR / "psychometric.csv"
    if psych_path.exists():
        tables["psychometric"] = pd.read_csv(psych_path)
        print(f"  psychometric.csv  {len(tables['psychometric']):>6,} rows")
    else:
        tables["psychometric"] = pd.DataFrame()
        print("  WARNING: psychometric.csv not found.")

    return tables


# ---------------------------------------------------------------------------
# Feature engineering: per-user per-day aggregation
# ---------------------------------------------------------------------------

def build_features(tables: dict) -> pd.DataFrame:
    print("\nEngineering features …")

    # --- logon -----------------------------------------------------------
    logon = tables["logon"].copy()
    if not logon.empty:
        logon["_date"] = parse_date_col(logon["date"])
        logon["_hour"] = hour_of_day(logon["date"])
        logon["_after_hours"] = ((logon["_hour"] < 9) | (logon["_hour"] >= 18)).astype(int)
        logon["_is_logon"] = (logon["activity"].str.lower() == "logon").astype(int)
        logon["_is_logoff"] = (logon["activity"].str.lower() == "logoff").astype(int)
        # failed logons: represented by "Failed" activity or Logon after another Logon
        # CERT r4.2 uses "Logon"/"Logoff" only; we approximate failed logons as 0
        logon_grp = logon.groupby(["user", "_date"]).agg(
            logon_count=("_is_logon", "sum"),
            logoff_count=("_is_logoff", "sum"),
            failed_logon_count=("_is_logon", lambda x: 0),  # no explicit failed in r4.2
            after_hours_activity=("_after_hours", "sum"),
        ).reset_index().rename(columns={"_date": "date"})
    else:
        logon_grp = pd.DataFrame(columns=["user", "date", "logon_count",
                                           "logoff_count", "failed_logon_count",
                                           "after_hours_activity"])

    # --- device ----------------------------------------------------------
    device = tables["device"].copy()
    if not device.empty:
        device["_date"] = parse_date_col(device["date"])
        device["_connect"] = (device["activity"].str.lower() == "connect").astype(int)
        device["_disconnect"] = (device["activity"].str.lower() == "disconnect").astype(int)
        device_grp = device.groupby(["user", "_date"]).agg(
            device_connects=("_connect", "sum"),
            device_disconnects=("_disconnect", "sum"),
        ).reset_index().rename(columns={"_date": "date"})
        device_grp["device_events"] = device_grp["device_connects"] + device_grp["device_disconnects"]
    else:
        device_grp = pd.DataFrame(columns=["user", "date", "device_connects",
                                            "device_disconnects", "device_events"])

    # --- file ------------------------------------------------------------
    # file.csv in r4.2 = file copies to removable media (each row = one copy event)
    file_df = tables["file"].copy()
    if not file_df.empty:
        file_df["_date"] = parse_date_col(file_df["date"])
        file_df["_hour"] = hour_of_day(file_df["date"])
        file_df["_after_hours"] = ((file_df["_hour"] < 9) | (file_df["_hour"] >= 18)).astype(int)

        # For duration calculation we approximate using first/last event in the day
        file_time = pd.to_datetime(file_df["date"], errors="coerce")
        file_df["_ts"] = file_time

        file_grp = file_df.groupby(["user", "_date"]).agg(
            file_ops_count=("filename", "count"),
            unique_files_accessed=("filename", "nunique"),
            _ts_min=("_ts", "min"),
            _ts_max=("_ts", "max"),
            after_hours_file=("_after_hours", "sum"),
        ).reset_index().rename(columns={"_date": "date"})

        # ops-per-second: spread over the active window (min 1 second)
        file_grp["_window_sec"] = (
            (file_grp["_ts_max"] - file_grp["_ts_min"])
            .dt.total_seconds()
            .clip(lower=1)
        )
        file_grp["file_ops_rate"] = (
            file_grp["file_ops_count"] / file_grp["_window_sec"]
        ).round(6)

        # r4.2 file events are all "copy to removable media" — treat as reads/writes
        # We split 50/50 as a heuristic since the CSV has no read/write distinction
        file_grp["file_write_count"] = (file_grp["file_ops_count"] * 0.5).round(0).astype(int)
        file_grp["file_read_count"] = file_grp["file_ops_count"] - file_grp["file_write_count"]

        file_grp = file_grp.drop(columns=["_ts_min", "_ts_max", "_window_sec"])
    else:
        file_grp = pd.DataFrame(columns=["user", "date", "file_ops_count",
                                          "file_write_count", "file_read_count",
                                          "unique_files_accessed", "file_ops_rate",
                                          "after_hours_file"])

    # --- email -----------------------------------------------------------
    # email table is already aggregated per user×day by load_tables() chunked loader
    email = tables["email"].copy()
    if not email.empty and "emails_sent" in email.columns:
        # Already aggregated — just ensure date type consistency
        email["date"] = pd.to_datetime(email["date"], errors="coerce").dt.date
        email_grp = email[["user", "date", "emails_sent",
                            "after_hours_email", "unique_recipients"]].copy()
        email_grp["unique_recipients"] = email_grp["unique_recipients"].fillna(0).astype(int)
    elif not email.empty:
        # Fallback: raw email rows (only happens if load_tables is bypassed)
        email["_date"] = parse_date_col(email["date"])
        email["_hour"] = hour_of_day(email["date"])
        email["_after_hours"] = ((email["_hour"] < 9) | (email["_hour"] >= 18)).astype(int)
        email_grp = email.groupby(["user", "_date"]).agg(
            emails_sent=("id", "count"),
            after_hours_email=("_after_hours", "sum"),
            unique_recipients=("id", "count"),   # approximate
        ).reset_index().rename(columns={"_date": "date"})
    else:
        email_grp = pd.DataFrame(columns=["user", "date", "emails_sent",
                                           "unique_recipients", "after_hours_email"])

    # --- psychometric ----------------------------------------------------
    psych = tables["psychometric"].copy()
    if not psych.empty:
        # Normalize scores to 0-1 range (original scale: 0-100 integers)
        for col in ("O", "C", "E", "A", "N"):
            if col in psych.columns:
                psych[col] = psych[col].astype(float) / 100.0
        psych_map = psych.set_index("user_id")[["O", "C", "E", "A", "N"]].to_dict(orient="index")
    else:
        psych_map = {}

    # --- Merge all groups into one user×day frame -----------------------
    # Start from logon since every active day should have a logon event
    print("  Merging feature tables …")
    merged = logon_grp.copy() if not logon_grp.empty else pd.DataFrame(columns=["user", "date"])

    for grp, on_cols in [
        (device_grp, ["user", "date"]),
        (file_grp,   ["user", "date"]),
        (email_grp,  ["user", "date"]),
    ]:
        if not grp.empty:
            merged = merged.merge(grp, on=on_cols, how="outer")

    if merged.empty:
        raise RuntimeError("Feature merge produced an empty frame — check CSV files.")

    merged["user"] = merged["user"].fillna("UNKNOWN")
    merged["date"] = merged["date"].fillna(pd.Timestamp("1970-01-01").date())

    # after_hours_activity: combine logon + file + email after-hours counts
    for col in ("after_hours_file", "after_hours_email"):
        if col in merged.columns:
            merged["after_hours_activity"] = merged.get("after_hours_activity", 0) + merged[col].fillna(0)
            merged.drop(columns=[col], inplace=True)

    # Fill missings
    int_cols = ["logon_count", "logoff_count", "failed_logon_count", "after_hours_activity",
                "device_connects", "device_disconnects", "device_events",
                "file_ops_count", "file_write_count", "file_read_count",
                "unique_files_accessed", "emails_sent", "unique_recipients"]
    for col in int_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0).astype(int)

    if "file_ops_rate" not in merged.columns:
        merged["file_ops_rate"] = 0.0
    merged["file_ops_rate"] = merged["file_ops_rate"].fillna(0.0)

    if "unique_files_accessed" not in merged.columns:
        merged["unique_files_accessed"] = 0

    # Attach psychometric scores
    for score in ("O", "C", "E", "A", "N"):
        merged[score] = merged["user"].map(lambda u: psych_map.get(u, {}).get(score, 0.0))

    print(f"  Feature frame: {len(merged):,} user×day rows, {merged['user'].nunique():,} unique users")
    return merged


# ---------------------------------------------------------------------------
# Label generation
# ---------------------------------------------------------------------------

def attach_labels(features: pd.DataFrame) -> pd.DataFrame:
    """Mark (user, day) rows that appear in answers.csv as anomalous (1)."""
    if not ANSWERS_PATH.exists():
        print("  WARNING: answers.csv not found — all rows labeled NORMAL.")
        features["label"] = 0
        return features

    answers = pd.read_csv(ANSWERS_PATH)
    answers["_date"] = parse_date_col(answers["event_time"])
    malicious_pairs = set(zip(answers["user"], answers["_date"]))

    features["label"] = features.apply(
        lambda r: 1 if (r["user"], r["date"]) in malicious_pairs else 0,
        axis=1,
    )

    n_anomaly = (features["label"] == 1).sum()
    n_normal = (features["label"] == 0).sum()
    print(f"  Labels: {n_normal:,} NORMAL, {n_anomaly:,} ANOMALY")
    return features


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(features: pd.DataFrame) -> None:
    print("\nTraining IsolationForest …")

    # Ensure all required feature columns exist
    for col in FEATURE_COLUMNS:
        if col not in features.columns:
            features[col] = 0.0

    X = features[FEATURE_COLUMNS].fillna(0.0)
    y = features["label"].values  # 0=normal, 1=anomaly

    X_normal = X[y == 0]
    print(f"  Training on {len(X_normal):,} NORMAL samples ({len(X):,} total)")

    # Scale
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    X_all_scaled = scaler.transform(X)

    # IsolationForest — contamination reflects anomaly prevalence in the training window
    contamination = min(0.05, max(0.001, (y == 1).mean()))
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_normal_scaled)

    # Evaluate on all labeled data
    raw_scores = model.decision_function(X_all_scaled)   # higher = more normal
    # Convert: anomaly_score = sigmoid(-raw_score * 10) so that:
    #   very negative raw  → score near 1.0 (anomalous)
    #   very positive raw  → score near 0.0 (normal)
    anomaly_scores = 1.0 / (1.0 + np.exp(raw_scores * 10))

    if (y == 1).any():
        from sklearn.metrics import roc_auc_score, precision_recall_curve
        auc = roc_auc_score(y, anomaly_scores)
        print(f"  ROC-AUC on full dataset: {auc:.4f}")

    # ---------------------------------------------------------------------------
    # Threshold calibration
    # ---------------------------------------------------------------------------
    # Goal 1: bulk-file rows must score ABOVE the threshold.
    # Goal 2: minimize false positives on normal days.
    #
    # Strategy: find the score that corresponds to file_ops_count = BULK_FILE_THRESHOLD
    # as a sentinel sample, then pick a threshold just below that score.

    sentinel = pd.DataFrame([{col: 0.0 for col in FEATURE_COLUMNS}])
    sentinel["file_ops_count"] = BULK_FILE_THRESHOLD + 1
    sentinel["file_write_count"] = BULK_FILE_THRESHOLD // 2
    sentinel["file_read_count"] = BULK_FILE_THRESHOLD // 2
    sentinel["unique_files_accessed"] = BULK_FILE_THRESHOLD
    sentinel["file_ops_rate"] = 2.0   # 2 ops/sec sustained = burst

    sentinel_scaled = scaler.transform(sentinel[FEATURE_COLUMNS])
    sentinel_raw = model.decision_function(sentinel_scaled)[0]
    sentinel_score = float(1.0 / (1.0 + np.exp(sentinel_raw * 10)))

    # Find 95th percentile score of NORMAL days as an upper bound for FP control
    normal_scores = anomaly_scores[y == 0]
    p95_normal = float(np.percentile(normal_scores, 95))

    # Threshold = lower of (sentinel_score - small_margin) and (p95_normal + margin)
    threshold = min(sentinel_score - 0.02, p95_normal + 0.05)
    threshold = max(0.3, min(0.85, threshold))   # hard bounds

    # Verify bulk-file sentinel is caught
    assert sentinel_score > threshold, (
        f"Calibration failed: sentinel_score={sentinel_score:.4f} <= threshold={threshold:.4f}"
    )

    print(f"  Sentinel bulk-file score : {sentinel_score:.4f}")
    print(f"  95th-pct normal score    : {p95_normal:.4f}")
    print(f"  Calibrated threshold     : {threshold:.4f}")

    # Final classification metrics using calibrated threshold
    preds = (anomaly_scores >= threshold).astype(int)
    if (y == 1).any():
        from sklearn.metrics import classification_report
        print("\n  Classification report (calibrated threshold):")
        print(classification_report(y, preds, target_names=["NORMAL", "ANOMALY"]))

    # ---------------------------------------------------------------------------
    # Save artifacts
    # ---------------------------------------------------------------------------
    print("\nSaving artifacts …")
    joblib.dump(model, MODEL_OUT)
    print(f"  {MODEL_OUT}")

    joblib.dump(scaler, SCALER_OUT)
    print(f"  {SCALER_OUT}")

    with FEATURES_OUT.open("w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
    print(f"  {FEATURES_OUT}")

    with THRESHOLD_OUT.open("w", encoding="utf-8") as f:
        json.dump({"threshold": round(threshold, 6)}, f, indent=2)
    print(f"  {THRESHOLD_OUT}")

    print("\nDone.")


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def smoke_test() -> None:
    """Quick sanity check: load saved artifacts and score a synthetic bulk-file user."""
    print("\nRunning smoke test …")
    model = joblib.load(MODEL_OUT)
    scaler = joblib.load(SCALER_OUT)
    with FEATURES_OUT.open() as f:
        feat_cols = json.load(f)
    with THRESHOLD_OUT.open() as f:
        threshold = float(json.load(f)["threshold"])

    # Bulk-file user: 1000 file ops + 200 dir scans (approximated via high file_ops_count)
    bulk = {col: 0.0 for col in feat_cols}
    bulk["file_ops_count"] = 1000
    bulk["file_write_count"] = 500
    bulk["file_read_count"] = 500
    bulk["unique_files_accessed"] = 1000
    bulk["file_ops_rate"] = 5.0

    X = pd.DataFrame([bulk])[feat_cols]
    X_scaled = scaler.transform(X)
    raw = model.decision_function(X_scaled)[0]
    score = float(1.0 / (1.0 + np.exp(raw * 10)))
    label = "ANOMALY" if score >= threshold else "NORMAL"
    print(f"  Bulk-file user score: {score:.4f}  ->  {label}  (threshold={threshold:.4f})")
    if label != "ANOMALY":
        print("  WARNING: bulk-file user NOT flagged as ANOMALY — threshold may need manual adjustment.")
    else:
        print("  PASS: bulk-file user correctly flagged as ANOMALY.")

    # Normal user: moderate daily activity
    normal = {col: 0.0 for col in feat_cols}
    normal["file_ops_count"] = 5
    normal["logon_count"] = 1
    normal["logoff_count"] = 1
    normal["emails_sent"] = 10
    X2 = pd.DataFrame([normal])[feat_cols]
    X2_scaled = scaler.transform(X2)
    raw2 = model.decision_function(X2_scaled)[0]
    score2 = float(1.0 / (1.0 + np.exp(raw2 * 10)))
    label2 = "ANOMALY" if score2 >= threshold else "NORMAL"
    print(f"  Normal user score   : {score2:.4f}  ->  {label2}  (threshold={threshold:.4f})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tables = load_tables()
    features = build_features(tables)
    features = attach_labels(features)
    train(features)
    smoke_test()
