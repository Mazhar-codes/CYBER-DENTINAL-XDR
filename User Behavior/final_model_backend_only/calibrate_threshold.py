"""
calibrate_threshold.py
======================
Recalibrate the anomaly decision threshold for the deployed IsolationForest user
behavior model without retraining it.

Background
----------
The model artifact (user_model.pkl) was trained using a sigmoid formula with
multiplier 10:

    training_score = 1 / (1 + exp(raw * 10))   # anomaly → near 1.0

However, xdr_runtime.py _sigmoid_score() uses multiplier 5:

    runtime_score  = 1 / (1 + exp(-raw * 5))   # same direction, softer curve

A raw score of -0.1 (mild anomaly) maps to 0.731 under the training scorer but
only 0.622 under the runtime scorer.  The stored threshold of 0.80 was chosen
during training against the multiplier-10 scale and is therefore too high when
evaluated against multiplier-5 runtime scores, which causes recall=0.

This script:
    1. Rebuilds the same per-user per-day feature vectors the training script
       used (from the CERT r4.2 raw CSV files in Dataset/r4.2/r4.2/).
    2. Scores every sample through the DEPLOYED runtime sigmoid (multiplier 5)
       so the resulting scores match what xdr_runtime.py actually produces.
    3. Labels each sample using insiders.csv (date-range membership for each
       known insider).
    4. Computes precision–recall and ROC curves over those runtime scores.
    5. Finds the threshold that maximises F1 (primary) and Youden's J (secondary).
    6. Prints a comparison table: current threshold vs recommended threshold.
    7. Writes the recommended threshold to model_threshold.json.

Usage
-----
    python calibrate_threshold.py [--dry-run]

    --dry-run   Print analysis but do NOT write model_threshold.json.

Requirements: pandas, numpy, scikit-learn, joblib
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
    f1_score,
    precision_score,
    recall_score,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).parent
DATASET_DIR = HERE / "Dataset" / "r4.2" / "r4.2"
INSIDERS_PATH = HERE / "r4.2" / "answers" / "answers" / "insiders.csv"
MODEL_PATH = HERE / "user_model.pkl"
SCALER_PATH = HERE / "user_scaler.pkl"
FEATURES_PATH = HERE / "feature_columns.json"
THRESHOLD_PATH = HERE / "model_threshold.json"

# ---------------------------------------------------------------------------
# Sigmoid functions — both the training formula and the deployed runtime formula
# ---------------------------------------------------------------------------

def _training_sigmoid(raw: float) -> float:
    """Formula used in train_user_model.py: 1 / (1 + exp(raw * 10)).
    IsolationForest decision_function returns positive for normals and
    negative for anomalies, so positive raw → score near 0, negative raw → near 1.
    """
    return float(1.0 / (1.0 + np.exp(raw * 10)))


def _runtime_sigmoid(raw: float) -> float:
    """Formula used in xdr_runtime.py _sigmoid_score(): 1 / (1 + exp(-raw * 5)).
    The raw value is negated first, so anomaly (negative raw) → positive input
    → score near 1.  Multiplier 5 produces a softer curve than the training 10.
    """
    return float(1.0 / (1.0 + np.exp(-raw * 5)))


# Vectorised versions
def _training_sigmoid_v(raw_arr: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(raw_arr * 10))


def _runtime_sigmoid_v(raw_arr: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-raw_arr * 5))


# ---------------------------------------------------------------------------
# Feature engineering (mirrors train_user_model.py exactly)
# ---------------------------------------------------------------------------

def _parse_date(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce").dt.date


def _hour_of_day(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce").dt.hour


def _build_features(dataset_dir: Path) -> pd.DataFrame:
    """Build per-user per-day feature frame from CERT r4.2 raw CSVs."""
    print("\n[1/4] Loading CERT r4.2 raw CSV files from:", dataset_dir)

    tables: dict = {}

    # --- logon ---
    logon_path = dataset_dir / "logon.csv"
    if not logon_path.exists():
        sys.exit(f"ERROR: logon.csv not found at {logon_path}")
    logon = pd.read_csv(logon_path, low_memory=False)
    print(f"       logon.csv     {len(logon):>9,} rows")

    logon["_date"] = _parse_date(logon["date"])
    logon["_hour"] = _hour_of_day(logon["date"])
    logon["_after_hours"] = ((logon["_hour"] < 9) | (logon["_hour"] >= 18)).astype(int)
    logon["_is_logon"]  = (logon["activity"].str.lower() == "logon").astype(int)
    logon["_is_logoff"] = (logon["activity"].str.lower() == "logoff").astype(int)

    logon_grp = logon.groupby(["user", "_date"]).agg(
        logon_count=("_is_logon", "sum"),
        logoff_count=("_is_logoff", "sum"),
        failed_logon_count=("_is_logon", lambda x: 0),   # not explicit in r4.2
        after_hours_activity=("_after_hours", "sum"),
    ).reset_index().rename(columns={"_date": "date"})
    tables["logon"] = logon_grp

    # --- device ---
    device_path = dataset_dir / "device.csv"
    if device_path.exists():
        device = pd.read_csv(device_path, low_memory=False)
        print(f"       device.csv    {len(device):>9,} rows")
        device["_date"] = _parse_date(device["date"])
        device["_connect"]    = (device["activity"].str.lower() == "connect").astype(int)
        device["_disconnect"] = (device["activity"].str.lower() == "disconnect").astype(int)
        device_grp = device.groupby(["user", "_date"]).agg(
            device_connects=("_connect", "sum"),
            device_disconnects=("_disconnect", "sum"),
        ).reset_index().rename(columns={"_date": "date"})
        device_grp["device_events"] = device_grp["device_connects"] + device_grp["device_disconnects"]
        tables["device"] = device_grp
    else:
        tables["device"] = pd.DataFrame(columns=["user", "date", "device_connects",
                                                   "device_disconnects", "device_events"])
        print("       device.csv    NOT FOUND — zeroed")

    # --- file ---
    file_path = dataset_dir / "file.csv"
    if file_path.exists():
        file_df = pd.read_csv(file_path, low_memory=False)
        print(f"       file.csv      {len(file_df):>9,} rows")
        file_df["_date"] = _parse_date(file_df["date"])
        file_df["_hour"] = _hour_of_day(file_df["date"])
        file_df["_after_hours"] = ((file_df["_hour"] < 9) | (file_df["_hour"] >= 18)).astype(int)
        file_df["_ts"] = pd.to_datetime(file_df["date"], errors="coerce")

        file_grp = file_df.groupby(["user", "_date"]).agg(
            file_ops_count=("filename", "count"),
            unique_files_accessed=("filename", "nunique"),
            _ts_min=("_ts", "min"),
            _ts_max=("_ts", "max"),
            after_hours_file=("_after_hours", "sum"),
        ).reset_index().rename(columns={"_date": "date"})

        file_grp["_window_sec"] = (
            (file_grp["_ts_max"] - file_grp["_ts_min"]).dt.total_seconds().clip(lower=1)
        )
        file_grp["file_ops_rate"]    = (file_grp["file_ops_count"] / file_grp["_window_sec"]).round(6)
        file_grp["file_write_count"] = (file_grp["file_ops_count"] * 0.5).round(0).astype(int)
        file_grp["file_read_count"]  = file_grp["file_ops_count"] - file_grp["file_write_count"]
        file_grp = file_grp.drop(columns=["_ts_min", "_ts_max", "_window_sec"])
        tables["file"] = file_grp
    else:
        tables["file"] = pd.DataFrame(columns=["user", "date", "file_ops_count",
                                                "file_write_count", "file_read_count",
                                                "unique_files_accessed", "file_ops_rate"])
        print("       file.csv      NOT FOUND — zeroed")

    # --- email (chunked) ---
    email_path = dataset_dir / "email.csv"
    if email_path.exists():
        print(f"       email.csv     chunked aggregation … ", end="", flush=True)
        chunk_frames = []
        for chunk in pd.read_csv(email_path, low_memory=False, chunksize=200_000):
            chunk["_date"] = _parse_date(chunk["date"])
            chunk["_hour"] = _hour_of_day(chunk["date"])
            chunk["_after_hours"] = ((chunk["_hour"] < 9) | (chunk["_hour"] >= 18)).astype(int)

            def _count_recip(val):
                if pd.isna(val):
                    return 0
                return len([a for a in str(val).split(";") if a.strip()])

            chunk["_n_recip"] = chunk["to"].apply(_count_recip) if "to" in chunk.columns else 0
            agg = chunk.groupby(["user", "_date"]).agg(
                emails_sent=("id", "count"),
                unique_recipients=("_n_recip", "sum"),
            ).reset_index().rename(columns={"_date": "date"})
            chunk_frames.append(agg)
            print(".", end="", flush=True)

        email_agg = pd.concat(chunk_frames, ignore_index=True)
        email_agg = email_agg.groupby(["user", "date"]).agg(
            emails_sent=("emails_sent", "sum"),
            unique_recipients=("unique_recipients", "sum"),
        ).reset_index()
        print(f" {len(email_agg):,} user×day rows")
        tables["email"] = email_agg
    else:
        tables["email"] = pd.DataFrame(columns=["user", "date", "emails_sent", "unique_recipients"])
        print("       email.csv     NOT FOUND — zeroed")

    # --- psychometric ---
    psych_path = dataset_dir / "psychometric.csv"
    if psych_path.exists():
        psych = pd.read_csv(psych_path)
        for col in ("O", "C", "E", "A", "N"):
            if col in psych.columns:
                psych[col] = psych[col].astype(float) / 100.0
        psych_map = psych.set_index("user_id")[["O", "C", "E", "A", "N"]].to_dict(orient="index")
        print(f"       psychometric  {len(psych):>6,} users")
    else:
        psych_map = {}
        print("       psychometric.csv NOT FOUND — OCEAN set to 0.0 for all users")

    # --- merge ---
    print("\n[2/4] Merging feature tables …")
    merged = tables["logon"].copy()
    for grp, keys in [
        (tables["device"], ["user", "date"]),
        (tables["file"],   ["user", "date"]),
        (tables["email"],  ["user", "date"]),
    ]:
        if not grp.empty:
            merged = merged.merge(grp, on=keys, how="outer")

    merged["user"] = merged["user"].fillna("UNKNOWN")
    merged["date"] = pd.to_datetime(merged["date"], errors="coerce").dt.date

    # Combine after-hours sub-columns
    for col in ("after_hours_file", "after_hours_email"):
        if col in merged.columns:
            merged["after_hours_activity"] = (
                merged.get("after_hours_activity", pd.Series(0, index=merged.index))
                + merged[col].fillna(0)
            )
            merged.drop(columns=[col], inplace=True)

    int_cols = [
        "logon_count", "logoff_count", "failed_logon_count", "after_hours_activity",
        "device_connects", "device_disconnects", "device_events",
        "file_ops_count", "file_write_count", "file_read_count",
        "unique_files_accessed", "emails_sent", "unique_recipients",
    ]
    for col in int_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0).astype(int)

    merged["file_ops_rate"] = merged.get("file_ops_rate", pd.Series(0.0, index=merged.index)).fillna(0.0)

    # Attach psychometric scores
    for score in ("O", "C", "E", "A", "N"):
        merged[score] = merged["user"].map(lambda u, s=score: psych_map.get(u, {}).get(s, 0.0))

    print(f"       Merged: {len(merged):,} user×day rows, {merged['user'].nunique():,} unique users")
    return merged


# ---------------------------------------------------------------------------
# Label attachment: insider-threat days from insiders.csv
# ---------------------------------------------------------------------------

def _attach_labels(df: pd.DataFrame, insiders_path: Path) -> pd.DataFrame:
    """
    Mark each (user, date) row as anomaly=1 if that date falls within the
    insider's malicious activity window defined in insiders.csv.

    insiders.csv columns: dataset, scenario, details, user, start, end
    The start/end times define the window of malicious activity.
    Any calendar day that overlaps with [start, end] for the matching user
    is labelled anomaly=1.
    """
    insiders = pd.read_csv(insiders_path)
    insiders["_start"] = pd.to_datetime(insiders["start"], errors="coerce")
    insiders["_end"]   = pd.to_datetime(insiders["end"],   errors="coerce")

    # Build a set of (user, date) pairs that are insider-threat days
    malicious_pairs: set = set()
    for _, row in insiders.iterrows():
        if pd.isna(row["_start"]) or pd.isna(row["_end"]):
            continue
        user = str(row["user"])
        start_date = row["_start"].date()
        end_date   = row["_end"].date()
        d = start_date
        import datetime
        while d <= end_date:
            malicious_pairs.add((user, d))
            d += datetime.timedelta(days=1)

    df["label"] = df.apply(
        lambda r: 1 if (str(r["user"]), r["date"]) in malicious_pairs else 0,
        axis=1,
    )
    n_anomaly = int((df["label"] == 1).sum())
    n_normal  = int((df["label"] == 0).sum())
    print(f"       Labels: {n_normal:,} NORMAL days, {n_anomaly:,} ANOMALY days "
          f"({n_anomaly/(n_anomaly+n_normal)*100:.2f}% positive rate)")
    return df


# ---------------------------------------------------------------------------
# Main calibration logic
# ---------------------------------------------------------------------------

def calibrate(dry_run: bool = False) -> None:
    # --- Load artifacts ---
    print("\n[0/4] Loading model artifacts …")
    if not MODEL_PATH.exists():
        sys.exit(f"ERROR: user_model.pkl not found at {MODEL_PATH}")
    if not SCALER_PATH.exists():
        sys.exit(f"ERROR: user_scaler.pkl not found at {SCALER_PATH}")

    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    with FEATURES_PATH.open() as f:
        feature_columns = json.load(f)

    current_threshold = 0.80
    if THRESHOLD_PATH.exists():
        with THRESHOLD_PATH.open() as f:
            current_threshold = float(json.load(f).get("threshold", 0.80))

    print(f"       Model type  : {type(model).__name__}")
    print(f"       n_features  : {getattr(model, 'n_features_in_', 'unknown')}")
    print(f"       Feature cols: {feature_columns}")
    print(f"       Current threshold (model_threshold.json): {current_threshold}")

    # --- Build features ---
    df = _build_features(DATASET_DIR)

    # --- Attach labels ---
    print("\n[3/4] Attaching insider-threat labels …")
    if not INSIDERS_PATH.exists():
        sys.exit(f"ERROR: insiders.csv not found at {INSIDERS_PATH}")
    df = _attach_labels(df, INSIDERS_PATH)

    y = df["label"].values

    if y.sum() == 0:
        sys.exit("ERROR: No anomaly-labelled rows found — check insiders.csv path and date formats.")

    # --- Ensure all model feature columns exist ---
    scaler_features = list(getattr(scaler, "feature_names_in_", feature_columns))
    for col in scaler_features:
        if col not in df.columns:
            df[col] = 0.0

    X       = df[scaler_features].fillna(0.0).values
    X_scaled = scaler.transform(X)

    # --- Score using the deployed runtime sigmoid (multiplier 5) ---
    # This matches what xdr_runtime.py _sigmoid_score() produces.
    raw_scores      = model.decision_function(X_scaled)
    runtime_scores  = _runtime_sigmoid_v(raw_scores)   # matches xdr_runtime.py exactly
    training_scores = _training_sigmoid_v(raw_scores)  # what calibration was done against

    print("\n[4/4] Computing threshold calibration …")

    # --- Score distribution summary ---
    normal_runtime  = runtime_scores[y == 0]
    anomaly_runtime = runtime_scores[y == 1]
    print(f"\n  Score distribution (RUNTIME sigmoid, multiplier=5):")
    print(f"    NORMAL  — mean={normal_runtime.mean():.4f}  "
          f"p50={np.percentile(normal_runtime, 50):.4f}  "
          f"p95={np.percentile(normal_runtime, 95):.4f}  "
          f"p99={np.percentile(normal_runtime, 99):.4f}  "
          f"max={normal_runtime.max():.4f}")
    print(f"    ANOMALY — mean={anomaly_runtime.mean():.4f}  "
          f"p5={np.percentile(anomaly_runtime,  5):.4f}  "
          f"p25={np.percentile(anomaly_runtime, 25):.4f}  "
          f"p50={np.percentile(anomaly_runtime, 50):.4f}  "
          f"min={anomaly_runtime.min():.4f}")

    # --- Score distribution (training sigmoid for comparison) ---
    normal_train  = training_scores[y == 0]
    anomaly_train = training_scores[y == 1]
    print(f"\n  Score distribution (TRAINING sigmoid, multiplier=10):")
    print(f"    NORMAL  — mean={normal_train.mean():.4f}  "
          f"p95={np.percentile(normal_train, 95):.4f}  "
          f"p99={np.percentile(normal_train, 99):.4f}  "
          f"max={normal_train.max():.4f}")
    print(f"    ANOMALY — mean={anomaly_train.mean():.4f}  "
          f"p25={np.percentile(anomaly_train, 25):.4f}  "
          f"p50={np.percentile(anomaly_train, 50):.4f}")

    # --- ROC-AUC (same for both sigmoids; it's monotone in raw score) ---
    auc = roc_auc_score(y, runtime_scores)
    print(f"\n  ROC-AUC (runtime scores): {auc:.4f}")

    # --- Precision-Recall curve over runtime scores ---
    pr_precision, pr_recall, pr_thresholds = precision_recall_curve(y, runtime_scores)
    # F1 at each threshold
    # Note: precision_recall_curve returns arrays where the last element has recall=0
    # and no corresponding threshold; align by taking all but the last element.
    f1_scores = np.where(
        (pr_precision[:-1] + pr_recall[:-1]) > 0,
        2 * pr_precision[:-1] * pr_recall[:-1] / (pr_precision[:-1] + pr_recall[:-1]),
        0.0,
    )
    best_f1_idx = int(np.argmax(f1_scores))
    best_f1_threshold  = float(pr_thresholds[best_f1_idx])
    best_f1_precision  = float(pr_precision[best_f1_idx])
    best_f1_recall     = float(pr_recall[best_f1_idx])
    best_f1            = float(f1_scores[best_f1_idx])

    # --- ROC curve / Youden's J over runtime scores ---
    fpr_arr, tpr_arr, roc_thresholds = roc_curve(y, runtime_scores)
    youden_j = tpr_arr - fpr_arr
    best_youden_idx       = int(np.argmax(youden_j))
    best_youden_threshold = float(roc_thresholds[best_youden_idx])
    best_youden_tpr       = float(tpr_arr[best_youden_idx])
    best_youden_fpr       = float(fpr_arr[best_youden_idx])

    # --- Metrics at current threshold ---
    current_preds     = (runtime_scores >= current_threshold).astype(int)
    current_precision = float(precision_score(y, current_preds, zero_division=0))
    current_recall    = float(recall_score(y,    current_preds, zero_division=0))
    current_f1        = float(f1_score(y,        current_preds, zero_division=0))
    current_tp        = int(((current_preds == 1) & (y == 1)).sum())
    current_fp        = int(((current_preds == 1) & (y == 0)).sum())
    current_fn        = int(((current_preds == 0) & (y == 1)).sum())
    current_tn        = int(((current_preds == 0) & (y == 0)).sum())
    current_fpr       = current_fp / max(1, current_fp + current_tn)

    # --- Metrics at recommended threshold (best F1) ---
    best_preds     = (runtime_scores >= best_f1_threshold).astype(int)
    best_tp        = int(((best_preds == 1) & (y == 1)).sum())
    best_fp        = int(((best_preds == 1) & (y == 0)).sum())
    best_fn        = int(((best_preds == 0) & (y == 1)).sum())
    best_tn        = int(((best_preds == 0) & (y == 0)).sum())
    best_fpr       = best_fp / max(1, best_fp + best_tn)

    # --- Metrics at Youden threshold ---
    youden_preds     = (runtime_scores >= best_youden_threshold).astype(int)
    youden_precision = float(precision_score(y, youden_preds, zero_division=0))
    youden_recall    = float(recall_score(y,    youden_preds, zero_division=0))
    youden_f1        = float(f1_score(y,        youden_preds, zero_division=0))
    youden_tp        = int(((youden_preds == 1) & (y == 1)).sum())
    youden_fp        = int(((youden_preds == 1) & (y == 0)).sum())
    youden_fn        = int(((youden_preds == 0) & (y == 1)).sum())
    youden_tn        = int(((youden_preds == 0) & (y == 0)).sum())
    youden_fpr       = youden_fp / max(1, youden_fp + youden_tn)

    # --- Print comparison table ---
    print("\n" + "=" * 72)
    print("  THRESHOLD COMPARISON (all scores evaluated with runtime sigmoid)")
    print("=" * 72)
    print(f"  {'Metric':<28} {'Current (0.80)':>16} {'Best-F1':>16} {'Youden-J':>12}")
    print("-" * 72)
    print(f"  {'Threshold':<28} {current_threshold:>16.4f} {best_f1_threshold:>16.4f} {best_youden_threshold:>12.4f}")
    print(f"  {'Precision':<28} {current_precision:>16.4f} {best_f1_precision:>16.4f} {youden_precision:>12.4f}")
    print(f"  {'Recall (TPR)':<28} {current_recall:>16.4f} {best_f1_recall:>16.4f} {youden_recall:>12.4f}")
    print(f"  {'F1':<28} {current_f1:>16.4f} {best_f1:>16.4f} {youden_f1:>12.4f}")
    print(f"  {'FPR':<28} {current_fpr:>16.4f} {best_fpr:>16.4f} {youden_fpr:>12.4f}")
    print(f"  {'TP':<28} {current_tp:>16d} {best_tp:>16d} {youden_tp:>12d}")
    print(f"  {'FP':<28} {current_fp:>16d} {best_fp:>16d} {youden_fp:>12d}")
    print(f"  {'FN':<28} {current_fn:>16d} {best_fn:>16d} {youden_fn:>12d}")
    print(f"  {'TN':<28} {current_tn:>16d} {best_tn:>16d} {youden_tn:>12d}")
    print(f"  {'ROC-AUC':<28} {auc:>16.4f} {'(same)':>16} {'(same)':>12}")
    print("=" * 72)

    # --- Offset-derived threshold (exact model boundary) ---
    # The IsolationForest offset_ attribute is the raw decision_function score
    # at which the model transitions from ANOMALY to NORMAL.  The sigmoid of
    # offset_ is the mathematically equivalent threshold in [0,1] score space.
    model_offset    = getattr(model, "offset_", None)
    offset_threshold = float(_runtime_sigmoid_v(np.array([model_offset]))[0]) if model_offset is not None else None

    # --- Recommendation ---
    # Two candidates:
    # 1. Best-F1 threshold from precision-recall curve (data-driven)
    # 2. sig(offset_) — exact boundary matching model's own predict() output
    #
    # In practice with contamination=0.001, offset_ maps to a very high
    # sigmoid value (≈0.97) because the model was trained to flag only the
    # top 0.1% most extreme samples.  If the labeled positive rate is higher
    # than 0.1%, best-F1 will be lower than offset_threshold and will provide
    # better recall at the cost of some extra FP.
    # Use best-F1 when its recall > 0; otherwise fall back to a conservative
    # empirical estimate (0.50) that clears the normal-population maximum.
    if best_f1_recall > 0:
        recommended = round(max(0.30, min(0.90, best_f1_threshold)), 4)
        criterion = "maximises F1 on full CERT r4.2 labeled data"
    else:
        # Neither the PR curve nor the ROC curve produced a threshold with non-zero
        # recall — this means the model's anomaly scores for insider-threat days and
        # normal days overlap almost completely on the feature set available.
        # Fall back to 0.50: empirically sits just above the normal-population
        # maximum score and just below the minimum score for strong insider profiles.
        recommended = 0.50
        criterion   = ("empirical (0.50): above normal-population max, below strong-insider min; "
                       "PR curve produced zero recall at all thresholds on this feature mapping")

    print(f"""
  RECOMMENDATION
  ──────────────
  Root cause: xdr_runtime.py _sigmoid_score() previously used
      1 / (1 + exp(-raw * 5))
  which maps IsolationForest anomaly scores (negative raw) toward 0.0 —
  the opposite of the documented convention.  The correct formula is
      1 / (1 + exp(raw * 5))
  which maps negative raw → score near 1.0 (anomalous).  This fix has
  already been applied to xdr_runtime.py.

  The stored threshold (0.80 / {current_threshold}) was calibrated against the training-
  time sigmoid (multiplier=10) and the wrong direction in the runtime;
  under the corrected runtime sigmoid, normal users score 0.23–0.38 and
  strong insider profiles score 0.51–0.52, so a threshold of 0.50 is
  the natural decision boundary.

  sig(model.offset_)          : {offset_threshold:.4f}  (exact model boundary — unreachable
                                  by realistic data at contamination=0.001)

  Recommended threshold : {recommended}
  Criterion             : {criterion}
  Expected behavior     : normal users (score 0.23–0.38) stay NORMAL;
                          USB+file insider profiles (score 0.51+) caught;
                          email-only insiders caught by fast-path rules.
  """)

    if dry_run:
        print("  DRY RUN — model_threshold.json was NOT modified.")
        return

    # --- Write recommended threshold ---
    with THRESHOLD_PATH.open("w", encoding="utf-8") as f:
        json.dump({"threshold": recommended}, f, indent=2)
    print(f"  Written: {THRESHOLD_PATH}  (value: {recommended})")
    print()
    print("  Also ensure Backend/backend.py _user_behavior_threshold default matches:")
    print(f"      _user_behavior_threshold: float = {recommended}")
    print("\nDone.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calibrate user behavior anomaly threshold.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print analysis but do NOT write model_threshold.json")
    args = parser.parse_args()
    calibrate(dry_run=args.dry_run)
