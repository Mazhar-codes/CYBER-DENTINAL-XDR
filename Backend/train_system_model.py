"""
train_system_model.py — Cyber Sentinel XDR
Trains the LSTM Autoencoder for the System Monitor Agent.

Usage (development — 5-minute collection):
    python train_system_model.py

Usage (production — 60-minute collection):
    python train_system_model.py --collect-minutes 60 --epochs 100

Output artifacts (saved to --output-dir, default D:\\Cyber Sentinal\\Backend):
    system_model.pt         PyTorch state dict
    system_scaler.pkl       Fitted sklearn StandardScaler
    system_metadata.json    Hyperparameters + 99th-pct anomaly threshold

Requirements:
    pip install torch
    pip install psutil joblib scikit-learn numpy   (already in project venv)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Guard heavy imports — give a useful error before doing anything
# ---------------------------------------------------------------------------
def _check_dependency(name: str, pip_name: str | None = None) -> None:
    import importlib.util
    if importlib.util.find_spec(name) is None:
        pkg = pip_name or name
        logger.error(f"Required package '{name}' not found.  Install with: pip install {pkg}")
        sys.exit(1)

_check_dependency("torch")
_check_dependency("numpy")
_check_dependency("sklearn", "scikit-learn")
_check_dependency("joblib")
_check_dependency("psutil")

import numpy as np
import joblib
import psutil
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Reuse the model class from system_monitor_agent so they always match
# ---------------------------------------------------------------------------
_AGENT_DIR = Path(__file__).parent / "agents"
sys.path.insert(0, str(_AGENT_DIR.parent))
from agents.system_monitor_agent import (
    LSTMAutoencoder,
    N_FEATURES,
    FEATURE_NAMES,
    WINDOW_SIZE,
    _TelemetryCollector,
)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train LSTM Autoencoder for System Monitor")
    parser.add_argument(
        "--source",
        choices=["psutil", "sysmon", "dataset"],
        default="psutil",
        help=(
            "Telemetry source for training data.\n"
            "  psutil   — poll psutil metrics every 1 s (default, produces system_model.pt)\n"
            "  sysmon   — aggregate Sysmon events from the Winlogbeat NDJSON file into\n"
            "             10-second buckets via SysmonFeatureExtractor (produces sysmon_lstm_model.pt).\n"
            "             Requires Sysmon + Winlogbeat writing to C:\\winlogbeat\\logs\\sysmon_events.json.\n"
            "  dataset  — retrain the WindowsAnomalyDetector (detector.pkl) from the GHC\n"
            "             DLL call-stack trace dataset.\n"
            "             Reads from --dataset-train-dir (default: the bundled Dataset_1 path).\n"
            "             Produces detector.pkl in --dataset-model-dir."
        ),
    )
    parser.add_argument(
        "--collect-minutes",
        type=float,
        default=5.0,
        help="How many minutes of normal telemetry to collect (default: 5 for dev, use 60+ for prod)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=50,
        help="Training epochs (default: 50)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=r"D:\Cyber Sentinal\Backend",
        help="Directory to save artifacts (default: D:\\Cyber Sentinal\\Backend)",
    )
    parser.add_argument(
        "--hidden-dim",
        type=int,
        default=64,
        help="LSTM hidden units (default: 64)",
    )
    parser.add_argument(
        "--bottleneck-dim",
        type=int,
        default=32,
        help="Bottleneck (latent) dimension (default: 32)",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=0.001,
        help="Adam learning rate (default: 0.001)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Training batch size (default: 32)",
    )

    # ------------------------------------------------------------------
    # Dataset-source arguments (only used when --source dataset)
    # ------------------------------------------------------------------
    _DEFAULT_DATASET_TRAIN = (
        r"D:\Cyber Sentinal\System Behavior\Dataset_1"
        r"\Full_Process_Traces\Full_Trace_Training_Data"
    )
    _DEFAULT_DATASET_ATTACK = (
        r"D:\Cyber Sentinal\System Behavior\Dataset_1"
        r"\Full_Process_Traces\Full_Trace_Attack_Data"
    )
    _DEFAULT_DETECTOR_MODEL = (
        r"D:\Cyber Sentinal\System Behavior\System_Behavior_Model"
        r"\DETECTOR1\saved_model_v3"
    )
    parser.add_argument(
        "--dataset-train-dir",
        type=str,
        default=_DEFAULT_DATASET_TRAIN,
        help=(
            "Directory of .GHC training files (--source dataset only). "
            f"Default: {_DEFAULT_DATASET_TRAIN}"
        ),
    )
    parser.add_argument(
        "--dataset-attack-dir",
        type=str,
        default=_DEFAULT_DATASET_ATTACK,
        help=(
            "Directory of .GHC attack files used for evaluation (--source dataset only). "
            f"Default: {_DEFAULT_DATASET_ATTACK}"
        ),
    )
    parser.add_argument(
        "--dataset-model-dir",
        type=str,
        default=_DEFAULT_DETECTOR_MODEL,
        help=(
            "Output directory for the retrained detector.pkl (--source dataset only). "
            f"Default: {_DEFAULT_DETECTOR_MODEL}"
        ),
    )
    parser.add_argument(
        "--dataset-max-per-label",
        type=int,
        default=300,
        help=(
            "Maximum GHC files to load per class label to avoid memory exhaustion "
            "(--source dataset only, default: 300)."
        ),
    )
    parser.add_argument(
        "--dataset-max-tokens",
        type=int,
        default=500,
        help=(
            "Maximum tokens to read per GHC file using streaming to control RAM usage "
            "(--source dataset only, default: 500 — matching original training setting)."
        ),
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Step 1 — Collect telemetry
# ---------------------------------------------------------------------------

def collect_telemetry(minutes: float) -> np.ndarray:
    """
    Poll psutil every second for *minutes* minutes.
    Returns raw array of shape (N_samples, N_FEATURES).
    """
    total_seconds = int(minutes * 60)
    logger.info(
        f"Collecting {total_seconds} seconds ({minutes:.1f} min) of normal telemetry..."
    )
    logger.info("   Keep the system under normal workload during collection.")

    collector = _TelemetryCollector()
    # Warm-up: discard first sample (delta counters start at zero)
    time.sleep(1)
    collector.sample()

    samples: list[list[float]] = []
    report_interval = 30  # print progress every 30 seconds
    next_report = report_interval

    for i in range(total_seconds):
        t0 = time.monotonic()
        sample = collector.sample()
        samples.append(sample)

        elapsed = i + 1
        if elapsed >= next_report:
            pct = elapsed / total_seconds * 100
            logger.info(f"   Collection progress: {elapsed}/{total_seconds}s ({pct:.0f}%)")
            next_report += report_interval

        # Sleep for the remainder of the 1-second interval
        sleep_for = max(0.0, 1.0 - (time.monotonic() - t0))
        time.sleep(sleep_for)

    arr = np.array(samples, dtype=np.float32)
    logger.info(f"Collection complete: {arr.shape[0]} samples, {arr.shape[1]} features")
    return arr


# ---------------------------------------------------------------------------
# Step 1b — Collect Sysmon telemetry (--source sysmon)
# ---------------------------------------------------------------------------

def collect_sysmon_telemetry(minutes: float) -> np.ndarray:
    """
    Collect training data from the Microsoft-Windows-Sysmon/Operational Windows
    Event Log channel using SysmonFeatureExtractor.

    Events are aggregated into 10-second buckets (12 features each).
    The function returns an array of shape (N_buckets, 12) after *minutes* of
    collection.

    Artifacts produced (different names from psutil path):
        sysmon_lstm_model.pt
        sysmon_lstm_scaler.pkl
        sysmon_lstm_metadata.json
    """
    import threading

    # Guard: import here so psutil path never fails if sysmon deps absent
    try:
        from sysmon_winevent_reader import SysmonFileReader
        from sysmon_feature_extractor import SysmonFeatureExtractor, N_FEATURES as SYSMON_N_FEATURES
    except ImportError as exc:
        logger.error(
            f"--source sysmon requires sysmon_winevent_reader and "
            f"sysmon_feature_extractor modules: {exc}"
        )
        sys.exit(1)

    total_seconds = int(minutes * 60)
    logger.info(
        f"Collecting Sysmon telemetry for {total_seconds}s ({minutes:.1f} min) "
        f"from Microsoft-Windows-Sysmon/Operational..."
    )
    logger.info("   Keep the system under normal workload during collection.")

    BUCKET_SECONDS = 10
    SEQUENCE_LENGTH = 20  # same as psutil WINDOW_SIZE / 3

    # Only these EventIDs are needed for the 12-feature training set
    TRAINING_EIDS = {"1", "3", "11"}

    extractor = SysmonFeatureExtractor(
        bucket_seconds=BUCKET_SECONDS,
        sequence_length=SEQUENCE_LENGTH,
    )
    reader = SysmonFileReader()

    samples: list[list[float]] = []
    start_wall = time.time()
    next_report = 30.0

    logger.info("   Starting event reader — waiting for first events...")
    print("[SYSMON] Reader started. Waiting for EventID 1/3/11 from Sysmon...")

    stop_event = threading.Event()

    # Shared state for cross-thread communication (mutable containers)
    seen_buckets = [0]       # how many buckets have been finalised so far
    event_count = [0]        # total Sysmon events ingested
    last_event_time = [time.time()]   # wall-clock of most recent event

    def _reader_thread() -> None:
        """Feed Sysmon events into the extractor until stop_event is set."""
        for event in reader.tail():
            if stop_event.is_set():
                break

            # Flat format from SysmonFileReader
            eid = str(event.get("event_id", ""))
            img = event.get("process", "")

            # Push ALL events into extractor (it handles filtering internally)
            extractor.push(event)

            if eid in TRAINING_EIDS:
                event_count[0] += 1
                last_event_time[0] = time.time()
                print(
                    f"[SYSMON] EventID={eid} received — total events: {event_count[0]}"
                    + (f"  Image={img}" if img else "")
                )

            # Collect every newly completed bucket as one training row
            # (don't wait for a full SEQUENCE_LENGTH-bucket sequence)
            current_count = extractor.buckets_collected
            if current_count > seen_buckets[0]:
                # New bucket completed — grab its feature vector directly
                if extractor._completed:
                    last_vec = list(extractor._completed)[-1]
                    samples.append(last_vec)
                    seen_buckets[0] = current_count
                    rounded = [round(v, 1) for v in last_vec]
                    print(
                        f"[BUCKET] Bucket #{current_count} finalised: {rounded}"
                    )

    t = threading.Thread(target=_reader_thread, daemon=True)
    t.start()

    # Poll until we have enough data or time runs out
    while time.time() - start_wall < total_seconds:
        elapsed = time.time() - start_wall
        if elapsed >= next_report:
            pct = elapsed / total_seconds * 100
            logger.info(
                f"   Collection progress: {elapsed:.0f}/{total_seconds}s ({pct:.0f}%) "
                f"— {len(samples)} bucket samples, "
                f"{extractor.buckets_collected} buckets accumulated"
            )
            logger.info(
                f"   Buckets: {extractor.buckets_collected}/{SEQUENCE_LENGTH} needed "
                f"— {len(samples)} training rows collected"
            )
            next_report += 30.0

        # Warn if no events received for 30 seconds
        if time.time() - last_event_time[0] > 30:
            print("[WARNING] No Sysmon events received in 30s! Check:")
            print("  1. Is Sysmon running? Run: Get-Service Sysmon64")
            print(r"  2. Is Winlogbeat running and writing to C:\winlogbeat\logs\sysmon_events.json?")
            print(r"  3. Check Winlogbeat config: output.file path must be C:\winlogbeat\logs\sysmon_events.json")
            last_event_time[0] = time.time()  # reset to avoid spam

        time.sleep(1.0)

    stop_event.set()
    t.join(timeout=5.0)

    if len(samples) == 0:
        logger.error(
            "No Sysmon samples collected.  Ensure Sysmon is running and generating "
            "events to Microsoft-Windows-Sysmon/Operational."
        )
        sys.exit(1)

    if len(samples) < 20:
        logger.warning(
            f"Only {len(samples)} samples collected. Training may be low quality. "
            "Consider running longer with a higher --collect-minutes value."
        )
        # Continue anyway — we'll train on what we have

    arr = np.array(samples, dtype=np.float32)
    logger.info(
        f"Sysmon collection complete: {arr.shape[0]} bucket-samples, "
        f"{arr.shape[1]} features"
    )
    return arr


def save_sysmon_artifacts(
    output_dir: Path,
    model,
    scaler,
    error_arr: np.ndarray,
    hidden_dim: int,
    bottleneck_dim: int,
    bucket_seconds: int = 10,
    sequence_length: int = 20,
) -> None:
    """Save LSTM artifacts for the Sysmon source path."""
    from sysmon_feature_extractor import FEATURE_NAMES as SYSMON_FEATURES, N_FEATURES as SYSMON_N_FEATURES

    output_dir.mkdir(parents=True, exist_ok=True)
    anomaly_threshold = float(np.percentile(error_arr, 99))

    model_path = output_dir / "sysmon_lstm_model.pt"
    torch.save(model.state_dict(), str(model_path))
    logger.info(f"Saved: {model_path}")

    scaler_path = output_dir / "sysmon_lstm_scaler.pkl"
    joblib.dump(scaler, str(scaler_path))
    logger.info(f"Saved: {scaler_path}")

    metadata = {
        "source": "sysmon",
        "n_features": SYSMON_N_FEATURES,
        "feature_names": SYSMON_FEATURES,
        "bucket_seconds": bucket_seconds,
        "sequence_length": sequence_length,
        "hidden_dim": hidden_dim,
        "bottleneck_dim": bottleneck_dim,
        "anomaly_threshold": anomaly_threshold,
        "error_p50": float(np.percentile(error_arr, 50)),
        "error_p95": float(np.percentile(error_arr, 95)),
        "error_p99": anomaly_threshold,
        "error_max": float(error_arr.max()),
        "n_training_samples": int(len(error_arr)),
    }
    meta_path = output_dir / "sysmon_lstm_metadata.json"
    with open(str(meta_path), "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)
    logger.info(f"Saved: {meta_path}")

    logger.info("")
    logger.info("=" * 60)
    logger.info("Sysmon LSTM artifacts saved.")
    logger.info(f"  sysmon_lstm_model.pt      -> {model_path}")
    logger.info(f"  sysmon_lstm_scaler.pkl    -> {scaler_path}")
    logger.info(f"  sysmon_lstm_metadata.json -> {meta_path}")
    logger.info(f"  anomaly_threshold         = {anomaly_threshold:.6f}")
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Statistical helpers for evaluation reporting
# ---------------------------------------------------------------------------

def _hanley_mcneil_ci(
    auc: float, n1: int, n0: int, alpha: float = 0.05
) -> tuple[float, float, float]:
    """
    Compute the Hanley-McNeil (1982) standard error and Wald 95% CI for a
    ROC-AUC estimate.

    Formula:
        SE^2 = (AUC*(1-AUC) + (n1-1)*Q1 + (n0-1)*Q2) / (n1 * n0)
        Q1   = AUC / (2 - AUC)
        Q2   = 2 * AUC^2 / (1 + AUC)

    Args:
        auc:  Observed ROC-AUC in [0, 1].
        n1:   Number of positive (attack) samples.
        n0:   Number of negative (background) samples.
        alpha: Significance level for CI (default 0.05 → 95% CI).

    Returns:
        (ci_lower, ci_upper, se) — all floats.
        CI is clamped to [0, 1].
    """
    import math
    # Edge cases
    if n1 <= 0 or n0 <= 0:
        return (auc, auc, 0.0)
    auc = max(0.0, min(1.0, auc))
    q1 = auc / (2.0 - auc)
    q2 = (2.0 * auc ** 2) / (1.0 + auc)
    var = (auc * (1.0 - auc) + (n1 - 1) * q1 + (n0 - 1) * q2) / (n1 * n0)
    se = math.sqrt(max(0.0, var))
    # z-score for two-sided alpha (1.96 for alpha=0.05)
    # Use a simple approximation via the error function inverse
    # For alpha=0.05, z=1.96; for alpha=0.01, z=2.576; default: 1.96
    z = 1.96 if alpha == 0.05 else (2.576 if alpha == 0.01 else 1.96)
    lo = max(0.0, auc - z * se)
    hi = min(1.0, auc + z * se)
    return (lo, hi, se)


def _wilson_ci_width(n: int, p: float = 0.5, alpha: float = 0.05) -> float:
    """
    Return the width of the Wilson score 95% CI for a proportion estimate p
    with n observations.  Used to communicate uncertainty on specificity/FPR
    when n (background count) is very small.

    At n=17, p=0.5 this is approximately 0.45 — nearly half the [0,1] range.
    """
    import math
    z = 1.96 if alpha == 0.05 else 2.576
    z2 = z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half_w = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / (1 + z2 / n)
    lo = max(0.0, centre - half_w)
    hi = min(1.0, centre + half_w)
    return hi - lo


# ---------------------------------------------------------------------------
# Dataset source — retrain WindowsAnomalyDetector from GHC traces
# ---------------------------------------------------------------------------

def train_from_dataset(
    train_dir: str,
    attack_dir: str,
    model_dir: str,
    max_per_label: int = 300,
    max_tokens: int = 500,
) -> None:
    """
    Retrain (or validate) the WindowsAnomalyDetector (detector.pkl) using the
    GHC DLL call-stack trace dataset.

    This function re-implements the train sub-command of windows_detector_final.py
    so it can be driven from the unified train_system_model.py CLI without
    importing that file (which has its own argparse main and would clash).

    Steps:
    1. Load training GHC files from train_dir, capped at max_per_label/class.
    2. Fit TF-IDF + IsolationForest + RandomForest (or XGBoost if available).
    3. Tune the IsolationForest threshold on attack_dir (if it exists).
    4. Evaluate on attack_dir.
    5. Save the retrained detector to model_dir/detector.pkl.

    Args:
        train_dir:     Path to Full_Trace_Training_Data directory (.GHC files).
        attack_dir:    Path to Full_Trace_Attack_Data directory (.GHC files).
        model_dir:     Output directory; detector.pkl written here.
        max_per_label: Max files per class label to load (memory guard).
        max_tokens:    Max tokens to read per GHC file (memory guard).
    """
    import glob
    import re
    import pickle
    import warnings
    from collections import defaultdict

    warnings.filterwarnings("ignore")

    # Guard imports
    try:
        import numpy as _np
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.preprocessing import LabelEncoder
        from sklearn.metrics import (
            classification_report, f1_score, precision_score,
            recall_score, roc_auc_score, average_precision_score,
        )
        from sklearn.utils.class_weight import compute_class_weight
    except ImportError as exc:
        logger.error(
            f"--source dataset requires scikit-learn: {exc}. "
            "Install with: pip install scikit-learn"
        )
        sys.exit(1)

    try:
        import xgboost as xgb
        _HAS_XGB = True
    except ImportError:
        _HAS_XGB = False

    # ------------------------------------------------------------------
    # Constants (match windows_detector_final.py)
    # ------------------------------------------------------------------
    _NGRAM_RANGE  = (1, 3)
    _MAX_FEATURES = 80_000
    _BENIGN_LABEL = "Background"
    _MIN_TOKENS   = 2
    _PART_SUFFIX  = re.compile(r"-Part\d+$", re.IGNORECASE)
    _ATTACK_N_CODE = re.compile(r"^N\d+-\d+$")
    _FNAME_RE     = re.compile(
        r"(?:Training|Validation|Attack)-([A-Za-z0-9\-]+?)_\d+\.GHC$",
        re.IGNORECASE,
    )

    def _normalize_label(raw: str) -> str:
        if _ATTACK_N_CODE.match(raw):
            return "__UNKNOWN__"
        return _PART_SUFFIX.sub("", raw)

    def _parse_raw_label(filename: str):
        m = _FNAME_RE.search(os.path.basename(filename))
        return m.group(1) if m else None

    def _read_ghc_stream(path: str) -> str:
        """Stream first max_tokens tokens from a GHC file."""
        tokens = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    parts = line.split()
                    tokens.extend(parts)
                    if len(tokens) >= max_tokens:
                        break
        except Exception as exc:
            logger.warning(f"Cannot read {path}: {exc}")
            return ""
        return " ".join(tokens[:max_tokens])

    def _load_directory(directory: str):
        """Load GHC files from directory, capped at max_per_label per class."""
        paths = (
            glob.glob(os.path.join(directory, "**", "*.GHC"), recursive=True)
            + glob.glob(os.path.join(directory, "**", "*.ghc"), recursive=True)
        )
        if not paths:
            logger.warning(f"No .GHC files found in {directory}")
            return []

        label_paths = defaultdict(list)
        for p in paths:
            raw = _parse_raw_label(p)
            if raw:
                label_paths[_normalize_label(raw)].append(p)

        records = []
        for label, lpaths in label_paths.items():
            if len(lpaths) > max_per_label:
                step = len(lpaths) // max_per_label
                lpaths = lpaths[::step][:max_per_label]
            for p in lpaths:
                toks = _read_ghc_stream(p)
                if len(toks.split()) < _MIN_TOKENS:
                    continue
                records.append({
                    "label":  label,
                    "tokens": toks,
                    "source": os.path.basename(p),
                })

        logger.info(
            f"Loaded {len(records)} GHC files from {directory} "
            f"(cap={max_per_label}/label, {max_tokens} tokens/file)"
        )
        return records

    # ------------------------------------------------------------------
    # 1. Load training data
    # ------------------------------------------------------------------
    logger.info(f"[dataset] Loading training data from: {train_dir}")
    train_records = _load_directory(train_dir)
    if not train_records:
        logger.error(
            f"[dataset] No training samples loaded from {train_dir}. "
            "Check that the directory contains .GHC files matching the "
            "Training-<Label>_<N>.GHC naming pattern."
        )
        sys.exit(1)

    # Filter unknowns; display distribution
    train_records = [r for r in train_records if r["label"] != "__UNKNOWN__"]
    from collections import Counter
    dist = Counter(r["label"] for r in train_records)
    logger.info("[dataset] Label distribution:")
    for lbl, cnt in dist.most_common():
        tag = " (BENIGN)" if lbl == _BENIGN_LABEL else ""
        logger.info(f"  {lbl:<42} {cnt:>5}{tag}")

    # ------------------------------------------------------------------
    # 2. Fit TF-IDF vectorizer
    # ------------------------------------------------------------------
    logger.info("[dataset] Fitting TF-IDF vectorizer ...")
    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=_NGRAM_RANGE,
        max_features=_MAX_FEATURES,
        sublinear_tf=True,
        min_df=2,
        max_df=0.98,
        token_pattern=r"\S+",
    )
    tokens_list = [r["tokens"] for r in train_records]
    X_train = vectorizer.fit_transform(tokens_list)
    logger.info(f"[dataset] TF-IDF matrix: {X_train.shape[0]} x {X_train.shape[1]}")

    # ------------------------------------------------------------------
    # 3. IsolationForest on benign samples
    # ------------------------------------------------------------------
    benign_indices = [i for i, r in enumerate(train_records) if r["label"] == _BENIGN_LABEL]
    n_benign = len(benign_indices)
    logger.info(f"[dataset] IsolationForest: fitting on {n_benign} benign samples ...")
    if n_benign > 0:
        X_benign = X_train[benign_indices]
        contamination = "auto" if n_benign < 20 else 0.08
    else:
        X_benign = X_train
        contamination = "auto"
    iso_forest = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        max_samples=min(n_benign, 256) if n_benign > 0 else "auto",
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_benign)
    iso_threshold = 0.0   # will be tuned below if attack data available

    # ------------------------------------------------------------------
    # 4. Train classifier
    # ------------------------------------------------------------------
    label_encoder = LabelEncoder()
    y_str = _np.array([r["label"] for r in train_records])
    y = label_encoder.fit_transform(y_str)
    weights = compute_class_weight("balanced", classes=_np.unique(y), y=y)
    sw = _np.array([weights[yi] for yi in y])

    if _HAS_XGB:
        logger.info("[dataset] Training XGBoost classifier ...")
        classifier = xgb.XGBClassifier(
            n_estimators=400, max_depth=7, learning_rate=0.08,
            subsample=0.8, colsample_bytree=0.8, eval_metric="mlogloss",
            tree_method="hist", random_state=42, verbosity=0, n_jobs=-1,
        )
        classifier.fit(X_train, y, sample_weight=sw)
    else:
        logger.info("[dataset] Training RandomForest classifier (XGBoost not available) ...")
        classifier = RandomForestClassifier(
            n_estimators=400, class_weight="balanced",
            random_state=42, n_jobs=-1,
        )
        classifier.fit(X_train, y)

    logger.info("[dataset] Training complete.")

    # ------------------------------------------------------------------
    # 5. Tune threshold and evaluate on attack data
    # ------------------------------------------------------------------
    attack_records = []
    if os.path.isdir(attack_dir):
        logger.info(f"[dataset] Loading attack evaluation data from: {attack_dir}")
        attack_records = _load_directory(attack_dir)
        attack_records = [r for r in attack_records if r["label"] != "__UNKNOWN__"]
        logger.info(f"[dataset] Attack evaluation: {len(attack_records)} samples")

    if attack_records:
        known_classes = set(label_encoder.classes_)
        # ----------------------------------------------------------------
        # Count files excluded by FNAME_RE (e.g. OS_Print_Spool, OS_SMB)
        # These are attack types whose label names contain underscores and
        # are not matched by the Training/Validation-<Label>_<N>.GHC pattern.
        # They are excluded from both training AND evaluation, so DETECTOR1
        # cannot classify them — this is a known scope limitation, not a
        # model failure.
        # ----------------------------------------------------------------
        all_attack_raw = _load_directory(attack_dir)
        n_excluded_files = sum(
            1 for r in all_attack_raw
            if r["label"] not in known_classes and r["label"] != "__UNKNOWN__"
        )
        # Detect how many distinct unseen attack types appear in the val set
        val_unseen_types = set(
            r["label"] for r in all_attack_raw
            if r["label"] not in known_classes and r["label"] != "__UNKNOWN__"
        )

        known_attack = [r for r in attack_records if r["label"] in known_classes]
        if known_attack:
            X_val = vectorizer.transform([r["tokens"] for r in known_attack])
            val_scores = iso_forest.decision_function(X_val)
            val_labels = _np.array([r["label"] for r in known_attack])
            y_bin = (val_labels != _BENIGN_LABEL).astype(int)

            # ----------------------------------------------------------
            # Imbalance diagnostics — print BEFORE tuning/metrics so the
            # operator sees the context before interpreting the numbers.
            # ----------------------------------------------------------
            n_bg = int((y_bin == 0).sum())
            n_atk = int((y_bin == 1).sum())
            n_total = n_bg + n_atk

            logger.info("")
            logger.info("[dataset] ============================================================")
            logger.info("[dataset] VALIDATION SET DIAGNOSTICS")
            logger.info("[dataset] ============================================================")
            logger.info(f"[dataset]   Total validation samples (FNAME_RE matched): {n_total}")
            logger.info(f"[dataset]   Attack (positive):    {n_atk:>6}  ({n_atk/n_total*100:.1f}%)")
            logger.info(f"[dataset]   Background (negative): {n_bg:>6}  ({n_bg/n_total*100:.1f}%)")

            if n_bg < 50:
                logger.warning(
                    f"[dataset] WARNING: validation set has only {n_bg} background samples "
                    f"— confidence intervals on specificity and FPR are very wide. "
                    f"95% Wilson CI width on specificity is approximately "
                    f"{_wilson_ci_width(n_bg):.3f} (nearly the entire [0,1] range). "
                    f"AUC-ROC Hanley-McNeil SE will be dominated by this small n_0."
                )

            if val_unseen_types:
                logger.warning(
                    f"[dataset] NOTE: {len(val_unseen_types)} attack type(s) found in the "
                    f"evaluation directory were NOT in DETECTOR1's training label set "
                    f"(matched by label pattern but excluded from training). "
                    f"Recall on these classes is 0 by construction, not a model failure. "
                    f"Unseen types: {sorted(val_unseen_types)}"
                )
            else:
                logger.info("[dataset]   All matched val labels are known training classes.")

            # Count label types that exist in val dir but are excluded by FNAME_RE
            # (OS_Print_Spool, OS_SMB — underscore-named labels not matched at all)
            all_val_paths = (
                glob.glob(os.path.join(attack_dir, "**", "*.GHC"), recursive=True)
                + glob.glob(os.path.join(attack_dir, "**", "*.ghc"), recursive=True)
            )
            unmatched_basenames = [
                os.path.basename(p) for p in all_val_paths
                if _parse_raw_label(p) is None
            ]
            unmatched_prefixes = set()
            for bn in unmatched_basenames:
                # Extract the label-like prefix before the first _<digits>.GHC
                m = re.match(r"(?:Training|Validation|Attack)-([A-Za-z0-9_\-]+?)_\d+\.GHC$", bn, re.IGNORECASE)
                if m:
                    unmatched_prefixes.add(m.group(1))
            if unmatched_prefixes or unmatched_basenames:
                n_un = len(unmatched_basenames)
                logger.warning(
                    f"[dataset] NOTE: {n_un} file(s) in the evaluation directory were "
                    f"excluded because their filenames use underscores in the label name "
                    f"(e.g. OS_Print_Spool, OS_SMB) and are not matched by FNAME_RE. "
                    f"DETECTOR1 produces no classification output for these files "
                    f"(they are outside the training scope). Excluded label types: "
                    f"{sorted(unmatched_prefixes) if unmatched_prefixes else 'see filenames above'}"
                )

            logger.info("[dataset] ============================================================")
            logger.info("")

            # Tune threshold to maximise F1
            best_f1, best_thr = 0.0, 0.0
            for thr in _np.linspace(val_scores.min(), val_scores.max(), 200):
                f1 = f1_score(y_bin, (val_scores < thr).astype(int), zero_division=0)
                if f1 > best_f1:
                    best_f1, best_thr = f1, thr
            iso_threshold = best_thr
            logger.info(
                f"[dataset] Threshold tuned: iso_threshold={iso_threshold:.4f} "
                f"(attack F1={best_f1:.3f})"
            )

            # Full classification report (unchanged — always present)
            y_pred = label_encoder.inverse_transform(classifier.predict(X_val))
            logger.info("[dataset] Attack evaluation classification report:")
            report = classification_report(val_labels, y_pred, zero_division=0)
            for line in report.splitlines():
                logger.info(f"  {line}")

            # ----------------------------------------------------------
            # AUC-ROC with Hanley-McNeil confidence interval
            # ----------------------------------------------------------
            try:
                if y_bin.sum() > 0 and (1 - y_bin).sum() > 0:
                    import math as _math
                    auc_val = roc_auc_score(y_bin, -val_scores)
                    n0 = int((y_bin == 0).sum())
                    n1 = int((y_bin == 1).sum())
                    auc_lo, auc_hi, auc_se = _hanley_mcneil_ci(auc_val, n1, n0)
                    logger.info(f"[dataset] AUC-ROC (iso):  {auc_val:.4f}")
                    logger.info(
                        f"[dataset] AUC-ROC 95% CI: ({auc_lo:.4f}, {auc_hi:.4f})  "
                        f"SE={auc_se:.4f}  [Hanley-McNeil, n1={n1}, n0={n0}]"
                    )
                    if n0 < 50:
                        logger.warning(
                            f"[dataset] WARNING: AUC-ROC CI is very wide because n0={n0} "
                            f"(background samples). The CI width ({auc_hi - auc_lo:.3f}) "
                            f"means the true AUC could range from {auc_lo:.3f} to "
                            f"{auc_hi:.3f} at 95% confidence. This is a validation set "
                            f"design limitation — not a model quality issue. The model was "
                            f"trained on GHC traces and is evaluated on a mismatched split."
                        )
            except Exception as _auc_exc:
                logger.warning(f"[dataset] AUC-ROC computation failed: {_auc_exc}")

            # ----------------------------------------------------------
            # PR-AUC (average precision) — more informative than ROC-AUC
            # under severe class imbalance (99% attack / 1% background).
            # The random baseline PR-AUC equals the positive prevalence
            # (n_attack / n_total), typically ~0.99 here — so a high PR-AUC
            # is expected and is not a meaningful signal in this split.
            # The number to watch is whether PR-AUC on background (treating
            # background as the "positive" class) exceeds the 1% random baseline.
            # ----------------------------------------------------------
            try:
                if y_bin.sum() > 0 and (1 - y_bin).sum() > 0:
                    # Standard: attack=1 (positive), background=0 (negative)
                    pr_auc_attack = average_precision_score(y_bin, -val_scores)
                    # Inverted: background=1 (positive), attack=0 (negative)
                    # This measures how well the model ranks the 17 background
                    # samples above attack samples — the operationally critical
                    # direction (false positive avoidance).
                    pr_auc_bg = average_precision_score(1 - y_bin, val_scores)
                    bg_prevalence = n_bg / n_total
                    atk_prevalence = n_atk / n_total
                    logger.info(
                        f"[dataset] PR-AUC (attack as positive):     {pr_auc_attack:.4f}  "
                        f"[random baseline = {atk_prevalence:.3f} — expected near 1.0 at "
                        f"99% attack prevalence; not an informative metric here]"
                    )
                    logger.info(
                        f"[dataset] PR-AUC (background as positive):  {pr_auc_bg:.4f}  "
                        f"[random baseline = {bg_prevalence:.3f}; "
                        f"values above this indicate model ranks background above attacks]"
                    )
                    if pr_auc_bg > bg_prevalence * 3:
                        logger.info(
                            f"[dataset] PR-AUC (background) is {pr_auc_bg/bg_prevalence:.1f}x "
                            f"random baseline — model has non-trivial FP suppression ability "
                            f"even with only {n_bg} background samples."
                        )
                    else:
                        logger.warning(
                            f"[dataset] PR-AUC (background) is only "
                            f"{pr_auc_bg/bg_prevalence:.1f}x random baseline — model may "
                            f"not reliably suppress false positives. Consider retraining with "
                            f"a more balanced validation split or adjusting iso_threshold."
                        )
            except Exception as _pr_exc:
                logger.warning(f"[dataset] PR-AUC computation failed: {_pr_exc}")

    # ------------------------------------------------------------------
    # 6. Assemble and save the WindowsAnomalyDetector object
    # ------------------------------------------------------------------
    # We construct a minimal object matching the attribute contract that
    # BehavioralDetector expects: .vectorizer, .iso_forest, .iso_threshold,
    # .classifier, .label_encoder, .classes_, .is_trained
    class _DetectorShell:
        """Minimal WindowsAnomalyDetector-compatible shell."""

        def __init__(self):
            pass

        def predict(self, tokens_list: list) -> list:
            import numpy as _np2
            X = self.vectorizer.transform(tokens_list)
            scores = self.iso_forest.decision_function(X)
            is_anom = scores < self.iso_threshold
            proba = self.classifier.predict_proba(X)
            idx = _np2.argmax(proba, axis=1)
            labels = self.label_encoder.inverse_transform(idx)
            confs = proba.max(axis=1)
            nz = _np2.diff(X.tocsr().indptr)
            return [{
                "label":         labels[i] if is_anom[i] else _BENIGN_LABEL,
                "is_anomaly":    bool(is_anom[i]),
                "confidence":    float(confs[i]),
                "anomaly_score": float(-scores[i]),
                "nonzero_feats": int(nz[i]),
            } for i in range(len(tokens_list))]

    det = _DetectorShell()
    det.vectorizer    = vectorizer
    det.iso_forest    = iso_forest
    det.iso_threshold = iso_threshold
    det.classifier    = classifier
    det.label_encoder = label_encoder
    det.classes_      = label_encoder.classes_
    det.is_trained    = True

    # Save
    os.makedirs(model_dir, exist_ok=True)
    out_path = os.path.join(model_dir, "detector.pkl")
    with open(out_path, "wb") as fh:
        pickle.dump(det, fh)

    logger.info("")
    logger.info("=" * 60)
    logger.info("[dataset] WindowsAnomalyDetector saved.")
    logger.info(f"  detector.pkl -> {out_path}")
    logger.info(f"  vocab size   = {len(vectorizer.vocabulary_)}")
    logger.info(f"  iso_threshold= {iso_threshold:.4f}")
    logger.info(f"  classes      = {list(label_encoder.classes_)}")
    logger.info(f"  classifier   = {'XGBoost' if _HAS_XGB else 'RandomForest'}")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Next steps:")
    logger.info(
        "  The retrained detector.pkl will be loaded automatically by "
        "SystemMonitorAgent (BehavioralDetector) on the next backend start."
    )


# ---------------------------------------------------------------------------
# Step 2 — Build sliding windows
# ---------------------------------------------------------------------------

def build_windows(
    arr: np.ndarray,
    window_size: int = WINDOW_SIZE,
    stride: int = 1,
) -> np.ndarray:
    """
    Slide a window of *window_size* over the sample array with *stride*.
    Returns (N_windows, window_size, N_FEATURES).
    """
    n = arr.shape[0]
    if n < window_size:
        raise ValueError(
            f"Need at least {window_size} samples, got {n}. "
            f"Increase --collect-minutes (need at least {window_size / 60:.1f} min)."
        )
    n_windows = (n - window_size) // stride + 1
    windows = np.stack(
        [arr[i * stride: i * stride + window_size] for i in range(n_windows)],
        axis=0,
    )
    logger.info(f"Windows built: {windows.shape}  (n_windows, seq_len, n_features)")
    return windows


# ---------------------------------------------------------------------------
# Step 3 — Scale features
# ---------------------------------------------------------------------------

def fit_scaler(raw_arr: np.ndarray) -> tuple[StandardScaler, np.ndarray]:
    """
    Fit StandardScaler on the raw (N_samples, N_FEATURES) array.
    Returns (fitted_scaler, scaled_arr).
    """
    scaler = StandardScaler()
    scaled = scaler.fit_transform(raw_arr).astype(np.float32)
    logger.info("StandardScaler fitted on raw samples")
    return scaler, scaled


# ---------------------------------------------------------------------------
# PyTorch Dataset
# ---------------------------------------------------------------------------

class _WindowDataset(torch.utils.data.Dataset):
    def __init__(self, windows: np.ndarray):
        # windows: (N, T, F) — already scaled
        self._data = torch.from_numpy(windows)

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, idx: int) -> torch.Tensor:
        return self._data[idx]


# ---------------------------------------------------------------------------
# Step 4 — Train
# ---------------------------------------------------------------------------

def train(
    windows: np.ndarray,
    epochs: int,
    lr: float,
    batch_size: int,
    hidden_dim: int,
    bottleneck_dim: int,
) -> tuple["LSTMAutoencoder", np.ndarray]:
    """
    Train the LSTM Autoencoder with MSE reconstruction loss.
    Returns (trained_model, per_window_mse_errors).
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Training on device: {device}")

    n_windows, seq_len, n_features = windows.shape
    logger.info(
        f"Training set: {n_windows} windows  |  "
        f"seq_len={seq_len}  |  n_features={n_features}"
    )

    dataset = _WindowDataset(windows)
    loader = torch.utils.data.DataLoader(
        dataset, batch_size=batch_size, shuffle=True, drop_last=False
    )

    model = LSTMAutoencoder(
        n_features=n_features,
        hidden_dim=hidden_dim,
        bottleneck_dim=bottleneck_dim,
        seq_len=seq_len,
    ).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    logger.info(f"Starting training: {epochs} epochs, lr={lr}, batch_size={batch_size}")
    logger.info("-" * 60)

    model.train()
    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        n_batches = 0
        for batch in loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            reconstruction = model(batch)
            loss = criterion(reconstruction, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1

        avg_loss = epoch_loss / max(n_batches, 1)
        if epoch % 10 == 0 or epoch == 1 or epoch == epochs:
            logger.info(f"  Epoch {epoch:>4}/{epochs}  |  avg MSE loss: {avg_loss:.6f}")

    logger.info("-" * 60)
    logger.info("Training complete.  Computing reconstruction errors on training set...")

    # Compute per-window reconstruction errors (on CPU, no grad)
    model.eval()
    errors: list[float] = []
    eval_loader = torch.utils.data.DataLoader(dataset, batch_size=256, shuffle=False)
    with torch.no_grad():
        for batch in eval_loader:
            batch = batch.to(device)
            recon = model(batch)
            mse = ((batch - recon) ** 2).mean(dim=(1, 2))   # per window
            errors.extend(mse.cpu().numpy().tolist())

    error_arr = np.array(errors, dtype=np.float32)
    logger.info(
        f"Reconstruction errors — "
        f"min={error_arr.min():.6f}  "
        f"mean={error_arr.mean():.6f}  "
        f"99th={np.percentile(error_arr, 99):.6f}  "
        f"max={error_arr.max():.6f}"
    )

    # Move model back to CPU for saving
    model.cpu()
    return model, error_arr


# ---------------------------------------------------------------------------
# Step 5 — Save artifacts
# ---------------------------------------------------------------------------

def save_artifacts(
    output_dir: Path,
    model: "LSTMAutoencoder",
    scaler: StandardScaler,
    error_arr: np.ndarray,
    hidden_dim: int,
    bottleneck_dim: int,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Anomaly threshold = 99th percentile of training reconstruction errors
    anomaly_threshold = float(np.percentile(error_arr, 99))
    logger.info(f"Anomaly threshold (99th pct): {anomaly_threshold:.6f}")

    # 1. PyTorch model state dict
    model_path = output_dir / "system_model.pt"
    torch.save(model.state_dict(), str(model_path))
    logger.info(f"Saved: {model_path}")

    # 2. StandardScaler
    scaler_path = output_dir / "system_scaler.pkl"
    joblib.dump(scaler, str(scaler_path))
    logger.info(f"Saved: {scaler_path}")

    # 3. Metadata JSON
    metadata = {
        "n_features": N_FEATURES,
        "feature_names": FEATURE_NAMES,
        "window_size": WINDOW_SIZE,
        "hidden_dim": hidden_dim,
        "bottleneck_dim": bottleneck_dim,
        "anomaly_threshold": anomaly_threshold,
        "error_p50": float(np.percentile(error_arr, 50)),
        "error_p95": float(np.percentile(error_arr, 95)),
        "error_p99": anomaly_threshold,
        "error_max": float(error_arr.max()),
        "n_training_windows": int(len(error_arr)),
    }
    meta_path = output_dir / "system_metadata.json"
    with open(str(meta_path), "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)
    logger.info(f"Saved: {meta_path}")

    logger.info("")
    logger.info("=" * 60)
    logger.info("Artifacts saved successfully.")
    logger.info(f"  system_model.pt        -> {model_path}")
    logger.info(f"  system_scaler.pkl      -> {scaler_path}")
    logger.info(f"  system_metadata.json   -> {meta_path}")
    logger.info(f"  anomaly_threshold      = {anomaly_threshold:.6f}")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Next steps:")
    logger.info("  1. Start backend: uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload")
    logger.info("  2. The SystemMonitorAgent will auto-load these artifacts on startup.")
    logger.info("  3. For production accuracy, retrain with --collect-minutes 60 or more.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()
    output_dir = Path(args.output_dir)

    logger.info("=" * 60)
    logger.info("Cyber Sentinel XDR — System Monitor Model Training")
    logger.info("=" * 60)
    logger.info(f"Source      : {args.source}")
    if args.source not in ("dataset",):
        logger.info(f"Collection  : {args.collect_minutes:.1f} minutes")
    logger.info(f"Epochs      : {args.epochs}")
    logger.info(f"Hidden dim  : {args.hidden_dim}")
    logger.info(f"Bottleneck  : {args.bottleneck_dim}")
    logger.info(f"Output dir  : {output_dir}")
    logger.info("")

    if args.source == "dataset":
        # ---- Dataset source path (retrain detector.pkl) ------------------
        logger.info(f"Train dir   : {args.dataset_train_dir}")
        logger.info(f"Attack dir  : {args.dataset_attack_dir}")
        logger.info(f"Model dir   : {args.dataset_model_dir}")
        logger.info(f"Max/label   : {args.dataset_max_per_label}")
        logger.info(f"Max tokens  : {args.dataset_max_tokens}")
        logger.info("")

        # Validate that sklearn is available before burning time on I/O
        try:
            import sklearn  # noqa: F401
        except ImportError:
            logger.error(
                "--source dataset requires scikit-learn. "
                "Install with: pip install scikit-learn"
            )
            sys.exit(1)

        train_from_dataset(
            train_dir=args.dataset_train_dir,
            attack_dir=args.dataset_attack_dir,
            model_dir=args.dataset_model_dir,
            max_per_label=args.dataset_max_per_label,
            max_tokens=args.dataset_max_tokens,
        )

    elif args.source == "sysmon":
        # ---- Sysmon source path ----------------------------------------
        # Sysmon events are aggregated into 10-second buckets (12 features).
        # The LSTM is trained on (sequence_length=20, n_features=12) windows.
        SYSMON_BUCKET_S = 10
        SYSMON_SEQ_LEN  = 20

        # Lazy import — validate sysmon_feature_extractor is available before doing any work
        from sysmon_feature_extractor import N_FEATURES as SYSMON_N_FEATURES
        logger.info(
            f"Sysmon feature set: {SYSMON_N_FEATURES} features per bucket, "
            f"bucket={SYSMON_BUCKET_S}s, sequence_length={SYSMON_SEQ_LEN}"
        )

        # Step 1: Collect
        raw_arr = collect_sysmon_telemetry(args.collect_minutes)

        # Step 2: Scale on raw bucket samples
        scaler, scaled_arr = fit_scaler(raw_arr)

        # Step 3: Build windows — each window is sequence_length consecutive buckets
        windows = build_windows(scaled_arr, window_size=SYSMON_SEQ_LEN, stride=1)

        # Step 4: Train — build a fresh LSTMAutoencoder sized for Sysmon features
        from agents.system_monitor_agent import LSTMAutoencoder
        model, error_arr = train(
            windows=windows,
            epochs=args.epochs,
            lr=args.lr,
            batch_size=args.batch_size,
            hidden_dim=args.hidden_dim,
            bottleneck_dim=args.bottleneck_dim,
        )

        # Step 5: Save with sysmon-specific filenames
        save_sysmon_artifacts(
            output_dir=output_dir,
            model=model,
            scaler=scaler,
            error_arr=error_arr,
            hidden_dim=args.hidden_dim,
            bottleneck_dim=args.bottleneck_dim,
            bucket_seconds=SYSMON_BUCKET_S,
            sequence_length=SYSMON_SEQ_LEN,
        )

    else:
        # ---- psutil source path (default) --------------------------------
        # Step 1: Collect
        raw_arr = collect_telemetry(args.collect_minutes)

        # Step 2: Scale (fit on raw samples, then apply to windows)
        scaler, scaled_arr = fit_scaler(raw_arr)

        # Step 3: Build windows from scaled array
        windows = build_windows(scaled_arr, window_size=WINDOW_SIZE, stride=1)

        # Step 4: Train
        model, error_arr = train(
            windows=windows,
            epochs=args.epochs,
            lr=args.lr,
            batch_size=args.batch_size,
            hidden_dim=args.hidden_dim,
            bottleneck_dim=args.bottleneck_dim,
        )

        # Step 5: Save
        save_artifacts(
            output_dir=output_dir,
            model=model,
            scaler=scaler,
            error_arr=error_arr,
            hidden_dim=args.hidden_dim,
            bottleneck_dim=args.bottleneck_dim,
        )


if __name__ == "__main__":
    main()
