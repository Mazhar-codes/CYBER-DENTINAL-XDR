"""
train_sysmon_model.py — Cyber Sentinel XDR
Train (or retrain) the WindowsAnomalyDetector on the GHC process-trace dataset.

Dataset layout assumed (same structure as windows_detector_final.py):
    <dataset_root>/
        Full_Trace_Attack_Data/      — attack .GHC files, labelled by subdir name
        Full_Trace_Training_Data/    — training split (benign + attack)
        Full_Trace_Validation_Data/  — validation split

Output:
    <model_dir>/detector.pkl         — pickled WindowsAnomalyDetector

Usage examples:

  # Full train + validate (recommended)
  python train_sysmon_model.py

  # Custom paths
  python train_sysmon_model.py \\
      --dataset_root "D:/Cyber Sentinal/System Behavior/Dataset_1/Full_Process_Traces" \\
      --model_dir "D:/Cyber Sentinal/System Behavior/System_Behavior_Model/DETECTOR1/saved_model_v3" \\
      --max_per_label 400

  # Only retrain, skip validation evaluation
  python train_sysmon_model.py --no_eval

  # Also add live Sysmon NDJSON as benign reference data
  python train_sysmon_model.py \\
      --sysmon_benign "C:/winlogbeat/logs/sysmon_events.json"
"""

import argparse
import importlib.util
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

_REPO_ROOT   = Path(__file__).parent.parent          # D:\Cyber Sentinal
_DATASET_ROOT = (
    _REPO_ROOT
    / "System Behavior"
    / "Dataset_1"
    / "Full_Process_Traces"
)
_MODEL_DIR = (
    _REPO_ROOT
    / "System Behavior"
    / "System_Behavior_Model"
    / "DETECTOR1"
    / "saved_model_v3"
)
_DETECTOR_SRC = (
    _REPO_ROOT
    / "System Behavior"
    / "System_Behavior_Model"
    / "DETECTOR1"
    / "windows_detector_final.py"
)


# ---------------------------------------------------------------------------
# Dynamic import of windows_detector_final.py
# ---------------------------------------------------------------------------

def _import_detector_module():
    """
    Load windows_detector_final.py via importlib so we don't need it on
    sys.path, and so this script remains independent of its location.
    """
    src = str(_DETECTOR_SRC)
    if not os.path.exists(src):
        log.error(f"windows_detector_final.py not found: {src}")
        sys.exit(1)
    spec = importlib.util.spec_from_file_location("windows_detector_final", src)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Main training routine
# ---------------------------------------------------------------------------

def train(args):
    wdf = _import_detector_module()

    train_dir = Path(args.dataset_root) / "Full_Trace_Training_Data"
    val_dir   = Path(args.dataset_root) / "Full_Trace_Validation_Data"
    atk_dir   = Path(args.dataset_root) / "Full_Trace_Attack_Data"
    model_dir = str(args.model_dir)

    # ---- Load training data ----
    log.info(f"Loading training data from: {train_dir}")
    if not train_dir.exists():
        # Fall back to attack directory if no separate training split
        log.warning(
            f"Training split not found at {train_dir}. "
            f"Falling back to Full_Trace_Attack_Data."
        )
        train_dir = atk_dir

    train_df = wdf.load_directory(str(train_dir), max_per_label=args.max_per_label)
    if train_df.empty:
        log.error("No GHC training data found. Aborting.")
        sys.exit(1)

    # ---- Optional: add live Sysmon NDJSON as extra benign windows ----
    if args.sysmon_benign:
        import pandas as pd
        extra_dfs = []
        for ndjson_path in args.sysmon_benign:
            if os.path.exists(ndjson_path):
                log.info(f"Loading Sysmon benign NDJSON: {ndjson_path}")
                extra_dfs.append(
                    wdf.load_sysmon_ndjson(ndjson_path, wdf.BENIGN_LABEL, window=300, max_windows=500)
                )
            else:
                log.warning(f"Sysmon NDJSON not found — skipping: {ndjson_path}")
        if extra_dfs:
            import pandas as pd
            combined = pd.concat(extra_dfs, ignore_index=True)
            log.info(f"Adding {len(combined)} benign Sysmon windows to training data")
            import pandas as pd
            train_df = pd.concat([train_df, combined], ignore_index=True)

    wdf.show_distribution(train_df, "Training Data")

    # ---- Load validation data (used for threshold tuning + benign augmentation) ----
    val_df    = None
    extra_ben = None
    if val_dir.exists():
        log.info(f"Loading validation data from: {val_dir}")
        val_df = wdf.load_directory(str(val_dir), max_per_label=args.max_per_label)
        if not val_df.empty:
            import pandas as pd
            extra_ben = val_df[val_df["label"] == wdf.BENIGN_LABEL]
            wdf.show_distribution(val_df, "Validation Data")
        else:
            log.warning("Validation directory contained no usable GHC files.")
            val_df = None
    else:
        log.warning(f"Validation split not found: {val_dir}")

    # ---- Fit the detector ----
    det = wdf.WindowsAnomalyDetector()
    det.fit(train_df, benign_extra_df=extra_ben)

    # ---- Threshold tuning ----
    if val_df is not None and not val_df.empty:
        log.info("Tuning IsolationForest threshold on validation split ...")
        det.tune_threshold(val_df)

    # ---- Evaluation ----
    if not args.no_eval:
        if val_df is not None and not val_df.empty:
            wdf.evaluate(det, val_df, "Validation")
        if atk_dir.exists():
            log.info(f"Loading attack evaluation data from: {atk_dir}")
            atk_df = wdf.load_directory(str(atk_dir), max_per_label=min(args.max_per_label, 100))
            if not atk_df.empty:
                wdf.evaluate(det, atk_df, "Attack (held-out)")

    # ---- Save ----
    det.save(model_dir)

    # ---- Summary ----
    print("\n" + "=" * 62)
    print("  TRAINING COMPLETE")
    print("=" * 62)
    print(f"  Artifact     : {model_dir}/detector.pkl")
    print(f"  Vocab size   : {len(det.vectorizer.vocabulary_)}")
    print(f"  ISO threshold: {det.iso_threshold:.4f}")
    print(f"  Classes      : {list(det.label_encoder.classes_)}")
    print(f"  Training rows: {len(train_df)}")
    if val_df is not None:
        print(f"  Val rows     : {len(val_df)}")
    print("=" * 62)
    print()
    print("To run the detector:")
    print(
        f"  python \"System Behavior/System_Behavior_Model/DETECTOR1/"
        f"windows_detector_final.py\" run \\"
    )
    print(f"    --model_path \"{model_dir}\" \\")
    print(f"    --logfile \"C:/winlogbeat/logs/sysmon_events.json\"")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args():
    ap = argparse.ArgumentParser(
        description="Train the Sysmon WindowsAnomalyDetector on GHC process traces.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument(
        "--dataset_root",
        default=str(_DATASET_ROOT),
        help="Root of the GHC Full_Process_Traces dataset",
    )
    ap.add_argument(
        "--model_dir",
        default=str(_MODEL_DIR),
        help="Output directory for detector.pkl",
    )
    ap.add_argument(
        "--max_per_label",
        type=int,
        default=300,
        help="Maximum GHC files to load per class label (memory cap)",
    )
    ap.add_argument(
        "--sysmon_benign",
        nargs="+",
        metavar="NDJSON",
        default=None,
        help="Optional: one or more Winlogbeat NDJSON files to add as benign training data",
    )
    ap.add_argument(
        "--no_eval",
        action="store_true",
        help="Skip evaluation step (faster, useful for quick retrains)",
    )
    return ap.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    log.info(f"Dataset root : {args.dataset_root}")
    log.info(f"Model output : {args.model_dir}")
    log.info(f"Max/label    : {args.max_per_label}")
    train(args)
