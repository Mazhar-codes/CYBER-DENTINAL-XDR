"""
retrain_from_feedback.py
========================
OFFLINE, human-gated retraining consumer for the analyst FP/TP feedback corpus.

This is the second half of the "Feature #1" feedback loop. The live system only
*collects* labels (POST /feedback -> MongoDB `feedback` collection); it never
touches a running model. This script is the separate, manual, offline step that
turns those labels into an improved model.

Design guarantees (read before running):
  * NEVER overwrites the live model. A retrain writes
    `personal_baseline_model.candidate.pkl`. You promote it explicitly with
    `--promote`, which first backs up the current live model with a timestamp.
  * NEVER runs inside the request path. Run it by hand (or on a schedule) when
    you have accumulated enough labels — see `--stats`.
  * Idempotent: feedback docs consumed by a successful retrain are marked
    `used_in_training: True` so the next run does not re-use them. `--dry-run`
    skips that marking.

Target model: the PERSONAL NETWORK BASELINE (IsolationForest, no external
dataset required). A `false_positive` on a network/fusion alert means "this flow
was flagged but is actually normal" — exactly the signal an anomaly baseline
should absorb. Confirmed-normal flows are appended to the baseline's normal
corpus and the IsolationForest is refit.

Usage:
    python retrain_from_feedback.py --stats
    python retrain_from_feedback.py --target personal_baseline
    python retrain_from_feedback.py --target personal_baseline --dry-run
    python retrain_from_feedback.py --promote        # swap candidate -> live
"""
from __future__ import annotations

import argparse
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Reuse the project's centralized config (Mongo URI/DB, model_dir, .env loading).
try:
    from config import settings
except ImportError:  # allow running from repo root
    sys.path.insert(0, str(Path(__file__).parent))
    from config import settings

try:
    from pymongo import MongoClient
except ImportError:
    print("[FATAL] pymongo is required: pip install pymongo", file=sys.stderr)
    sys.exit(1)

# ── Config ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(settings.model_dir)
BASELINE_CSV = BASE_DIR / "personal_baseline.csv"
LIVE_MODEL = BASE_DIR / "personal_baseline_model.pkl"
CANDIDATE_MODEL = BASE_DIR / "personal_baseline_model.candidate.pkl"
FEATURES_PKL = BASE_DIR / "network_features.pkl"

# Retrain gate: minimum number of retrain-ready false-positive labels before a
# personal-baseline retrain is worthwhile. Below this it is statistical noise.
# (The heavier classifiers — network RandomForest, user IsolationForest — want
#  a larger corpus, ~300+ with both verdicts; see --stats guidance.)
DEFAULT_MIN_LABELS = 50

# Feedback whose `model` field maps to the network/personal-baseline path.
NETWORK_MODELS = {"fusion", "network"}

# Poisoning guard: a false-positive click must NOT be able to teach the baseline
# that a high-confidence attack is "normal". Feedback marked false_positive whose
# attack_type is one of these decisive classes (or whose score is >= the ceiling)
# is EXCLUDED from the normal corpus — the detector's high-confidence verdict
# wins over a single analyst click. These flows are reported, not trained on.
DECISIVE_ATTACKS = {
    "portscan", "port scan", "ddos", "dos", "syn_flood", "syn flood",
    "brute force", "bruteforce", "botnet", "c2 beaconing", "heartbleed",
    "ransomware activity", "malware activity",
}
POISON_SCORE_CEILING = 0.90


def _is_decisive_attack(doc: dict) -> bool:
    at = str(doc.get("attack_type", "")).lower().strip()
    if any(tok in at for tok in DECISIVE_ATTACKS):
        return True
    try:
        return float(doc.get("score") or 0.0) >= POISON_SCORE_CEILING
    except (TypeError, ValueError):
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect():
    client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=20000)
    client.admin.command("ping")  # fail fast if unreachable
    return client, client[settings.mongo_db]


def _load_feature_columns() -> list[str]:
    if FEATURES_PKL.exists():
        cols = joblib.load(FEATURES_PKL)
        if isinstance(cols, (list, tuple)):
            return list(cols)
    # Fall back to the baseline CSV header
    return list(pd.read_csv(BASELINE_CSV, nrows=0).columns)


def _feedback_to_row(features: dict, columns: list[str]) -> dict | None:
    """Coerce a stored feature dict into one baseline row aligned to `columns`.
    Returns None if the dict has no usable numeric overlap with the schema."""
    if not isinstance(features, dict) or not features:
        return None
    row = {c: 0.0 for c in columns}
    hits = 0
    for k, v in features.items():
        if k in row:
            try:
                fv = float(v)
                if np.isfinite(fv):
                    row[k] = fv
                    hits += 1
            except (TypeError, ValueError):
                continue
    return row if hits > 0 else None


# ── Stats / gate readout ─────────────────────────────────────────────────────
def cmd_stats(db) -> int:
    coll = db["feedback"]
    total = coll.count_documents({})
    unused = coll.count_documents({"used_in_training": False})
    used = total - unused

    by_verdict = Counter()
    by_model = Counter()
    retrain_ready = 0  # unused false_positive with a usable feature vector
    columns = _load_feature_columns()

    proj = {"verdict": 1, "model": 1, "features": 1, "attack_type": 1, "score": 1}
    for doc in coll.find({"used_in_training": False}, proj):
        v = doc.get("verdict", "?")
        by_verdict[v] += 1
        by_model[doc.get("model", "?")] += 1
        if (v == "false_positive" and not _is_decisive_attack(doc)
                and _feedback_to_row(doc.get("features"), columns)):
            retrain_ready += 1

    print("=" * 60)
    print("FEEDBACK CORPUS STATS")
    print("=" * 60)
    print(f"  Total labels           : {total:,}")
    print(f"  Already used in training: {used:,}")
    print(f"  Unused (available)      : {unused:,}")
    print(f"  Unused by verdict       : {dict(by_verdict)}")
    print(f"  Unused by model         : {dict(by_model)}")
    print(f"  Retrain-ready FPs*      : {retrain_ready:,}")
    print("   *false_positive labels that carry a usable feature vector")
    print("-" * 60)
    fp = by_verdict.get("false_positive", 0)
    tp = by_verdict.get("true_positive", 0)
    print("  GUIDANCE")
    print(f"   Personal baseline retrain needs >= {DEFAULT_MIN_LABELS} retrain-ready FPs.")
    if retrain_ready >= DEFAULT_MIN_LABELS:
        print(f"   -> READY: {retrain_ready} available. Run:")
        print("        python retrain_from_feedback.py --target personal_baseline")
    else:
        print(f"   -> NOT YET: {retrain_ready}/{DEFAULT_MIN_LABELS}. Keep labeling false positives.")
    print(f"   Heavier classifier retrains want ~300+ labels with BOTH verdicts")
    print(f"   present (have FP={fp}, TP={tp}) plus their base dataset.")
    print("=" * 60)
    return 0


# ── Personal baseline retrain ────────────────────────────────────────────────
def cmd_retrain_personal(db, min_labels: int, dry_run: bool) -> int:
    if not BASELINE_CSV.exists():
        print(f"[FATAL] baseline corpus missing: {BASELINE_CSV}", file=sys.stderr)
        print("        Run collect_baseline.py + train_personal_model.py first.", file=sys.stderr)
        return 2

    columns = _load_feature_columns()
    coll = db["feedback"]

    query = {"used_in_training": False, "verdict": "false_positive",
             "model": {"$in": list(NETWORK_MODELS)}}
    docs = list(coll.find(query))

    rows, consumed_ids = [], []
    guarded = 0        # decisive-attack FPs excluded by the poisoning guard
    no_vector = 0      # FPs with no usable feature vector (not retrain-ready)
    for d in docs:
        if _is_decisive_attack(d):
            guarded += 1
            continue
        row = _feedback_to_row(d.get("features"), columns)
        if row is None:
            no_vector += 1
            continue
        rows.append(row)
        consumed_ids.append(d["_id"])

    print("=" * 60)
    print("PERSONAL BASELINE RETRAIN (feedback-augmented)")
    print("=" * 60)
    print(f"  Unused network/fusion false-positives : {len(docs):,}")
    print(f"  ...excluded by poisoning guard*        : {guarded:,}")
    print(f"  ...no usable feature vector            : {no_vector:,}")
    print(f"  ...retrain-ready (used below)          : {len(rows):,}")
    if guarded:
        print("   *high-confidence attacks — a single FP click cannot teach the")
        print("    baseline they are normal; reported but never trained on.")

    if len(rows) < min_labels:
        print("-" * 60)
        print(f"[GATE] Need >= {min_labels} retrain-ready false positives; have {len(rows)}.")
        print("       Nothing retrained. Label more FPs (--stats to check) or lower")
        print("       the bar with --min-labels N if you understand the risk.")
        print("=" * 60)
        return 1

    # ── Build augmented normal corpus ────────────────────────────────────────
    base_df = pd.read_csv(BASELINE_CSV)
    base_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    base_df.fillna(0, inplace=True)
    base_df = base_df.reindex(columns=columns, fill_value=0.0)

    fp_df = pd.DataFrame(rows, columns=columns)
    aug_df = pd.concat([base_df, fp_df], ignore_index=True)
    print(f"  Baseline normal flows                  : {len(base_df):,}")
    print(f"  + confirmed-normal (FP) flows appended : {len(fp_df):,}")
    print(f"  = augmented training set               : {len(aug_df):,}")

    X = aug_df.values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=300, contamination=0.01, max_samples="auto",
        random_state=42, n_jobs=-1,
    )
    model.fit(X_scaled)
    scores = model.decision_function(X_scaled)
    threshold = float(np.percentile(scores, 1))
    self_flag = float((scores < threshold).mean())

    # ── Before/after on the labeled false positives ─────────────────────────
    fp_X = fp_df.values
    before_flagged = after_flagged = None
    if LIVE_MODEL.exists():
        try:
            old = joblib.load(LIVE_MODEL)
            old_model, old_scaler, old_thr = old["model"], old["scaler"], old["threshold"]
            old_cols = old.get("features", columns)
            fp_aligned = fp_df.reindex(columns=old_cols, fill_value=0.0).values
            before_flagged = int((old_model.decision_function(old_scaler.transform(fp_aligned)) < old_thr).sum())
        except Exception as e:  # noqa: BLE001
            print(f"  (could not score with live model for before/after: {e})")
    after_flagged = int((model.decision_function(scaler.transform(fp_X)) < threshold).sum())

    print("-" * 60)
    print(f"  New anomaly threshold  : {threshold:.6f}")
    print(f"  New self-flag rate     : {self_flag:.2%} (target ~1%)")
    if before_flagged is not None:
        print(f"  Labeled FPs flagged BY OLD model : {before_flagged}/{len(fp_df)}")
    print(f"  Labeled FPs flagged BY NEW model : {after_flagged}/{len(fp_df)}"
          f"  (lower is better — these are confirmed normal)")

    # ── Save candidate (never the live file) ────────────────────────────────
    artifacts = {
        "model": model, "scaler": scaler, "threshold": threshold, "features": columns,
        "stats": {
            "n_training_flows": int(len(aug_df)),
            "n_feedback_fp": int(len(fp_df)),
            "score_mean": float(scores.mean()), "score_std": float(scores.std()),
            "score_min": float(scores.min()), "score_max": float(scores.max()),
            "threshold": threshold, "self_flag_rate": self_flag,
            "retrained_at": _now_iso(),
        },
    }
    joblib.dump(artifacts, CANDIDATE_MODEL)
    print("-" * 60)
    print(f"  Candidate saved -> {CANDIDATE_MODEL.name}")
    print("  The LIVE model was NOT changed. Review the numbers above, then:")
    print("      python retrain_from_feedback.py --promote")

    # ── Mark consumed ────────────────────────────────────────────────────────
    if dry_run:
        print(f"  [dry-run] {len(consumed_ids)} feedback docs left unmarked.")
    else:
        coll.update_many(
            {"_id": {"$in": consumed_ids}},
            {"$set": {"used_in_training": True, "used_at": _now_iso()}},
        )
        print(f"  Marked {len(consumed_ids)} feedback docs used_in_training=True.")
    print("=" * 60)
    return 0


# ── Promote candidate -> live ────────────────────────────────────────────────
def cmd_promote() -> int:
    if not CANDIDATE_MODEL.exists():
        print(f"[FATAL] no candidate to promote: {CANDIDATE_MODEL}", file=sys.stderr)
        print("        Run a retrain first.", file=sys.stderr)
        return 2
    if LIVE_MODEL.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = BASE_DIR / f"personal_baseline_model.{stamp}.bak.pkl"
        shutil.copy2(LIVE_MODEL, backup)
        print(f"  Backed up live model -> {backup.name}")
    shutil.move(str(CANDIDATE_MODEL), str(LIVE_MODEL))
    print(f"  Promoted candidate -> {LIVE_MODEL.name}")
    print("  RESTART the backend for the new model to take effect.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Offline feedback-driven retraining.")
    p.add_argument("--stats", action="store_true", help="Show corpus stats + retrain gate readout.")
    p.add_argument("--target", choices=["personal_baseline"], help="Retrain this model from feedback.")
    p.add_argument("--min-labels", type=int, default=DEFAULT_MIN_LABELS,
                   help=f"Min retrain-ready FPs required (default {DEFAULT_MIN_LABELS}).")
    p.add_argument("--dry-run", action="store_true", help="Retrain but do not mark feedback consumed.")
    p.add_argument("--promote", action="store_true", help="Swap candidate model into live (with backup).")
    args = p.parse_args()

    if args.promote:
        return cmd_promote()

    if not (args.stats or args.target):
        p.print_help()
        return 0

    try:
        client, db = _connect()
    except Exception as e:  # noqa: BLE001
        print(f"[FATAL] MongoDB unreachable: {e}", file=sys.stderr)
        return 2

    try:
        if args.stats:
            return cmd_stats(db)
        if args.target == "personal_baseline":
            return cmd_retrain_personal(db, args.min_labels, args.dry_run)
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
