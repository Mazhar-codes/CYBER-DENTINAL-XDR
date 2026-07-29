"""
windows_detector_final.py  — v4
Train + real-time detection with false-positive reduction.
MemoryError fix: stream large GHC files instead of loading all at once.
"""

import os, re, sys, glob, json, time, pickle, signal, logging, warnings
import argparse
from collections import deque, defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (classification_report, f1_score,
                              precision_score, recall_score, roc_auc_score)
from sklearn.utils.class_weight import compute_class_weight

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)s  %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="ignore")


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# MEMORY FIX: was 5000, reduced to 500 so each GHC file uses ~10x less RAM
MAX_TOKENS   = 500
MIN_TOKENS   = 2
NGRAM_RANGE  = (1, 3)
MAX_FEATURES = 80_000
BENIGN_LABEL = "Background"

# Known-benign Windows processes — never alert on these
# (unless EventID 8/25 — CreateRemoteThread / ProcessTampering)
BENIGN_WHITELIST = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe",
    "svchost.exe", "spoolsv.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "conhost.exe", "ctfmon.exe",
    "trustedinstaller.exe", "tiworker.exe", "wuauclt.exe",
    "msiexec.exe", "wudfhost.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "searchapp.exe",
    "wmiprvse.exe", "dllhost.exe", "msdtc.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "msedgewebview2.exe",
    "iexplore.exe",
    "microsoftedgeupdate.exe", "updater.exe", "googleupdate.exe",
    "backgroundtaskhost.exe", "smartscreen.exe", "consent.exe",
    "ipfsvc.exe", "lnbitssvc.exe", "wudfsvc.exe",
    "mpdefendercoreservice.exe", "msmpeng.exe", "nissrv.exe",
    "securityhealthservice.exe", "powershell_ise.exe", "unknown",
}

HIGH_ALERT_PROCESSES = {
    "mimikatz.exe", "meterpreter.exe", "psexec.exe", "psexecsvc.exe",
}

_PART_SUFFIX  = re.compile(r"-Part\d+$", re.IGNORECASE)
ATTACK_N_CODE = re.compile(r"^N\d+-\d+$")
FNAME_RE      = re.compile(
    r"(?:Training|Validation|Attack)-([A-Za-z0-9\-]+?)_\d+\.GHC$",
    re.IGNORECASE
)

SYSMON_EVENTS = {
    "1":  "ProcessCreate",     "2":  "FileCreationTimeChanged",
    "3":  "NetworkConnect",    "5":  "ProcessTerminate",
    "6":  "DriverLoad",        "7":  "ImageLoad",
    "8":  "CreateRemoteThread","10": "ProcessAccess",
    "11": "FileCreate",        "12": "RegistryObjectAddedOrDeleted",
    "13": "RegistryValueSet",  "15": "FileCreateStreamHash",
    "17": "PipeCreated",       "22": "DNSQuery",
    "23": "FileDelete",        "25": "ProcessTampering",
    "26": "FileDeleteDetected",
}
HIGH_RISK = {"8", "25"}


# ══════════════════════════════════════════════════════════════════════════════
# TOKEN CONVERSION
# ══════════════════════════════════════════════════════════════════════════════

def sysmon_event_to_token(event: dict):
    try:
        winlog   = event.get("winlog", event)
        event_id = str(winlog.get("event_id") or winlog.get("EventID") or "")
        if event_id not in SYSMON_EVENTS:
            return None, {}
        data     = winlog.get("event_data", winlog.get("EventData", {}))
        eid_name = SYSMON_EVENTS[event_id]
        if event_id == "7":
            img   = data.get("ImageLoaded", data.get("Image", ""))
            base  = os.path.basename(img).lower()
            token = f"{base}+{eid_name}"
        elif event_id == "3":
            port  = data.get("DestinationPort", "0")
            proto = data.get("Protocol", "tcp")
            token = f"net+{eid_name}_{proto}_{port}"
        elif event_id in ("12", "13"):
            key   = data.get("TargetObject", "")
            hive  = key.split("\\")[0].lower() if "\\" in key else "registry"
            token = f"{hive}+{eid_name}"
        else:
            img   = data.get("Image", data.get("ParentImage", ""))
            base  = os.path.basename(img).lower() if img else "unknown.exe"
            token = f"{base}+{eid_name}"
        meta = {
            "event_id":    event_id,
            "pid":         str(data.get("ProcessId",
                               data.get("SourceProcessId", "0"))),
            "image":       data.get("Image",
                           data.get("ParentImage", "unknown")),
            "commandline": data.get("CommandLine", ""),
            "high_risk":   event_id in HIGH_RISK,
        }
        return token, meta
    except Exception:
        return None, {}


def load_sysmon_ndjson(ndjson_path: str, label: str,
                       window: int = 300, max_windows: int = 500) -> pd.DataFrame:
    log.info(f"Loading Sysmon NDJSON: {ndjson_path}  label={label}")
    buf     = deque(maxlen=window)
    records = []
    fname   = os.path.basename(ndjson_path)
    with open(ndjson_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            token, _ = sysmon_event_to_token(event)
            if token is None:
                continue
            buf.append(token)
            if len(buf) == window and len(records) < max_windows:
                records.append({
                    "raw_label": label, "label": label,
                    "tokens":    " ".join(buf),
                    "source":    f"{fname}_w{len(records)}",
                })
                for _ in range(window // 2):
                    if buf:
                        buf.popleft()
    log.info(f"  -> {len(records)} windows from {os.path.basename(ndjson_path)}")
    return pd.DataFrame(records)


# ══════════════════════════════════════════════════════════════════════════════
# GHC DATA LOADING  — memory-safe streaming version
# ══════════════════════════════════════════════════════════════════════════════

def normalize_label(raw: str) -> str:
    if ATTACK_N_CODE.match(raw):
        return "__UNKNOWN__"
    return _PART_SUFFIX.sub("", raw)

def parse_raw_label(filename: str):
    m = FNAME_RE.search(os.path.basename(filename))
    return m.group(1) if m else None

def read_ghc_stream(path: str, max_tokens: int = MAX_TOKENS) -> str:
    """
    MEMORY FIX: Read only the first max_tokens tokens from a GHC file
    using streaming so we never load the whole file into memory.
    A GHC file with 500k tokens at ~8 bytes each = 4 MB per file.
    With MAX_TOKENS=500 we read ~4 KB per file max.
    """
    tokens = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                tokens.extend(parts)
                if len(tokens) >= max_tokens:
                    break
    except Exception as e:
        log.warning(f"Cannot read {path}: {e}")
        return ""
    return " ".join(tokens[:max_tokens])

def load_directory(directory: str, max_per_label: int = 300) -> pd.DataFrame:
    """
    MEMORY FIX: Load at most max_per_label files per class label
    so we don't blow up on large datasets.
    """
    paths = (glob.glob(os.path.join(directory, "**", "*.GHC"), recursive=True) +
             glob.glob(os.path.join(directory, "**", "*.ghc"), recursive=True))
    if not paths:
        log.warning(f"No GHC files in {directory}")
        return pd.DataFrame(columns=["raw_label", "label", "tokens", "source"])

    # Group by label first so we can cap per-label
    label_paths = defaultdict(list)
    for p in paths:
        raw = parse_raw_label(p)
        if raw:
            label_paths[normalize_label(raw)].append(p)

    records = []
    for label, lpaths in label_paths.items():
        # Sample evenly if too many files
        if len(lpaths) > max_per_label:
            step = len(lpaths) // max_per_label
            lpaths = lpaths[::step][:max_per_label]

        for p in lpaths:
            tokens = read_ghc_stream(p, MAX_TOKENS)
            if len(tokens.split()) < MIN_TOKENS:
                continue
            records.append({
                "raw_label": parse_raw_label(p),
                "label":     label,
                "tokens":    tokens,
                "source":    os.path.basename(p),
            })

    df = pd.DataFrame(records) if records else pd.DataFrame(
        columns=["raw_label", "label", "tokens", "source"])
    log.info(f"Loaded {len(df)} GHC files from {directory} "
             f"(capped at {max_per_label}/label, {MAX_TOKENS} tokens/file)")
    return df


def show_distribution(df: pd.DataFrame, title: str):
    print(f"\n{'─'*60}")
    print(f"  {title} — {len(df)} samples")
    print(f"{'─'*60}")
    for lbl, n in df["label"].value_counts().items():
        bar = "█" * min(n, 40)
        tag = " <- BENIGN"  if lbl == BENIGN_LABEL else \
              " <- UNKNOWN" if lbl == "__UNKNOWN__" else ""
        print(f"  {lbl:<42} {n:>5}  {bar}{tag}")
    print(f"{'─'*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# MODEL
# ══════════════════════════════════════════════════════════════════════════════

class WindowsAnomalyDetector:
    def __init__(self):
        self.vectorizer    = TfidfVectorizer(
            analyzer="word", ngram_range=NGRAM_RANGE,
            max_features=MAX_FEATURES, sublinear_tf=True,
            min_df=2, max_df=0.98, token_pattern=r"\S+",
        )
        self.label_encoder = LabelEncoder()
        self.classifier    = None
        self.iso_forest    = None
        self.iso_threshold = 0.0
        self.classes_      = None
        self.is_trained    = False

    def fit(self, train_df: pd.DataFrame, benign_extra_df: pd.DataFrame = None):
        df = train_df[train_df["label"] != "__UNKNOWN__"].copy()
        log.info(f"Training on {len(df)} samples, {df['label'].nunique()} classes")

        log.info("Fitting TF-IDF ...")
        X = self.vectorizer.fit_transform(df["tokens"])
        log.info(f"Feature matrix: {X.shape[0]} x {X.shape[1]}")

        benign_rows = df[df["label"] == BENIGN_LABEL]
        if benign_extra_df is not None and not benign_extra_df.empty:
            extra = benign_extra_df[benign_extra_df["label"] == BENIGN_LABEL]
            benign_rows = pd.concat([benign_rows, extra], ignore_index=True)
        n_benign = len(benign_rows)
        log.info(f"Isolation Forest: {n_benign} benign samples")
        X_benign = self.vectorizer.transform(benign_rows["tokens"]) \
                   if n_benign else X
        contamination = "auto" if n_benign < 20 else 0.08
        self.iso_forest = IsolationForest(
            n_estimators=300, contamination=contamination,
            max_samples=min(n_benign, 256) if n_benign else "auto",
            random_state=42, n_jobs=-1,
        )
        self.iso_forest.fit(X_benign)

        y_str = df["label"].values
        y     = self.label_encoder.fit_transform(y_str)
        self.classes_ = self.label_encoder.classes_
        weights = compute_class_weight("balanced", classes=np.unique(y), y=y)
        sw = np.array([weights[yi] for yi in y])

        if HAS_XGB:
            log.info("Training XGBoost ...")
            self.classifier = xgb.XGBClassifier(
                n_estimators=400, max_depth=7, learning_rate=0.08,
                subsample=0.8, colsample_bytree=0.8, eval_metric="mlogloss",
                tree_method="hist", random_state=42, verbosity=0, n_jobs=-1,
            )
            self.classifier.fit(X, y, sample_weight=sw)
        else:
            log.info("Training RandomForest ...")
            self.classifier = RandomForestClassifier(
                n_estimators=400, class_weight="balanced",
                random_state=42, n_jobs=-1,
            )
            self.classifier.fit(X, y)

        self.is_trained = True
        log.info("Training complete.")

    def tune_threshold(self, val_df: pd.DataFrame):
        known = val_df[val_df["label"].isin(self.label_encoder.classes_)].copy()
        if known.empty or known["label"].nunique() < 2:
            return
        X_val  = self.vectorizer.transform(known["tokens"])
        scores = self.iso_forest.decision_function(X_val)
        y_bin  = (known["label"].values != BENIGN_LABEL).astype(int)
        best_f1, best_thr = 0.0, 0.0
        for thr in np.linspace(scores.min(), scores.max(), 200):
            f1 = f1_score(y_bin, (scores < thr).astype(int), zero_division=0)
            if f1 > best_f1:
                best_f1, best_thr = f1, thr
        self.iso_threshold = best_thr
        log.info(f"Threshold tuned: {best_thr:.4f}  (val F1={best_f1:.3f})")

    def predict(self, tokens_list: list) -> list:
        assert self.is_trained
        X       = self.vectorizer.transform(tokens_list)
        scores  = self.iso_forest.decision_function(X)
        is_anom = scores < self.iso_threshold
        proba   = self.classifier.predict_proba(X)
        idx     = np.argmax(proba, axis=1)
        labels  = self.label_encoder.inverse_transform(idx)
        confs   = proba.max(axis=1)
        nz      = np.diff(X.tocsr().indptr)
        return [{
            "label":         labels[i] if is_anom[i] else BENIGN_LABEL,
            "is_anomaly":    bool(is_anom[i]),
            "confidence":    float(confs[i]),
            "anomaly_score": float(-scores[i]),
            "nonzero_feats": int(nz[i]),
        } for i in range(len(tokens_list))]

    def save(self, directory: str):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "detector.pkl")
        with open(path, "wb") as f:
            pickle.dump(self, f)
        log.info(f"Model saved -> {path}")

    @staticmethod
    def load(directory: str) -> "WindowsAnomalyDetector":
        path = os.path.join(directory, "detector.pkl")
        with open(path, "rb") as f:
            model = pickle.load(f)
        log.info(f"Model loaded <- {path}")
        return model


# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION
# ══════════════════════════════════════════════════════════════════════════════

def evaluate(det, df: pd.DataFrame, name: str):
    print(f"\n{'='*62}")
    print(f"  EVALUATION — {name}  ({len(df)} samples)")
    print(f"{'='*62}")
    unknown_df = df[df["label"] == "__UNKNOWN__"]
    eval_df    = df[df["label"].isin(det.label_encoder.classes_)].copy()
    print(f"  Known: {len(eval_df)}   Unknown: {len(unknown_df)}")
    if not eval_df.empty:
        X       = det.vectorizer.transform(eval_df["tokens"])
        scores  = det.iso_forest.decision_function(X)
        is_anom = scores < det.iso_threshold
        y_str   = eval_df["label"].values
        y_pred  = det.label_encoder.inverse_transform(det.classifier.predict(X))
        print(classification_report(y_str, y_pred, zero_division=0))
        y_bt = (y_str != BENIGN_LABEL).astype(int)
        y_bp = is_anom.astype(int)
        if y_bt.sum() > 0 and (1 - y_bt).sum() > 0:
            print(f"  ISO F1     : {f1_score(y_bt, y_bp, zero_division=0):.3f}")
            print(f"  ISO Recall : {recall_score(y_bt, y_bp, zero_division=0):.3f}")
            try:
                print(f"  AUC-ROC    : {roc_auc_score(y_bt, -scores):.3f}")
            except Exception:
                pass
    print(f"{'='*62}\n")


# ══════════════════════════════════════════════════════════════════════════════
# REAL-TIME MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class SysmonMonitor:
    ALERT_COOLDOWN_SECS = 120   # suppress repeated alerts for same PID
    MIN_FEAT_HITS       = 5     # minimum TF-IDF hits to trust a score
    MARGIN              = 0.005 # score must beat threshold by this much

    def __init__(self, detector, logfile, window=200, stride=15,
                 thresh=None, diag=False, whitelist_override=False):
        self.detector           = detector
        self.logfile            = logfile
        self.window_sz          = window
        self.stride             = stride
        self.diag               = diag
        self.whitelist_override = whitelist_override
        self.processes          = {}
        self.total_events       = 0
        self.total_scored       = 0
        self.total_suppressed   = 0
        self.total_alerts       = 0
        self.all_scores         = []
        self.alert_log          = []
        self._last_alert_time   = {}
        self._running           = True
        signal.signal(signal.SIGINT, self._stop)

        model_thr   = float(getattr(detector, "iso_threshold", 0.0))
        self.thresh = thresh if thresh is not None else -model_thr
        log.info(f"iso_threshold={model_thr:.4f}  "
                 f"alert when score > {self.thresh:+.4f} + margin {self.MARGIN}")

    def _stop(self, *_):
        self._running = False

    def _ps(self, pid, image):
        if pid not in self.processes:
            self.processes[pid] = {
                "window": deque(maxlen=self.window_sz),
                "counter": 0, "image": image, "pid": pid,
            }
        return self.processes[pid]

    def _is_whitelisted(self, image: str) -> bool:
        if self.whitelist_override:
            return False
        return os.path.basename(image).lower() in BENIGN_WHITELIST

    def _in_cooldown(self, pid: str) -> bool:
        last = self._last_alert_time.get(pid)
        return last is not None and (time.time() - last) < self.ALERT_COOLDOWN_SECS

    def _score(self, ps, high_risk=False):
        tokens_str   = " ".join(ps["window"])
        result       = self.detector.predict([tokens_str])[0]
        score        = result["anomaly_score"]
        nz           = result["nonzero_feats"]
        self.total_scored += 1
        self.all_scores.append(score)

        exe          = os.path.basename(ps["image"]).lower()
        whitelisted  = self._is_whitelisted(ps["image"])
        in_cooldown  = self._in_cooldown(ps["pid"])
        low_feats    = nz < self.MIN_FEAT_HITS
        score_ok     = score > (self.thresh + self.MARGIN)
        force_alert  = exe in HIGH_ALERT_PROCESSES

        should_alert = (
            force_alert or
            (high_risk and not whitelisted) or
            (score_ok and not whitelisted and not in_cooldown and not low_feats)
        )

        if self.diag:
            reasons = []
            if whitelisted:  reasons.append("WHITELIST")
            if in_cooldown:  reasons.append("COOLDOWN")
            if low_feats:    reasons.append(f"LOW_FEATS({nz})")
            if not score_ok: reasons.append("BELOW_MARGIN")
            sup = f"  [SUPPRESSED: {','.join(reasons)}]" \
                  if (not should_alert and (score > self.thresh or high_risk)) else ""
            tag = "<-- ALERT" if should_alert else ""
            print(f"  [DIAG] pid={ps['pid']:<6} proc={exe:<24} "
                  f"score={score:+.4f}  nz={nz:>3}  "
                  f"label={result['label']:<18} {tag}{sup}")

        if should_alert:
            self._last_alert_time[ps["pid"]] = time.time()
            self._alert(ps, result, high_risk, nz)
        elif score > self.thresh and not should_alert:
            self.total_suppressed += 1

    def _alert(self, ps, result, high_risk, nz):
        self.total_alerts += 1
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tag = "  [HIGH-RISK]" if high_risk else ""
        img = os.path.basename(ps["image"])
        print(f"\n{'#'*62}")
        print(f"  !! ANOMALY [{ts}]{tag}")
        print(f"  PID        : {ps['pid']}")
        print(f"  Process    : {img}")
        print(f"  Label      : {result['label']}")
        print(f"  Score      : {result['anomaly_score']:+.4f}  "
              f"(threshold {self.thresh:+.4f})")
        print(f"  Confidence : {result['confidence']:.1%}")
        print(f"  Feat hits  : {nz}")
        if high_risk:
            print(f"  !! CreateRemoteThread or ProcessTampering !!")
        print(f"{'#'*62}\n")
        self.alert_log.append({
            "ts": ts, "pid": ps["pid"], "image": img,
            "label": result["label"], "score": result["anomaly_score"],
            "confidence": result["confidence"], "high_risk": high_risk,
        })

    def _status(self):
        print(f"\r  Events:{self.total_events}  Scored:{self.total_scored}  "
              f"Alerts:{self.total_alerts}  Suppressed:{self.total_suppressed}   ",
              end="", flush=True)

    def _score_report(self):
        if not self.all_scores:
            print("\n[INFO] No windows scored yet.")
            return
        scores = np.array(self.all_scores)
        unique = np.unique(np.round(scores, 4))
        print(f"\n{'='*62}")
        print("  SESSION REPORT")
        print(f"{'='*62}")
        print(f"  Events     : {self.total_events}")
        print(f"  Scored     : {self.total_scored}")
        print(f"  Alerts     : {self.total_alerts}")
        print(f"  Suppressed : {self.total_suppressed}")
        print(f"  Score range: {scores.min():+.4f} to {scores.max():+.4f}")
        print(f"  Std dev    : {scores.std():.4f}")
        print(f"  Unique vals: {len(unique)}", end="")
        if len(unique) == 1:
            print("  !! ALL SAME — vocabulary mismatch — retrain needed")
        else:
            print()
        if len(unique) > 1:
            sug = float(np.percentile(scores, 95))
            print(f"\n  To flag only top 5%:  --thresh {sug:.4f}")
        print(f"{'='*62}\n")

    def run(self, from_start=False):
        print(f"\n{'='*62}")
        print(f"  Windows Sysmon Anomaly Detector")
        print(f"{'='*62}")
        print(f"  Logfile      : {self.logfile}")
        print(f"  Window/Stride: {self.window_sz} / {self.stride}")
        print(f"  Threshold    : {self.thresh:+.4f} + margin {self.MARGIN}")
        print(f"  Min feat hits: {self.MIN_FEAT_HITS}")
        print(f"  PID cooldown : {self.ALERT_COOLDOWN_SECS}s")
        print(f"  Whitelist    : {'OFF' if self.whitelist_override else f'{len(BENIGN_WHITELIST)} processes'}")
        print(f"  Vocab size   : {len(self.detector.vectorizer.vocabulary_)}")
        print(f"  Mode         : {'from start' if from_start else 'tail (new events only)'}")
        print(f"  Ctrl+C to stop\n")

        if not os.path.exists(self.logfile):
            log.error(f"Log file not found: {self.logfile}")
            sys.exit(1)

        with open(self.logfile, "r", encoding="utf-8", errors="ignore") as fh:
            if not from_start:
                fh.seek(0, 2)
            while self._running:
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    self._status()
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                token, meta = sysmon_event_to_token(event)
                if token is None:
                    continue
                self.total_events += 1
                ps = self._ps(meta["pid"], meta["image"])
                ps["window"].append(token)
                ps["counter"] += 1
                if len(ps["window"]) < 10:
                    continue
                if meta["high_risk"]:
                    self._score(ps, high_risk=True)
                elif ps["counter"] % self.stride == 0:
                    self._score(ps)

        print(f"\n  Stopped.")
        if self.alert_log:
            out = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out, "w") as f:
                json.dump(self.alert_log, f, indent=2)
            print(f"  Alert log: {out}")
        self._score_report()


# ══════════════════════════════════════════════════════════════════════════════
# VOCAB DIAGNOSTIC
# ══════════════════════════════════════════════════════════════════════════════

def vocab_check(det, ndjson_path: str, n_events: int = 500):
    vocab = set(det.vectorizer.vocabulary_.keys())
    print(f"\n{'='*62}")
    print("  VOCABULARY OVERLAP DIAGNOSTIC")
    print(f"{'='*62}")
    print(f"  Vocab size     : {len(vocab)}")
    print(f"  Sample entries : {list(vocab)[:4]}")
    sysmon_tokens = set()
    seen = 0
    with open(ndjson_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if seen >= n_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            token, _ = sysmon_event_to_token(event)
            if token:
                sysmon_tokens.add(token)
                seen += 1
    hits    = sysmon_tokens & vocab
    overlap = len(hits) / len(sysmon_tokens) if sysmon_tokens else 0
    print(f"  Sysmon tokens  : {len(sysmon_tokens)}")
    print(f"  In vocab       : {len(hits)}  ({overlap:.1%})")
    if overlap == 0:
        print("\n  !! ZERO OVERLAP — retrain with --sysmon_benign")
    elif overlap < 0.1:
        print("\n  !! LOW OVERLAP — add more Sysmon NDJSON to training")
    else:
        print("\n  GOOD overlap:")
        for t in sorted(hits)[:10]:
            print(f"    {t}")
    print(f"{'='*62}\n")


# ══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

def cmd_train(args):
    train_df = load_directory(args.train_dir)
    if train_df.empty:
        print("[ERROR] No GHC training data."); sys.exit(1)

    if args.sysmon_benign:
        dfs = []
        for path in args.sysmon_benign:
            if os.path.exists(path):
                dfs.append(load_sysmon_ndjson(path, BENIGN_LABEL))
            else:
                log.warning(f"Not found: {path}")
        if dfs:
            sdf = pd.concat(dfs, ignore_index=True)
            log.info(f"Adding {len(sdf)} Sysmon benign windows")
            train_df = pd.concat([train_df, sdf], ignore_index=True)

    if args.sysmon_attack:
        for path, label in args.sysmon_attack:
            if os.path.exists(path):
                sdf = load_sysmon_ndjson(path, label, max_windows=300)
                log.info(f"Adding {len(sdf)} attack windows (label={label})")
                train_df = pd.concat([train_df, sdf], ignore_index=True)

    show_distribution(train_df, "Training Data")

    extra_benign = pd.DataFrame()
    if args.val_dir and os.path.isdir(args.val_dir):
        val_all      = load_directory(args.val_dir)
        extra_benign = val_all[val_all["label"] == BENIGN_LABEL]

    det = WindowsAnomalyDetector()
    det.fit(train_df, benign_extra_df=extra_benign)

    if args.val_dir and os.path.isdir(args.val_dir):
        val_df = load_directory(args.val_dir)
        det.tune_threshold(val_df)
        evaluate(det, val_df, "Validation")

    if args.attack_dir and os.path.isdir(args.attack_dir):
        evaluate(det, load_directory(args.attack_dir), "Attack")

    det.save(args.model_path)
    print(f"\nModel  : {args.model_path}/detector.pkl")
    print(f"Vocab  : {len(det.vectorizer.vocabulary_)} features")
    print(f"Thresh : {det.iso_threshold:.4f}")
    print(f"\nRun detector:")
    print(f"  python windows_detector_final.py run \\")
    print(f"    --model_path {args.model_path} \\")
    print(f"    --logfile <your_log.ndjson>")


def cmd_run(args):
    det = WindowsAnomalyDetector.load(args.model_path)
    mon = SysmonMonitor(
        det, args.logfile,
        window=args.window, stride=args.stride,
        thresh=args.thresh, diag=args.diag,
        whitelist_override=args.no_whitelist,
    )
    mon.run(from_start=args.from_start)


def cmd_vocab(args):
    det = WindowsAnomalyDetector.load(args.model_path)
    vocab_check(det, args.logfile)


def main():
    ap  = argparse.ArgumentParser(description="Windows Anomaly Detector v4")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("train", help="Train the model")
    pt.add_argument("--train_dir",     required=True)
    pt.add_argument("--val_dir")
    pt.add_argument("--attack_dir")
    pt.add_argument("--model_path",    default="saved_model_v3")
    pt.add_argument("--sysmon_benign", nargs="+", metavar="NDJSON",
                    help="Benign Sysmon NDJSON files to add as Background")
    pt.add_argument("--sysmon_attack", nargs="+", metavar="NDJSON:LABEL",
                    help="Attack NDJSON files: path:Label e.g. attack.ndjson:Browser-Attack")

    pr = sub.add_parser("run", help="Real-time monitoring")
    pr.add_argument("--model_path",   default="saved_model_v3")
    pr.add_argument("--logfile",      required=True)
    pr.add_argument("--from_start",   action="store_true",
                    help="Read log from beginning (default: tail new events only)")
    pr.add_argument("--diag",         action="store_true",
                    help="Show every score including suppressed ones")
    pr.add_argument("--no_whitelist", action="store_true",
                    help="Disable whitelist (alert for ALL processes)")
    pr.add_argument("--window",       type=int,   default=200)
    pr.add_argument("--stride",       type=int,   default=15)
    pr.add_argument("--thresh",       type=float, default=None)

    pv = sub.add_parser("vocab", help="Check vocabulary overlap")
    pv.add_argument("--model_path", default="saved_model_v3")
    pv.add_argument("--logfile",    required=True)

    args = ap.parse_args()

    if hasattr(args, "sysmon_attack") and args.sysmon_attack:
        parsed = []
        for item in args.sysmon_attack:
            if ":" in item:
                path, label = item.rsplit(":", 1)
                parsed.append((path, label))
        args.sysmon_attack = parsed or None

    {"train": cmd_train, "run": cmd_run, "vocab": cmd_vocab}[args.cmd](args)


if __name__ == "__main__":
    main()