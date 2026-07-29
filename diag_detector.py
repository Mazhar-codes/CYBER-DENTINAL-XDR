import sys, pickle

class WindowsAnomalyDetector:
    pass
setattr(sys.modules["__main__"], "WindowsAnomalyDetector", WindowsAnomalyDetector)

DETECTOR_PATH = r"D:\Cyber Sentinal\System Behavior\System_Behavior_Model\DETECTOR1\saved_model_v3\detector.pkl"
ATK_FILE = r"D:\Cyber Sentinal\System Behavior\Dataset_1\Full_Process_Traces\Full_Trace_Attack_Data\V1-CesarFTP-N1-1\V1-CesarFTP-N1-1_1048.GHC"

import joblib
det = joblib.load(DETECTOR_PATH)
print("label_encoder.classes_:", list(det.label_encoder.classes_))
print("classifier.classes_   :", list(det.classifier.classes_))

import glob
bg_dir = r"D:\Cyber Sentinal\System Behavior\Dataset_1\Full_Process_Traces\Full_Trace_Validation_Data"
bg_candidates = glob.glob(bg_dir + r"\*.GHC") + glob.glob(bg_dir + r"\*.ghc")
BG_FILE = bg_candidates[0]
print("\nUsing background file:", BG_FILE)
print("Using attack file     :", ATK_FILE)

for label, path in [("BACKGROUND (real validation file)", BG_FILE),
                     ("ATTACK (real CesarFTP file)", ATK_FILE)]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    doc = " ".join(text.split())
    X = det.vectorizer.transform([doc])
    proba = det.classifier.predict_proba(X)[0]
    pred_idx = det.classifier.predict(X)[0]
    pred_name = det.label_encoder.inverse_transform([pred_idx])[0]
    print(f"\n=== {label} ===")
    print(f"  predicted class: {pred_name}")
    print(f"  full probability vector (class -> prob):")
    for cls, p in zip(det.label_encoder.classes_, proba):
        print(f"    {cls:25s}: {p:.4f}")
