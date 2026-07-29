---
name: User Behavior Layer — IsolationForest Retrain (2026-04-21)
description: Records what changed in the user behavior detection layer on 2026-04-21, key bugs found, and outstanding gaps
type: project
---

On 2026-04-21 the OC-SVM user behavior model was replaced with an IsolationForest (200 trees, contamination=0.05) trained on 330,452 CERT r4.2 user-day records. The new model correctly flags bulk-file sessions (score 0.4713 > threshold 0.3). Feature set expanded from 12 to 19. Fast-path rules added: file_ops >= 300 → ANOMALY immediately, unique_dirs >= 50 → ANOMALY.

**Why:** OC-SVM was scoring 1000 file creates + 20-pass reads + 200 dir scans as NORMAL — a confirmed detection failure.

**How to apply:** When reviewing user behavior code or scores, the active model is IsolationForest, threshold = 0.3. The old OC-SVM artifacts are gone. The file retrain_corrected_answers_metrics.json in final_model_backend_only is from an even older 12-feature model and is deprecated.

Key bug found and NOT yet fixed as of this analysis:
- backend.py _handle_user_result lines 595-599: double-applies sigmoid to an already-[0,1] score. This inverts display scores on the dashboard. Must be fixed — replace display_score sigmoid with raw_score passthrough.

Key remaining gaps:
- OCEAN features still all 0.0 (no live source)
- Winlogbeat not confirmed writing to C:\XDR_Logs\ — win32evtlog fallback active
- unique_dirs fast-path fires but is not reflected in output rows or reason strings
- network_classifier.pkl not trained (blocks SHAP for network events)
- personal_baseline_model.pkl not trained (blocks Gate 1 network detection)
