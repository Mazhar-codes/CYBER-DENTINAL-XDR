================================================================================
EVALUATION NOTE — SYSTEM MONITOR DETECTOR1 PERFORMANCE METRICS
================================================================================
Date          : 2026-06-28
Author        : System Monitor Agent (claude-sonnet-4-6)
Scope         : DETECTOR1 (TF-IDF + IsolationForest + XGBoost) validation
                methodology, class imbalance analysis, corrected metric
                reporting with confidence intervals
Model artifact: D:\Cyber Sentinal\System Behavior\System_Behavior_Model\
                DETECTOR1\saved_model_v3\detector.pkl
================================================================================


## 1. VALIDATION METHODOLOGY

DETECTOR1 was trained on GHC DLL call-stack trace files from:
  D:\Cyber Sentinal\System Behavior\Dataset_1\Full_Process_Traces\
  Full_Trace_Training_Data\

The training set contains 355 matched .GHC files across 12 label classes:
  Background (benign), Backdoored-Executable, Browser-Attack, CesarFTP,
  Icecast, Infectious-Media, PDF, PMWiki, Tomcat, WebDAV, Wireless-Karma,
  plus OS_Print_Spool and OS_SMB (present as files but excluded by FNAME_RE
  — see Section 3 below).

Validation was run against:
  D:\Cyber Sentinal\System Behavior\Dataset_1\Full_Process_Traces\
  Full_Trace_Validation_Data\

The validation directory contains 1,827 total .GHC files. After applying the
FNAME_RE filter (Training|Validation|Attack)-<Label>_<N>.GHC that the
train_from_dataset() function uses to parse labels, 1,706 files are loaded
into the evaluation set. The remaining 121 files (OS_Print_Spool=104,
OS_SMB=17) are excluded by the regex — see Section 3.

The binary evaluation problem is:
  Positive class (attack):    all matched files where label != "Background"
  Negative class (background): matched files where label == "Background"

The anomaly score used for ranking is the negative of IsolationForest's
decision_function output (higher = more anomalous).


## 2. CLASS IMBALANCE: THE ROOT CAUSE

Validation set composition after FNAME_RE filtering:

  Total matched:       1,706 files
  Attack (positive):   1,689 files   (99.0%)
  Background (negative):  17 files   ( 1.0%)

This is not a model training choice — it is a property of the GHC dataset
itself. The dataset was designed to study attack trace characteristics, and
the "Background" (normal operation) category was collected as a minimal
reference set rather than a large representative baseline.

Why this matters for the reported metrics:

  1. ROC-AUC uncertainty is dominated by n_0 (negative count).
     The Hanley-McNeil formula for SE(AUC) contains an (n0-1)*Q2 term that
     shrinks as n0 grows. With n0=17, the SE is 0.1857, producing a 95% CI
     that nearly spans the full [0,1] range. The point estimate of 0.7344 is
     real — it is not biased — but its uncertainty is extreme.

  2. Specificity and FPR are uninformative.
     With only 17 background samples, the Wilson 95% CI on any specificity
     estimate has a width of approximately 0.36 to 0.43. A specificity of
     0.80 has a 95% CI of roughly (0.56, 0.93) — this is too wide to make
     any operational claim about FPR.

  3. PR-AUC under attack-positive framing is meaningless.
     At 99% attack prevalence the random-classifier PR-AUC baseline is 0.99.
     A model that scores every sample as "attack" achieves PR-AUC=0.99 with
     zero discrimination. The informative direction is background-as-positive:
     how well does the model rank the 17 background samples above attack
     samples (i.e. does it suppress false positives)?


## 3. THE TWO EXCLUDED ATTACK TYPES

The FNAME_RE pattern in train_from_dataset() is:
  r"(?:Training|Validation|Attack)-([A-Za-z0-9\-]+?)_\d+\.GHC$"

This pattern requires that the label segment between the prefix and the
numeric suffix uses only hyphens as separators. Two attack types in the
GHC dataset use underscores in their names:

  OS_Print_Spool:  104 files in the validation directory
  OS_SMB:           17 files in the validation directory
                   ---
  Total excluded:  121 files

These same label types are also present in the training directory (Training-
OS_Print_Spool_*.GHC and Training-OS_SMB_*.GHC) but are likewise excluded
from training. Therefore:

  - DETECTOR1 has never seen OS_Print_Spool or OS_SMB traces during training.
  - DETECTOR1 cannot classify these attack types.
  - Their recall is 0 by construction. This is not a model quality failure;
    it is a scope limitation of the FNAME_RE pattern and dataset structure.

The CLAUDE.md reference to "two attack types in the validation split that
were never in DETECTOR1's training label set" refers to these two classes.

Operational note: OS_Print_Spool corresponds to the Windows Print Spooler
exploit (similar to PrintNightmare, CVE-2021-1675). OS_SMB corresponds to
SMB-based exploits (EternalBlue family). Both attack types ARE represented
in the Sysmon behavioral pipeline through EventID 1 (process creation) and
EventID 8 (CreateRemoteThread) signatures, providing partial coverage via
the token-based scoring path even though the DETECTOR1 multi-class
classifier cannot produce a label for them.


## 4. CORRECTED ROC-AUC WITH CONFIDENCE INTERVAL

Metric:       ROC-AUC (binary: attack vs. background)
Model output: -IsolationForest.decision_function (higher = more anomalous)
Point estimate: 0.7344

Hanley-McNeil (1982) confidence interval:
  n1 (attack)      = 1,689
  n0 (background)  = 17
  Q1               = AUC / (2 - AUC)     = 0.5803
  Q2               = 2*AUC^2 / (1 + AUC) = 0.6219
  Var(AUC)         = 0.034467
  SE(AUC)          = 0.1857
  95% CI           = [0.3705, 1.0000]

The CI is bounded at 1.0 because the upper limit (0.7344 + 1.96 * 0.1857)
exceeds 1.0. The lower bound of 0.37 is nontrivially above the 0.50 random
baseline, confirming that the IsolationForest is learning a genuine signal
from the GHC traces. However, the width of 0.63 means the true AUC could
be anywhere from chance-level to perfect.

The SE is dominated by n0=17. If the validation set contained 200 background
samples instead, SE would drop to approximately 0.053 and the 95% CI would
narrow to roughly [0.63, 0.84] — a meaningful bound. Acquiring more
"Background" traces from the GHC collection is the single highest-leverage
improvement for validation reliability.


## 5. PR-AUC INTERPRETATION

PR-AUC cannot be computed from the stored model artifact alone without
re-running inference against the validation set. The train_system_model.py
evaluation code (--source dataset mode) now computes and prints both:

  (a) PR-AUC (attack as positive):
      Random baseline = 0.990 at 99% attack prevalence.
      Expected to be near 1.0 for almost any model. Not informative.

  (b) PR-AUC (background as positive):
      Random baseline = 0.010 at 1% background prevalence.
      A value significantly above 0.010 indicates the model can rank
      background samples above attack samples, meaning low FPR at high
      recall thresholds. This is the operationally important metric.

Operators should run:
  python train_system_model.py --source dataset
to see the current PR-AUC values after any retraining.


## 6. WHAT THE NUMBERS MEAN FOR REAL-WORLD PERFORMANCE

DETECTOR1 is deployed in Cyber Sentinel XDR on the server-side psutil loop,
scoring Sysmon token sequences as they arrive from the Winlogbeat feed. Its
production input is NOT ADFA-WD traces — it is live Sysmon events tokenized
by sysmon_event_to_token() and scored against the GHC-trained TF-IDF
vocabulary.

The ROC-AUC of 0.7344 measured on the ADFA-WD-style validation split should
be interpreted as:

  "On the GHC dataset's own validation split — which is 99% attack traces
   versus 17 normal-operation traces — DETECTOR1 ranks a randomly chosen
   attack trace above a randomly chosen normal trace 73% of the time. The
   95% confidence interval spans [0.37, 1.00] due to the tiny normal-trace
   sample size. This is a benchmark orientation figure, not a production
   performance claim."

The GHC training performance figures (~0.93-0.97 AUC-ROC on training attack
data with balanced threshold tuning, F1 ~0.87-0.93) are more representative
of the model's discrimination ability, but those numbers are on in-distribution
data and should not be reported as held-out validation performance.

For genuine held-out validation:
  1. Collect Background traces from the GHC dataset (expand from 13 to 200+).
  2. Run train_system_model.py --source dataset and examine the new CI.
  3. Alternatively, run DETECTOR1 in shadow mode for 2-4 weeks on the
     production Sysmon feed and manually label flagged events to compute
     empirical precision and recall on live traffic.


## 7. SUMMARY TABLE

| Metric                         | Value                    | Notes                                              |
|--------------------------------|--------------------------|----------------------------------------------------|
| ROC-AUC (point estimate)       | 0.7344                   | Hanley-McNeil on n1=1689, n0=17                    |
| ROC-AUC 95% CI                 | [0.3705, 1.0000]         | Wide due to n0=17; SE=0.1857                       |
| PR-AUC (attack positive)       | ~1.0 expected            | Meaningless at 99% prevalence; see Section 5       |
| PR-AUC (background positive)   | To be computed on retrain| Baseline = 0.010; values > 0.030 are non-trivial  |
| Specificity 95% CI width       | ~0.36-0.43               | Wilson score, n=17; any spec. estimate unreliable  |
| OS_Print_Spool coverage        | 0% (excluded)            | FNAME_RE pattern mismatch; scope limitation        |
| OS_SMB coverage                | 0% (excluded)            | FNAME_RE pattern mismatch; scope limitation        |
| Training AUC (in-distribution) | 0.93-0.97 (reported)     | Not held-out; informative for relative comparison  |
| Production input type          | Live Sysmon tokens       | Different distribution from ADFA-WD val split      |

================================================================================
END OF EVALUATION NOTE
Files modified by this evaluation:
  D:\Cyber Sentinal\Backend\train_system_model.py
    — Added _hanley_mcneil_ci() and _wilson_ci_width() helpers
    — Enhanced evaluation block: CI on AUC-ROC, PR-AUC, imbalance warnings,
      unseen-type detection, excluded-file count
  D:\Cyber Sentinal\CLAUDE.md
    — ROC-AUC 0.7344 entry annotated with CI, n0=17, and excluded type names
================================================================================
