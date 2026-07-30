# Analysis: "Fixing the Two Underperforming Agents" — Should We Do These Improvements?

_Assessment of `improvements future must.pdf` for Cyber Sentinel XDR._
_Written 2026-07-30._

## Verdict in one line
**Yes — do it, but understand what kind of win it is.** The PDF is correct and high-quality.
Most of its recommendations will **not raise your headline accuracy numbers** — several will
*lower* them — but they will **dramatically raise the project's credibility and scientific
validity**, which is worth far more for a thesis/paper than an inflated 99%. The single most
valuable change (fixing evaluation methodology) is also one of the cheapest.

> Key mental shift the PDF is pushing: **stop optimizing for a big accuracy number, start
> optimizing for an honest, defensible evaluation.** A reviewer trusts an honest 0.85 far more
> than a suspicious 0.99.

---

## What the PDF says (summary)

It targets the two weakest agents:

### Agent 1 — Insider Threat / User Behavior (IsolationForest, CERT r4.2)
- Your **0% precision/recall is a *threshold* artifact, not a model failure** — ROC-AUC 0.83
  proves the model has real signal. The score just never crosses the fixed τ=0.80.
- **Accuracy / fixed-threshold F1 are the wrong metrics** for this extreme class imbalance.
  The field uses **Cumulative Recall at budget k (CR-k)** and **PR-AUC**.
- **OCEAN personality features are a liability** — synthetic in CERT, absent in real orgs,
  and you already substitute proxies at inference (a train/deploy mismatch). Ablate & likely drop.
- Realistic one-class numbers cluster at **AUC 0.85–0.95**; supervised 0.99s exploit synthetic
  scenarios + data leakage → report them only as an *upper bound*.

### Agent 2 — Host / System Behavior (DETECTOR1 on ADFA-WD)
- **ADFA-WD is a broken foundation**: Windows-XP-SP2-era, tiny, known-hard (best honest
  published detection ~64–72%). Your 98.91% accuracy / AUC 0.7344 with CI [0.37, 1.00] is
  **statistically meaningless** (17-negative validation split).
- **Fatal train/deploy mismatch**: trained on ADFA-WD DLL traces, deployed on live Sysmon.
- **Two attack classes (OS_Print_Spool, OS_SMB) are excluded by a regex bug** → guaranteed 0
  recall on them. Fixable in hours.
- Fix: **migrate to Sysmon-native labeled data** (Atomic Red Team + Sysmon self-generated,
  EVTX-ATTACK-SAMPLES, Mordor, or a DARPA OpTC host subset) + add a **Sigma-rule baseline**.
- **Don't chase fancy architectures** (USAD/TranAD/Anomaly Transformer) — their gains are largely
  an illusion of the point-adjust evaluation protocol.

### Cross-cutting
- A perfectly synchronized network+host+identity labeled corpus **doesn't really exist** — say so;
  DARPA OpTC / Unraveled are the best available.
- **Head-to-head comparison tables vs named published baselines are the single cheapest
  credibility win.**

---

## My assessment — per recommendation

| # | Recommendation | Worth it? | Effort | Effect |
|---|---|---|---|---|
| 1 | **Fix evaluation: PR-AUC + CR-k, characterize τ=0.50, drop fixed-accuracy F1** | ✅ **Highest ROI** | ~days | Turns the embarrassing 0% F1 into a real, defensible number. Pure win. |
| 2 | **Fix the excluded-class regex** (OS_Print_Spool, OS_SMB) | ✅ Yes | hours | Real bug; removes a guaranteed-0-recall artifact. |
| 3 | **Build comparison tables vs named baselines** | ✅ Yes | days | Cheapest credibility gain; makes the paper look serious. |
| 4 | **Add Sigma-rule / MITRE baseline (Zircolite + SigmaHQ) on host side** | ✅ Yes | days | Standard, cheap, directly comparable; shows where ML adds value. |
| 5 | **Generate same-distribution Sysmon training data (Atomic Red Team)** | ✅ Yes (flagship) | 1–2 wks | Fixes the disqualifying train/deploy mismatch for Agent 2. Biggest scientific-validity win. |
| 6 | **Add supervised LightGBM/XGBoost insider benchmark** (user-disjoint splits) | ✅ Yes | days | Strong labeled upper bound alongside the deployable one-class model. |
| 7 | **Ablate & likely drop OCEAN features** | ✅ Yes | days | Removes a methodological liability; strengthens the honesty narrative. |
| 8 | **Migrate to CERT r5.2/r6.2; evaluate fusion on OpTC/Unraveled** | ⚠️ If time | 1–2 wks | Nice-to-have; larger/newer data. Not blocking. |
| 9 | **Provenance GNN (ThreaTrace/FLASH) or LSTM-VAE** | ❌ Low priority | high/risky | The PDF itself says don't chase this. Only if 1–8 are done. |

---

## Will this make the project "more accurate"?

**Honest answer: not in the way you might hope — and that's fine.**
- Some numbers will **go DOWN** when reported honestly (e.g., the host agent's "98.91%" is not
  real; PR-AUC on the insider agent will be a modest, believable value; dropping OCEAN may barely
  move AUC). That is the *point* — the current high numbers are artifacts.
- What goes **UP** is **credibility, reproducibility, and scientific validity** — the things a
  thesis committee or paper reviewer actually judges. An examiner who sees "we identified our own
  evaluation was inflated and corrected it" scores that higher than a shiny 99%.
- Detection *capability* genuinely improves in one place: **fixing the τ threshold + regex bug**
  converts models that currently *appear* broken (0% F1, 0 recall on 2 classes) into working ones.

So: **more credible and more honest = yes, strongly. Bigger headline accuracy = no (deliberately).**

---

## Is it possible (for a student team, given the timeline)?

- **This week / cheap (do first):** #1 metrics reinstrumentation, #2 regex fix, #3 comparison
  tables, #7 OCEAN ablation. These are mostly *analysis + reporting* changes — very feasible,
  no new infrastructure.
- **1–2 weeks:** #4 Sigma baseline, #5 Atomic Red Team Sysmon generation, #6 supervised insider
  benchmark. Feasible on your existing Windows box; #5 is the highest-value medium effort.
- **Stretch / optional:** #8 dataset migration, #9 GNN. Skip unless everything else is done.

⚠️ **Timeline reality:** the FIT 2026 paper deadline is very near (Jul 31). Only the
*framing/reporting* wins (#1 discussion, #3 tables, the honesty paragraphs) are realistically
doable before that. The data/model work (#5, #6, #8) is for the **thesis / a later paper
revision**, not tomorrow. Prioritize the "why accuracy is misleading here" paragraph + PR-AUC
recomputation for the immediate deadline.

---

## Recommended order (mirrors the PDF's ranked plan)
1. Reinstrument insider eval → PR-AUC + recall-at-budget; characterize τ=0.50. **(convert 0% F1 → real number)**
2. Fix the host-agent excluded-class regex.
3. Write the "why accuracy is misleading under extreme imbalance" section + honest comparison tables.
4. OCEAN ablation (report with/without; state non-deployability).
5. Sigma/Zircolite host baseline.
6. Atomic Red Team + Sysmon self-generated training set (fixes Agent 2's foundation).
7. Supervised LightGBM insider benchmark (user-disjoint, time-respecting splits).
8. (Optional) CERT r6.2 + OpTC/Unraveled fusion eval.

## Bottom line
The PDF is right. These aren't "make the demo flashier" changes — they're "make the science
defensible" changes, and that is exactly what elevates an FYP/paper from *looks impressive* to
*is trustworthy*. Do the cheap methodology + honesty fixes immediately; schedule the Sysmon-native
data work for the thesis phase; ignore the GNN unless you have spare time.
