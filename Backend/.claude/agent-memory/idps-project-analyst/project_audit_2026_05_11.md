---
name: Full Project Audit 2026-05-11
description: Confirmed bugs and gaps from comprehensive file-verified project audit; overall 93% complete, 8.4/10 health
type: project
---

Full project audit completed 2026-05-11 by reading actual files.

**Overall: 93% complete, health 8.4/10. Lab/Demo ready. NOT yet production ready.**

## Confirmed Active Bugs (not fixed as of audit date)

**BUG-001** — `unisolate_host` missing from `_ENDPOINT_VALID_ACTIONS` frozenset in backend.py line 3418.
POST /endpoint/command with action="unisolate_host" always returns HTTP 400.
Fix: add "unisolate_host" to the frozenset.

**BUG-002** — Heartbleed advisory actions (`patch_openssl`, `rotate_certificates`,
`check_exposed_secrets`, `update_software`) are NOT in `_ADVISORY_ACTIONS` frozenset
(backend.py line 3423). They get forwarded to the endpoint agent as executable actions,
which rejects them, causing partial failure of Heartbleed response plans.
Fix: add all four to `_ADVISORY_ACTIONS`.

**BUG-003** — `torch` is not listed in `Backend/requirements.txt` even though
SystemMonitorAgent requires it. Fresh install will silently fail; system score=0.0 always.
Fix: add `torch>=2.0.0` to requirements.txt.

## Key Verified Facts

- sklearn version in active venv: 1.7.2 (system_model.pt retrained today — compatible)
- PyTorch version in venv: 2.11.0+cpu (installed, just not in requirements.txt)
- reportlab version in venv: 4.5.0 (PDF reports work)
- `reports/` directory exists at D:\Cyber Sentinal\reports
- `D:\Cyber Sentinal\timeline` directory exists
- personal_baseline_model.pkl exists (2.6 MB)
- system_metadata.json threshold: 3.5685651302337646 (retrained today)
- Frontend .env does NOT exist — 15 files hardcode http://localhost:8000

## Layer Completion Summary

Network Detection: 97% | User Behavior: 65% (OCEAN=0.0) | System Monitor: 90%
Malware: 99% | Fusion Engine: 100% | SHAP: 85% (Sysmon not covered)
SOAR/Endpoint: 95% (BUG-001) | EDR: 97% (BUG-002) | Auth: 98% | MongoDB: 99%
Frontend: 97% | Attack Graph: 93% | Replay: 93% | PDF: 97%

## Why not production ready

1. JWT stored in localStorage (XSS-extractable) — not httpOnly cookies
2. No TLS between endpoint agent and backend (API key in plaintext HTTP)
3. In-memory rate limiter resets on server restart
4. START_WINLOGBEAT config setting has no effect (no subprocess launcher)

**Why:** Production deployment to real SOC environment requires these security controls.
**How to apply:** Do not recommend this as production-ready. Frame as "lab-ready after P0 fixes."
