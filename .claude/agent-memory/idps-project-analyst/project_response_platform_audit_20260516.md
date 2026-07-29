---
name: Response Platform Audit — 2026-05-16
description: Enterprise Response Philosophy compliance audit — all 16 attack scenarios, reversibility gaps, permission issues, severity mis-mappings in response_engine.py and SOAR pipeline
type: project
---

Audit of the response platform against the user-defined Enterprise Response Philosophy (LOW=log, MEDIUM=alert, HIGH=analyst approval, CRITICAL=auto-execute).

**Health score: 5.8/10**

**Why:** 7 of 16 attack scenarios fall through to the generic default handler with no typed response plan. 2 critical reversibility gaps (unisolate_host missing from server executor; unlock_account missing from entire codebase). lock_account misclassified as advisory when it is fully executable.

**How to apply:** When reviewing any response_engine.py changes, ensure all 16 attack scenarios have dedicated branches. When reviewing backend.py _server_soar_executor, verify unisolate_host and unlock_account are present.

---

## Critical Bugs Found (Phase 1 priority)

1. `unisolate_host` is ABSENT from `_server_soar_executor` in `backend.py`. Server host isolation is irreversible via SOAR. Fix: add `elif action == "unisolate_host"` block after line 3529 in backend.py.

2. `unlock_account` does not exist ANYWHERE. `lock_account` is permanently irreversible. Fix: add `_action_unlock_account()` in `endpoint_agent/command_listener.py` + `elif action == "unlock_account"` in `backend.py` server executor.

3. `lock_account` is in `_ADVISORY_ACTIONS` (backend.py line 3733) but is a fully executable action in the endpoint agent. It is never dispatched. Fix: move to `_ENDPOINT_VALID_ACTIONS`.

4. IP validation regex in `_server_soar_executor` block_ip/unblock_ip uses weaker pattern than endpoint agent (misses octet range validation). Fix: use same `_IP_RE` pattern from command_listener.py.

5. `lock_account` in server executor lacks username input validation regex (endpoint agent has it). Injection risk low (shell=False) but input validation is inconsistent.

6. `auto_execute = severity == "CRITICAL"` is attack-type-agnostic — Port Scan and Lateral Movement can auto-execute at CRITICAL. Philosophy mandates analyst approval for these. Fix: add `_NO_AUTO_EXECUTE_ATTACKS` frozenset override.

## Attack Scenarios With No Response Plan (7)
- Process Injection
- Persistence Mechanism
- Impossible Travel
- Insider Threat (MITRE_MAP entry exists but no elif branch in response_engine.py)
- Trojan/Malware (arrives via malware fusion path but no named branch)
- Worm
- Rootkit

## Missing SOAR Actions (not implemented in any execution plane)
- `unlock_account`
- `unisolate_host` (server side only — endpoint agent has it)
- `restore_quarantine_file`
- `rate_limit_traffic` (advisory stub, no netsh/Suricata implementation)
- `invalidate_sessions` (not wired to auth system)
- `disable_smb_rdp`
- `remove_persistence`

## Report file
`D:\Cyber Sentinal\timeline\response_platform_audit_20260516_202212.md`
