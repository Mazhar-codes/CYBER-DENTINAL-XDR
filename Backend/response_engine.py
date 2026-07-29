"""
Response Engine — Cyber Sentinel XDR
Generates intelligent rule-based response plans from fusion alerts.
Maps attack types to MITRE ATT&CK techniques and recommended SOAR actions.
No LLM dependency — pure deterministic rule matching.
"""
import re
import uuid
from datetime import datetime, timezone

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique registry
# ---------------------------------------------------------------------------
_MITRE_MAP = {
    "ransomware":            "T1486",
    "c2 beaconing":          "T1071",
    "botnet":                "T1071",
    "privilege escalation":  "T1068",
    "lateral movement":      "T1021",
    "portscan":              "T1046",
    "port scan":             "T1046",
    "ddos":                  "T1498",
    "dos":                   "T1498",
    "brute force":           "T1110",
    "bruteforce":            "T1110",
    "infiltration":          "T1190",
    "heartbleed":            "T1190",
    "advanced persistent":   "T1059",
    "insider threat":        "T1078.004",
    "impossible travel":     "T1078",
    "malware":               "T1204",
    "trojan":                "T1204",
    "worm":                  "T1210",
    "rootkit":               "T1014",
    "process injection":     "T1055",
    "persistence":           "T1547",
    "system anomaly":        "T1496",
    "suspicious process":    "T1059",
    # Behavioral detector labels (translated from SystemMonitorAgent DETECTOR1 output)
    "backdoor":              "T1059",      # Backdoor Execution → Command and Scripting Interpreter
    "ftp exploit":           "T1190",     # FTP Exploit → Exploit Public-Facing Application
    "smb exploit":           "T1021.002", # SMB Exploit → Remote Services: SMB/Windows Admin Shares
    "print spooler":         "T1021.002", # Print Spooler Exploit → Remote Services
    "browser exploit":       "T1189",     # Browser Exploit → Drive-by Compromise
    "pdf exploit":           "T1189",     # PDF Exploit → Drive-by Compromise
    "removable media":       "T1091",     # Removable Media Attack → Replication Through Removable Media
    "web server exploit":    "T1190",     # Web Server Exploit → Exploit Public-Facing Application
    "webdav exploit":        "T1190",     # WebDAV Exploit → Exploit Public-Facing Application
    "wiki cms exploit":      "T1190",     # Wiki CMS Exploit → Exploit Public-Facing Application
    "media server exploit":  "T1190",     # Media Server Exploit → Exploit Public-Facing Application
    "rogue ap":              "T1557",     # Rogue AP Attack → Adversary-in-the-Middle
}

_DEFAULT_MITRE = "T1059"

# Attack types that must NEVER auto-execute regardless of severity.
# These require human review before any SOAR action is taken.
_NO_AUTO_EXECUTE_ATTACKS = frozenset({
    "port scan",
    "portscan",
    "lateral movement",
    "privilege escalation",
    "insider threat",
    "impossible travel",
})


def _match_attack(attack_type: str) -> str:
    """Return the lowercase attack_type string normalized for keyword matching."""
    return (attack_type or "").lower()


def _get_mitre(attack_lower: str) -> str:
    for keyword, technique in _MITRE_MAP.items():
        if keyword in attack_lower:
            return technique
    return _DEFAULT_MITRE


def _derive_domain(sources: list) -> str:
    """Map contributing model sources to human-readable domain label."""
    src_set = {str(s).lower() for s in (sources or [])}
    parts = []
    if "network" in src_set:
        parts.append("Network")
    if "user" in src_set:
        parts.append("User Behavior")
    if "system" in src_set:
        parts.append("System")
    if "malware" in src_set:
        parts.append("Malware")
    return " + ".join(parts) if parts else "Multi-Domain"


def _extract_ip_target(fusion_alert: dict, shap_explanation: list):
    """
    Return a valid IPv4 block target, or None if no real IP can be determined.
    Priority: fusion_alert['src_ip'] → SHAP ip features → None (never a placeholder).
    """
    # Priority 1: direct src_ip carried in the fusion alert dict
    for key in ("src_ip", "source_ip", "attacker_ip", "remote_ip"):
        candidate = str(fusion_alert.get(key, "")).strip()
        if candidate and _IPV4_RE.match(candidate):
            return candidate

    # Priority 2: IP-labelled feature in SHAP explanation
    for item in (shap_explanation or []):
        if not isinstance(item, dict):
            continue
        feature_name = str(item.get("feature", "")).lower()
        feature_value = str(item.get("value", "")).strip()
        if any(kw in feature_name for kw in ("ip", "src", "dst", "dest", "host")):
            if feature_value and _IPV4_RE.match(feature_value):
                return feature_value

    # Priority 3: any SHAP value that looks like an IPv4 address
    for item in (shap_explanation or []):
        if not isinstance(item, dict):
            continue
        val = str(item.get("value", "")).strip()
        if val and _IPV4_RE.match(val):
            return val

    return None  # no valid IP — caller must skip the block_ip action


def _block_ip_action(target_ip, reason: str):
    """Return a block_ip action dict, or None if target_ip is invalid."""
    if not target_ip or not _IPV4_RE.match(str(target_ip)):
        return None
    return {"action": "block_ip", "target": str(target_ip), "reason": reason}


def _extract_shap_target(shap_explanation: list) -> str:
    """Legacy shim — returns 'suspicious_ip' fallback. Prefer _extract_ip_target."""
    for item in (shap_explanation or []):
        if not isinstance(item, dict):
            continue
        feature_name = str(item.get("feature", "")).lower()
        feature_value = str(item.get("value", "")).strip()
        if any(kw in feature_name for kw in ("ip", "src", "dst", "dest", "host")):
            if feature_value and feature_value not in ("0", "0.0", "", "nan", "unknown"):
                return feature_value
    return "suspicious_ip"


# ---------------------------------------------------------------------------
# Core plan-generation function
# ---------------------------------------------------------------------------

def generate_response_plan(fusion_alert: dict) -> dict:
    """
    Generate a structured response plan from a fusion alert.

    Parameters
    ----------
    fusion_alert : dict
        {
          "endpoint_id": str,
          "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
          "attack_type": str,
          "contributing_signals": list,
          "shap_explanation": list,
          "threat_score": float
        }

    Returns
    -------
    dict
        {
          "plan_id": str,
          "endpoint_id": str,
          "severity": str,
          "risk_level": str,
          "summary": str,
          "mitre_technique": str,
          "recommended_actions": list[dict],
          "auto_execute": bool,
          "created_at": datetime
        }
    """
    endpoint_id = str(fusion_alert.get("endpoint_id", "unknown"))
    severity = str(fusion_alert.get("severity", "LOW")).upper()
    attack_type = str(fusion_alert.get("attack_type", "Unknown"))
    shap_explanation = fusion_alert.get("shap_explanation") or []
    threat_score = float(fusion_alert.get("threat_score", 0.0))

    attack_lower = _match_attack(attack_type)
    mitre_technique = _get_mitre(attack_lower)

    # --- helpers to build actions without placeholder targets ----------------
    def _proc_target():
        """Real process name from fusion data, or None."""
        for k in ("process_name", "malware_process_name", "suspicious_process", "process"):
            v = str(fusion_alert.get(k, "")).strip()
            if v and v not in ("", "unknown", "None", "null"):
                return v
        for item in shap_explanation:
            if not isinstance(item, dict):
                continue
            fname = str(item.get("feature", "")).lower()
            fval  = str(item.get("value",   "")).strip()
            if any(kw in fname for kw in ("process", "proc", "exe")) and fval:
                return fval
        return None

    def _kill(reason: str):
        t = _proc_target()
        return {"action": "kill_process", "target": t, "reason": reason} if t else None

    def _block(reason: str):
        return _block_ip_action(_extract_ip_target(fusion_alert, shap_explanation), reason)
    # -------------------------------------------------------------------------

    # Build the action list based on attack type (case-insensitive keyword matching)
    recommended_actions: list = []

    if "ransomware" in attack_lower:
        _actions_raw = [
            _kill("Terminate processes associated with ransomware encryption activity"),
            {"action": "isolate_host",      "target": endpoint_id, "reason": "Prevent ransomware lateral spread to other network hosts"},
            {"action": "scan_filesystem",   "target": endpoint_id, "reason": "Identify encrypted files and ransomware dropper artifacts"},
            {"action": "monitor_persistence","target": endpoint_id, "reason": "Check for persistence installed by ransomware dropper"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"Ransomware activity detected on endpoint {endpoint_id}. "
            "Immediate isolation and filesystem scan initiated."
        )

    elif "c2 beaconing" in attack_lower or "botnet" in attack_lower:
        _blk = _block("Block command-and-control server communication channel")
        _actions_raw = [
            _blk,
            _kill("Terminate process responsible for C2 beaconing activity"),
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Check for scheduled tasks or registry run-key persistence mechanisms"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        _blk_note = f"Blocking C2 IP {_blk['target']}" if _blk else "No confirmed C2 IP — manual investigation required"
        summary = (
            f"C2 beaconing / botnet communication detected on endpoint {endpoint_id}. "
            f"{_blk_note}."
        )

    elif "privilege escalation" in attack_lower:
        _actions_raw = [
            _kill("Terminate the process that performed unauthorized privilege escalation"),
            {"action": "lock_account",    "target": endpoint_id, "reason": "Lock the escalated account pending investigation"},
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Enumerate persistence installed during escalation"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"Privilege escalation detected on endpoint {endpoint_id}. "
            "Account lockout and persistence monitoring initiated."
        )

    elif "lateral movement" in attack_lower:
        _blk = _block("Block inbound SMB (445) and RDP (3389) traffic from source IP")
        _actions_raw = [
            {"action": "isolate_host", "target": endpoint_id, "reason": "Prevent further lateral movement to adjacent hosts via SMB/RDP"},
            _blk,
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"Lateral movement detected originating from endpoint {endpoint_id}. "
            "Host isolation initiated."
        )

    elif "portscan" in attack_lower or "port scan" in attack_lower:
        _blk = _block("Block scanning source IP to prevent reconnaissance enumeration")
        _actions_raw = [
            _blk,
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Check for implants dropped during reconnaissance phase"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        _blk_note = f"Blocking source IP {_blk['target']}" if _blk else "Source IP not resolved — check network logs"
        summary = (
            f"Port scan activity detected targeting endpoint {endpoint_id}. "
            f"{_blk_note}."
        )

    elif "ddos" in attack_lower or "dos" in attack_lower:
        _blk = _block("Block flood source IP to mitigate service disruption")
        _actions_raw = [
            _blk,
            {"action": "scan_filesystem", "target": endpoint_id, "reason": "Check for DDoS agent or botnet client installed on host"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"DDoS/DoS attack detected against endpoint {endpoint_id}. "
            "IP blocking and host scan initiated."
        )

    elif "brute force" in attack_lower or "bruteforce" in attack_lower:
        _blk = _block("Block brute-force source IP after repeated failed authentication attempts")
        _actions_raw = [
            _blk,
            {"action": "lock_account", "target": endpoint_id, "reason": "Temporarily lock the targeted account to prevent credential compromise"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        _blk_note = f"Blocking source IP {_blk['target']}" if _blk else "Source IP unknown"
        summary = (
            f"Brute force attack detected against endpoint {endpoint_id}. "
            f"{_blk_note} and account lockout initiated."
        )

    elif "heartbleed" in attack_lower:
        _blk = _block("Block source IP exploiting Heartbleed (CVE-2014-0160) OpenSSL memory disclosure")
        _actions_raw = [
            _blk,
            {"action": "patch_openssl",        "target": endpoint_id, "reason": "Apply OpenSSL security patch — advisory"},
            {"action": "rotate_certificates",  "target": endpoint_id, "reason": "Rotate all TLS certificates and private keys potentially exposed"},
            {"action": "check_exposed_secrets","target": endpoint_id, "reason": "Audit for secrets leaked from OpenSSL heap"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        _blk_note = f"Blocking source IP {_blk['target']}" if _blk else "Source IP unknown"
        summary = (
            f"Heartbleed (CVE-2014-0160) exploitation detected on endpoint {endpoint_id}. "
            f"{_blk_note}. Immediate patching and certificate rotation required."
        )

    elif "infiltration" in attack_lower:
        recommended_actions = [
            {"action": "isolate_host",    "target": endpoint_id, "reason": "Isolate compromised host to contain active infiltration"},
            {"action": "scan_filesystem", "target": endpoint_id, "reason": "Scan for web shells, backdoors, and dropped payloads"},
        ]
        summary = (
            f"Active infiltration detected on endpoint {endpoint_id}. "
            "Immediate isolation and filesystem scan initiated."
        )

    elif "process injection" in attack_lower:
        _actions_raw = [
            _kill("Terminate the process hosting injected shellcode or DLL payload"),
            {"action": "scan_filesystem",     "target": endpoint_id, "reason": "Scan for injected DLLs and dropper artifacts"},
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Check for persistence installed alongside injection"},
        ]
        if severity == "CRITICAL":
            _actions_raw.insert(1, {
                "action": "isolate_host", "target": endpoint_id,
                "reason": "CRITICAL: isolate host to contain active in-memory attack",
            })
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"Process injection detected on endpoint {endpoint_id}. "
            "Filesystem scan and persistence monitoring initiated."
        )

    elif "persistence" in attack_lower:
        recommended_actions = [
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Enumerate registry run keys, startup folder, and scheduled tasks"},
            {"action": "scan_filesystem",     "target": endpoint_id, "reason": "Scan for persistence dropper binaries recently written to disk"},
        ]
        summary = (
            f"Persistence mechanism detected on endpoint {endpoint_id}. "
            "Registry enumeration and filesystem scan initiated."
        )

    elif "impossible travel" in attack_lower:
        recommended_actions = [
            {"action": "lock_account", "target": endpoint_id, "reason": "Lock the account exhibiting geographically impossible login pattern"},
            {"action": "force_logout", "target": endpoint_id, "reason": "Force logout all active sessions for the affected account (advisory)"},
        ]
        summary = (
            f"Impossible travel detected for account on endpoint {endpoint_id}. "
            "Account lockout initiated — human review required."
        )

    elif "insider threat" in attack_lower:
        recommended_actions = [
            {"action": "lock_account",        "target": endpoint_id, "reason": "Lock the account associated with insider threat indicators"},
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Check for data staging or persistence by insider actor"},
        ]
        summary = (
            f"Insider threat indicators detected on endpoint {endpoint_id}. "
            "Account lockout and persistence monitoring initiated — human review required."
        )

    elif "trojan" in attack_lower or ("malware" in attack_lower and "ransomware" not in attack_lower):
        _malware_file = str(fusion_alert.get("file_path", "")).strip() or endpoint_id
        _blk = _block("Block suspected C2 communication IP")
        _actions_raw = [
            {"action": "quarantine_file",  "target": _malware_file, "reason": "Quarantine the malicious executable or payload file"},
            _kill("Terminate the running malicious process"),
            {"action": "scan_filesystem",  "target": endpoint_id,   "reason": "Full filesystem scan for additional dropped payloads"},
            _blk,
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"Trojan/Malware detected on endpoint {endpoint_id}. "
            "File quarantine and filesystem scan initiated."
        )

    elif "worm" in attack_lower:
        _blk = _block("Block worm propagation source IP to prevent further lateral infection")
        _actions_raw = [
            {"action": "isolate_host",    "target": endpoint_id, "reason": "Immediately isolate host — worms spread via network shares and RDP"},
            _blk,
            _kill("Terminate the worm process responsible for self-replication"),
            {"action": "scan_filesystem", "target": endpoint_id, "reason": "Scan for worm copies dropped across filesystem shares"},
        ]
        recommended_actions = [a for a in _actions_raw if a is not None]
        summary = (
            f"Worm propagation detected on endpoint {endpoint_id}. "
            "Immediate isolation initiated — worms spread fast."
        )

    elif "rootkit" in attack_lower:
        recommended_actions = [
            {"action": "scan_filesystem",     "target": endpoint_id, "reason": "Scan for rootkit-installed drivers, hidden files, and hooked binaries"},
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Enumerate persistence mechanisms installed by the rootkit"},
            {"action": "lock_account",        "target": endpoint_id, "reason": "Lock accounts that may have been backdoored by the rootkit"},
            {"action": "isolate_host",        "target": endpoint_id, "reason": "Isolate host for forensic imaging (advisory — confirm rootkit first)"},
        ]
        summary = (
            f"Rootkit indicators detected on endpoint {endpoint_id}. "
            "Filesystem scan and persistence enumeration initiated."
        )

    else:
        # Default / unknown attack type — safe actions only
        recommended_actions = [
            {"action": "scan_filesystem",     "target": endpoint_id, "reason": "Scan for suspicious binaries and recently modified files"},
            {"action": "monitor_persistence", "target": endpoint_id, "reason": "Check for persistence mechanisms associated with the detected threat"},
        ]
        _ts_norm = threat_score / 100 if threat_score > 1 else threat_score
        summary = (
            f"Elevated threat indicators detected on endpoint {endpoint_id}. "
            f"Threat score: {_ts_norm:.0%}. SOC investigation recommended."
        )

    _sources = fusion_alert.get("sources", fusion_alert.get("contributing_signals", []))
    plan = {
        "plan_id":             str(uuid.uuid4()),
        "endpoint_id":         endpoint_id,
        "severity":            severity,
        "risk_level":          severity,
        "summary":             summary,
        "mitre_technique":     mitre_technique,
        "attack_type":         attack_type,
        "threat_score":        threat_score,
        "domain":              _derive_domain(_sources),
        "sources":             _sources,
        "contributing_signals": fusion_alert.get("contributing_signals", []),
        "shap_explanation":    shap_explanation,
        "recommended_actions": recommended_actions,
        "auto_execute":        (
            severity in ("HIGH", "CRITICAL")
            and not any(kw in attack_lower for kw in _NO_AUTO_EXECUTE_ATTACKS)
        ),
        "created_at":          datetime.now(timezone.utc).isoformat(),
    }

    return plan
