"""
Report Generator — Cyber Sentinel XDR
Generates PDF incident reports using ReportLab.

Requires: reportlab>=4.0.0
"""
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Line
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics import renderPDF
    from reportlab.platypus.flowables import Flowable
    _REPORTLAB_OK = True

    # ---------------------------------------------------------------------------
    # Brand colours (only defined when reportlab is available)
    # ---------------------------------------------------------------------------
    _DARK_BLUE   = colors.HexColor("#0D2137")
    _MID_BLUE    = colors.HexColor("#1565C0")
    _ACCENT_BLUE = colors.HexColor("#42A5F5")
    _GREEN       = colors.HexColor("#2E7D32")
    _ORANGE      = colors.HexColor("#E65100")
    _RED         = colors.HexColor("#B71C1C")
    _LIGHT_GREY  = colors.HexColor("#F5F5F5")
    _BORDER_GREY = colors.HexColor("#BDBDBD")
    _WHITE       = colors.white
    _BLACK       = colors.black

    _SEVERITY_COLOURS = {
        "CRITICAL": colors.HexColor("#7F1D1D"),
        "HIGH":     colors.HexColor("#DC2626"),
        "MEDIUM":   colors.HexColor("#F9A825"),
        "LOW":      _GREEN,
    }

    _TABLE_HEADER_STYLE = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _MID_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0), _WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_LIGHT_GREY, _WHITE]),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, _BORDER_GREY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("WORDWRAP",      (0, 0), (-1, -1), "CJK"),
    ])

except ImportError:
    _REPORTLAB_OK = False
    colors = None  # type: ignore
    Drawing = None  # type: ignore
    Rect = None  # type: ignore
    String = None  # type: ignore
    Line = None  # type: ignore
    HorizontalBarChart = None  # type: ignore
    renderPDF = None  # type: ignore
    Flowable = object  # type: ignore
    _DARK_BLUE = _MID_BLUE = _ACCENT_BLUE = _GREEN = _ORANGE = _RED = None
    _LIGHT_GREY = _BORDER_GREY = _WHITE = _BLACK = None
    _SEVERITY_COLOURS = {}
    _TABLE_HEADER_STYLE = None


# ---------------------------------------------------------------------------
# MITRE ATT&CK lookup — covers the 19 MITRE techniques the system maps to
# ---------------------------------------------------------------------------
MITRE_LOOKUP = {
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": (
            "Adversary encrypts data on target systems to interrupt availability. "
            "Commonly associated with ransomware campaigns."
        ),
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": (
            "Adversary uses application layer protocols to communicate with compromised "
            "systems and avoid detection."
        ),
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversary exploits a vulnerability to obtain higher privilege levels "
            "on the target system."
        ),
    },
    "T1021": {
        "name": "Remote Services / Lateral Movement",
        "tactic": "Lateral Movement",
        "description": (
            "Adversary uses valid accounts or exploits to move laterally through "
            "the network via remote services."
        ),
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "Adversary scans victim network to discover open ports, services, "
            "and potential targets."
        ),
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversary floods network resources to degrade or deny service "
            "availability to legitimate users."
        ),
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversary attempts to gain access to accounts by systematically "
            "trying passwords or credential pairs."
        ),
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversary exploited a weakness in a public-facing application "
            "(e.g., web server, VPN, OpenSSL/Heartbleed CVE-2014-0160) to gain "
            "initial access or extract data from the target network."
        ),
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversary abuses command and script interpreters to execute "
            "commands and payloads."
        ),
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversary degrades or denies access to a service by exhausting "
            "resources on the target endpoint, rendering it unavailable to legitimate users."
        ),
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": (
            "Adversary relied on a user running a malicious file or link "
            "to execute malware on the endpoint."
        ),
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": (
            "Adversary injected malicious code into a legitimate running process "
            "to evade detection or escalate privileges."
        ),
    },
    "T1014": {
        "name": "Rootkit",
        "tactic": "Defense Evasion",
        "description": (
            "Adversary deployed a rootkit to hide malicious software and maintain "
            "persistent, covert access to the system."
        ),
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversary exploited vulnerable remote services (e.g., SMB, RDP) "
            "to spread laterally through the network."
        ),
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence / Privilege Escalation",
        "description": (
            "Adversary configured malware to execute automatically at system boot "
            "or user logon to maintain persistence."
        ),
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": (
            "Adversary hijacked system resources (CPU, GPU, memory) for unauthorized "
            "tasks such as cryptomining."
        ),
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Initial Access",
        "description": (
            "Adversary used legitimate account credentials to gain access and "
            "blend in with normal user activity."
        ),
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Persistence / Privilege Escalation / Defense Evasion",
        "description": (
            "Adversary leveraged valid cloud or service account credentials "
            "to access systems and escalate privileges."
        ),
    },
}


# ---------------------------------------------------------------------------
# Attack-type-specific remediation playbooks (keyed by lowercase substring).
# Surfaced in the "Recommended Remediation" section so the report tells the
# analyst what to DO, not just what happened.
# ---------------------------------------------------------------------------
REMEDIATION_LOOKUP = {
    "portscan": [
        "Block the source IP at the perimeter firewall and internal ACLs.",
        "Confirm the scan did not progress to exploitation — review logs on any host whose ports responded.",
        "Verify only required services/ports are exposed; close or firewall the rest.",
        "Enable port-scan rate-limiting / SYN-flood protection on edge devices.",
        "If the source is internal, isolate the host and investigate for compromise.",
    ],
    "ddos": [
        "Engage upstream DDoS scrubbing / rate-limiting at the ISP or CDN.",
        "Block or rate-limit the offending source ranges; enable SYN cookies.",
        "Scale or shed load on the targeted service; enable connection caps.",
        "Preserve NetFlow/packet captures as evidence for the attack window.",
    ],
    "dos": [
        "Rate-limit or block the source generating the flood.",
        "Enable SYN cookies and connection-rate caps on the target service.",
        "Monitor resource exhaustion (CPU, sockets, memory) on the endpoint.",
    ],
    "ransomware": [
        "ISOLATE the endpoint from the network immediately to stop encryption spread.",
        "Do NOT pay; preserve encrypted samples and ransom notes for forensics.",
        "Identify patient-zero and the initial access vector; hunt for lateral movement.",
        "Restore from known-good, offline backups after full eradication.",
        "Rotate all credentials that were valid on the affected host.",
    ],
    "malware": [
        "Quarantine the identified file and kill the associated process.",
        "Submit the sample hash to threat intel (VirusTotal) for family attribution.",
        "Scan the host and peers for the same IOC; check persistence mechanisms.",
        "Reimage if the malware achieved persistence or privilege escalation.",
    ],
    "c2": [
        "Block the C2 destination IP/domain at the firewall and DNS sinkhole it.",
        "Identify and terminate the beaconing process on the endpoint.",
        "Hunt for the same C2 indicator across all endpoints.",
        "Capture the beacon interval and JA3/TLS fingerprint for detection tuning.",
    ],
    "beacon": [
        "Block the C2 destination and sinkhole associated domains.",
        "Terminate the beaconing process and collect its binary for analysis.",
        "Correlate the periodic traffic pattern against other hosts.",
    ],
    "brute": [
        "Lock or throttle the targeted account(s); enforce account-lockout policy.",
        "Block the source IP and require MFA on the exposed service.",
        "Review authentication logs for a successful login after the attempts.",
        "Rotate credentials for any account that may have been guessed.",
    ],
    "lateral": [
        "Isolate the source and destination hosts of the lateral movement.",
        "Disable the abused account/service and rotate its credentials.",
        "Audit SMB/RDP/WMI exposure and restrict admin-to-admin traffic.",
    ],
    "privilege": [
        "Isolate the host; a privilege-escalation attempt indicates active compromise.",
        "Identify the exploited vulnerability/CVE and patch it.",
        "Audit for newly created admin accounts or modified group memberships.",
    ],
    "infiltration": [
        "Isolate the affected host and preserve volatile memory for forensics.",
        "Trace the initial access vector (phishing, exploit, valid account).",
        "Hunt for staged payloads, persistence, and outbound exfiltration.",
    ],
    "heartbleed": [
        "Patch the affected OpenSSL version immediately (CVE-2014-0160).",
        "Rotate all certificates and private keys that were in memory.",
        "Invalidate active sessions and reset any exposed credentials/secrets.",
    ],
    "backdoor": [
        "Isolate the host and terminate the backdoor process/listener.",
        "Remove persistence (services, run keys, scheduled tasks) and reimage.",
        "Rotate credentials and hunt for the same backdoor across the fleet.",
    ],
    "exfil": [
        "Block the outbound destination and cap egress bandwidth for the host.",
        "Identify what data left the network and its sensitivity.",
        "Preserve flow records; isolate the host and revoke its credentials.",
    ],
    "botnet": [
        "Block the C2 infrastructure and sinkhole associated domains.",
        "Identify and clean the bot process; check for worm-like spread.",
        "Rotate credentials on the infected host after eradication.",
    ],
    "insider": [
        "Preserve the user's session and file/access logs as evidence.",
        "Review the account's recent access against its normal baseline.",
        "Engage HR/legal per policy before any account action.",
        "Restrict access to sensitive resources pending investigation.",
    ],
}

_DEFAULT_REMEDIATION = [
    "Isolate the affected endpoint if active compromise is suspected.",
    "Preserve logs, flows, and any artifacts for forensic review.",
    "Block the identified source indicator at the firewall.",
    "Hunt for the same indicators across the rest of the fleet.",
    "Escalate to a senior analyst and document the investigation.",
]

# ---------------------------------------------------------------------------
# Threat-intelligence knowledge base — deep, attack-type-specific explanation
# rendered in the "Attack Narrative & Threat Analysis" section. Each entry has:
#   what   — what the attack/technique is (definition)
#   how    — how it works and how this system detected it (mechanics)
#   impact — why it is dangerous (potential consequences)
#   next   — the attacker's likely next steps (so the analyst can get ahead)
# Keyed by lowercase substring; first match wins (see _threat_intel_for).
# ---------------------------------------------------------------------------
THREAT_INTEL = {
    "portscan": {
        "what": "A port scan is a reconnaissance technique in which an attacker sends probe "
                "packets to a range of TCP/UDP ports on one or more hosts to discover which "
                "services are listening and reachable.",
        "how": "The scanner opens (or half-opens) many short-lived connections — typically SYN "
               "packets that never complete the handshake — across sequential or targeted ports. "
               "The signature is many distinct destination ports contacted by a single source in a "
               "short window, which is exactly what the rule engine and ML classifier flagged here "
               "(note the high SYN-flag count relative to completed connections in the evidence table).",
        "impact": "A scan by itself does not compromise a host, but it maps the attack surface — open "
                  "ports, service versions, and firewall gaps — that an adversary uses to plan the next "
                  "stage. A scan originating from an INTERNAL host frequently means that host is already "
                  "compromised and is being used to pivot.",
        "next": "Expect service/version fingerprinting, vulnerability scanning against the discovered "
                "ports, and then targeted exploitation or brute-force against exposed services such as "
                "RDP (3389), SMB (445), or SSH (22).",
    },
    "ddos": {
        "what": "A Distributed Denial of Service (DDoS) attack overwhelms a target with more traffic or "
                "connection requests than it can process, exhausting bandwidth, CPU, or connection tables "
                "so legitimate users are denied service.",
        "how": "Many sources (often a botnet) send high volumes of packets — SYN floods, UDP/ICMP floods, "
               "or application-layer requests. The engine flags the abnormal packet rate, connection rate, "
               "and low completed-handshake ratio characteristic of a flood.",
        "impact": "Service outage, degraded performance, and financial/reputational loss. DDoS is also used "
                  "as a smokescreen to distract responders while a separate intrusion is carried out.",
        "next": "The attacker may sustain or escalate the flood, rotate source IPs to evade blocks, or pair "
                "the DoS with a parallel intrusion attempt while defenders are distracted.",
    },
    "dos": {
        "what": "A Denial of Service (DoS) attack exhausts the resources of a single target service or "
                "endpoint so it can no longer serve legitimate requests.",
        "how": "A single source generates a flood of connections or malformed requests that consume "
               "sockets, CPU, or memory. The engine detects the resource-exhaustion traffic pattern.",
        "impact": "Loss of availability for the targeted service and possible cascading failures on "
                  "dependent systems.",
        "next": "The source may intensify the flood or pivot to a distributed approach; monitor for a "
                "concurrent intrusion under cover of the outage.",
    },
    "ransomware": {
        "what": "Ransomware is malware that encrypts files on the victim's system and any reachable network "
                "shares, then demands payment for the decryption key. This event combines malicious file "
                "activity with abnormal system resource behaviour — the classic ransomware signature.",
        "how": "After initial access the payload enumerates files and spawns rapid read-write-rename/delete "
               "cycles to encrypt data, usually deletes volume shadow copies, and drops a ransom note. The "
               "sharp resource-usage spike and mass file modification are the behavioural indicators detected.",
        "impact": "Irreversible data loss without offline backups, full operational shutdown, and extortion. "
                  "Modern ransomware also exfiltrates data first for 'double extortion'.",
        "next": "Encryption spreads to mapped drives and peer hosts within minutes; attackers may exfiltrate "
                "data, disable backups and AV, and post to a leak site. IMMEDIATE network isolation is critical.",
    },
    "malware": {
        "what": "Malware is any software built to harm, exploit, or gain unauthorised access to a system. "
                "This detection flagged a Portable Executable (PE) file whose static structure matches "
                "known-malicious characteristics learned by the LightGBM classifier from the EMBER dataset.",
        "how": "The engine extracts static PE features (imported APIs, section entropy, header anomalies, "
               "byte/string patterns) and scores them. A high score means the binary resembles malware "
               "families seen in training WITHOUT requiring an exact signature match — enabling detection of "
               "novel/obfuscated variants.",
        "impact": "Depending on family, malware can steal credentials, install a backdoor, join a botnet, "
                  "mine cryptocurrency, or stage ransomware. A high-confidence, unsigned, untrusted binary "
                  "should be treated as an active threat.",
        "next": "The file may attempt persistence (run keys, services, scheduled tasks), privilege "
                "escalation, C2 contact, or lateral spread. Quarantine it and hunt for the same hash "
                "across every endpoint.",
    },
    "c2": {
        "what": "Command-and-Control (C2) is the channel a compromised host uses to receive attacker "
                "instructions. 'Beaconing' is the periodic check-in traffic a malware implant sends to its "
                "controller.",
        "how": "The implant contacts the C2 server at regular intervals — often over HTTP/HTTPS/DNS to blend "
               "in with normal traffic. The engine detects the periodicity and destination characteristics "
               "that distinguish a beacon from ordinary browsing.",
        "impact": "This confirms an ACTIVE compromise: the host is under remote attacker control and can be "
                  "tasked to exfiltrate data, download further payloads, or pivot deeper.",
        "next": "The attacker escalates via credential theft, lateral movement, and data staging/exfiltration. "
                "Blocking the C2 destination and eradicating the implant are urgent.",
    },
    "beacon": None,  # alias → resolved to "c2" below
    "brute": {
        "what": "A brute-force attack attempts to guess valid credentials by systematically trying many "
                "username/password combinations against an authentication service.",
        "how": "The attacker submits rapid, repeated login attempts (dictionary lists or credential "
               "stuffing). A high failed-authentication rate from one source against an account or service "
               "is the signature.",
        "impact": "A successful guess yields a VALID account, granting access that blends in with legitimate "
                  "activity. Aggressive attempts can also lock users out (denial of service).",
        "next": "On success: account takeover, privilege enumeration, and lateral movement using the valid "
                "credentials. Enforce account lockout and MFA immediately.",
    },
    "lateral": {
        "what": "Lateral movement is how an attacker moves from an initially compromised host to other "
                "systems, expanding control toward high-value targets like domain controllers.",
        "how": "Adversaries abuse remote services (SMB, RDP, WMI, PsExec) with stolen or valid credentials. "
               "Unusual host-to-host administrative traffic is the indicator flagged here.",
        "impact": "Widens the breach, brings the attacker closer to sensitive data and identity "
                  "infrastructure, and makes full eradication much harder.",
        "next": "Credential harvesting, privilege escalation to domain admin, and data discovery/staging. "
                "Isolate involved hosts and rotate the abused credentials.",
    },
    "privilege": {
        "what": "Privilege escalation is when an attacker exploits a flaw or misconfiguration to gain higher "
                "permissions than granted (e.g., standard user → SYSTEM/root).",
        "how": "Techniques include exploiting unpatched kernel/service vulnerabilities, token manipulation, "
               "or abusing misconfigured services. The engine flagged the anomalous process behaviour "
               "associated with the attempt.",
        "impact": "Elevated privileges let the attacker disable defences, read all data, install persistent "
                  "implants, and move laterally with authority — effectively total control of the host.",
        "next": "Expect credential dumping, defence evasion, persistence, and progression toward domain "
                "compromise. Treat the host as fully compromised.",
    },
    "infiltration": {
        "what": "Infiltration via a public-facing application is when an adversary abuses a weakness in an "
                "internet-exposed service (web server, VPN, API) to gain an initial foothold.",
        "how": "The attacker sends crafted requests exploiting a vulnerability (injection, insecure "
               "deserialization, authentication bypass) to execute code or extract data.",
        "impact": "Provides initial access into the internal network, typically followed by persistence and "
                  "lateral movement.",
        "next": "Web shell or backdoor deployment, credential theft, and pivoting inward from the exposed host.",
    },
    "heartbleed": {
        "what": "Heartbleed (CVE-2014-0160) is a vulnerability in older OpenSSL versions that lets an "
                "attacker read chunks of server memory, potentially exposing private keys, credentials, and "
                "session tokens.",
        "how": "A malformed TLS heartbeat request tricks the server into returning up to 64 KB of memory per "
               "request; repeated requests harvest whatever secrets happen to be in memory.",
        "impact": "Leaked private keys enable decryption and server impersonation; leaked credentials and "
                  "session tokens enable account takeover — all with no trace in normal application logs.",
        "next": "Assume any secret in server memory was exposed: patch OpenSSL, rotate ALL keys/certificates, "
                "and invalidate active sessions and credentials.",
    },
    "backdoor": {
        "what": "A backdoor is a covert mechanism that bypasses normal authentication to give an attacker "
                "persistent remote access to a system.",
        "how": "It may be a hidden service, network listener, scheduled task, or trojanised binary that "
               "awaits attacker connections or beacons outbound.",
        "impact": "Persistent, stealthy access that survives reboots and lets the attacker re-enter even "
                  "after other remediation — a foothold for long-term compromise.",
        "next": "Remove all persistence and reimage the host; rotate credentials; hunt for the same backdoor "
                "signature across the fleet.",
    },
    "botnet": {
        "what": "A botnet is a network of compromised hosts ('bots') centrally controlled by an attacker to "
                "perform coordinated tasks such as DDoS, spam, or credential attacks.",
        "how": "The bot on this host communicates with C2 infrastructure to receive commands, exhibiting the "
               "beaconing and traffic patterns flagged by the engine.",
        "impact": "The host is fully attacker-controlled, participates in attacks against third parties, and "
                  "may self-propagate to other machines.",
        "next": "Clean the bot process, block the C2 infrastructure, check for worm-like spread, and rotate "
                "credentials after eradication.",
    },
    "insider": {
        "what": "An insider threat is anomalous activity by a legitimate user account — a malicious insider "
                "or, just as often, a hijacked/compromised account — that deviates from that user's "
                "established behavioural baseline.",
        "how": "The user-behaviour model flagged deviations such as off-hours logons, unusual session origins, "
               "or access volumes outside the learned baseline (see the User Behaviour rules and score).",
        "impact": "Insiders operate with VALID credentials, so data theft or sabotage is hard to detect and "
                  "can be high-impact. A compromised account looks identical to the real user until analysed.",
        "next": "Preserve session and access evidence, compare recent activity against the baseline, and "
                "engage HR/legal per policy before taking account action.",
    },
}
# Resolve the beacon alias to the c2 entry.
THREAT_INTEL["beacon"] = THREAT_INTEL["c2"]

_DEFAULT_INTEL = {
    "what": "This event was raised by correlated signals across multiple detection domains that together "
            "exceeded the alerting threshold.",
    "how": "The fusion engine combined the network, system, user-behaviour, and malware model scores; the "
           "weighted result indicated anomalous and potentially malicious activity.",
    "impact": "The precise impact depends on the confirmed technique; the event should be treated as a "
              "credible threat pending analyst triage.",
    "next": "Triage the contributing signals, confirm the underlying technique, and apply the recommended "
            "remediation for the identified attack class.",
}


def _threat_intel_for(attack_type: str, mitre: str) -> dict:
    """Resolve deep threat-intel content by keyword match on attack type / MITRE."""
    key = (str(attack_type) + " " + str(mitre)).lower()
    for token, intel in THREAT_INTEL.items():
        if intel and token in key:
            return intel
    return _DEFAULT_INTEL

# Human-readable labels + units for the CIC network flow features we surface as
# evidence. Only present, non-zero values are shown.
_NETWORK_EVIDENCE_FIELDS = [
    ("Destination Port",              "Destination Port",        ""),
    ("Flow Duration",                 "Flow Duration",           "µs"),
    ("Total Fwd Packets",             "Forward Packets",         ""),
    ("Total Backward Packets",        "Backward Packets",        ""),
    ("Total Length of Fwd Packets",   "Fwd Bytes",               "B"),
    ("Total Length of Bwd Packets",   "Bwd Bytes",               "B"),
    ("Flow Bytes/s",                  "Flow Throughput",         "B/s"),
    ("Flow Packets/s",                "Packet Rate",             "pkt/s"),
    ("Fwd Packets/s",                 "Fwd Packet Rate",         "pkt/s"),
    ("SYN Flag Count",                "SYN Flags",               ""),
    ("ACK Flag Count",                "ACK Flags",               ""),
    ("RST Flag Count",                "RST Flags",               ""),
    ("FIN Flag Count",                "FIN Flags",               ""),
    ("PSH Flag Count",                "PSH Flags",               ""),
    ("Average Packet Size",           "Avg Packet Size",         "B"),
    ("Down/Up Ratio",                 "Down/Up Ratio",           ""),
]


def _resolve_features(alert: dict, response_plan: dict, contributing: list) -> dict:
    """Find the richest available network flow feature dict from the alert, the
    response plan (source_features stashed at plan creation), or a contributing
    signal. Returns {} when none is present."""
    for src in (alert.get("source_features"), response_plan.get("source_features"),
                alert.get("features")):
        if isinstance(src, dict) and src:
            return src
    for sig in (contributing or []):
        if isinstance(sig, dict) and isinstance(sig.get("features"), dict) and sig["features"]:
            return sig["features"]
    return {}


def _resolve_src_ip(alert: dict, response_plan: dict, contributing: list) -> str:
    """Best-effort attacker/source IP from plan, alert, or a contributing signal."""
    import re as _re
    for cand in (response_plan.get("src_ip"), alert.get("src_ip"), alert.get("source_ip"),
                 alert.get("host")):
        c = str(cand or "").strip()
        if _re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", c):
            return c
    for sig in (contributing or []):
        if isinstance(sig, dict):
            c = str(sig.get("src_ip", sig.get("host", "")) or "").strip()
            if _re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", c):
                return c
    return ""


def _fmt_num(v) -> str:
    """Compact numeric formatting: ints plain, large numbers with separators."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    if f == int(f):
        return f"{int(f):,}"
    if abs(f) >= 1000:
        return f"{f:,.0f}"
    return f"{f:.2f}"


def _remediation_steps(attack_type: str, mitre: str) -> list:
    """Resolve attack-type-specific remediation steps by keyword match."""
    key = (str(attack_type) + " " + str(mitre)).lower()
    for token, steps in REMEDIATION_LOOKUP.items():
        if token in key:
            return steps
    return _DEFAULT_REMEDIATION


def _build_narrative_text(
    attack_type: str, severity: str, score: float, src_ip: str,
    target: str, features: dict,
) -> str:
    """Compose a plain-English incident narrative from the available signals."""
    attack = attack_type or "suspicious activity"
    sev = (severity or "UNKNOWN").upper()
    src = src_ip or "an unidentified source"
    tgt = target or "the monitored endpoint"
    dport = ""
    try:
        dp = int(float(features.get("Destination Port", 0)))
        if dp > 0:
            dport = str(dp)
    except (TypeError, ValueError):
        pass

    parts = [
        f"Cyber Sentinel XDR detected a <b>{attack}</b> event classified "
        f"<b>{sev}</b> with a fused threat score of <b>{score * 100:.0f}/100</b>. "
        f"The activity originated from <b>{src}</b> and targeted <b>{tgt}</b>"
        + (f" on port <b>{dport}</b>." if dport else "."),
    ]
    a = attack.lower()
    if "portscan" in a or "port scan" in a:
        parts.append(
            "The traffic pattern — many short-lived connections probing multiple "
            "ports/hosts from a single source — is characteristic of reconnaissance "
            "(MITRE T1046). Port scanning frequently precedes targeted exploitation, "
            "so this source should be treated as hostile until proven otherwise."
        )
    elif "ddos" in a or "dos" in a:
        parts.append(
            "A high-volume flood of traffic aimed at exhausting network or endpoint "
            "resources was observed, consistent with a denial-of-service attempt.")
    elif "ransomware" in a:
        parts.append(
            "The combination of malicious file activity and abnormal system behaviour "
            "matches ransomware tradecraft. Immediate isolation is critical to prevent "
            "encryption from spreading to shared drives and peers.")
    elif "malware" in a:
        parts.append(
            "A binary matching malicious characteristics was identified on the host. "
            "Confirm containment and hunt for the same indicator across the fleet.")
    elif "c2" in a or "beacon" in a:
        parts.append(
            "Periodic outbound traffic consistent with command-and-control beaconing "
            "was observed, indicating a host may already be compromised.")
    elif "brute" in a:
        parts.append(
            "Repeated authentication attempts against an account were detected, "
            "consistent with a credential brute-force attack.")
    else:
        parts.append(
            "The correlated signals across detection domains raised this event above "
            "the alerting threshold and warrant analyst review.")
    parts.append(
        "Automated response actions were generated to contain the threat (see the "
        "Response Actions section); recommended manual remediation follows in the "
        "Recommended Remediation section.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Constants that are always available (regardless of reportlab)
# ---------------------------------------------------------------------------
# Resolve the reports directory from centralized config (frozen-aware, and
# env-overridable via XDR_REPORTS_DIR). Fall back to a repo-relative path if
# config cannot be imported — never to an absolute drive path.
try:
    from config import settings as _cfg_settings
    _REPORTS_DIR = Path(_cfg_settings.reports_dir)
except Exception:
    _REPORTS_DIR = Path(os.environ.get("XDR_REPORTS_DIR", str(Path(__file__).parent.parent / "reports")))

# Logo — resolved relative to this file so it works regardless of cwd
_LOGO_PATH = Path(__file__).parent / "logo.jpg"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_badge_colour(severity: str):
    return _SEVERITY_COLOURS.get(str(severity).upper(), _BORDER_GREY)


def _execution_final_status(execution_results: list) -> str:
    """
    Derive the overall response status from individual execution results.
    Returns "CONTAINED", "PARTIAL", "PENDING", "ADVISORY", or "FAILED".

    Advisory actions (logged server-side, never executed by the endpoint agent)
    are excluded from the success/failure count so they don't push the verdict
    to FAILED when no executable action has yet returned a result.
    """
    # Must stay in sync with _ADVISORY in _build_response_actions() and
    # _ADVISORY_ACTIONS in backend.py.
    _ADV_SET = frozenset({
        "log_user_session",
        "restrict_access", "rate_limit_traffic",
        "log_event",
        "patch_openssl", "rotate_certificates", "check_exposed_secrets", "update_software",
        "force_logout", "review_account", "review_logs",
        "invalidate_sessions",
        "collect_forensics",
        "alert_admin",
    })

    if not execution_results:
        return "PARTIAL"

    total     = len(execution_results)
    executed  = sum(
        1 for r in execution_results
        if str(r.get("status", "")).lower() in ("completed", "success", "ok", "done")
        or str(r.get("result", r.get("result_message", ""))).startswith("[OK]")
    )
    advisory  = sum(
        1 for r in execution_results
        if r.get("advisory", False)
        or str(r.get("result", r.get("result_message", ""))).startswith("[ADV]")
        or str(r.get("action", "")).lower() in _ADV_SET
    )
    failed    = sum(
        1 for r in execution_results
        if str(r.get("status", "")).lower() in ("failed", "error")
        or str(r.get("result", r.get("result_message", ""))).startswith("[FAIL]")
    )
    pending   = sum(
        1 for r in execution_results
        if str(r.get("status", "")).lower() in ("pending", "sent", "queued")
        or str(r.get("result", r.get("result_message", ""))).startswith("[...]")
    )

    # Advisory-only plans — all human-review, nothing to execute
    actionable = total - advisory
    if actionable == 0:
        return "ADVISORY"

    if executed >= actionable:
        return "CONTAINED"
    if executed > 0 or advisory > 0:
        return "PARTIAL"
    # Nothing has failed yet — commands are still queued/in-flight
    if pending > 0 and failed == 0:
        return "PENDING"
    return "FAILED"


def _status_colour(status: str):
    return {
        "CONTAINED": _GREEN,
        "PARTIAL":   _ORANGE,
        "FAILED":    _RED,
        "PENDING":   _MID_BLUE,
        "ADVISORY":  _MID_BLUE,
    }.get(status, _BORDER_GREY)


def _truncate(value, max_len: int = 60) -> str:
    s = str(value) if value is not None else ""
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


# ---------------------------------------------------------------------------
# SHAP bar chart flowable
# ---------------------------------------------------------------------------

class _SHAPBarChart(Flowable):
    """
    A ReportLab Flowable that renders a horizontal bar chart of SHAP feature
    importances using Drawing + HorizontalBarChart primitives.

    Positive values (increase risk) are drawn in red; negative values
    (decrease risk) are drawn in green.  The chart degrades gracefully:
    if ``items`` is empty it renders a grey "no data" notice instead.
    """

    _BAR_HEIGHT = 10       # points per bar
    _BAR_GAP    = 5        # points between bars
    _LABEL_WIDTH = 120     # points reserved for the left-side feature label
    _VALUE_WIDTH = 45      # points reserved for the right-side value label
    _CHART_MIN_WIDTH = 200 # minimum available width for the bar itself

    def __init__(self, items: list, available_width: float = 450):
        """
        Parameters
        ----------
        items           : Normalised list of {"feature": str, "value": float} dicts.
                          Plain strings are accepted; their value defaults to 0.0.
        available_width : Page content width in points (used to size the drawing).
        """
        super().__init__()
        self._items = items[:15]          # cap at 15 bars
        self._avail = available_width
        self._title_height = 16           # points for the title text above chart
        self._padding = 8                 # top/bottom padding

    # ReportLab calls this to know how tall the flowable is before placing it.
    def wrap(self, availWidth, availHeight):
        n = max(len(self._items), 1)
        bar_area = n * (self._BAR_HEIGHT + self._BAR_GAP) + self._BAR_GAP
        total_h = self._title_height + self._padding * 2 + bar_area + 20  # +20 axis area
        self._computed_width = min(availWidth, self._avail)
        self._computed_height = total_h
        return self._computed_width, self._computed_height

    def draw(self):
        w = self._computed_width
        h = self._computed_height

        # Title
        from reportlab.pdfbase.pdfmetrics import stringWidth
        title_text = "SHAP Feature Importance"
        title_fs = 10
        title_x = w / 2 - stringWidth(title_text, "Helvetica-Bold", title_fs) / 2
        self.canv.setFont("Helvetica-Bold", title_fs)
        self.canv.setFillColor(_MID_BLUE)
        self.canv.drawString(title_x, h - self._title_height, title_text)

        if not self._items:
            # Graceful degradation — no data notice
            self.canv.setFont("Helvetica", 9)
            self.canv.setFillColor(_BORDER_GREY)
            msg = "No SHAP data available for this alert."
            msg_x = w / 2 - stringWidth(msg, "Helvetica", 9) / 2
            self.canv.drawString(msg_x, h / 2 - 4, msg)
            return

        # Dimensions
        label_w = self._LABEL_WIDTH
        value_w = self._VALUE_WIDTH
        chart_w = max(w - label_w - value_w - 16, self._CHART_MIN_WIDTH)
        chart_top = h - self._title_height - self._padding
        bar_h = self._BAR_HEIGHT
        bar_gap = self._BAR_GAP

        # Find the max absolute value to scale bars
        values = []
        for item in self._items:
            if isinstance(item, dict):
                try:
                    values.append(float(item.get("value", item.get("importance", item.get("shap_value", 0.0)))))
                except (TypeError, ValueError):
                    values.append(0.0)
            else:
                values.append(0.0)

        max_abs = max((abs(v) for v in values), default=1.0) or 1.0
        zero_x = label_w + 8 + chart_w / 2   # zero line x position in canvas coords

        # Draw zero line
        self.canv.setStrokeColor(_BORDER_GREY)
        self.canv.setLineWidth(0.5)
        axis_bottom = chart_top - len(self._items) * (bar_h + bar_gap) - bar_gap - 6
        self.canv.line(zero_x, chart_top, zero_x, axis_bottom)

        # "0" label below zero line
        self.canv.setFont("Helvetica", 7)
        self.canv.setFillColor(_BORDER_GREY)
        self.canv.drawCentredString(zero_x, axis_bottom - 8, "0")

        # Draw each bar
        for idx, (item, val) in enumerate(zip(self._items, values)):
            if isinstance(item, dict):
                feat_label = _truncate(str(item.get("feature", item.get("name", "unknown"))), 22)
            else:
                feat_label = _truncate(str(item), 22)

            bar_top_y = chart_top - (idx * (bar_h + bar_gap)) - bar_gap
            bar_bottom_y = bar_top_y - bar_h
            bar_center_y = (bar_top_y + bar_bottom_y) / 2

            # Feature label (left)
            self.canv.setFont("Helvetica", 7.5)
            self.canv.setFillColor(_BLACK)
            label_y = bar_center_y - 3.5
            self.canv.drawRightString(label_w + 4, label_y, feat_label)

            # Bar
            bar_pixel_len = (abs(val) / max_abs) * (chart_w / 2 - 4)
            bar_color = colors.HexColor("#C62828") if val >= 0 else colors.HexColor("#2E7D32")

            if val >= 0:
                bar_x = zero_x
            else:
                bar_x = zero_x - bar_pixel_len

            self.canv.setFillColor(bar_color)
            self.canv.setStrokeColor(bar_color)
            self.canv.rect(bar_x, bar_bottom_y, bar_pixel_len, bar_h, fill=1, stroke=0)

            # Value label (right of bar area)
            val_str = f"{val:+.4f}"
            self.canv.setFont("Helvetica", 7)
            self.canv.setFillColor(_BLACK)
            val_x = label_w + 8 + chart_w + 4
            self.canv.drawString(val_x, label_y, val_str)


# ---------------------------------------------------------------------------
# Style factory
# ---------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "XDRTitle",
        parent=base["Title"],
        fontSize=26,
        textColor=_DARK_BLUE,
        fontName="Helvetica-Bold",
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "XDRSubtitle",
        parent=base["Normal"],
        fontSize=13,
        textColor=_MID_BLUE,
        fontName="Helvetica",
        spaceAfter=2,
        alignment=TA_CENTER,
    )
    section_heading = ParagraphStyle(
        "XDRSection",
        parent=base["Heading2"],
        fontSize=11,
        textColor=_WHITE,
        fontName="Helvetica-Bold",
        backColor=_MID_BLUE,
        leftIndent=-6,
        rightIndent=-6,
        spaceBefore=10,
        spaceAfter=4,
        borderPadding=(4, 6, 4, 6),
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "XDRBody",
        parent=base["Normal"],
        fontSize=9,
        textColor=_BLACK,
        fontName="Helvetica",
        spaceAfter=3,
    )
    label_style = ParagraphStyle(
        "XDRLabel",
        parent=base["Normal"],
        fontSize=9,
        textColor=_MID_BLUE,
        fontName="Helvetica-Bold",
    )
    small_style = ParagraphStyle(
        "XDRSmall",
        parent=base["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#616161"),
        fontName="Helvetica",
        alignment=TA_CENTER,
    )
    status_style_base = ParagraphStyle(
        "XDRStatus",
        parent=base["Normal"],
        fontSize=20,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=6,
    )

    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "section": section_heading,
        "body": body_style,
        "label": label_style,
        "small": small_style,
        "status_base": status_style_base,
    }


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_header(styles, incident_id: str, generated_at: str) -> list:
    elements = []

    # ── Logo + title row ────────────────────────────────────────────────────
    logo_cell: list = []
    if _LOGO_PATH.exists():
        logo_img = Image(str(_LOGO_PATH), width=28 * mm, height=28 * mm)
        logo_img.hAlign = "LEFT"
        logo_cell.append(logo_img)
    else:
        logo_cell.append(Paragraph("", styles["body"]))

    title_cell = [
        Paragraph("CYBER SENTINEL XDR", styles["title"]),
        Paragraph("INCIDENT REPORT", styles["subtitle"]),
    ]

    header_table = Table(
        [[logo_cell, title_cell]],
        colWidths=[32 * mm, None],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(header_table)

    elements.append(Spacer(1, 4 * mm))
    elements.append(HRFlowable(width="100%", thickness=2, color=_MID_BLUE))
    elements.append(Spacer(1, 2 * mm))
    elements.append(
        Paragraph(
            f"Report ID: {incident_id}  &nbsp;&nbsp; Generated: {generated_at}",
            styles["small"],
        )
    )
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_incident_summary(
    styles, incident_id: str, alert: dict, endpoint_info: dict,
    response_plan: dict | None = None, contributing: list | None = None,
) -> list:
    elements = []
    elements.append(Paragraph("1 — Incident Summary", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    response_plan = response_plan or {}
    contributing = contributing or []
    severity = str(alert.get("severity", "UNKNOWN")).upper()
    sev_colour = _severity_badge_colour(severity)
    attack_type = str(alert.get("attack_type", alert.get("attack", "Unknown")))
    ts = str(alert.get("ts", alert.get("timestamp", alert.get("created_at", "N/A"))))
    if "T" in ts:
        ts = ts.replace("T", " ")[:19] + " UTC"
    hostname = str(endpoint_info.get("hostname", alert.get("endpoint_id", "N/A")))
    ip_address = str(endpoint_info.get("ip_address", "N/A"))
    threat_score = float(alert.get("threat_score", 0.0))

    src_ip = _resolve_src_ip(alert, response_plan, contributing) or "N/A (internal correlation)"
    features = _resolve_features(alert, response_plan, contributing)
    # Detection domains (which model layers contributed)
    sources = (alert.get("sources") or response_plan.get("sources")
               or alert.get("contributing_signals") or [])
    domains = sorted({str(s.get("source") if isinstance(s, dict) else s).lower()
                      for s in sources if s}) if sources else []
    domain_str = ", ".join(d for d in domains if d) or "network"
    # Detection method
    n_signals = len(contributing) if contributing else len(sources)
    if len(domains) >= 2:
        method = f"Multi-domain correlation ({n_signals} signals)"
    elif "network" in domain_str:
        method = "Network flow analysis (rule + ML classifier)"
    else:
        method = f"{domain_str.title()} model detection"
    target_port = ""
    try:
        dp = int(float(features.get("Destination Port", 0)))
        if dp > 0:
            target_port = str(dp)
    except (TypeError, ValueError):
        pass

    data = [
        ["Field", "Value"],
        ["Incident ID",       incident_id],
        ["Timestamp",         ts],
        ["Severity",          severity],
        ["Attack Type",       attack_type],
        ["Threat Score",      f"{threat_score * 100:.1f} / 100"],
        ["Target Endpoint",   hostname],
        ["Target IP",         ip_address],
        ["Source / Attacker IP", src_ip],
    ]
    if target_port:
        data.append(["Targeted Port", target_port])
    data += [
        ["Detection Domains", domain_str],
        ["Detection Method",  method],
        ["MITRE Technique",   str(response_plan.get("mitre_technique", "N/A")) or "N/A"],
    ]

    col_widths = [55 * mm, 115 * mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _MID_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0), _WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_LIGHT_GREY, _WHITE]),
        ("FONTSIZE",      (0, 1), (-1, -1), 9),
        ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",     (0, 1), (0, -1), _MID_BLUE),
        ("BACKGROUND",    (1, 3), (1, 3), sev_colour),   # severity row — MUST BE AFTER ROWBACKGROUNDS
        ("TEXTCOLOR",     (1, 3), (1, 3), _WHITE),
        ("FONTNAME",      (1, 3), (1, 3), "Helvetica-Bold"),
        ("GRID",          (0, 0), (-1, -1), 0.4, _BORDER_GREY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("WORDWRAP",      (0, 0), (-1, -1), "CJK"),
    ])
    table.setStyle(style)
    elements.append(table)
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_attack_timeline(
    styles,
    contributing_signals: list,
    alert: dict | None = None,
    response_plan: dict | None = None,
) -> list:
    """
    Section 2 — Attack Timeline.

    Each row is built from a contributing signal dict when available.
    When signals are plain strings (e.g. ``["network", "system"]``), the
    row is enriched from the top-level ``alert`` dict so that Source,
    Severity, Confidence, and Detail are never hard-coded or empty.
    """
    elements = []
    elements.append(Paragraph("3 — Attack Timeline", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    if not contributing_signals:
        elements.append(Paragraph("No contributing signals recorded.", styles["body"]))
        elements.append(Spacer(1, 4 * mm))
        return elements

    alert = alert or {}
    response_plan = response_plan or {}

    # Derive fallback values from the top-level alert
    _fallback_ts       = str(alert.get("ts", alert.get("timestamp", alert.get("created_at", "N/A"))))
    _fallback_severity = str(alert.get("severity", "N/A")).upper()
    _fallback_score    = alert.get("threat_score", alert.get("confidence", alert.get("score", 0.0)))
    try:
        _fallback_conf = float(_fallback_score)
    except (TypeError, ValueError):
        _fallback_conf = 0.0
    _fallback_attack   = str(
        alert.get("attack_type", alert.get("attack", response_plan.get("attack_type", "Unknown")))
    )

    # Derive sources list from response_plan when signals are bare strings
    _plan_sources: list = response_plan.get("sources", [])

    # Sort by timestamp if present, otherwise preserve order
    def _sig_ts(sig):
        raw = sig.get("timestamp", sig.get("ts", "")) if isinstance(sig, dict) else ""
        return str(raw)

    sorted_signals = sorted(contributing_signals, key=_sig_ts)

    def _fmt_ts(raw_ts) -> str:
        """Truncate ISO 8601 timestamp to YYYY-MM-DD HH:MM:SS (19 chars)."""
        s = str(raw_ts) if raw_ts is not None else "N/A"
        if "T" in s:
            s = s.replace("T", " ")[:19]
        return s

    # Build normalised rows first, then collapse duplicates. Contributing signals
    # from a single detection cycle are often identical (e.g. three PortScan flow
    # samples) — showing three identical rows adds no information, so identical
    # rows are merged and annotated with an occurrence count.
    built: list = []
    for sig in sorted_signals:
        if not isinstance(sig, dict):
            source_str = str(sig)
            joined = ", ".join(str(s) for s in _plan_sources) if _plan_sources else source_str
            row_source   = _truncate(joined, 20)
            row_ts       = _fmt_ts(_fallback_ts)
            row_severity = _fallback_severity
            row_conf     = f"{_fallback_conf:.2f}"
            row_detail   = _truncate(_fallback_attack, 40)
        else:
            source_raw = sig.get("source", sig.get("sources"))
            if isinstance(source_raw, list):
                source_raw = ", ".join(str(s) for s in source_raw)
            row_source   = _truncate(str(source_raw) if source_raw else "unknown", 20)
            row_ts       = _fmt_ts(sig.get("timestamp", sig.get("ts", _fallback_ts)))
            row_severity = _truncate(sig.get("severity", _fallback_severity), 10)
            try:
                conf_val = float(sig.get("confidence", sig.get("score", sig.get("threat_score", _fallback_conf))))
            except (TypeError, ValueError):
                conf_val = _fallback_conf
            row_conf   = f"{conf_val:.2f}"
            row_detail = _truncate(
                sig.get("prediction", sig.get("detail", sig.get("attack_type", _fallback_attack))),
                40,
            )
        built.append((row_source, row_ts, row_severity, row_conf, row_detail))

    # Collapse identical rows (same source/severity/confidence/detail), keeping
    # the earliest timestamp and counting occurrences.
    merged: list = []
    counts: dict = {}
    for r in built:
        key = (r[0], r[2], r[3], r[4])  # source, severity, conf, detail
        if key in counts:
            idx_pos = counts[key]
            merged[idx_pos] = (merged[idx_pos][0], min(merged[idx_pos][1], r[1]),
                               merged[idx_pos][2], merged[idx_pos][3], merged[idx_pos][4],
                               merged[idx_pos][5] + 1)
        else:
            counts[key] = len(merged)
            merged.append((r[0], r[1], r[2], r[3], r[4], 1))

    data = [["#", "Source", "Timestamp", "Severity", "Confidence", "Detail"]]
    for idx, (m_src, m_ts, m_sev, m_conf, m_detail, m_n) in enumerate(merged, start=1):
        detail = m_detail + (f"  (x{m_n} flows)" if m_n > 1 else "")
        data.append([str(idx), m_src, m_ts, m_sev, m_conf, detail])

    # Column widths (points): #=20, Source=55, Timestamp=130, Severity=55,
    # Confidence=55, Detail=125  → total 440pt ≈ letter-page usable width.
    # Using mm: 7+19.5+46+19.5+19.5+44.5 = 155.5 mm ≈ 170 mm usable on A4
    col_widths = [7 * mm, 19.5 * mm, 46 * mm, 19.5 * mm, 19.5 * mm, 44.5 * mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle(list(_TABLE_HEADER_STYLE._cmds))
    # Row font size reduced to 8pt so long values don't overflow
    style.add("FONTSIZE",  (0, 1), (-1, -1), 8)
    # Detail column gets explicit word-wrap
    style.add("WORDWRAP",  (5, 0), (5, -1), "CJK")
    # All rows align to TOP so multi-line cells don't visually bleed into neighbours
    style.add("VALIGN",    (0, 0), (-1, -1), "TOP")
    table.setStyle(style)
    elements.append(table)
    elements.append(Spacer(1, 4 * mm))
    return elements


def _malware_detail_rows(alert: dict, contributing: list) -> list:
    """Extract malware-specific artifact fields (file, hash, label, confidence)
    from the alert / contributing signals for the malware evidence sub-table."""
    def _first(*keys):
        for src in [alert] + [s for s in (contributing or []) if isinstance(s, dict)]:
            for k in keys:
                v = src.get(k)
                if v not in (None, "", 0):
                    return v
        return None

    rows = []
    fp = _first("file_path", "path", "filepath", "file")
    if fp:
        rows.append(["File Path", _truncate(str(fp), 70)])
    for label, keys in [
        ("File Hash (SHA-256)", ("sha256", "hash", "sha_256")),
        ("File Hash (MD5)",     ("md5",)),
        ("Classifier Label",    ("label",)),
        ("Model Confidence",    ("confidence", "malware_score", "model_score")),
        ("Trusted / Signed",    ("trusted",)),
        ("Trust Reason",        ("trust_reason",)),
    ]:
        v = _first(*keys)
        if v is None:
            continue
        if label == "Model Confidence":
            try:
                v = f"{float(v) * 100:.1f}%" if float(v) <= 1.0 else f"{float(v):.1f}%"
            except (TypeError, ValueError):
                pass
        elif label == "Trusted / Signed":
            v = "Yes" if v in (True, "true", 1, "1") else "No"
        rows.append([label, _truncate(str(v), 70)])
    return rows


def _build_narrative_section(
    styles, section_no: str, alert: dict, response_plan: dict, contributing: list,
) -> list:
    """Plain-English incident narrative + deep, attack-type-specific threat analysis
    (what the attack is, how it works, its impact, and the attacker's next steps)."""
    elements = []
    elements.append(Paragraph(f"{section_no} — Attack Narrative & Threat Analysis", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    attack_type = str(alert.get("attack_type", response_plan.get("attack_type", "Unknown")))
    mitre = str(response_plan.get("mitre_technique", ""))
    severity = str(alert.get("severity", response_plan.get("severity", "UNKNOWN")))
    try:
        score = float(alert.get("threat_score", response_plan.get("threat_score", 0.0)))
    except (TypeError, ValueError):
        score = 0.0
    src_ip = _resolve_src_ip(alert, response_plan, contributing)
    target = str(alert.get("endpoint_id", response_plan.get("endpoint_id", "the endpoint")))
    features = _resolve_features(alert, response_plan, contributing)

    # Incident-specific opening narrative
    text = _build_narrative_text(attack_type, severity, score, src_ip, target, features)
    elements.append(Paragraph(text, styles["body"]))
    elements.append(Spacer(1, 3 * mm))

    # Deep, attack-type-specific threat analysis
    intel = _threat_intel_for(attack_type, mitre)
    for heading, key in (
        ("What this attack is",        "what"),
        ("How it works &amp; how it was detected", "how"),
        ("Potential impact",           "impact"),
        ("Likely attacker next steps", "next"),
    ):
        body = intel.get(key)
        if body:
            elements.append(Paragraph(f"<b>{heading}:</b> {body}", styles["body"]))
            elements.append(Spacer(1, 1.5 * mm))

    # Malware-specific artifact detail (only when the detection is malware and
    # the alert carries file/hash/label fields).
    if "malware" in (attack_type.lower() + " " + str(alert.get("attack_type", "")).lower()) \
            or alert.get("label") or alert.get("file_path"):
        mrows = _malware_detail_rows(alert, contributing)
        if mrows:
            elements.append(Spacer(1, 1 * mm))
            elements.append(Paragraph("<b>Detected file details:</b>", styles["body"]))
            elements.append(Spacer(1, 1 * mm))
            mtable = Table([["Attribute", "Value"]] + mrows, colWidths=[50 * mm, 120 * mm], repeatRows=1)
            mstyle = TableStyle(list(_TABLE_HEADER_STYLE._cmds))
            mstyle.add("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold")
            mstyle.add("TEXTCOLOR", (0, 1), (0, -1), _MID_BLUE)
            mtable.setStyle(mstyle)
            elements.append(mtable)

    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_detection_evidence(
    styles, section_no: str, alert: dict, response_plan: dict, contributing: list,
) -> list:
    """Technical evidence table built from the raw network flow feature vector.
    Only present, non-zero fields are shown; skipped entirely when no flow data
    is available (e.g. a pure system/user correlation)."""
    features = _resolve_features(alert, response_plan, contributing)
    rows = []
    for key, label, unit in _NETWORK_EVIDENCE_FIELDS:
        if key not in features:
            continue
        try:
            val = float(features.get(key))
        except (TypeError, ValueError):
            continue
        if val == 0.0:
            continue
        disp = _fmt_num(val) + (f" {unit}" if unit else "")
        rows.append([label, disp])

    elements = []
    elements.append(Paragraph(f"{section_no} — Detection Details & Network Evidence", styles["section"]))
    elements.append(Spacer(1, 2 * mm))
    if not rows:
        elements.append(Paragraph(
            "No network flow evidence is associated with this incident (it was raised "
            "by system/user/host-behaviour correlation rather than a network flow).",
            styles["body"],
        ))
        elements.append(Spacer(1, 4 * mm))
        return elements
    elements.append(Paragraph(
        "The following flow-level measurements were extracted from the traffic that "
        "triggered this detection and form the technical basis of the verdict.",
        styles["body"],
    ))
    elements.append(Spacer(1, 2 * mm))

    data = [["Flow Attribute", "Observed Value"]] + rows
    table = Table(data, colWidths=[85 * mm, 85 * mm], repeatRows=1)
    style = TableStyle(list(_TABLE_HEADER_STYLE._cmds))
    style.add("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold")
    style.add("TEXTCOLOR", (0, 1), (0, -1), _MID_BLUE)
    table.setStyle(style)
    elements.append(table)
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_iocs(
    styles, section_no: str, alert: dict, response_plan: dict, contributing: list,
    mitre_technique: str,
) -> list:
    """Indicators of Compromise — the actionable artifacts an analyst can block/hunt."""
    src_ip = _resolve_src_ip(alert, response_plan, contributing)
    features = _resolve_features(alert, response_plan, contributing)
    attack_type = str(alert.get("attack_type", response_plan.get("attack_type", "Unknown")))

    rows = []
    if src_ip:
        rows.append(["Source IPv4", src_ip, "Block at firewall; hunt across fleet"])
    try:
        dp = int(float(features.get("Destination Port", 0)))
        if dp > 0:
            rows.append(["Destination Port", str(dp), "Verify service exposure"])
    except (TypeError, ValueError):
        pass
    if attack_type and attack_type.lower() != "unknown":
        rows.append(["Attack Signature", attack_type, "Detection pattern"])
    if mitre_technique:
        rows.append(["MITRE Technique", mitre_technique, "ATT&CK reference"])

    elements = []
    elements.append(Paragraph(f"{section_no} — Indicators of Compromise (IOCs)", styles["section"]))
    elements.append(Spacer(1, 2 * mm))
    if not rows:
        elements.append(Paragraph(
            "No discrete network IOCs were extracted for this incident.", styles["body"]))
        elements.append(Spacer(1, 4 * mm))
        return elements
    data = [["Type", "Indicator", "Analyst Action"]] + rows
    table = Table(data, colWidths=[42 * mm, 68 * mm, 60 * mm], repeatRows=1)
    style = TableStyle(list(_TABLE_HEADER_STYLE._cmds))
    style.add("FONTNAME", (1, 1), (1, -1), "Courier-Bold")
    table.setStyle(style)
    elements.append(table)
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_remediation(
    styles, section_no: str, attack_type: str, mitre_technique: str,
) -> list:
    """Attack-type-specific recommended remediation steps."""
    steps = _remediation_steps(attack_type, mitre_technique)
    elements = []
    elements.append(Paragraph(f"{section_no} — Recommended Remediation", styles["section"]))
    elements.append(Spacer(1, 2 * mm))
    elements.append(Paragraph(
        f"Recommended manual actions for a <b>{attack_type or 'threat'}</b> incident, "
        "in priority order:",
        styles["body"],
    ))
    elements.append(Spacer(1, 1 * mm))
    for i, step in enumerate(steps, start=1):
        elements.append(Paragraph(f"<b>{i}.</b> {step}", styles["body"]))
    elements.append(Spacer(1, 4 * mm))
    return elements


def _normalise_shap_items(shap_explanation) -> list:
    """
    Normalise the SHAP payload to a flat list of items.
    Each item is either a dict with "feature" + numeric value key,
    or a plain string.  Returns [] if nothing usable is found.
    """
    if not shap_explanation:
        return []
    items = shap_explanation
    if isinstance(shap_explanation, dict):
        items = shap_explanation.get("top_features", shap_explanation.get("reason", []))
    if not isinstance(items, list):
        items = [str(items)]
    return items


def _build_shap_section(styles, shap_explanation: list) -> list:
    """Section 3 — SHAP Explanation: visual bar chart + detail table."""
    elements = []
    elements.append(Paragraph("7 — SHAP Explanation", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    items = _normalise_shap_items(shap_explanation)

    # --- Visual bar chart (always rendered; shows "no data" notice when empty) ---
    # A4 usable width (210 mm - 40 mm margins) in points = ~482 pt; leave a few mm
    chart_width_pt = 170 * mm  # ~482 pt converted via mm
    chart = _SHAPBarChart(items, available_width=float(chart_width_pt))
    elements.append(chart)
    elements.append(Spacer(1, 3 * mm))

    if not items:
        elements.append(
            Paragraph(
                "SHAP explanation not available for this alert "
                "(model may not support explainability or explanation was not captured).",
                styles["body"],
            )
        )
        elements.append(Spacer(1, 4 * mm))
        return elements

    # --- Detail table (feature name, numeric value, direction) ---
    data = [["Rank", "Feature", "Importance / Value", "Direction"]]
    for rank, item in enumerate(items[:15], start=1):
        if isinstance(item, dict):
            feature = _truncate(item.get("feature", item.get("name", "unknown")), 35)
            importance = item.get("importance", item.get("shap_value", item.get("value", 0.0)))
            try:
                imp_float = float(importance)
                imp_str = f"{imp_float:+.4f}"
                direction = "Increases risk" if imp_float > 0 else "Decreases risk"
            except (TypeError, ValueError):
                imp_str = _truncate(str(importance), 20)
                direction = "—"
        else:
            feature = _truncate(str(item), 50)
            imp_str = "—"
            direction = "—"

        data.append([str(rank), feature, imp_str, direction])

    col_widths = [12 * mm, 75 * mm, 45 * mm, 38 * mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)

    # Colour positive/negative importance values
    tbl_style = TableStyle(list(_TABLE_HEADER_STYLE._cmds))
    for row_idx, row_data in enumerate(data[1:], start=1):
        dir_val = row_data[3]
        if dir_val == "Increases risk":
            tbl_style.add("TEXTCOLOR", (3, row_idx), (3, row_idx), _RED)
            tbl_style.add("FONTNAME",  (3, row_idx), (3, row_idx), "Helvetica-Bold")
        elif dir_val == "Decreases risk":
            tbl_style.add("TEXTCOLOR", (3, row_idx), (3, row_idx), _GREEN)
            tbl_style.add("FONTNAME",  (3, row_idx), (3, row_idx), "Helvetica-Bold")

    table.setStyle(tbl_style)
    elements.append(table)
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_mitre_section(styles, mitre_technique: str, severity: str) -> list:
    """
    Section 2b — MITRE ATT&CK Mapping.
    Shows the technique ID, name, tactic, and a brief description.
    Falls back gracefully when the technique ID is not in MITRE_LOOKUP.
    """
    elements = []
    elements.append(Paragraph("5 — MITRE ATT&amp;CK Mapping", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    tech_id = str(mitre_technique or "").strip().upper()
    info = MITRE_LOOKUP.get(tech_id)
    accent = _severity_badge_colour(severity)

    if not tech_id or tech_id in ("N/A", "UNKNOWN", ""):
        elements.append(
            Paragraph("No MITRE ATT&CK technique was mapped to this alert.", styles["body"])
        )
        elements.append(Spacer(1, 4 * mm))
        return elements

    # Technique ID badge row
    id_style = ParagraphStyle(
        "MITREId",
        parent=styles["body"],
        fontSize=14,
        fontName="Helvetica-Bold",
        textColor=accent,
        spaceAfter=2,
    )
    elements.append(Paragraph(tech_id, id_style))

    if info:
        name_style = ParagraphStyle(
            "MITREName",
            parent=styles["body"],
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=_DARK_BLUE,
            spaceAfter=1,
        )
        elements.append(Paragraph(info["name"], name_style))

        # Tactic badge — small coloured box rendered as a one-cell table
        tactic_data = [[f"Tactic: {info['tactic']}"]]
        tactic_table = Table(tactic_data, colWidths=[60 * mm])
        tactic_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), _MID_BLUE),
            ("TEXTCOLOR",    (0, 0), (-1, -1), _WHITE),
            ("FONTNAME",     (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(tactic_table)
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph(info["description"], styles["body"]))
    else:
        # Technique ID present but not in lookup (future technique or custom)
        elements.append(
            Paragraph(
                f"Technique {tech_id} is not in the local MITRE lookup. "
                "Refer to https://attack.mitre.org/ for details.",
                styles["body"],
            )
        )

    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_response_actions(styles, response_plan: dict, execution_results: list) -> list:
    elements = []
    elements.append(Paragraph("8 — Response Actions", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    recommended = response_plan.get("recommended_actions", [])
    if not recommended:
        elements.append(
            Paragraph("No automated response actions were executed for this incident.", styles["body"])
        )
        elements.append(Spacer(1, 4 * mm))
        return elements

    # Build execution result lookup: {action_key: result_doc}
    exec_map: dict = {}
    for res in (execution_results or []):
        if not isinstance(res, dict):
            continue
        key = str(res.get("action", "")).lower()
        if key:
            exec_map[key] = res

    # Advisory actions — those that are NEVER sent to the endpoint agent.
    # Must be kept in sync with _ADVISORY_ACTIONS in backend.py.
    # Actions with real SOAR executor implementations (kill_process, block_ip,
    # unblock_ip, isolate_host, unisolate_host, quarantine_file,
    # restore_quarantine_file, lock_account, unlock_account, scan_filesystem,
    # monitor_persistence) must NOT appear here — they execute automatically
    # and their status comes back via endpoint_commands ACK.
    _ADVISORY = frozenset({
        "log_user_session",
        "restrict_access", "rate_limit_traffic",
        "log_event",
        "patch_openssl", "rotate_certificates", "check_exposed_secrets", "update_software",
        "alert_admin", "force_logout", "review_account", "review_logs",
        "invalidate_sessions",
        "collect_forensics",
    })

    # Status symbol mapping (ASCII equivalents — ReportLab PDF fonts may not have unicode)
    _STATUS_SYMBOL = {
        "Executed": "[OK]",
        "Advisory": "[ADV]",
        "Failed":   "[FAIL]",
        "Pending":  "[...]",
    }

    data = [["Status", "Action", "Target", "Result / Reason", "Executed At"]]
    for action_def in recommended:
        if not isinstance(action_def, dict):
            continue
        action = str(action_def.get("action", "unknown"))
        target = _truncate(str(action_def.get("target", "—")), 22)
        reason = _truncate(str(action_def.get("reason", "—")), 40)

        # Determine if advisory
        is_advisory = action.lower() in _ADVISORY

        exec_result = exec_map.get(action.lower(), {})
        raw_status = str(exec_result.get("status", ""))
        exec_ts = _truncate(
            str(exec_result.get("executed_at", exec_result.get("completed_at", "—"))), 20
        )
        result_msg = _truncate(
            str(exec_result.get("result_message", exec_result.get("result", reason))), 40
        )

        # Normalise status label
        if is_advisory:
            display_status = "Advisory"
        else:
            status_upper = raw_status.upper()
            if status_upper in ("COMPLETED", "SUCCESS", "OK", "DONE"):
                display_status = "Executed"
            elif status_upper in ("FAILED", "ERROR"):
                display_status = "Failed"
            else:
                display_status = "Pending"

        symbol = _STATUS_SYMBOL.get(display_status, "[?]")
        status_cell = f"{symbol} {display_status}"

        data.append([status_cell, action, target, result_msg, exec_ts])

    # Column widths: Status(22) + Action(32) + Target(26) + Result(58) + ExecutedAt(32) = 170 mm
    col_widths = [22 * mm, 32 * mm, 26 * mm, 58 * mm, 32 * mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)

    tbl_style = TableStyle(list(_TABLE_HEADER_STYLE._cmds))
    # Ensure text wraps rather than overflows in all cells
    tbl_style.add("WORDWRAP",     (0, 0), (-1, -1), "CJK")
    tbl_style.add("LEFTPADDING",  (0, 0), (-1, -1), 4)
    tbl_style.add("RIGHTPADDING", (0, 0), (-1, -1), 4)
    # Colour-code the Status column cells
    for row_idx, row_data in enumerate(data[1:], start=1):
        raw_cell = row_data[0]
        if "[OK]" in raw_cell:
            tbl_style.add("BACKGROUND", (0, row_idx), (0, row_idx), colors.HexColor("#E8F5E9"))
            tbl_style.add("TEXTCOLOR",  (0, row_idx), (0, row_idx), _GREEN)
            tbl_style.add("FONTNAME",   (0, row_idx), (0, row_idx), "Helvetica-Bold")
        elif "[FAIL]" in raw_cell:
            tbl_style.add("BACKGROUND", (0, row_idx), (0, row_idx), colors.HexColor("#FFEBEE"))
            tbl_style.add("TEXTCOLOR",  (0, row_idx), (0, row_idx), _RED)
            tbl_style.add("FONTNAME",   (0, row_idx), (0, row_idx), "Helvetica-Bold")
        elif "[ADV]" in raw_cell:
            tbl_style.add("BACKGROUND", (0, row_idx), (0, row_idx), colors.HexColor("#FFF8E1"))
            tbl_style.add("TEXTCOLOR",  (0, row_idx), (0, row_idx), _ORANGE)
            tbl_style.add("FONTNAME",   (0, row_idx), (0, row_idx), "Helvetica-Bold")
        elif "[...]" in raw_cell:
            tbl_style.add("TEXTCOLOR",  (0, row_idx), (0, row_idx), _MID_BLUE)

    table.setStyle(tbl_style)
    elements.append(table)
    elements.append(Spacer(1, 2 * mm))

    # Legend
    legend_style = ParagraphStyle(
        "ActionLegend",
        parent=styles["small"],
        alignment=TA_LEFT,
        fontSize=7,
        textColor=colors.HexColor("#757575"),
    )
    elements.append(
        Paragraph(
            "[OK] Executed  &nbsp;  [ADV] Advisory (human action required)  "
            "&nbsp;  [...] Pending  &nbsp;  [FAIL] Failed",
            legend_style,
        )
    )
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_final_status(styles, execution_results: list, response_plan: dict) -> list:
    elements = []

    final_status = _execution_final_status(execution_results)
    status_colour = _status_colour(final_status)

    status_style = ParagraphStyle(
        "StatusDynamic",
        parent=styles["status_base"],
        textColor=status_colour,
        fontSize=22,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=0,
        spaceBefore=0,
    )

    verdict_para = Paragraph(final_status, status_style)
    verdict_table = Table([[verdict_para]], colWidths=[170 * mm], rowHeights=[20 * mm])
    verdict_table.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("BOX",           (0, 0), (-1, -1), 1.5, status_colour),
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FAFAFA")),
    ]))

    # KeepTogether prevents the section heading from splitting from the verdict box
    elements.append(KeepTogether([
        Paragraph("10 — Final Status", styles["section"]),
        Spacer(1, 5 * mm),
        verdict_table,
    ]))
    elements.append(Spacer(1, 4 * mm))

    descriptions = {
        "CONTAINED": (
            "All recommended response actions were executed successfully. "
            "The threat has been neutralised and the endpoint is no longer at risk."
        ),
        "PARTIAL": (
            "Some response actions were executed but not all completed successfully. "
            "Manual follow-up is required to fully contain this incident."
        ),
        "PENDING": (
            "Response actions are queued and awaiting execution by the endpoint agent. "
            "No actions have failed — monitor the command queue for completion."
        ),
        "ADVISORY": (
            "All recommended actions are advisory and require human review. "
            "No automated SOAR commands were dispatched for this incident."
        ),
        "FAILED": (
            "Response actions could not be executed. "
            "Immediate manual intervention is required — escalate to Tier-2 SOC analyst."
        ),
    }
    desc = descriptions.get(final_status, "Status unknown — manual review required.")
    elements.append(Paragraph(desc, styles["body"]))
    elements.append(Spacer(1, 4 * mm))

    # Summary metrics table
    total_actions = len(response_plan.get("recommended_actions", []))
    exec_statuses = [str(r.get("status", "")).lower() for r in (execution_results or [])]
    executed = sum(1 for s in exec_statuses if s in ("completed", "success", "ok", "done"))
    failed = sum(1 for s in exec_statuses if s in ("failed", "error"))
    pending = total_actions - executed - failed

    data = [
        ["Metric", "Value"],
        ["Total Actions Planned",   str(total_actions)],
        ["Actions Executed",        str(executed)],
        ["Actions Failed",          str(failed)],
        ["Actions Pending",         str(max(0, pending))],
        ["MITRE ATT&CK Technique",  response_plan.get("mitre_technique", "N/A")],
        ["Auto-Executed",           "Yes" if response_plan.get("auto_execute") else "No"],
    ]
    col_widths = [80 * mm, 90 * mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(_TABLE_HEADER_STYLE)
    elements.append(table)
    elements.append(Spacer(1, 4 * mm))
    return elements


def _build_analyst_certification(
    styles,
    admin_name: str,
    admin_role: str,
    generated_at: str,
    severity: str,
) -> list:
    """
    Section 6 — Analyst Certification.
    Professional sign-off block with role, timestamp, system branding,
    a signature line, and a coloured CERTIFIED stamp.
    """
    elements = []
    elements.append(Paragraph("11 — Analyst Certification", styles["section"]))
    elements.append(Spacer(1, 3 * mm))
    elements.append(HRFlowable(width="100%", thickness=0.8, color=_BORDER_GREY))
    elements.append(Spacer(1, 3 * mm))

    accent = _severity_badge_colour(severity)

    # Two-column layout via a 2-cell table
    role_display = str(admin_role).capitalize() if admin_role else "SOC Analyst"

    left_content = (
        f"<b>Report Generated By:</b> <b>{admin_name}</b><br/>"
        f"<b>Role:</b> {role_display}<br/>"
        f"<b>Generated At:</b> {generated_at}<br/>"
        "<b>System:</b> Cyber Sentinel XDR v1.0"
    )

    sig_line_style = ParagraphStyle(
        "SigLine",
        parent=styles["body"],
        alignment=TA_CENTER,
        spaceAfter=2,
    )
    sig_name_style = ParagraphStyle(
        "SigName",
        parent=styles["body"],
        fontSize=13,
        fontName="Helvetica-Bold",
        textColor=_DARK_BLUE,
        alignment=TA_CENTER,
        spaceBefore=2,
        spaceAfter=2,
    )
    sig_role_style = ParagraphStyle(
        "SigRole",
        parent=styles["body"],
        fontSize=8,
        fontName="Helvetica",
        textColor=colors.HexColor("#616161"),
        alignment=TA_CENTER,
        spaceAfter=0,
    )

    sig_block = Table(
        [
            [Paragraph(f"<b>{admin_name}</b>", sig_name_style)],
            [Paragraph(f"{role_display}  |  {generated_at}", sig_role_style)],
        ],
        colWidths=[60 * mm],
    )
    sig_block.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))

    left_para = Paragraph(left_content, styles["body"])
    right_para = sig_block

    cert_data = [[left_para, right_para]]
    cert_table = Table(cert_data, colWidths=[110 * mm, 60 * mm])
    cert_table.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("ALIGN",         (1, 0), (1, 0),   "CENTER"),
    ]))
    elements.append(cert_table)
    elements.append(Spacer(1, 4 * mm))

    # CERTIFIED stamp — one-cell coloured table
    stamp_data = [["  CERTIFIED  "]]
    stamp_table = Table(stamp_data, colWidths=[40 * mm])
    stamp_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), accent),
        ("TEXTCOLOR",    (0, 0), (-1, -1), _WHITE),
        ("FONTNAME",     (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("BOX",          (0, 0), (-1, -1), 1.5, accent),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
    ]))
    # Right-align the stamp
    stamp_wrapper_data = [["", stamp_table]]
    stamp_wrapper = Table(stamp_wrapper_data, colWidths=[130 * mm, 40 * mm])
    stamp_wrapper.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(stamp_wrapper)
    elements.append(Spacer(1, 4 * mm))

    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["small"],
        fontSize=7.5,
        textColor=colors.HexColor("#757575"),
        alignment=TA_CENTER,
        spaceAfter=0,
    )
    elements.append(
        Paragraph(
            "This report was automatically generated by Cyber Sentinel XDR. "
            "The findings represent the AI-assisted analysis of detected threats "
            "and should be reviewed by a qualified security professional.",
            disclaimer_style,
        )
    )
    elements.append(Spacer(1, 2 * mm))
    return elements


def _build_footer(styles, admin_name: str, generated_at: str) -> list:
    """Minimal bottom-of-page footer line."""
    elements = []
    elements.append(HRFlowable(width="100%", thickness=1, color=_BORDER_GREY))
    elements.append(Spacer(1, 2 * mm))
    elements.append(
        Paragraph(
            "Cyber Sentinel XDR &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"Analyst: <b>{admin_name}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"{generated_at} &nbsp;&nbsp;|&nbsp;&nbsp; CONFIDENTIAL — SOC USE ONLY",
            styles["small"],
        )
    )
    return elements


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def generate_incident_report(
    incident_id: str,
    alert: dict,
    response_plan: dict,
    execution_results: list,
    admin_name: str,
    endpoint_info: dict,
    admin_role: str = "admin",
) -> str:
    """
    Generate a PDF incident report and save it to the reports directory.

    Parameters
    ----------
    incident_id       : Unique incident identifier (used as filename).
    alert             : Fused alert document from MongoDB fused_alerts collection.
    response_plan     : Response plan dict from generate_response_plan().
    execution_results : List of endpoint_commands documents with status.
    admin_name        : Name/username of the SOC analyst (derived from JWT server-side).
    endpoint_info     : endpoint_registry document (hostname, ip_address, etc.).
    admin_role        : JWT role of the caller (admin/analyst); used in certification block.
                        Defaults to "admin" for API-key callers.

    Returns
    -------
    str — Absolute path to the saved PDF file.

    Raises
    ------
    ImportError  — If reportlab is not installed.
    RuntimeError — If PDF generation fails.
    """
    if not _REPORTLAB_OK:
        raise ImportError(
            "reportlab is required for PDF generation. "
            "Install it with: pip install reportlab>=4.0.0"
        )

    # Ensure reports directory exists
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Sanitise incident_id for use as filename
    safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in incident_id)
    pdf_path = str(_REPORTS_DIR / f"{safe_id}.pdf")
    generated_at = _now_str()

    severity = str(alert.get("severity", response_plan.get("severity", "UNKNOWN"))).upper()
    mitre_technique = str(response_plan.get("mitre_technique", "")).strip()

    styles = _build_styles()

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"Incident Report — {incident_id}",
        author=admin_name,
        subject="Cyber Sentinel XDR Incident Report",
    )

    story = []

    # Page 1 — Header
    story += _build_header(styles, incident_id, generated_at)

    contributing = (
        alert.get("contributing_signals")
        or response_plan.get("contributing_signals")
        or alert.get("sources")
        or []
    )
    attack_type = str(alert.get("attack_type", response_plan.get("attack_type", "Unknown")))

    # Section 1 — Incident Summary (enriched: attacker IP, target port, domains)
    story += _build_incident_summary(
        styles, incident_id, alert, endpoint_info, response_plan, contributing
    )

    # Section 2 — Attack Narrative (plain-English story of the incident)
    story += _build_narrative_section(styles, "2", alert, response_plan, contributing)

    # Section 3 — Attack Timeline
    story += _build_attack_timeline(styles, contributing, alert=alert, response_plan=response_plan)

    # Section 4 — Detection Details & Network Evidence (from raw flow features)
    story += _build_detection_evidence(styles, "4", alert, response_plan, contributing)

    # Section 5 — MITRE ATT&CK Mapping
    story += _build_mitre_section(styles, mitre_technique, severity)

    # Section 6 — Indicators of Compromise
    story += _build_iocs(styles, "6", alert, response_plan, contributing, mitre_technique)

    # Section 7 — SHAP Explanation (visual bar chart + detail table)
    shap_data = (
        alert.get("shap_explanation")
        or alert.get("shap")
        or response_plan.get("shap_explanation")
        or []
    )
    story += _build_shap_section(styles, shap_data)

    # Section 8 — Response Actions
    story += _build_response_actions(styles, response_plan, execution_results)

    # Section 9 — Recommended Remediation (attack-type-specific playbook)
    story += _build_remediation(styles, "9", attack_type, mitre_technique)

    # Section 10 — Final Status
    story += _build_final_status(styles, execution_results, response_plan)

    # Section 11 — Analyst Certification
    story += _build_analyst_certification(
        styles, admin_name, admin_role, generated_at, severity
    )

    # Footer line
    story += _build_footer(styles, admin_name, generated_at)

    try:
        doc.build(story)
    except Exception as exc:
        raise RuntimeError(f"PDF generation failed for incident {incident_id}: {exc}") from exc

    return pdf_path
