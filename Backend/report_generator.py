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
# Constants that are always available (regardless of reportlab)
# ---------------------------------------------------------------------------
# Prefer XDR_REPORTS_DIR env var (set via config.py / .env); fall back to the
# original hard-coded path so existing deployments are unaffected.
_REPORTS_DIR = Path(os.environ.get("XDR_REPORTS_DIR", r"D:\Cyber Sentinal\reports"))

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


def _build_incident_summary(styles, incident_id: str, alert: dict, endpoint_info: dict) -> list:
    elements = []
    elements.append(Paragraph("1 — Incident Summary", styles["section"]))
    elements.append(Spacer(1, 2 * mm))

    severity = str(alert.get("severity", "UNKNOWN")).upper()
    sev_colour = _severity_badge_colour(severity)
    attack_type = str(alert.get("attack_type", alert.get("attack", "Unknown")))
    ts = str(alert.get("ts", alert.get("timestamp", alert.get("created_at", "N/A"))))
    hostname = str(endpoint_info.get("hostname", alert.get("endpoint_id", "N/A")))
    ip_address = str(endpoint_info.get("ip_address", "N/A"))
    threat_score = float(alert.get("threat_score", 0.0))

    data = [
        ["Field", "Value"],
        ["Incident ID",      incident_id],
        ["Timestamp",        ts],
        ["Severity",         severity],
        ["Attack Type",      attack_type],
        ["Threat Score",     f"{threat_score * 100:.1f} / 100"],
        ["Endpoint",         hostname],
        ["IP Address",       ip_address],
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
    elements.append(Paragraph("2 — Attack Timeline", styles["section"]))
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

    data = [["#", "Source", "Timestamp", "Severity", "Confidence", "Detail"]]
    for idx, sig in enumerate(sorted_signals, start=1):
        if not isinstance(sig, dict):
            # Plain string — the signal IS the source name
            source_str = str(sig)
            # Try to find a richer source label from the plan's sources list
            if _plan_sources:
                joined = ", ".join(str(s) for s in _plan_sources)
            else:
                joined = source_str
            row_source   = _truncate(joined, 20)
            row_ts       = _fmt_ts(_fallback_ts)
            row_severity = _fallback_severity
            row_conf     = f"{_fallback_conf:.2f}"
            row_detail   = _truncate(_fallback_attack, 40)
        else:
            # Rich signal dict — read directly, fall back to alert-level values
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

        data.append([str(idx), row_source, row_ts, row_severity, row_conf, row_detail])

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
    elements.append(Paragraph("3 — SHAP Explanation", styles["section"]))
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
    elements.append(Paragraph("2b — MITRE ATT&amp;CK Mapping", styles["section"]))
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
    elements.append(Paragraph("4 — Response Actions", styles["section"]))
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
        Paragraph("5 — Final Status", styles["section"]),
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
    elements.append(Paragraph("6 — Analyst Certification", styles["section"]))
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

    # Section 1 — Incident Summary
    story += _build_incident_summary(styles, incident_id, alert, endpoint_info)

    # Section 2 — Attack Timeline
    contributing = (
        alert.get("contributing_signals")
        or response_plan.get("contributing_signals")
        or alert.get("sources")
        or []
    )
    story += _build_attack_timeline(styles, contributing, alert=alert, response_plan=response_plan)

    # Section 2b — MITRE ATT&CK Mapping
    story += _build_mitre_section(styles, mitre_technique, severity)

    # Section 3 — SHAP Explanation (visual bar chart + detail table)
    shap_data = (
        alert.get("shap_explanation")
        or alert.get("shap")
        or response_plan.get("shap_explanation")
        or []
    )
    story += _build_shap_section(styles, shap_data)

    # Section 4 — Response Actions
    story += _build_response_actions(styles, response_plan, execution_results)

    # Section 5 — Final Status
    story += _build_final_status(styles, execution_results, response_plan)

    # Section 6 — Analyst Certification
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
