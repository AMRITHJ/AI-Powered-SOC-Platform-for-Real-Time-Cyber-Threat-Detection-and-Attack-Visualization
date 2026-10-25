# backend/forensics.py

import os
import sys
import ipaddress
from datetime import datetime, timezone

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from backend.config import REPORTS_DIR, MITIGATIONS

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
    )

    RL_OK = True

except ImportError:
    RL_OK = False
    print("[FORENSICS] Install reportlab: pip install reportlab")


# ============================================================
# Helper functions
# ============================================================

def safe_value(value, default="N/A"):
    """
    Convert None or empty values into a clean report value.
    """

    if value is None:
        return default

    if isinstance(value, str) and not value.strip():
        return default

    return value


def is_private_ip(ip):
    """
    Check whether an IP address is private/local.

    Examples:
        192.168.x.x
        10.x.x.x
        172.16.x.x - 172.31.x.x
    """

    try:
        return ipaddress.ip_address(str(ip)).is_private

    except (ValueError, TypeError):
        return False


def format_confidence(value):
    """
    Format ML confidence cleanly.

    Supports:
        None        -> N/A
        0.95        -> 95.00%
        95.2        -> 95.20%
        "94.5%"     -> 94.5%
    """

    if value is None:
        return "N/A"

    if isinstance(value, str):

        value = value.strip()

        if not value:
            return "N/A"

        if value.endswith("%"):
            return value

        try:
            value = float(value)

        except ValueError:
            return value

    if isinstance(value, (int, float)):

        if 0 <= value <= 1:
            return f"{value * 100:.2f}%"

        return f"{value:.2f}%"

    return str(value)


def get_detection_information(event):
    """
    Determine how the event was detected.

    Behavioral events should not incorrectly claim that they
    were classified by Random Forest / Isolation Forest.
    """

    attack_type = str(
        safe_value(
            event.get("attack_type"),
            "UNKNOWN"
        )
    ).upper()

    ml_label = safe_value(
        event.get("ml_label")
    )

    ml_confidence = format_confidence(
        event.get("ml_conf_pct")
    )

    # Some parts of the project may use "confidence"
    # instead of "ml_conf_pct".
    if ml_confidence == "N/A":
        ml_confidence = format_confidence(
            event.get("confidence")
        )

    # --------------------------------------------------------
    # Determine detection method
    # --------------------------------------------------------

    if ml_label != "N/A":

        detection_method = safe_value(
            event.get("model"),
            "Machine Learning"
        )

    else:

        behavioral_attacks = {
            "PORT_SCAN",
            "PORT SCAN",
            "BRUTE_FORCE",
            "BRUTE FORCE",
            "SSH_BRUTE_FORCE",
            "SSH BRUTE FORCE",
            "RECON",
            "RECONNAISSANCE",
            "SYN_SCAN",
            "SYN SCAN",
        }

        if attack_type in behavioral_attacks:

            detection_method = (
                "Behavioral / Signature Detection"
            )

        else:

            detection_method = safe_value(
                event.get("detection_method"),
                "Behavioral / Rule-Based Detection"
            )

    # --------------------------------------------------------
    # Isolation Forest / anomaly result
    # --------------------------------------------------------

    anomaly_value = event.get("anomaly")

    # Support alternative field names if present
    if anomaly_value is None:
        anomaly_value = event.get("is_anomaly")

    if anomaly_value is True or anomaly_value == 1:
        anomaly_status = "Anomalous"

    elif anomaly_value is False or anomaly_value == 0:
        anomaly_status = "Normal"

    else:
        anomaly_status = "Not evaluated"

    return {
        "attack_type": attack_type,
        "detection_method": detection_method,
        "ml_label": ml_label,
        "ml_confidence": ml_confidence,
        "anomaly_status": anomaly_status,
    }


# ============================================================
# Main forensic report
# ============================================================

def generate_detection_report(event, session=None, cti=None):

    if not RL_OK:
        return ""

    os.makedirs(
        REPORTS_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Incident information
    # --------------------------------------------------------

    incident_id = event.get(
        "id",
        f"INC-{int(datetime.now(timezone.utc).timestamp())}"
    )

    filepath = os.path.join(
        REPORTS_DIR,
        f"{incident_id}.pdf"
    )

    severity = str(
        safe_value(
            event.get("severity"),
            "MEDIUM"
        )
    ).upper()

    src_ip = str(
        safe_value(
            event.get("src_ip"),
            "---"
        )
    )

    dst_ip = str(
        safe_value(
            event.get("dst_ip"),
            "---"
        )
    )

    detection = get_detection_information(
        event
    )

    attack_type = detection["attack_type"]

    # --------------------------------------------------------
    # PDF document
    # --------------------------------------------------------

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    styles = getSampleStyleSheet()

    story = []

    # --------------------------------------------------------
    # Colors
    # --------------------------------------------------------

    severity_color = {

        "CRITICAL":
            colors.HexColor("#ff4444"),

        "HIGH":
            colors.HexColor("#ff8c00"),

        "MEDIUM":
            colors.HexColor("#ffd700"),

        "LOW":
            colors.HexColor("#26a641")
    }

    # --------------------------------------------------------
    # Styles
    # --------------------------------------------------------

    title_style = ParagraphStyle(
        "title",
        fontSize=20,
        textColor=colors.HexColor("#58a6ff"),
        fontName="Helvetica-Bold",
        spaceAfter=4
    )

    small_style = ParagraphStyle(
        "small",
        fontSize=10,
        leading=13,
        spaceAfter=4
    )

    section_style = ParagraphStyle(
        "section",
        fontSize=13,
        textColor=colors.HexColor("#58a6ff"),
        fontName="Helvetica-Bold",
        spaceAfter=4
    )

    # ========================================================
    # Helper: Add section
    # ========================================================

    def add_section(title):

        story.append(
            Spacer(
                1,
                0.3 * cm
            )
        )

        story.append(
            HRFlowable(
                width="100%",
                thickness=1,
                color=colors.lightgrey
            )
        )

        story.append(
            Paragraph(
                title,
                section_style
            )
        )

    # ========================================================
    # Helper: Add table
    # ========================================================

    def add_table(rows):

        data = []

        for key, value in rows:

            value = safe_value(value)

            data.append(
                [
                    Paragraph(
                        f"<b>{key}</b>",
                        small_style
                    ),

                    Paragraph(
                        str(value),
                        small_style
                    )
                ]
            )

        table = Table(
            data,
            colWidths=[
                5 * cm,
                11 * cm
            ],
            repeatRows=0
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE"
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),

                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    ),
                ]
            )
        )

        story.append(table)

    # ========================================================
    # Header
    # ========================================================

    story.append(
        Paragraph(
            "FORENSIC INCIDENT REPORT",
            title_style
        )
    )

    story.append(
        Paragraph(
            "SOC Platform - MSc Cyber Security",
            small_style
        )
    )

    generated_time = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    story.append(
        Paragraph(
            f"Generated: {generated_time} UTC",
            small_style
        )
    )

    # ========================================================
    # Severity banner
    # ========================================================

    banner = Table(
        [
            [
                f"{severity} SEVERITY",
                attack_type.replace("_", " ")
            ]
        ],
        colWidths=[
            8 * cm,
            8 * cm
        ]
    )

    banner.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    severity_color.get(
                        severity,
                        colors.grey
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, -1),
                    colors.white
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, -1),
                    "Helvetica-Bold"
                ),

                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER"
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ]
        )
    )

    story.append(banner)

    # ========================================================
    # 1. Incident Summary
    # ========================================================

    add_section(
        "1. Incident Summary"
    )

    add_table(
        [
            (
                "Incident ID",
                incident_id
            ),

            (
                "Attack Type",
                attack_type
            ),

            (
                "Severity",
                severity
            ),

            (
                "Source IP",
                src_ip
            ),

            (
                "Destination IP",
                dst_ip
            )
        ]
    )

    # ========================================================
    # 2. Detection Analysis
    # ========================================================

    add_section(
        "2. Detection Analysis"
    )

    add_table(
        [
            (
                "Detection Method",
                detection["detection_method"]
            ),

            (
                "Attack Classification",
                attack_type
            ),

            (
                "ML Label",
                detection["ml_label"]
            ),

            (
                "ML Confidence",
                detection["ml_confidence"]
            ),

            (
                "Anomaly Status",
                detection["anomaly_status"]
            )
        ]
    )

    # ========================================================
    # 3. Threat Intelligence
    # ========================================================

    add_section(
        "3. Threat Intelligence"
    )

    # Private laboratory addresses should not receive
    # public CTI reputation scores.

    if is_private_ip(src_ip):

        add_table(
            [
                (
                    "CTI Status",
                    "Not applicable - Private laboratory IP"
                ),

                (
                    "Risk Score",
                    "N/A"
                ),

                (
                    "Risk Label",
                    "N/A"
                )
            ]
        )

    elif cti:

        risk_score = safe_value(
            cti.get("risk_score")
        )

        risk_label = safe_value(
            cti.get("risk_label")
        )

        add_table(
            [
                (
                    "CTI Status",
                    "External threat intelligence available"
                ),

                (
                    "Risk Score",
                    risk_score
                ),

                (
                    "Risk Label",
                    risk_label
                )
            ]
        )

    else:

        add_table(
            [
                (
                    "CTI Status",
                    "No threat intelligence available"
                ),

                (
                    "Risk Score",
                    "N/A"
                ),

                (
                    "Risk Label",
                    "N/A"
                )
            ]
        )

    # ========================================================
    # 4. Mitigations
    # ========================================================

    mitigations = (
        event.get("mitigations")
        or MITIGATIONS.get(
            attack_type,
            []
        )
    )

    if mitigations:

        add_section(
            "4. Mitigations"
        )

        for i, item in enumerate(
            mitigations,
            1
        ):

            story.append(
                Paragraph(
                    f"{i}. {item}",
                    small_style
                )
            )

    else:

        add_section(
            "4. Mitigations"
        )

        story.append(
            Paragraph(
                "No specific mitigation recommendations "
                "are available for this event.",
                small_style
            )
        )

    # ========================================================
    # Footer
    # ========================================================

    story.append(
        Spacer(
            1,
            0.5 * cm
        )
    )

    story.append(
        Paragraph(
            "Auto-generated by SOC Platform",
            small_style
        )
    )

    # ========================================================
    # Build report
    # ========================================================

    try:

        doc.build(story)

        print(
            f"[FORENSICS] Report created: {filepath}"
        )

        return filepath

    except Exception as exc:

        print(
            f"[FORENSICS] Report generation failed: {exc}"
        )

        return ""


# ============================================================
# Quick report
# ============================================================

def generate_quick_report(event):

    return generate_detection_report(
        event
    )