
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def generate_analysis_report(result, analyzer_name=None):
    """Generate a PDF from any PhishGuard AnalysisResult."""

    name = analyzer_name or getattr(result, "analyzer", "Security")
    name = str(name)

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=(612, 792),
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45,
        title=f"PhishGuard {name} Investigation Report",
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="PGTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#10213B"),
        alignment=TA_CENTER,
        spaceAfter=12,
    ))

    styles.add(ParagraphStyle(
        name="PGSection",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#087F91"),
        spaceBefore=16,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        name="PGBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=15,
        spaceAfter=7,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="PGSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=12,
        textColor=colors.HexColor("#53647A"),
    ))

    def paragraph(value, style="PGBody"):
        return Paragraph(
            escape(str(value if value is not None else "")),
            styles[style],
        )

    def section(title):
        story.append(
            Paragraph(escape(title), styles["PGSection"])
        )

    def field(label, value):
        if value is None or value == "":
            return

        if isinstance(value, dict):
            value = ", ".join(
                f"{key}: {item}"
                for key, item in value.items()
            )
        elif isinstance(value, (list, tuple)):
            value = ", ".join(map(str, value))

        story.append(paragraph(f"{label}: {value}"))

    story = []

    story.append(
        Paragraph("PHISHGUARD", styles["PGTitle"])
    )

    story.append(
        paragraph(
            f"{name.upper()} SECURITY INVESTIGATION REPORT",
            "PGSmall",
        )
    )

    story.append(Spacer(1, 20))

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    field("Generated", generated_at)
    field("Analyzer", name)
    field("Target", getattr(result, "target", "Unknown"))

    verdict = getattr(result, "verdict", "Unknown")
    verdict = getattr(verdict, "value", verdict)

    score = getattr(result, "score", 0)
    confidence = getattr(result, "confidence", None)

    if confidence is None:
        confidence_text = "N/A"
    else:
        confidence_text = f"{float(confidence) * 100:.0f}%"

    metrics = [
        ["RISK SCORE", "VERDICT", "CONFIDENCE"],
        [
            paragraph(f"{score}/100"),
            paragraph(str(verdict).replace("_", " ").title()),
            paragraph(confidence_text),
        ],
    ]

    table = Table(
        metrics,
        colWidths=[170, 170, 170],
        repeatRows=1,
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#10213B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1),
         colors.HexColor("#EDF7FA")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("BOX", (0, 0), (-1, -1), 0.5,
         colors.HexColor("#BDD5E2")),
    ]))

    story.append(Spacer(1, 15))
    story.append(table)

    section("Investigation Summary")

    story.append(paragraph(
        getattr(result, "summary", "")
        or "No investigation summary available."
    ))

    # Include analyzer-specific metadata.
    metadata = getattr(result, "metadata", {}) or {}

    if name.lower() == "email":
        section("Email Information")

        for key, label in [
            ("subject", "Subject"),
            ("from", "From"),
            ("from_domain", "Sender Domain"),
            ("reply_to", "Reply-To"),
            ("date", "Date"),
            ("message_id", "Message ID"),
            ("size", "Email Size"),
            ("authentication", "Authentication"),
            ("url_count", "Links Found"),
            ("attachment_count", "Attachments"),
        ]:
            field(label, metadata.get(key))

    section("Detected Signals")

    signals = getattr(result, "signals", []) or []

    if signals:
        for index, signal in enumerate(signals, start=1):
            title = (
                getattr(signal, "title", None)
                or getattr(signal, "id", None)
                or f"Signal {index}"
            )

            description = (
                getattr(signal, "description", None)
                or "No description available."
            )

            severity = getattr(signal, "severity", "")
            severity = getattr(severity, "value", severity)

            story.append(paragraph(
                f"{index}. [{severity}] {title}: {description}"
            ))

            evidence = getattr(signal, "evidence", None)

            if evidence:
                story.append(
                    paragraph(f"Evidence: {evidence}", "PGSmall")
                )
    else:
        story.append(paragraph("No signals returned."))

    section("Security Recommendations")

    recommendations = (
        getattr(result, "recommendations", []) or []
    )

    if recommendations:
        for index, recommendation in enumerate(
            recommendations, start=1
        ):
            story.append(paragraph(
                f"{index}. {recommendation}"
            ))
    else:
        story.append(paragraph(
            "No recommendations returned."
        ))

    story.append(Spacer(1, 20))

    story.append(paragraph(
        "Disclaimer: This report contains automated static "
        "security analysis. A low risk score does not guarantee "
        "that the analyzed content is safe. No external threat "
        "intelligence lookups were requested.",
        "PGSmall",
    ))

    document.build(story)

    buffer.seek(0)
    return buffer.getvalue()


# Preserve the existing URL PDF integration.
def generate_url_report(result):
    return generate_analysis_report(result, "URL")


def generate_email_report(result):
    return generate_analysis_report(result, "Email")


def generate_qr_report(result):
    return generate_analysis_report(result, "QR Code")


def generate_file_report(result):
    return generate_analysis_report(result, "File")


def generate_social_report(result):
    return generate_analysis_report(result, "Social Media")
