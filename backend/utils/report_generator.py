"""
TRINETRA AI - PDF Report Generator
=====================================
Builds a downloadable PDF summarizing a single ScanHistory record:
scan type, input, verdict, confidence, risk, reasons, and
recommendations, with a timestamp and branded header.
"""

from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

VERDICT_COLORS = {
    "safe": colors.HexColor("#0a9b6c"),
    "suspicious": colors.HexColor("#c47f00"),
    "scam": colors.HexColor("#c62c4f"),
}

BRAND_COLOR = colors.HexColor("#00a6bf")
DARK_TEXT = colors.HexColor("#1a2436")
MUTED_TEXT = colors.HexColor("#5c6b7f")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TrinetraTitle", fontName="Helvetica-Bold", fontSize=20,
        textColor=DARK_TEXT, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="TrinetraTagline", fontName="Helvetica", fontSize=9.5,
        textColor=MUTED_TEXT, spaceAfter=14,
    ))
    styles.add(ParagraphStyle(
        name="SectionHead", fontName="Helvetica-Bold", fontSize=12.5,
        textColor=DARK_TEXT, spaceBefore=16, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="Body", fontName="Helvetica", fontSize=10, leading=15,
        textColor=DARK_TEXT,
    ))
    styles.add(ParagraphStyle(
        name="BulletBody", fontName="Helvetica", fontSize=10, leading=15,
        textColor=DARK_TEXT, leftIndent=14, bulletIndent=0,
    ))
    return styles


def generate_scan_report_pdf(record) -> BytesIO:
    """
    Build a PDF report for a ScanHistory record and return it as an
    in-memory BytesIO buffer (never touches disk).
    """
    buffer = BytesIO()
    styles = _styles()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=22 * mm, bottomMargin=20 * mm,
        leftMargin=20 * mm, rightMargin=20 * mm,
        title=f"TRINETRA AI Scan Report #{record.id}",
    )

    verdict = record.verdict
    verdict_color = VERDICT_COLORS.get(verdict, DARK_TEXT)
    story = []

    # ---- Header ----
    story.append(Paragraph("TRINETRA AI", styles["TrinetraTitle"]))
    story.append(Paragraph("Smart Third-Eye Cyber Scam Detection System &mdash; Scan Report", styles["TrinetraTagline"]))
    story.append(HRFlowable(width="100%", thickness=1.2, color=BRAND_COLOR, spaceAfter=14))

    # ---- Verdict banner ----
    verdict_table = Table(
        [[Paragraph(f"<b>VERDICT: {verdict.upper()}</b>", ParagraphStyle(
            "VerdictText", fontName="Helvetica-Bold", fontSize=14, textColor=colors.white,
        ))]],
        colWidths=[170 * mm],
    )
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 14))

    # ---- Summary table ----
    summary_rows = [
        ["Scan Type", record.scan_type.capitalize()],
        ["Record ID", f"#{record.id}"],
        ["Confidence Score", f"{record.confidence_score}%"],
        ["Risk Score", f"{record.risk_score}"],
        ["Scanned At", record.created_at.strftime("%d %b %Y, %I:%M %p")],
        ["Report Generated", __import__("datetime").datetime.now().strftime("%d %b %Y, %I:%M %p")],
    ]
    summary_table = Table(summary_rows, colWidths=[45 * mm, 125 * mm])
    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), DARK_TEXT),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#e2e6ea")),
    ]))
    story.append(summary_table)

    # ---- Input content ----
    story.append(Paragraph("Scanned Input", styles["SectionHead"]))
    story.append(Paragraph(_escape(record.input_summary), styles["Body"]))

    # ---- Explanation / reasons ----
    story.append(Paragraph("Analysis &amp; Reasons", styles["SectionHead"]))
    reasons = [r.strip() for r in (record.explanation or "").split(". ") if r.strip()]
    if reasons:
        for reason in reasons:
            text = reason if reason.endswith((".", "!", "?")) else reason + "."
            story.append(Paragraph(f"&bull; {_escape(text)}", styles["BulletBody"]))
    else:
        story.append(Paragraph("No additional analysis notes were recorded for this scan.", styles["Body"]))

    # ---- Recommendations ----
    story.append(Paragraph("Recommendations", styles["SectionHead"]))
    for tip in _recommendations_for(verdict):
        story.append(Paragraph(f"&bull; {_escape(tip)}", styles["BulletBody"]))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#e2e6ea")))
    story.append(Paragraph(
        "Generated by TRINETRA AI &mdash; Final Year Engineering Project. "
        "This report is a system-generated summary and does not constitute legal or financial advice.",
        ParagraphStyle("Footer", fontName="Helvetica-Oblique", fontSize=8, textColor=MUTED_TEXT, spaceBefore=10),
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer


def _recommendations_for(verdict: str) -> list:
    common = ["Never share OTPs, PINs, or passwords with anyone, even claimed bank/support staff."]
    if verdict == "safe":
        return ["No common scam indicators were found, but always stay cautious with unexpected requests."] + common
    if verdict == "suspicious":
        return [
            "Verify the sender/source independently before acting on this content.",
            "Do not click links or share details until you're confident it's genuine.",
        ] + common
    return [
        "Do not click links, call numbers, or share any details related to this content.",
        "Block and report the source through the relevant app or platform.",
        "If you already shared sensitive details, contact your bank/service provider immediately.",
    ] + common


def _escape(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
