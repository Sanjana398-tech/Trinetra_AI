"""
TRINETRA AI - Payment Screenshot OCR & Analysis
===================================================
Extracts raw text from an uploaded payment screenshot with Tesseract
OCR, parses out the fields a genuine payment confirmation usually
contains (amount, UPI ID, transaction/UTR reference, bank name,
timestamp), and flags text-pattern indicators commonly missing or
inconsistent in fabricated screenshots.

Scope note: this performs OCR + text-pattern analysis, not pixel-level
image forensics (error-level analysis, metadata/EXIF inspection, font
consistency checks). That's a reasonable and clearly-documented scope
for a rule-based module — see README for the distinction.
"""

import re
from datetime import datetime

from PIL import Image, ImageOps
import pytesseract


# =============================================================
# OCR
# =============================================================

def _configure_tesseract(tesseract_cmd: str = ""):
    if tesseract_cmd:
        pytesseract.pytesseract.tesseract_cmd = tesseract_cmd


def extract_text(image_path: str, tesseract_cmd: str = "") -> str:
    """
    Run OCR on an image file and return the raw extracted text.
    Applies light preprocessing (grayscale, upscale, autocontrast)
    since payment-app screenshots are often small/compressed.
    """
    _configure_tesseract(tesseract_cmd)

    with Image.open(image_path) as img:
        img = img.convert("L")  # grayscale
        img = ImageOps.autocontrast(img)
        if img.width < 900:
            scale = 900 / img.width
            img = img.resize((int(img.width * scale), int(img.height * scale)), Image.LANCZOS)
        text = pytesseract.image_to_string(img)

    return text.strip()


# =============================================================
# Field extraction
# =============================================================

_AMOUNT_RE = re.compile(r"(?:₹|Rs\.?|INR)\s?([\d][\d,]*(?:\.\d{1,2})?)", re.IGNORECASE)
_UPI_ID_RE = re.compile(r"[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,20}")
_TXN_ID_RE = re.compile(
    r"(?:UTR|Txn(?:\s*ID)?|Transaction\s*ID|Ref(?:erence)?(?:\s*No\.?| ID)?)\s*[:\-]?\s*([A-Za-z0-9]{6,25})",
    re.IGNORECASE,
)
_TIMESTAMP_RE = re.compile(
    r"(\d{1,2}\s?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s?,?\s?\d{2,4}"
    r"(?:,?\s?\d{1,2}[:.]\d{2}\s?(?:AM|PM|am|pm)?)?|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})",
    re.IGNORECASE,
)

KNOWN_BANKS = [
    "State Bank of India", "SBI", "HDFC Bank", "HDFC", "ICICI Bank", "ICICI", "Axis Bank",
    "Punjab National Bank", "PNB", "Bank of Baroda", "Kotak Mahindra Bank", "Kotak",
    "Canara Bank", "Union Bank", "IDFC First Bank", "Yes Bank", "IndusInd Bank",
    "Google Pay", "GPay", "PhonePe", "Paytm", "Amazon Pay", "BHIM", "Cred",
]

# Loose set of real-world UPI handle suffixes. Not exhaustive — used only as a
# soft signal, not a hard rule (new/regional handles exist that aren't listed).
KNOWN_UPI_SUFFIXES = {
    "ybl", "okhdfcbank", "okaxis", "oksbi", "okicici", "paytm", "apl", "ibl",
    "axl", "sbi", "icici", "hdfcbank", "axisbank", "upi", "yesbank", "okbizaxis",
    "rbl", "idfcbank", "federal", "kotak", "pockets", "freecharge",
}

SUSPICIOUS_TEXT_MARKERS = [
    "sample", "test transaction", "demo", "dummy", "template", "specimen",
    "not a valid receipt", "screenshot for reference",
]


def parse_fields(raw_text: str) -> dict:
    """Extract amount / UPI ID / transaction ID / bank name / timestamp from OCR'd text."""
    text = raw_text or ""

    amount_match = _AMOUNT_RE.search(text)
    amount = amount_match.group(1) if amount_match else None

    upi_match = _UPI_ID_RE.search(text)
    upi_id = upi_match.group(0) if upi_match else None

    txn_match = _TXN_ID_RE.search(text)
    transaction_id = txn_match.group(1) if txn_match else None

    bank_name = None
    for bank in KNOWN_BANKS:
        if re.search(re.escape(bank), text, re.IGNORECASE):
            bank_name = bank
            break

    ts_match = _TIMESTAMP_RE.search(text)
    timestamp = ts_match.group(1) if ts_match else None

    return {
        "amount": amount,
        "upi_id": upi_id,
        "transaction_id": transaction_id,
        "bank_name": bank_name,
        "timestamp": timestamp,
    }


# =============================================================
# Fraud-indicator analysis (rule-based, no ML model — see README scope note)
# =============================================================

def analyze(raw_text: str, fields: dict) -> dict:
    """
    Score suspicious indicators found in the OCR'd text/fields.
    Returns {verdict, risk, confidence, reasons}.
    """
    text = raw_text or ""
    text_lower = text.lower()
    reasons = []
    risk = 0.0

    if len(text.strip()) < 25:
        risk += 20
        reasons.append("Very little text could be read from this image — either the quality is too "
                        "low, or it may not be a genuine payment confirmation screen.")

    if not fields.get("transaction_id"):
        risk += 25
        reasons.append("No transaction ID / UTR reference number was found. Genuine payment "
                        "confirmations almost always include one.")

    if not fields.get("timestamp"):
        risk += 15
        reasons.append("No date/time stamp was detected on this screenshot.")

    if not fields.get("bank_name"):
        risk += 10
        reasons.append("Couldn't identify a recognized bank or payment app name in this screenshot.")

    if not fields.get("amount"):
        risk += 15
        reasons.append("No payment amount could be clearly read from this image.")

    if fields.get("upi_id"):
        suffix = fields["upi_id"].split("@")[-1].lower()
        if suffix not in KNOWN_UPI_SUFFIXES:
            risk += 10
            reasons.append(f"The UPI handle suffix '@{suffix}' isn't one of the common banks/apps — "
                            "double-check it's a real payment provider.")

    matched_markers = [m for m in SUSPICIOUS_TEXT_MARKERS if m in text_lower]
    if matched_markers:
        risk += 30
        reasons.append("Contains wording associated with mock/sample receipts rather than a real one.")

    if re.search(r"\b(failed|declined|pending)\b", text_lower) and re.search(r"\b(success|successful|completed|paid)\b", text_lower):
        risk += 20
        reasons.append("Contains contradictory status words (e.g. both 'success' and 'failed/pending') "
                        "in the same image — a common sign of an edited screenshot.")

    risk = min(100.0, round(risk, 1))

    if risk >= 55:
        verdict = "scam"
    elif risk >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    fields_found = sum(1 for v in fields.values() if v)
    confidence = round(50 + (fields_found / 5) * 40 + (10 if len(text.strip()) > 60 else 0), 1)
    confidence = min(99.0, confidence)

    if not reasons:
        reasons.append("All expected payment confirmation details were found with no contradictions detected.")

    return {"verdict": verdict, "risk": risk, "confidence": confidence, "reasons": reasons}


def safety_tips(verdict: str) -> list:
    common = [
        "Always confirm a payment independently in your own banking app or passbook — never rely on a screenshot alone.",
        "A transaction ID/UTR can be verified directly with your bank if you're unsure.",
    ]
    if verdict == "safe":
        return ["This screenshot's extracted details look consistent, but always verify independently before releasing goods or services."] + common
    if verdict == "suspicious":
        return ["Ask the sender for the transaction ID/UTR and verify it in your own bank statement before proceeding."] + common
    return [
        "Do not release goods, services, or refunds based on this screenshot alone.",
        "Treat this as unverified until the money actually reflects in your account.",
    ] + common
