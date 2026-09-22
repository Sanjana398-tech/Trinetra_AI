"""
TRINETRA AI - Fake Payment Screenshot Detection Routes
==========================================================
Accepts an uploaded payment screenshot, runs Tesseract OCR to extract
its text, parses out the fields a genuine payment confirmation should
have (amount, UPI ID, transaction ID, bank name, timestamp), and flags
missing/inconsistent fields as fraud indicators. No ML model is used
here — it's a transparent, rule-based scoring engine (see README for
the OCR module's scope).
"""

import os
import uuid

from flask import Blueprint, render_template, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog
from backend.utils.screenshot_analyze import extract_text, parse_fields, analyze, safety_tips

screenshot_scan_bp = Blueprint("screenshot_scan", __name__, url_prefix="/scan/screenshot")


def _allowed_image(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]


def _summary_line(fields: dict) -> str:
    parts = []
    if fields.get("amount"):
        parts.append(f"₹{fields['amount']}")
    if fields.get("bank_name"):
        parts.append(fields["bank_name"])
    if fields.get("transaction_id"):
        parts.append(f"Txn {fields['transaction_id']}")
    return "Payment screenshot: " + (", ".join(parts) if parts else "no clear fields extracted")


@screenshot_scan_bp.route("", methods=["GET", "POST"])
@login_required
def scan_screenshot():
    result = None

    if request.method == "POST":
        file = request.files.get("screenshot_image")

        if not file or file.filename == "":
            result = {"error": "Please choose a payment screenshot to upload."}
        elif not _allowed_image(file.filename):
            allowed = ", ".join(sorted(current_app.config["ALLOWED_IMAGE_EXTENSIONS"]))
            result = {"error": f"Unsupported file type. Allowed formats: {allowed}."}
        else:
            filename = secure_filename(file.filename)
            temp_name = f"{uuid.uuid4().hex}_{filename}"
            temp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], temp_name)

            raw_text, ocr_error = None, None
            try:
                file.save(temp_path)
                raw_text = extract_text(temp_path, current_app.config.get("TESSERACT_CMD", ""))
            except Exception as exc:  # noqa: BLE001 - never crash on a bad upload / missing tesseract
                current_app.logger.exception("OCR extraction failed")
                if "tesseract is not installed" in str(exc).lower() or isinstance(exc, FileNotFoundError):
                    ocr_error = ("Tesseract OCR isn't installed or isn't on PATH on this machine. "
                                 "Install it (see README) and try again.")
                else:
                    ocr_error = "Couldn't read that image. Try a clearer screenshot in PNG, JPG, or WEBP format."
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)  # never retain uploaded screenshots longer than needed

            if ocr_error:
                result = {"error": ocr_error}
            elif not raw_text:
                result = {"error": "No readable text could be extracted from this image. "
                                    "Try a clearer, higher-resolution screenshot."}
            else:
                fields = parse_fields(raw_text)
                analysis = analyze(raw_text, fields)
                tips = safety_tips(analysis["verdict"])

                record = ScanHistory(
                    user_id=current_user.id,
                    scan_type="screenshot",
                    input_summary=_summary_line(fields)[:240],
                    verdict=analysis["verdict"],
                    confidence_score=analysis["confidence"],
                    risk_score=analysis["risk"],
                    explanation=" ".join(analysis["reasons"]),
                )
                db.session.add(record)
                db.session.add(SystemLog(
                    level="info",
                    message=f"Screenshot scan classified as {analysis['verdict']} ({analysis['confidence']}%).",
                    source="screenshot_scan",
                ))
                db.session.commit()

                result = {
                    "verdict": analysis["verdict"],
                    "confidence": analysis["confidence"],
                    "risk": analysis["risk"],
                    "reasons": analysis["reasons"],
                    "tips": tips,
                    "fields": fields,
                    "raw_text": raw_text,
                    "record_id": record.id,
                }

    return render_template(
        "scan/screenshot.html",
        active_page="screenshot-scan",
        page_title="Fake Payment Screenshot Detection",
        result=result,
    )
