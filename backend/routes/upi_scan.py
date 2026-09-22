"""
TRINETRA AI - UPI Fraud Scan Routes
====================================
Accepts UPI ID/VPA, transaction amount, and note, extracts features,
 runs the saved GNN + XGBoost model, and returns Safe / Suspicious / Scam verdict,
confidence score, risk score, reasons, and recommendations.

Every scan is persisted to ScanHistory.
"""

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog
from backend.utils.classifiers import classify_upi
from backend.utils.model_loader import get_upi_detector
from backend.utils.upi_features import is_valid_upi_id

upi_scan_bp = Blueprint("upi_scan", __name__, url_prefix="/scan/upi")


@upi_scan_bp.route("", methods=["GET", "POST"])
@login_required
def scan_upi():
    # Check if UPI model is ready
    detector = get_upi_detector()
    models_ready = detector is not None

    result = None
    submitted_upi = ""
    submitted_amount = ""
    submitted_note = ""

    if request.method == "POST":
        submitted_upi = (request.form.get("upi_id") or "").strip()
        submitted_amount = (request.form.get("amount") or "").strip()
        submitted_note = (request.form.get("note") or "").strip()

        if not submitted_upi:
            result = {"error": "Please enter a UPI ID (Virtual Payment Address) to analyze."}
        elif not is_valid_upi_id(submitted_upi):
            result = {"error": "Please enter a valid UPI ID, such as username@bank."}
        else:
            try:
                amount_val = float(submitted_amount) if submitted_amount else 0.0
            except (TypeError, ValueError):
                amount_val = 0.0
                result = {"error": "Amount must be a valid number."}

            if not result and (amount_val < 0 or amount_val > 10_000_000):
                result = {"error": "Amount must be between 0 and 10,000,000."}

            if not result:
                classification = classify_upi(submitted_upi, amount_val, submitted_note)

                if classification is None:
                    result = {
                        "error": "The UPI detection model is currently unavailable. Please check the model files."
                    }
                else:
                    # Construct input summary for database logging
                    note_summary = f", Note: '{submitted_note}'" if submitted_note else ""
                    amount_summary = f", Amount: Rs. {amount_val}" if amount_val > 0 else ""
                    input_summary = f"UPI ID: {submitted_upi}{amount_summary}{note_summary}"

                    record = ScanHistory(
                        user_id=current_user.id,
                        scan_type="upi",
                        input_summary=input_summary[:240],
                        verdict=classification["verdict"],
                        confidence_score=classification["confidence"],
                        risk_score=classification["risk"],
                        explanation=" ".join(classification["reasons"]),
                    )

                    db.session.add(record)
                    db.session.add(SystemLog(
                        level="info",
                        message=f"UPI scan classified as {classification['verdict']} ({classification['confidence']}%).",
                        source="upi_scan",
                    ))
                    try:
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
                        result = {"error": "The scan was analyzed but could not be saved. Please try again."}
                        classification = None

                    if classification is not None:
                        result = {
                            **classification,
                            "record_id": record.id
                        }

    return render_template(
        "scan/upi.html",
        active_page="upi-scan",
        page_title="UPI Fraud Detection",
        models_ready=models_ready,
        result=result,
        submitted_upi=submitted_upi,
        submitted_amount=submitted_amount,
        submitted_note=submitted_note,
    )
