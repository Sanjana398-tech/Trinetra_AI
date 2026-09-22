"""
TRINETRA AI - QR Code Scanner Routes
=======================================
Accepts an uploaded QR code image, decodes it (OpenCV, no network
calls), then automatically routes the decoded content into whichever
detection engine fits: the URL Phishing model if it looks like a URL,
otherwise the Message Scam model — so a QR code containing plain text
(e.g. a fake "you've won" payload) still gets analyzed sensibly. UPI payment
payloads are analyzed with the saved GNN + XGBoost detector.
"""

import os
import uuid
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, render_template, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog
from backend.utils.qr_decode import decode_qr
from backend.utils.url_features import find_url_in_text
from backend.utils.classifiers import classify_url, classify_message, classify_upi

qr_scan_bp = Blueprint("qr_scan", __name__, url_prefix="/scan/qr")


def _allowed_image(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]


@qr_scan_bp.route("", methods=["GET", "POST"])
@login_required
def scan_qr():
    result = None

    if request.method == "POST":
        file = request.files.get("qr_image")

        if not file or file.filename == "":
            result = {"error": "Please choose a QR code image to upload."}
        elif not _allowed_image(file.filename):
            allowed = ", ".join(sorted(current_app.config["ALLOWED_IMAGE_EXTENSIONS"]))
            result = {"error": f"Unsupported file type. Allowed formats: {allowed}."}
        else:
            filename = secure_filename(file.filename)
            temp_name = f"{uuid.uuid4().hex}_{filename}"
            temp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], temp_name)

            try:
                file.save(temp_path)
                decoded_data, decode_error = decode_qr(temp_path)
            except Exception:  # noqa: BLE001 - never crash on a bad upload
                current_app.logger.exception("QR decode failed")
                decoded_data, decode_error = None, "Something went wrong reading that image. Please try another file."
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)  # never retain uploaded images longer than needed

            if decode_error:
                result = {"error": decode_error}
            else:
                parsed = urlparse(decoded_data.strip())
                upi_params = parse_qs(parsed.query)
                is_upi_payload = (
                    parsed.scheme.lower() == "upi"
                    and parsed.netloc.lower() == "pay"
                    and bool((upi_params.get("pa") or [""])[0].strip())
                )

                try:
                    if is_upi_payload:
                        classification = classify_upi(decoded_data)
                    else:
                        url_candidate = find_url_in_text(decoded_data)
                        classification = classify_url(url_candidate) if url_candidate else classify_message(decoded_data)
                except ValueError as error:
                    classification = None
                    result = {"error": str(error), "decoded_data": decoded_data}

                if classification is None:
                    if result is None:
                        result = {
                            "error": "QR code decoded successfully, but the detection model isn't trained yet. "
                                     "Run the training scripts (see README) and try again.",
                            "decoded_data": decoded_data,
                        }
                else:
                    record = ScanHistory(
                        user_id=current_user.id,
                        scan_type="qr",
                        input_summary=f"QR decoded \u2192 {decoded_data}"[:240],
                        verdict=classification["verdict"],
                        confidence_score=classification["confidence"],
                        risk_score=classification["risk"],
                        explanation=" ".join(classification["reasons"]),
                    )
                    db.session.add(record)
                    db.session.add(SystemLog(
                        level="info",
                        message=f"QR scan ({classification['engine']} engine) classified as "
                                f"{classification['verdict']} ({classification['confidence']}%).",
                        source="qr_scan",
                    ))
                    db.session.commit()

                    result = {**classification, "decoded_data": decoded_data, "record_id": record.id}

    return render_template(
        "scan/qr.html",
        active_page="qr-scan",
        page_title="QR Code Scanner",
        result=result,
    )
