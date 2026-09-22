"""
TRINETRA AI - URL Phishing Detection Routes

Accepts a URL, extracts lexical/structural features,
runs the trained XGBoost model, and returns:

- Safe / Suspicious / Scam verdict
- Confidence score
- Risk score
- Rule-based reasons
- Cybersecurity recommendations

Every scan is persisted to ScanHistory.
"""

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog

from backend.utils.xgboost_loader import (
    model,
    feature_columns,
    predict_url,
)

from backend.utils.url_features import (
    extract_url_features,
    explain_reasons,
    safety_tips,
)

import pandas as pd


url_scan_bp = Blueprint(
    "url_scan",
    __name__,
    url_prefix="/scan/url"
)

MAX_URL_CHARS = 2048


def classify_url(url):
    """
    Extract URL features and run XGBoost prediction.
    """

    if model is None:
        return None

    if feature_columns is None:
        return None

    try:
        # ------------------------------------------
        # Extract features
        # ------------------------------------------

        features = extract_url_features(url)

        # ------------------------------------------
        # Convert to DataFrame
        # ------------------------------------------

        X = pd.DataFrame(
            [features],
            columns=feature_columns
        )

        # ------------------------------------------
        # XGBoost prediction
        # ------------------------------------------

        prediction = predict_url(X)

        if prediction is None:
            return None

        # ------------------------------------------
        # Probabilities
        # ------------------------------------------

        safe_probability = float(
            prediction["safe_probability"]
        )

        scam_probability = float(
            prediction["scam_probability"]
        )

        confidence = float(
            prediction["confidence"]
        )

        # ------------------------------------------
        # Verdict
        # ------------------------------------------

        if prediction["prediction"] == "SCAM":

            verdict = "scam"

            risk = scam_probability

        else:

            # XGBoost itself gives SAFE/SCAM.
            # We use probability to create
            # Trinetra's three-level verdict.

            if scam_probability >= 70:

                verdict = "scam"

            elif scam_probability >= 40:

                verdict = "suspicious"

            else:

                verdict = "safe"

            risk = scam_probability

        # ------------------------------------------
        # Reasons
        # ------------------------------------------

        reasons = explain_reasons(url)

        # ------------------------------------------
        # Recommendations
        # ------------------------------------------

        recommendations = safety_tips(verdict)

        # ------------------------------------------
        # Final classification
        # ------------------------------------------

        return {
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "risk": round(risk, 2),

            "reasons": reasons,

            "recommendations": recommendations,

            "safe_probability": round(
                safe_probability,
                2
            ),

            "scam_probability": round(
                scam_probability,
                2
            ),
        }

    except Exception as e:

        print("❌ URL classification error:")
        print(e)

        return None


@url_scan_bp.route("", methods=["GET", "POST"])
@login_required
def scan_url():

    models_ready = (
        model is not None
        and feature_columns is not None
    )

    result = None
    submitted_url = ""

    # ==========================================
    # POST REQUEST
    # ==========================================

    if request.method == "POST":

        submitted_url = (
            request.form.get("url_text") or ""
        ).strip()

        # --------------------------------------
        # Empty URL
        # --------------------------------------

        if not submitted_url:

            result = {
                "error": "Please paste a URL to analyze."
            }

        # --------------------------------------
        # URL too long
        # --------------------------------------

        elif len(submitted_url) > MAX_URL_CHARS:

            result = {
                "error": (
                    f"That URL is too long "
                    f"(max {MAX_URL_CHARS} characters)."
                )
            }

        # --------------------------------------
        # Classification
        # --------------------------------------

        else:

            classification = classify_url(
                submitted_url
            )

            # ----------------------------------
            # Model unavailable
            # ----------------------------------

            if classification is None:

                result = {
                    "error": (
                        "The URL detection model "
                        "isn't available. Please "
                        "check the XGBoost model "
                        "installation."
                    )
                }

            # ----------------------------------
            # Save result
            # ----------------------------------

            else:

                record = ScanHistory(

                    user_id=current_user.id,

                    scan_type="url",

                    input_summary=submitted_url[:240],

                    verdict=classification["verdict"],

                    confidence_score=(
                        classification["confidence"]
                    ),

                    risk_score=(
                        classification["risk"]
                    ),

                    explanation=" ".join(
                        classification["reasons"]
                    ),
                )

                db.session.add(record)

                # ----------------------------------
                # System log
                # ----------------------------------

                db.session.add(
                    SystemLog(

                        level="info",

                        message=(
                            f"URL scan classified as "
                            f"{classification['verdict']} "
                            f"("
                            f"{classification['confidence']}"
                            f"% confidence)."
                        ),

                        source="url_scan",
                    )
                )

                db.session.commit()

                result = {
                    **classification,
                    "record_id": record.id
                }

    # ==========================================
    # RENDER PAGE
    # ==========================================

    return render_template(

        "scan/url.html",

        active_page="url-scan",

        page_title="URL Phishing Detection",

        models_ready=models_ready,

        result=result,

        submitted_url=submitted_url,
    )