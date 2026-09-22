"""
Message Scam Detection Route

Accepts SMS / Email / WhatsApp text, runs it through the trained
Fine-tuned DistilBERT model and returns a Safe / Scam verdict with
a confidence score, a risk score, plain-English reasons, and
cybersecurity recommendations.

Every scan is persisted to ScanHistory.

If the DistilBERT model isn't available, the page still renders
and shows a friendly warning instead of crashing.
"""

from flask import Blueprint, render_template, request, session
from flask_login import login_required, current_user

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog

from backend.utils.distilbert_loader import (
    model,
    tokenizer,
    predict_message,
)
from backend.utils.localization import to_english


# ============================================================
# BLUEPRINT
# ============================================================

message_scan_bp = Blueprint(
    "message_scan",
    __name__,
    url_prefix="/scan/message"
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_INPUT_CHARS = 4000


# ============================================================
# HELPER FUNCTION
# ============================================================

def _summarize(text: str, limit: int = 240) -> str:
    """
    Create a short version of the scanned message
    for storing in ScanHistory.
    """

    text = " ".join(text.split())

    return (
        text
        if len(text) <= limit
        else text[: limit - 1] + "…"
    )


# ============================================================
# MESSAGE SCAN ROUTE
# ============================================================

@message_scan_bp.route("", methods=["GET", "POST"])
@login_required
def scan_message():

    # --------------------------------------------------------
    # Check whether DistilBERT is available
    # --------------------------------------------------------

    models_ready = (
        model is not None
        and tokenizer is not None
    )

    result = None
    submitted_text = ""

    # ========================================================
    # HANDLE POST REQUEST
    # ========================================================

    if request.method == "POST":

        # ----------------------------------------------------
        # Get submitted message
        # ----------------------------------------------------

        submitted_text = (
            request.form.get("message_text") or ""
        ).strip()

        # ----------------------------------------------------
        # Validate empty message
        # ----------------------------------------------------

        if not submitted_text:

            result = {
                "error": "Please paste a message to analyze."
            }

        # ----------------------------------------------------
        # Validate message length
        # ----------------------------------------------------

        elif len(submitted_text) > MAX_INPUT_CHARS:

            result = {
                "error": (
                    f"That message is too long "
                    f"(max {MAX_INPUT_CHARS} characters)."
                )
            }

        # ----------------------------------------------------
        # Check model availability
        # ----------------------------------------------------

        elif not models_ready:

            result = {
                "error": (
                    "The DistilBERT detection model "
                    "is currently unavailable. "
                    "Please check the model files."
                )
            }

        # ----------------------------------------------------
        # RUN DISTILBERT
        # ----------------------------------------------------

        else:
            analysis_text = to_english(submitted_text, session.get("language", "en"))

            prediction = predict_message(
                analysis_text
            )

            # =================================================
            # SCAM RESULT
            # =================================================

            if prediction["prediction"] == "SCAM":

                verdict = "scam"

                # Risk should represent the probability
                # that the message is a scam.
                risk = prediction["scam_probability"]

                reasons = [
                    (
                        "The message contains patterns "
                        "associated with scam or phishing messages."
                    ),
                    (
                        f"DistilBERT classified this message "
                        f"as SCAM with "
                        f"{prediction['confidence']}% confidence."
                    ),
                ]

                recommendations = [
                    "Do not click links in the message.",
                    (
                        "Do not share OTPs, passwords, "
                        "UPI PINs, or banking information."
                    ),
                    (
                        "Verify the sender through an "
                        "official source."
                    ),
                ]

            # =================================================
            # SAFE RESULT
            # =================================================

            else:

                verdict = "safe"

                # IMPORTANT:
                # Risk = probability of being a scam.
                # Therefore for SAFE messages we use
                # scam_probability, NOT safe_probability.

                risk = prediction["scam_probability"]

                reasons = [
                    (
                        "The trained DistilBERT model did not "
                        "detect strong scam patterns."
                    ),
                    (
                        f"DistilBERT classified this message "
                        f"as SAFE with "
                        f"{prediction['confidence']}% confidence."
                    ),
                ]

                recommendations = [
                    (
                        "Continue to verify unexpected "
                        "requests independently."
                    ),
                    (
                        "Do not share sensitive information "
                        "unless you trust the recipient."
                    ),
                ]

            # =================================================
            # CREATE CLASSIFICATION RESULT
            # =================================================

            classification = {
                "verdict": verdict,
                "confidence": prediction["confidence"],
                "risk": round(risk, 2),
                "reasons": reasons,
                "recommendations": recommendations,
                "safe_probability": prediction[
                    "safe_probability"
                ],
                "scam_probability": prediction[
                    "scam_probability"
                ],
            }

            # =================================================
            # SAVE SCAN TO DATABASE
            # =================================================

            record = ScanHistory(
                user_id=current_user.id,
                scan_type="message",
                input_summary=_summarize(
                    submitted_text
                ),
                verdict=classification["verdict"],
                confidence_score=classification[
                    "confidence"
                ],
                risk_score=classification["risk"],
                explanation=" ".join(
                    classification["reasons"]
                ),
            )

            db.session.add(record)

            # =================================================
            # SAVE SYSTEM LOG
            # =================================================

            db.session.add(
                SystemLog(
                    level="info",
                    message=(
                        f"Message scan classified as "
                        f"{classification['verdict']} "
                        f"({classification['confidence']}% "
                        f"confidence)."
                    ),
                    source="message_scan",
                )
            )

            # =================================================
            # COMMIT DATABASE
            # =================================================

            db.session.commit()

            # =================================================
            # FINAL RESULT
            # =================================================

            result = {
                **classification,
                "record_id": record.id,
            }

    # ========================================================
    # RENDER MESSAGE SCAN PAGE
    # ========================================================

    return render_template(
        "scan/message.html",
        active_page="message-scan",
        page_title="Message Scam Detection",
        models_ready=models_ready,
        result=result,
        submitted_text=submitted_text,
    )