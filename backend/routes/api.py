"""
TRINETRA AI - Secure Chat Integration API
============================================
JSON API endpoints for the Secure Chat backend. Runs text messages,
URLs, voice notes, images, and payment requests through the trained
models and saves every successful analysis to ScanHistory.

All endpoints are called server-to-server (Secure Chat backend -> Trinetra AI).

Endpoints:
    POST /api/analyze-message     JSON: { message, user_id }         -> DistilBERT
    POST /api/analyze-url         JSON: { url, user_id }              -> XGBoost URL model
    POST /api/analyze-screenshot  multipart: image + user_id field    -> OCR + rules / DistilBERT
    POST /api/analyze-upi         JSON: { upi_id, amount, note, user_id } -> UPI GNN + XGBoost
    POST /api/analyze-voice       multipart: audio + user_id field    -> Whisper + DistilBERT

Every successful analysis:
  - Saves a ScanHistory row with source="secure-chat", external_user_id=user_id
  - Returns scan_id in the JSON response

ScanHistory scan_type mappings (matches existing history categories):
    analyze-message    -> "message"
    analyze-url        -> "url"
    analyze-screenshot -> "screenshot"
    analyze-upi        -> "upi"
    analyze-voice      -> "voice"
"""

import os
import re
import uuid
import logging
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, request, jsonify, current_app, session
from flask_login import current_user
from werkzeug.utils import secure_filename

from backend.utils.distilbert_loader import model, tokenizer, predict_message
from backend.utils.voice_transcribe import transcribe_audio
from backend.utils import screenshot_analyze
from backend.utils.classifiers import classify_upi, classify_url, classify_message
from backend.utils.qr_decode import decode_qr
from backend.utils.upi_features import is_valid_upi_id
from backend.utils.localization import (
    normalize_language,
    to_english,
    from_english,
    translate,
)
from backend.utils.message_reasons import (
    generate_reasons as _gen_message_reasons,
    safety_tips as _message_safety_tips,
)
# URL analysis uses xgboost_loader + url_features directly
# (same path as url_scan.py — classify_url in classifiers.py needs sklearn)
from backend.utils.xgboost_loader import (
    model as url_model,
    feature_columns as url_feature_columns,
    predict_url,
)
from backend.utils.url_features import (
    extract_url_features,
    explain_reasons as url_reasons,
    safety_tips as url_tips,
    find_url_in_text,
)
import pandas as pd
from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog

logger = logging.getLogger(__name__)

# ============================================================
# BLUEPRINT
# ============================================================

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.after_request
def localize_api_errors(response):
    """Translate Secure Chat API errors without changing detection payloads."""
    if not response.is_json:
        return response
    payload = response.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get("success") is not False:
        return response
    body = request.get_json(silent=True) if request.is_json else {}
    language = _request_language(body or {})
    payload["error"] = from_english(payload.get("error", "Request failed"), language)
    payload["language"] = language
    response.set_data(jsonify(payload).get_data())
    return response

# ============================================================
# CONFIGURATION
# ============================================================

MAX_INPUT_CHARS = 4000
ALLOWED_AUDIO_EXT = {"webm", "ogg", "mp3", "wav", "m4a", "mp4"}
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "gif", "bmp"}

UPI_ID_RE = re.compile(r"^[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,20}$")

PAYMENT_KEYWORDS_RE = re.compile(
    r"\b(paid|payment|transaction|txn|debit|credit|upi|refund|"
    r"sent|received|bank|balance|utr|wallet)\b",
    re.IGNORECASE,
)

VERDICT_TO_PREDICTION = {
    "safe": "SAFE",
    "suspicious": "SUSPICIOUS",
    "scam": "SCAM",
}


# ============================================================
# HELPERS
# ============================================================

def _request_language(body=None):
    """Resolve language for browser sessions and Secure Chat callers."""
    body = body or {}
    requested = body.get("language") if isinstance(body, dict) else None
    requested = requested or request.form.get("language") or session.get("language", "en")
    return normalize_language(requested)


def _localize_api_payload(payload, language):
    """Localize API display fields while preserving machine-readable keys."""
    localized = dict(payload)
    language = normalize_language(language)
    verdict = localized.get("verdict")
    if not verdict and localized.get("prediction"):
        verdict = str(localized["prediction"]).lower()
    if verdict:
        localized["verdict_label"] = translate(str(verdict).lower(), language)
        localized["prediction_label"] = translate(str(verdict).lower(), language)
        alert = localized.get("alert") or (
            "This result strongly matches known scam patterns. Do not act on it."
            if str(verdict).lower() == "scam"
            else "Review this result carefully before taking action."
        )
        localized["alert"] = from_english(alert, language)
    # reasons/tips/recommendations may be pre-translated (XAI path) or raw
    # English (URL/UPI/screenshot paths). Only translate when not pre-localized.
    # We detect pre-localization by the presence of the "xai_available" key.
    if not localized.get("xai_available"):
        for field in ("reasons", "tips", "recommendations"):
            if localized.get(field):
                localized[field] = [from_english(item, language) for item in localized[field]]
    if localized.get("error"):
        localized["error"] = from_english(localized["error"], language)
    localized["confidence_label"] = translate("Confidence", language)
    localized["risk_label"] = translate("Risk Score", language)
    localized["view_record_label"] = translate("View Full Scan Record", language)
    localized["language"] = language
    return localized

def _extension(filename):
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _save_temp_upload(file_storage, allowed_ext):
    """Validate + save an uploaded file to the temp folder.
    Returns (path, error_response_tuple_or_None)."""
    if not file_storage or not file_storage.filename:
        return None, (jsonify({"success": False, "error": "No file was uploaded"}), 400)

    ext = _extension(file_storage.filename)
    if ext not in allowed_ext:
        return None, (jsonify({"success": False, "error": "Unsupported file format"}), 400)

    safe_name = secure_filename(file_storage.filename) or f"upload.{ext}"
    temp_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"],
        f"{uuid.uuid4().hex}_{safe_name}",
    )
    try:
        file_storage.save(temp_path)
    except Exception:
        logger.exception("Failed to save uploaded file")
        return None, (jsonify({"success": False, "error": "Failed to store the uploaded file"}), 500)

    return temp_path, None


def _remove_temp(path):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _get_external_user_id(source):
    """Pull user_id from JSON body or multipart form field."""
    if request.is_json:
        body = request.get_json(silent=True) or {}
        return str(body.get("user_id") or "").strip() or None
    return str(source or "").strip() or None


def _save_scan(scan_type, input_summary, verdict, confidence, risk,
               explanation, external_user_id):
    """
    Persist a ScanHistory record for a Secure Chat analysis.
    Returns the saved record (with .id populated) or None on failure.
    """
    try:
        record = ScanHistory(
            user_id=(current_user.id if current_user.is_authenticated else None),
            source="secure-chat",
            external_user_id=external_user_id,
            scan_type=scan_type,
            input_summary=input_summary[:240],
            verdict=verdict.lower(),
            confidence_score=float(confidence),
            risk_score=float(risk),
            explanation=explanation,
        )
        db.session.add(record)
        db.session.add(SystemLog(
            level="info",
            message=(
                f"Secure Chat {scan_type} scan → {verdict.lower()} "
                f"({confidence:.1f}%) [user={external_user_id or 'anon'}]"
            ),
            source=f"api/{scan_type}",
        ))
        db.session.commit()
        logger.info(
            "Saved ScanHistory id=%s scan_type=%s verdict=%s source=secure-chat",
            record.id, scan_type, verdict.lower(),
        )
        return record
    except Exception:
        db.session.rollback()
        logger.exception("Failed to save ScanHistory for scan_type=%s", scan_type)
        return None


# ============================================================
# XAI HELPERS  (message-level explanation for Secure Chat)
# ============================================================

def _build_xai(message_text: str, verdict: str, confidence: float, language: str) -> dict:
    """
    Build the XAI "Why?" payload for a single message analysis result.

    - For SAFE:        returns xai_available=False; no reasons/tips/speech.
    - For SCAM/SUSPICIOUS: runs the message_reasons pattern engine against the
      original (possibly non-English) text AND the English translation so
      indicators in either form are captured.  Translates all output using
      the static catalog in localization.py (no network calls).  Falls back
      to English text when a static translation is not available.

    Never invents reasons — every reason returned is pattern-matched from the
    actual message text.
    """
    verdict_lower = verdict.strip().lower()

    if verdict_lower == "safe":
        return {
            "xai_available": False,
            "reasons": [],
            "tips": [],
            "speech_text": "",
            "speech_language": language,
        }

    # Run reason engine on the original text (captures non-Latin script
    # words that may have been preserved after translation) AND on the
    # English version so English patterns always fire.
    en_text = to_english(message_text, "auto")
    reasons_en = _gen_message_reasons(message_text, verdict_lower, confidence)
    reasons_en_only = _gen_message_reasons(en_text, verdict_lower, confidence)
    # Deduplicate while preserving order (first-seen wins)
    seen: set = set()
    merged_reasons: list = []
    for r in reasons_en + reasons_en_only:
        if r not in seen:
            seen.add(r)
            merged_reasons.append(r)

    tips_en = _message_safety_tips(verdict_lower)

    # Translate using static catalog (translate() never makes network calls).
    # Falls back to the original English string when no static entry exists.
    localized_reasons = [translate(r, language) for r in merged_reasons]
    localized_tips    = [translate(t, language) for t in tips_en]

    # Build speech_text from static catalog parts (guaranteed offline).
    verdict_word = "scam" if verdict_lower == "scam" else "suspicious"
    warning_key  = f"Warning: This message has been detected as {verdict_word}."
    closing_key  = "Do not share personal details or click any links."
    warning_loc  = translate(warning_key, language)
    closing_loc  = translate(closing_key, language)

    # Add up to 3 indicator reasons (skip the confidence sentence)
    indicator_reasons = [r for r in merged_reasons if not r.startswith("The AI model is")]
    mid_parts = [translate(r, language) for r in indicator_reasons[:3]]

    speech_text = " ".join([warning_loc] + mid_parts + [closing_loc])

    return {
        "xai_available": True,
        "reasons": localized_reasons,
        "tips": localized_tips,
        "speech_text": speech_text,
        "speech_language": language,
    }


# ============================================================
# 1. TEXT MESSAGE ANALYSIS  →  scan_type = "message"
# ============================================================

@api_bp.route("/analyze-message", methods=["POST"])
def analyze_message():
    """
    Analyze a text message with DistilBERT.

    Body (JSON):
        { "message": "...", "user_id": "optional" }

    Returns:
        prediction, confidence, safe_probability, scam_probability, scan_id
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    body = request.get_json(silent=True) or {}
    message_text = (body.get("message") or "").strip()
    external_user_id = str(body.get("user_id") or "").strip() or None
    language = _request_language(body)

    if not message_text:
        return jsonify({"success": False, "error": "message field is required and cannot be empty"}), 400
    if len(message_text) > MAX_INPUT_CHARS:
        return jsonify({"success": False, "error": f"Message too long (max {MAX_INPUT_CHARS} characters)"}), 400
    if model is None or tokenizer is None:
        return jsonify({"success": False, "error": "AI model is currently unavailable"}), 503

    try:
        analysis_text = to_english(message_text, language)
        result = predict_message(analysis_text)

        prediction      = result["prediction"]
        confidence      = float(result["confidence"])
        safe_prob       = float(result["safe_probability"])
        scam_prob       = float(result["scam_probability"])

        record = _save_scan(
            scan_type="message",
            input_summary=message_text,
            verdict=prediction,
            confidence=confidence,
            risk=scam_prob,
            explanation=(
                f"Secure Chat message — DistilBERT: {prediction} "
                f"({confidence:.1f}% confidence, scam prob {scam_prob:.1f}%)"
            ),
            external_user_id=external_user_id,
        )

        alert_text = (
            "This message strongly matches known scam patterns. Do not act on it."
            if prediction == "SCAM"
            else "No common scam patterns detected in this message. Continue to stay cautious."
        )

        # Build XAI explanation — only populated for SCAM/SUSPICIOUS
        xai = _build_xai(message_text, prediction, confidence, language)

        return jsonify(_localize_api_payload({
            "success": True,
            "prediction": prediction,
            "prediction_label": translate(prediction.lower(), language),
            "confidence": confidence,
            "confidence_label": translate("Confidence", language),
            "safe_probability": safe_prob,
            "safe_label": translate("Safe", language),
            "scam_probability": scam_prob,
            "scam_label": translate("Scam", language),
            "probability_label": translate("Probability", language),
            "alert": translate(alert_text, language),
            "language": language,
            "scan_id": record.id if record else None,
            # ── XAI fields ────────────────────────────────────────────
            "xai_available": xai["xai_available"],
            "reasons": xai["reasons"],
            "tips": xai["tips"],
            "speech_text": xai["speech_text"],
            "speech_language": xai["speech_language"],
        }, language)), 200

    except Exception:
        db.session.rollback()
        logger.exception("analyze-message failed")
        return jsonify({"success": False, "error": "Analysis failed due to an internal error"}), 500


# ============================================================
# 2. URL ANALYSIS  →  scan_type = "url"
# ============================================================

@api_bp.route("/analyze-url", methods=["POST"])
def analyze_url():
    """
    Analyze a URL with the trained XGBoost URL model.

    Body (JSON):
        { "url": "https://...", "user_id": "optional" }

    Returns:
        prediction, confidence, risk, reasons, scan_id
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    external_user_id = str(body.get("user_id") or "").strip() or None
    language = _request_language(body)

    if not url:
        return jsonify({"success": False, "error": "url field is required and cannot be empty"}), 400
    if len(url) > 2048:
        return jsonify({"success": False, "error": "URL too long (max 2048 characters)"}), 400
    if url_model is None or url_feature_columns is None:
        return jsonify({"success": False, "error": "URL detection model is currently unavailable"}), 503

    try:
        # Build feature DataFrame exactly like url_scan.py
        features = extract_url_features(url)
        X = pd.DataFrame([features], columns=url_feature_columns)
        raw = predict_url(X)
    except Exception:
        logger.exception("predict_url failed for url=%s", url[:80])
        return jsonify({"success": False, "error": "Analysis failed due to an internal error"}), 500

    if raw is None:
        return jsonify({"success": False, "error": "URL detection model is currently unavailable"}), 503

    # Derive three-level verdict from scam probability (matches url_scan.py logic)
    scam_prob = float(raw["scam_probability"])
    safe_prob = float(raw["safe_probability"])
    confidence = float(raw["confidence"])

    if raw["prediction"] == "SCAM":
        verdict = "scam"
    elif scam_prob >= 70:
        verdict = "scam"
    elif scam_prob >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    risk    = scam_prob
    reasons = url_reasons(url)

    record = _save_scan(
        scan_type="url",
        input_summary=url,
        verdict=verdict,
        confidence=confidence,
        risk=risk,
        explanation=" | ".join(reasons) if reasons else f"XGBoost URL model: {verdict}",
        external_user_id=external_user_id,
    )

    return jsonify(_localize_api_payload({
        "success": True,
        "prediction": VERDICT_TO_PREDICTION.get(verdict, "SUSPICIOUS"),
        "confidence": confidence,
        "risk": risk,
        "reasons": reasons,
        "scan_id": record.id if record else None,
    }, language)), 200


# ============================================================
# 3. IMAGE / SCREENSHOT ANALYSIS  →  scan_type = "screenshot"
# ============================================================

@api_bp.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    """
    Analyze an image with OCR + payment-fraud rules (and DistilBERT fallback).

    Accepts multipart:  image = <file>,  user_id = <string (optional)>

    Returns:
        prediction, confidence, safe_probability, scam_probability,
        analysis_type, reasons, scan_id
    """
    external_user_id = _get_external_user_id(request.form.get("user_id"))
    language = _request_language()

    temp_path, error = _save_temp_upload(request.files.get("image"), ALLOWED_IMAGE_EXT)
    if error:
        return error

    # ---- QR first: QR images may contain a UPI URI, URL, or message ----
    decoded_qr = None
    try:
        decoded_qr, _qr_error = decode_qr(temp_path)
    except Exception:
        logger.exception("QR detection failed")

    if decoded_qr:
        parsed_qr = urlparse(decoded_qr.strip())
        qr_params = parse_qs(parsed_qr.query)
        is_upi_qr = (
            parsed_qr.scheme.lower() == "upi"
            and parsed_qr.netloc.lower() == "pay"
            and bool((qr_params.get("pa") or [""])[0].strip())
        )
        try:
            if is_upi_qr:
                classification = classify_upi(decoded_qr)
                analysis_type = "qr-upi"
            else:
                qr_url = find_url_in_text(decoded_qr)
                classification = classify_url(qr_url) if qr_url else classify_message(decoded_qr)
                analysis_type = "qr-url" if qr_url else "qr-text"
        except Exception:
            logger.exception("QR content classification failed")
            _remove_temp(temp_path)
            return jsonify({"success": False, "error": "The QR content could not be analyzed"}), 422

        _remove_temp(temp_path)
        if classification is None:
            return jsonify({"success": False, "error": "The QR content model is currently unavailable"}), 503

        record = _save_scan(
            scan_type="screenshot",
            input_summary=f"QR decoded: {decoded_qr}",
            verdict=classification["verdict"],
            confidence=classification["confidence"],
            risk=classification["risk"],
            explanation=" | ".join(classification.get("reasons", [])),
            external_user_id=external_user_id,
        )
        return jsonify(_localize_api_payload({
            "success": True,
            "verdict": classification["verdict"],
            "prediction": VERDICT_TO_PREDICTION.get(classification["verdict"], "SUSPICIOUS"),
            "confidence": float(classification["confidence"]),
            "safe_probability": round(100 - float(classification["risk"]), 2),
            "scam_probability": float(classification["risk"]),
            "analysis_type": analysis_type,
            "content": decoded_qr,
            "decoded_content": decoded_qr,
            "reasons": classification.get("reasons", []),
            "tips": classification.get("tips", []),
            "scan_id": record.id if record else None,
        }, language)), 200

    # ---- OCR fallback for ordinary screenshots ----
    try:
        raw_text = screenshot_analyze.extract_text(
            temp_path,
            current_app.config.get("TESSERACT_CMD", ""),
        ).strip()
    except Exception:
        logger.exception("OCR failed")
        _remove_temp(temp_path)
        return jsonify({"success": False, "error": "OCR is currently unavailable on the server"}), 503
    finally:
        _remove_temp(temp_path)

    # ---- Layer 1: plain photo with barely any text ----
    if len(raw_text) < 15:
        record = _save_scan(
            scan_type="screenshot",
            input_summary="[plain photo — no readable text]",
            verdict="safe",
            confidence=90.0,
            risk=10.0,
            explanation="No readable text found — treated as a plain photo.",
            external_user_id=external_user_id,
        )
        return jsonify(_localize_api_payload({
            "success": True,
            "verdict": "safe",
            "prediction": "SAFE",
            "confidence": 90.0,
            "safe_probability": 90.0,
            "scam_probability": 10.0,
            "analysis_type": "photo",
            "content": raw_text,
            "reasons": ["No readable text was found — treated as a plain photo."],
            "scan_id": record.id if record else None,
        }, language)), 200

    # ---- Layer 2: payment screenshot fraud rules ----
    fields = screenshot_analyze.parse_fields(raw_text)
    looks_like_payment = bool(
        fields.get("amount")
        or fields.get("upi_id")
        or fields.get("transaction_id")
        or PAYMENT_KEYWORDS_RE.search(raw_text)
    )

    # OCR screenshots containing a URL use the current URL model.
    url_candidate = find_url_in_text(raw_text)
    if url_candidate and not looks_like_payment:
        classification = classify_url(url_candidate)
        if classification is None:
            return jsonify({"success": False, "error": "URL detection model is currently unavailable"}), 503

        record = _save_scan(
            scan_type="screenshot",
            input_summary=raw_text[:240],
            verdict=classification["verdict"],
            confidence=classification["confidence"],
            risk=classification["risk"],
            explanation=" | ".join(classification.get("reasons", [])),
            external_user_id=external_user_id,
        )
        return jsonify(_localize_api_payload({
            "success": True,
            "verdict": classification["verdict"],
            "prediction": VERDICT_TO_PREDICTION.get(classification["verdict"], "SUSPICIOUS"),
            "confidence": float(classification["confidence"]),
            "safe_probability": round(100 - float(classification["risk"]), 2),
            "scam_probability": float(classification["risk"]),
            "analysis_type": "image-url",
            "content": raw_text,
            "reasons": classification.get("reasons", []),
            "tips": classification.get("tips", []),
            "scan_id": record.id if record else None,
        }, language)), 200

    if looks_like_payment:
        result = screenshot_analyze.analyze(raw_text, fields)
        verdict = result["verdict"]
        confidence = result["confidence"]
        risk = result["risk"]
        reasons = result["reasons"]
        prediction = VERDICT_TO_PREDICTION.get(verdict, "SUSPICIOUS")

        record = _save_scan(
            scan_type="screenshot",
            input_summary=raw_text[:240],
            verdict=verdict,
            confidence=confidence,
            risk=risk,
            explanation=" | ".join(reasons),
            external_user_id=external_user_id,
        )
        return jsonify(_localize_api_payload({
            "success": True,
            "verdict": verdict,
            "prediction": prediction,
            "confidence": confidence,
            "safe_probability": round(100 - risk, 2),
            "scam_probability": risk,
            "analysis_type": "payment-screenshot",
            "content": raw_text,
            "reasons": reasons,
            "scan_id": record.id if record else None,
        }, language)), 200

    # ---- Layer 3: image-text -> DistilBERT ----
    if model is None or tokenizer is None:
        return jsonify({"success": False, "error": "AI model is currently unavailable"}), 503

    try:
        pred = predict_message(to_english(raw_text[:MAX_INPUT_CHARS], language))
        prediction = pred["prediction"]
        confidence = pred["confidence"]
        safe_prob = pred["safe_probability"]
        scam_prob = pred["scam_probability"]
        reasons = ["Readable text in the image was analyzed by DistilBERT."]

        record = _save_scan(
            scan_type="screenshot",
            input_summary=raw_text[:240],
            verdict=prediction,
            confidence=confidence,
            risk=scam_prob,
            explanation=f"Image text via DistilBERT: {prediction} ({confidence:.1f}%)",
            external_user_id=external_user_id,
        )
        return jsonify(_localize_api_payload({
            "success": True,
            "verdict": prediction.lower(),
            "prediction": prediction,
            "confidence": confidence,
            "safe_probability": safe_prob,
            "scam_probability": scam_prob,
            "analysis_type": "image-text",
            "content": raw_text,
            "reasons": reasons,
            "scan_id": record.id if record else None,
        }, language)), 200

    except Exception:
        logger.exception("Image text classification failed")
        return jsonify({"success": False, "error": "Analysis failed due to an internal error"}), 500


# ============================================================
# 4. UPI PAYMENT REQUEST ANALYSIS  →  scan_type = "upi"
# ============================================================

@api_bp.route("/analyze-upi", methods=["POST"])
def analyze_upi():
    """
    Analyze a UPI payment request with the saved GNN + XGBoost model.

    Body (JSON):
        { "upi_id": "...", "amount": 500, "note": "...", "user_id": "optional" }

    Returns:
        prediction, confidence, risk, reasons, scan_id
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    body = request.get_json(silent=True) or {}
    upi_id  = (body.get("upi_id") or "").strip()
    note    = (body.get("note") or "").strip()
    external_user_id = str(body.get("user_id") or "").strip() or None
    language = _request_language(body)

    raw_amount = body.get("amount")
    try:
        amount = float(raw_amount) if raw_amount not in (None, "") else 0.0
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "amount must be a valid number"}), 400

    if not upi_id:
        return jsonify({"success": False, "error": "upi_id field is required"}), 400
    if not is_valid_upi_id(upi_id):
        return jsonify({"success": False, "error": "Invalid UPI ID format"}), 400
    if amount < 0 or amount > 10_000_000:
        return jsonify({"success": False, "error": "Amount out of range"}), 400

    try:
        result = classify_upi(upi_id, amount, note)
    except Exception:
        logger.exception("classify_upi failed")
        return jsonify({"success": False, "error": "Analysis failed due to an internal error"}), 500

    if result is None:
        return jsonify({"success": False, "error": "UPI detection model is currently unavailable"}), 503

    verdict    = result["verdict"]
    confidence = result["confidence"]
    risk       = result["risk"]
    reasons    = result.get("reasons", [])

    record = _save_scan(
        scan_type="upi",
        input_summary=f"{upi_id}" + (f" | ₹{amount}" if amount else "") + (f" | {note}" if note else ""),
        verdict=verdict,
        confidence=confidence,
        risk=risk,
        explanation=" | ".join(reasons) if reasons else f"UPI Random Forest: {verdict}",
        external_user_id=external_user_id,
    )

    return jsonify(_localize_api_payload({
        "success": True,
        "verdict": verdict,
        "prediction": VERDICT_TO_PREDICTION.get(verdict, "SUSPICIOUS"),
        "confidence": confidence,
        "risk": risk,
        "reasons": reasons,
        "scan_id": record.id if record else None,
    }, language)), 200


# ============================================================
# 5. VOICE MESSAGE ANALYSIS  →  scan_type = "voice"
# ============================================================

@api_bp.route("/analyze-voice", methods=["POST"])
def analyze_voice():
    """
    Transcribe a voice note with Whisper, then classify the transcript
    with DistilBERT.

    Accepts multipart:  audio = <file>,  user_id = <string (optional)>

    Returns:
        prediction, confidence, safe_probability, scam_probability,
        transcription, scan_id
    """
    external_user_id = _get_external_user_id(request.form.get("user_id"))
    language = _request_language()

    temp_path, error = _save_temp_upload(request.files.get("audio"), ALLOWED_AUDIO_EXT)
    if error:
        return error

    try:
        transcript, transcribe_error = transcribe_audio(temp_path)
    finally:
        _remove_temp(temp_path)

    if transcribe_error or not transcript:
        return jsonify({
            "success": False,
            "error": transcribe_error or "No speech could be detected",
        }), 422

    if model is None or tokenizer is None:
        return jsonify({"success": False, "error": "AI model is currently unavailable"}), 503

    try:
        analysis_transcript = to_english(transcript, language)
        pred       = predict_message(analysis_transcript)
        prediction = pred["prediction"]
        confidence = pred["confidence"]
        safe_prob  = pred["safe_probability"]
        scam_prob  = pred["scam_probability"]

        record = _save_scan(
            scan_type="voice",
            input_summary=f"Voice transcript: {transcript[:200]}",
            verdict=prediction,
            confidence=confidence,
            risk=scam_prob,
            explanation=(
                f"Secure Chat voice note — Whisper transcription + DistilBERT: "
                f"{prediction} ({confidence:.1f}%)"
            ),
            external_user_id=external_user_id,
        )

        # Build XAI explanation — only populated for SCAM/SUSPICIOUS
        xai = _build_xai(transcript, prediction, confidence, language)

        return jsonify(_localize_api_payload({
            "success": True,
            "verdict": prediction.lower(),
            "prediction": prediction,
            "confidence": confidence,
            "safe_probability": safe_prob,
            "scam_probability": scam_prob,
            "transcription": transcript,
            "scan_id": record.id if record else None,
            # ── XAI fields ─────────────────────────────────────────────
            "xai_available": xai["xai_available"],
            "reasons": xai["reasons"],
            "tips": xai["tips"],
            "speech_text": xai["speech_text"],
            "speech_language": xai["speech_language"],
        }, language)), 200

    except Exception:
        logger.exception("Voice classification failed")
        return jsonify({"success": False, "error": "Analysis failed due to an internal error"}), 500
