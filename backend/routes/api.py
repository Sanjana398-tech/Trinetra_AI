"""
TRINETRA AI - Secure Chat Integration API
============================================
JSON API endpoints for the Secure Chat backend. Runs text messages,
URLs, voice notes, images, QR codes, and payment requests through the
trained models and saves every successful analysis to ScanHistory.

All endpoints are called server-to-server (Secure Chat backend → Trinetra AI).
All detection logic lives in backend/utils/detection.py; this file only
handles HTTP validation, file upload/cleanup, and response serialisation.

Endpoints:
    POST /api/analyze-message     JSON: { message, user_id }
    POST /api/analyze-url         JSON: { url, user_id }
    POST /api/analyze-screenshot  multipart: image + user_id
    POST /api/analyze-qr          multipart: image + user_id   ← NEW
    POST /api/analyze-upi         JSON: { upi_id, amount, note, user_id }
    POST /api/analyze-voice       multipart: audio + user_id

Every successful analysis:
  - Saves a ScanHistory row (source="secure-chat", external_user_id=user_id)
  - Returns scan_id in the JSON response

ScanHistory scan_type mappings:
    analyze-message    → "message"
    analyze-url        → "url"
    analyze-screenshot → "screenshot"
    analyze-qr         → "qr"          ← dedicated type, never "screenshot"
    analyze-upi        → "upi"
    analyze-voice      → "voice"

Response contract (every success):
    {
        "success":        true,
        "type":           "text|url|upi|qr|image|voice",
        "classification": "SAFE|SUSPICIOUS|SCAM",
        "risk_score":     0-100,
        "alert_required": bool,
        "scan_id":        int|null,
        "message":        str,
        "language":       str,
        # + backward-compat keys: verdict, prediction, confidence, risk,
        #   should_warn, alert, reasons, tips, detection_type,
        #   and type-specific extras (transcription, analysis_type, …)
    }
"""

import os
import logging
import uuid

from flask import Blueprint, jsonify, request, session
from flask_login import current_user
from werkzeug.utils import secure_filename

from backend.utils.detection import (
    save_scan,
    build_response,
    detect_text,
    detect_url,
    detect_upi,
    detect_qr,
    detect_image,
    detect_voice,
    MAX_CONTENT_CHARS,
    ScanPersistenceError,
)
from backend.utils.localization import (
    detect_supported_language,
    normalize_language,
    from_english,
)
from backend.utils.upi_features import is_valid_upi_id
# XAI helpers (kept for analyze-message backward-compat)
from backend.utils.message_reasons import (
    generate_reasons as _gen_message_reasons,
    safety_tips as _message_safety_tips,
)
from backend.utils.localization import to_english, translate

logger = logging.getLogger(__name__)

# ============================================================
# BLUEPRINT
# ============================================================

api_bp = Blueprint("api", __name__, url_prefix="/api")

@api_bp.errorhandler(ScanPersistenceError)
def _handle_scan_persistence_error(_error):
    return jsonify({
        "success": False,
        "error": "Detection completed but could not be saved",
    }), 500

# ============================================================
# CONFIGURATION
# ============================================================

MAX_INPUT_CHARS = MAX_CONTENT_CHARS   # 4000
MAX_URL_CHARS   = 2048
ALLOWED_AUDIO_EXT = {"webm", "ogg", "mp3", "wav", "m4a", "mp4"}
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "gif", "bmp"}


# ============================================================
# AFTER-REQUEST: translate error messages for non-English callers
# ============================================================

@api_bp.after_request
def _localise_error_responses(response):
    """Translate the 'error' field of failure responses into the caller's language."""
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
# SHARED HELPERS
# ============================================================

def _request_language(body=None):
    """Resolve language code from JSON body, form field, or session."""
    body = body or {}
    raw = (
        (body.get("language") if isinstance(body, dict) else None)
        or request.form.get("language")
        or session.get("language", "en")
    )
    return normalize_language(raw)


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _save_temp_upload(file_storage, allowed_ext):
    """
    Validate and persist an uploaded file to the temp folder.
    Returns (path, error_response_or_None).
    """
    if not file_storage or not file_storage.filename:
        return None, (jsonify({"success": False, "error": "No file was uploaded"}), 400)

    ext = _extension(file_storage.filename)
    if ext not in allowed_ext:
        return None, (jsonify({"success": False, "error": "Unsupported file format"}), 400)

    from flask import current_app
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


def _external_user_id():
    """Pull user_id from JSON body or multipart form."""
    if request.is_json:
        return str((request.get_json(silent=True) or {}).get("user_id") or "").strip() or None
    return str(request.form.get("user_id") or "").strip() or None


def _error_status(error_msg: str) -> int:
    """Map a detection error message to the appropriate HTTP status code."""
    msg = (error_msg or "").lower()
    if any(marker in msg for marker in (
        "unavailable", "not installed", "timed out", "couldn't load",
    )):
        return 503
    if any(marker in msg for marker in (
        "no speech", "no qr code", "not a valid", "couldn't transcribe",
    )):
        return 422
    if "invalid" in msg or "required" in msg or "unsupported" in msg or "too long" in msg:
        return 400
    return 500


def _build_xai(message_text: str, verdict: str, confidence: float, language: str) -> dict:
    """
    Build the XAI 'Why?' payload for text/voice results.
    Safe → xai_available=False. Scam/Suspicious → pattern-matched reasons.
    """
    verdict_lower = verdict.strip().lower()
    if verdict_lower == "safe":
        return {"xai_available": False, "reasons": [], "tips": [], "speech_text": "", "speech_language": language}

    en_text = to_english(message_text, "auto")
    reasons_orig = _gen_message_reasons(message_text, verdict_lower, confidence)
    reasons_en   = _gen_message_reasons(en_text, verdict_lower, confidence)
    seen: set = set()
    merged: list = []
    for r in reasons_orig + reasons_en:
        if r not in seen:
            seen.add(r)
            merged.append(r)

    tips_en = _message_safety_tips(verdict_lower)
    localized_reasons = [translate(r, language) for r in merged]
    localized_tips    = [translate(t, language) for t in tips_en]

    verdict_word = "scam" if verdict_lower == "scam" else "suspicious"
    warning_loc  = translate(f"Warning: This message has been detected as {verdict_word}.", language)
    closing_loc  = translate("Do not share personal details or click any links.", language)
    indicators   = [r for r in merged if not r.startswith("The AI model is")]
    mid_parts    = [translate(r, language) for r in indicators[:3]]
    speech_text  = " ".join([warning_loc] + mid_parts + [closing_loc])

    return {
        "xai_available":   True,
        "reasons":         localized_reasons,
        "tips":            localized_tips,
        "speech_text":     speech_text,
        "speech_language": language,
    }


# ============================================================
# 1. TEXT MESSAGE ANALYSIS  →  scan_type = "message"
# ============================================================

@api_bp.route("/analyze-message", methods=["POST"])
def analyze_message():
    """
    POST /api/analyze-message
    Body (JSON): { "message": "...", "user_id": "optional", "language": "en" }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    body     = request.get_json(silent=True) or {}
    text     = (body.get("message") or "").strip()
    uid      = str(body.get("user_id") or "").strip() or None
    language = _request_language(body)

    if not text:
        return jsonify({"success": False, "error": "message field is required and cannot be empty"}), 400
    if len(text) > MAX_INPUT_CHARS:
        return jsonify({"success": False, "error": f"Message too long (max {MAX_INPUT_CHARS} characters)"}), 400

    language = detect_supported_language(text, language)
    result, extras, error = detect_text(text, language)
    if error:
        return jsonify({"success": False, "error": error}), _error_status(error)

    record = save_scan(
        scan_type="message",
        input_summary=text,
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk=result["risk"],
        explanation=(
            f"DistilBERT: {result['verdict'].upper()} "
            f"({result['confidence']:.1f}%, risk {result['risk']:.1f}%)"
        ),
        external_user_id=uid,
    )

    # Augment with XAI reasons (pattern-matched, no network calls)
    xai = _build_xai(text, result["verdict"], result["confidence"], language)
    result["reasons"] = xai["reasons"]
    result["tips"]    = xai["tips"]

    response = build_response(
        scan_type="message",
        model_result=result,
        record=record,
        language=language,
        extras={
            **extras,
            "xai_available":   xai["xai_available"],
            "speech_text":     xai["speech_text"],
            "speech_language": xai["speech_language"],
        },
    )
    return jsonify(response), 200


# ============================================================
# 2. URL ANALYSIS  →  scan_type = "url"
# ============================================================

@api_bp.route("/analyze-url", methods=["POST"])
def analyze_url():
    """
    POST /api/analyze-url
    Body (JSON): { "url": "https://...", "user_id": "optional" }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    body     = request.get_json(silent=True) or {}
    url      = (body.get("url") or "").strip()
    uid      = str(body.get("user_id") or "").strip() or None
    language = _request_language(body)

    if not url:
        return jsonify({"success": False, "error": "url field is required and cannot be empty"}), 400
    if len(url) > MAX_URL_CHARS:
        return jsonify({"success": False, "error": f"URL too long (max {MAX_URL_CHARS} characters)"}), 400

    language = detect_supported_language(url, language)
    result, extras, error = detect_url(url)
    if error:
        return jsonify({"success": False, "error": error}), _error_status(error)

    language = detect_supported_language(extras.get("content", ""), language)
    record = save_scan(
        scan_type="url",
        input_summary=url,
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk=result["risk"],
        explanation=" | ".join(result.get("reasons", [])) or f"XGBoost URL: {result['verdict']}",
        external_user_id=uid,
    )

    return jsonify(build_response(
        scan_type="url",
        model_result=result,
        record=record,
        language=language,
        extras=extras,
    )), 200


# ============================================================
# 3. IMAGE / SCREENSHOT ANALYSIS  →  scan_type = "screenshot"
# ============================================================

@api_bp.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    """
    POST /api/analyze-screenshot
    multipart: image=<file>, user_id=<string (optional)>
    """
    uid      = _external_user_id()
    language = _request_language()

    temp_path, upload_error = _save_temp_upload(request.files.get("image"), ALLOWED_IMAGE_EXT)
    if upload_error:
        return upload_error

    try:
        result, extras, error = detect_image(temp_path, language)
    finally:
        _remove_temp(temp_path)

    if error:
        return jsonify({"success": False, "error": error}), _error_status(error)

    record = save_scan(
        scan_type="screenshot",
        input_summary=extras.get("content", "[image]"),
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk=result["risk"],
        explanation=" | ".join(result.get("reasons", [])) or f"Image OCR: {result['verdict']}",
        external_user_id=uid,
    )

    return jsonify(build_response(
        scan_type="screenshot",
        model_result=result,
        record=record,
        language=language,
        extras=extras,
    )), 200


# ============================================================
# 4. QR CODE ANALYSIS  →  scan_type = "qr"   ← NEW
# ============================================================

@api_bp.route("/analyze-qr", methods=["POST"])
def analyze_qr():
    """
    POST /api/analyze-qr
    multipart: image=<QR code image file>, user_id=<string (optional)>

    Decodes the QR, routes the content through the correct existing model:
      • upi://pay?pa=...  → UPI GNN+XGBoost
      • URL               → XGBoost URL model
      • plain text        → DistilBERT

    ScanHistory scan_type is always "qr" (not "screenshot").
    """
    uid      = _external_user_id()
    language = _request_language()

    temp_path, upload_error = _save_temp_upload(request.files.get("image"), ALLOWED_IMAGE_EXT)
    if upload_error:
        return upload_error

    try:
        result, extras, error = detect_qr(temp_path, language)
    finally:
        _remove_temp(temp_path)

    if error:
        # "No QR code found" is a 422 (valid image, no detectable QR)
        # rather than a 503 model failure, so the client can surface it clearly.
        status = 422 if "no qr code" in (error or "").lower() or "no qr" in (error or "").lower() else _error_status(error)
        return jsonify({"success": False, "error": error}), status

    decoded = extras.get("decoded_content", "")
    language = detect_supported_language(decoded, language)
    record = save_scan(
        scan_type="qr",
        input_summary=f"QR → {decoded}",
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk=result["risk"],
        explanation=" | ".join(result.get("reasons", [])) or f"QR ({extras.get('analysis_type','unknown')}): {result['verdict']}",
        external_user_id=uid,
    )

    return jsonify(build_response(
        scan_type="qr",
        model_result=result,
        record=record,
        language=language,
        extras=extras,
    )), 200


# ============================================================
# 5. UPI PAYMENT REQUEST ANALYSIS  →  scan_type = "upi"
# ============================================================

@api_bp.route("/analyze-upi", methods=["POST"])
def analyze_upi():
    """
    POST /api/analyze-upi
    Body (JSON): { "upi_id": "...", "amount": 500, "note": "...", "user_id": "optional" }
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    body     = request.get_json(silent=True) or {}
    upi_id   = (body.get("upi_id") or "").strip()
    note     = (body.get("note") or "").strip()
    uid      = str(body.get("user_id") or "").strip() or None
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

    language = detect_supported_language(note, language)
    result, extras, error = detect_upi(upi_id, amount, note)
    if error:
        return jsonify({"success": False, "error": error}), _error_status(error)

    summary = upi_id + (f" | ₹{amount}" if amount else "") + (f" | {note}" if note else "")
    record = save_scan(
        scan_type="upi",
        input_summary=summary,
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk=result["risk"],
        explanation=" | ".join(result.get("reasons", [])) or f"UPI GNN+XGBoost: {result['verdict']}",
        external_user_id=uid,
    )

    return jsonify(build_response(
        scan_type="upi",
        model_result=result,
        record=record,
        language=language,
        extras=extras,
    )), 200


# ============================================================
# 6. VOICE MESSAGE ANALYSIS  →  scan_type = "voice"
# ============================================================

@api_bp.route("/analyze-voice", methods=["POST"])
def analyze_voice():
    """
    POST /api/analyze-voice
    multipart: audio=<file>, user_id=<string (optional)>
    Whisper transcribes; DistilBERT classifies the transcript.
    """
    uid      = _external_user_id()
    language = _request_language()

    temp_path, upload_error = _save_temp_upload(request.files.get("audio"), ALLOWED_AUDIO_EXT)
    if upload_error:
        return upload_error

    try:
        result, extras, error = detect_voice(temp_path, language)
    finally:
        _remove_temp(temp_path)

    if error:
        status = 422 if "no speech" in (error or "").lower() else _error_status(error)
        return jsonify({"success": False, "error": error}), status

    transcript = extras.get("transcription", "")
    language = detect_supported_language(transcript, language)
    record = save_scan(
        scan_type="voice",
        input_summary=f"Voice transcript: {transcript[:200]}",
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk=result["risk"],
        explanation=f"Whisper+DistilBERT: {result['verdict']} ({result['confidence']:.1f}%)",
        external_user_id=uid,
    )

    # Augment with XAI reasons using the transcript
    xai = _build_xai(transcript, result["verdict"], result["confidence"], language)
    result["reasons"] = xai["reasons"]
    result["tips"]    = xai["tips"]

    return jsonify(build_response(
        scan_type="voice",
        model_result=result,
        record=record,
        language=language,
        extras={
            **extras,
            "xai_available":   xai["xai_available"],
            "speech_text":     xai["speech_text"],
            "speech_language": xai["speech_language"],
        },
    )), 200
