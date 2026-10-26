"""
TRINETRA AI - Shared Detection Service
=======================================
Single authoritative layer that every API path goes through.

Responsibilities
----------------
1. Run the correct existing model for each scan type.
2. Normalise every model's raw output into the common verdict/risk shape.
3. Save exactly one ScanHistory row per successful detection.
4. Build the normalised JSON response that both api_bp and secure_chat_bp
   return to callers.

Design constraints
------------------
- Does NOT retrain or replace any model.
- Does NOT change the database schema.
- Reuses all existing classifier functions unchanged.
- Both api_bp (/api/analyze-*) and secure_chat_bp (/api/secure-chat/v1/detect)
  call the functions in this module instead of duplicating logic.

Response contract
-----------------
Every successful detection returns a dict that always contains:

    {
        "success":        True,
        "type":           "text|url|upi|qr|image|voice",
        "classification": "SAFE|SUSPICIOUS|SCAM",
        "risk_score":     float,       # 0-100, higher = more dangerous
        "alert_required": bool,        # True when classification != SAFE
        "scan_id":        int | None,  # ScanHistory row id
        "message":        str,         # human-readable summary
        "language":       str,         # language code used
        # — type-specific extras are merged in on top —
    }

Failures always return a dict with success=False and an "error" key.
HTTP status codes are determined by the caller (route), not here.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlparse

from flask import current_app
from flask_login import current_user

from backend.db_models import ScanHistory, SystemLog
from backend.extensions import db
from backend.utils.classifiers import classify_message, classify_url, classify_upi
from backend.utils.localization import to_english, translate
from backend.utils.qr_decode import decode_qr
from backend.utils.screenshot_analyze import (
    analyze as _ocr_analyze,
    extract_text,
    parse_fields,
    safety_tips as _ocr_safety_tips,
)
from backend.utils.url_features import find_url_in_text

logger = logging.getLogger(__name__)

class ScanPersistenceError(RuntimeError):
    """Raised when a successful detection cannot be recorded in history."""

# ── Payment keyword detector (shared with both API paths) ──────────────────
import re
_PAYMENT_KW_RE = re.compile(
    r"\b(paid|payment|transaction|txn|debit|credit|upi|refund|"
    r"sent|received|bank|balance|utr|wallet)\b",
    re.IGNORECASE,
)

# ── Canonical verdict → classification string ──────────────────────────────
_VERDICT_TO_CLASSIFICATION = {
    "safe":       "SAFE",
    "suspicious": "SUSPICIOUS",
    "scam":       "SCAM",
}

# ── Human-readable type labels for alerts ──────────────────────────────────
_TYPE_LABELS = {
    "text":       "message",
    "url":        "URL",
    "upi":        "UPI payment request",
    "qr":         "QR code",
    "image":      "image",
    "voice":      "voice message",
    "screenshot": "image",  # legacy alias
    "message":    "message",  # legacy alias
}

MAX_CONTENT_CHARS = 4000
MAX_SUMMARY_CHARS = 240


# ═══════════════════════════════════════════════════════════════════════════
# 1.  NORMALISATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _normalise_verdict(raw: str) -> str:
    """Lowercase raw verdict → canonical 'safe'|'suspicious'|'scam'."""
    v = (raw or "").strip().lower()
    if v in {"scam", "fraud"}:
        return "scam"
    if v in {"suspicious", "warning"}:
        return "suspicious"
    return "safe"


def _build_alert(verdict: str, scan_type: str, language: str) -> str | None:
    """Return a translated alert string for SCAM/SUSPICIOUS, None for SAFE."""
    label = _TYPE_LABELS.get(scan_type, "content")
    if verdict == "scam":
        return translate(
            f"Warning: this {label} was identified as a potential scam. "
            "Do not act on it or share sensitive information.",
            language,
        )
    if verdict == "suspicious":
        return translate(
            f"Caution: this {label} looks suspicious. "
            "Verify it independently before taking action.",
            language,
        )
    return None


# ═══════════════════════════════════════════════════════════════════════════
# 2.  SCAN HISTORY
# ═══════════════════════════════════════════════════════════════════════════

def save_scan(
    *,
    scan_type: str,
    input_summary: str,
    verdict: str,
    confidence: float,
    risk: float,
    explanation: str,
    external_user_id: str | None,
    source: str = "secure-chat",
) -> ScanHistory:
    """
    Persist exactly one ScanHistory record.

    Returns the saved record (with .id populated). Raises ScanPersistenceError
    when the database write fails so API callers cannot report an unrecorded
    detection as successful.
    """
    try:
        record = ScanHistory(
            user_id=(current_user.id if current_user.is_authenticated else None),
            source=source,
            external_user_id=external_user_id,
            scan_type=scan_type,
            input_summary=input_summary[:MAX_SUMMARY_CHARS],
            verdict=_normalise_verdict(verdict),
            confidence_score=float(confidence),
            risk_score=float(risk),
            explanation=explanation,
        )
        db.session.add(record)
        db.session.add(SystemLog(
            level="info",
            message=(
                f"{source} {scan_type} scan → {_normalise_verdict(verdict)} "
                f"({confidence:.1f}%) [user={external_user_id or 'anon'}]"
            ),
            source=f"api/{scan_type}",
        ))
        db.session.commit()
        logger.info(
            "ScanHistory id=%s scan_type=%s verdict=%s source=%s",
            record.id, scan_type, record.verdict, source,
        )
        return record
    except Exception:
        db.session.rollback()
        logger.exception("Failed to save ScanHistory scan_type=%s", scan_type)
        raise ScanPersistenceError("Could not save scan result") from None


# ═══════════════════════════════════════════════════════════════════════════
# 3.  RESPONSE BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_response(
    *,
    scan_type: str,
    model_result: dict,
    record: ScanHistory | None,
    language: str,
    extras: dict | None = None,
) -> dict:
    """
    Build the normalised response dict from a model result.

    The response always contains the contract keys.  Model-specific extras
    (transcription, analysis_type, decoded_content, …) are merged on top.

    model_result must contain: verdict, confidence, risk, engine.
    """
    verdict   = _normalise_verdict(model_result["verdict"])
    classif   = _VERDICT_TO_CLASSIFICATION.get(verdict, "SUSPICIOUS")
    risk      = round(float(model_result.get("risk", 0)), 2)
    confidence = round(float(model_result.get("confidence", 0)), 2)
    alert     = _build_alert(verdict, scan_type, language)

    # Map scan_type to the public "type" string Secure Chat expects
    public_type = {
        "message": "text",
        "screenshot": "image",
    }.get(scan_type, scan_type)

    response = {
        # ── contract keys (always present) ──────────────────────────
        "success":        True,
        "type":           public_type,
        "classification": classif,
        "risk_score":     risk,
        "alert_required": verdict != "safe",
        "scan_id":        record.id if record else None,
        "message":        alert or translate(
            f"No common scam patterns detected in this {_TYPE_LABELS.get(scan_type, 'content')}.",
            language,
        ),
        "language":       language,
        # ── backward-compat keys (kept so existing Secure Chat callers ─
        # ── don't break) ────────────────────────────────────────────
        "verdict":        verdict.title(), # "Safe" / "Suspicious" / "Scam"
        "prediction":     classif,
        "confidence":     confidence,
        "risk":           risk,
        "should_warn":    verdict != "safe",
        "alert":          alert,
        "reasons":        [translate(r, language) for r in model_result.get("reasons", [])],
        "tips":           [translate(t, language) for t in model_result.get("tips", [])],
        "detection_type": model_result.get("engine", "unknown"),
    }

    # Merge type-specific extras (transcription, analysis_type, decoded_content …)
    if extras:
        response.update(extras)

    return response


# ═══════════════════════════════════════════════════════════════════════════
# 4.  PER-TYPE DETECTION FUNCTIONS
#     Each function returns (model_result_dict, extras_dict, error_string).
#     On success: (result, extras, None).
#     On failure: (None, None, error_message).
# ═══════════════════════════════════════════════════════════════════════════

def detect_text(text: str, language: str) -> tuple[dict | None, dict, str | None]:
    """Run DistilBERT on a text message."""
    from backend.utils.distilbert_loader import model, tokenizer, predict_message

    if model is None or tokenizer is None:
        return None, {}, "AI model is currently unavailable"

    try:
        en_text = to_english(text, language)
        raw = predict_message(en_text)
    except Exception:
        logger.exception("detect_text failed")
        return None, {}, "Analysis failed due to an internal error"

    if raw is None:
        return None, {}, "AI model is currently unavailable"

    prediction = raw["prediction"]          # "SAFE" or "SCAM"
    confidence = float(raw["confidence"])
    safe_prob  = float(raw["safe_probability"])
    scam_prob  = float(raw["scam_probability"])
    verdict    = "scam" if prediction == "SCAM" else "safe"

    result = {
        "engine":     "DistilBERT",
        "verdict":    verdict,
        "confidence": confidence,
        "risk":       scam_prob,
        "reasons":    [],
        "tips":       [],
    }
    extras = {
        "safe_probability":  round(safe_prob, 2),
        "scam_probability":  round(scam_prob, 2),
    }
    return result, extras, None


def detect_url(url: str) -> tuple[dict | None, dict, str | None]:
    """Run XGBoost on a URL."""
    result = classify_url(url)
    if result is None:
        return None, {}, "URL detection model is currently unavailable"
    return result, {}, None


def detect_upi(upi_id: str, amount: float, note: str) -> tuple[dict | None, dict, str | None]:
    """Run GNN+XGBoost on a UPI payment request."""
    result = classify_upi(upi_id, amount, note)
    if result is None:
        return None, {}, "UPI detection model is currently unavailable"
    return result, {}, None


def _route_qr_content(
    decoded: str, language: str
) -> tuple[dict | None, str, str | None]:
    """
    Given the decoded string from a QR code, select the right model and
    return (model_result, analysis_subtype, error).

    analysis_subtype values: "qr-upi" | "qr-url" | "qr-text"
    """
    parsed = urlparse(decoded.strip())
    params = parse_qs(parsed.query)
    is_upi = (
        parsed.scheme.lower() == "upi"
        and parsed.netloc.lower() == "pay"
        and bool((params.get("pa") or [""])[0].strip())
    )

    if is_upi:
        result = classify_upi(decoded)
        return result, "qr-upi", (None if result else "UPI detection model is currently unavailable")

    url_candidate = find_url_in_text(decoded)
    if url_candidate:
        result = classify_url(url_candidate)
        return result, "qr-url", (None if result else "URL detection model is currently unavailable")

    result = classify_message(to_english(decoded[:MAX_CONTENT_CHARS], language))
    return result, "qr-text", (None if result else "AI model is currently unavailable")


def detect_qr(
    image_path: str, language: str
) -> tuple[dict | None, dict, str | None]:
    """
    Decode a QR image then route its content to the appropriate model.

    Returns (model_result, extras, error).
    extras always contains "decoded_content" and "analysis_type".
    """
    try:
        decoded, qr_error = decode_qr(image_path)
    except Exception:
        logger.exception("QR decode raised unexpectedly")
        return None, {}, "QR code could not be read from that image"

    if not decoded:
        error_msg = qr_error or "No QR code found in this image"
        return None, {}, error_msg

    try:
        result, subtype, error = _route_qr_content(decoded, language)
    except Exception:
        logger.exception("QR content classification failed")
        return None, {}, "The QR content could not be analyzed"

    if error or result is None:
        return None, {}, error or "QR detection model is currently unavailable"

    extras = {
        "decoded_content": decoded,
        "content":         decoded[:MAX_CONTENT_CHARS],
        "analysis_type":   subtype,
    }
    return result, extras, None


def detect_image(
    image_path: str, language: str
) -> tuple[dict | None, dict, str | None]:
    """
    Analyze an image:
      1. Try QR decode first.
      2. Fall back to OCR → payment rules / URL model / DistilBERT.

    Returns (model_result, extras, error).
    """
    # ── Step 1: try QR ────────────────────────────────────────────────
    try:
        decoded, _ = decode_qr(image_path)
    except Exception:
        logger.exception("QR decode in detect_image failed; falling back to OCR")
        decoded = None

    if decoded:
        try:
            result, subtype, error = _route_qr_content(decoded, language)
        except Exception:
            logger.exception("QR content classification in detect_image failed")
            result, subtype, error = None, "qr-text", "QR content could not be analyzed"

        if result is not None:
            extras = {
                "decoded_content": decoded,
                "content":         decoded[:MAX_CONTENT_CHARS],
                "analysis_type":   subtype,
            }
            return result, extras, None
        # QR found but classifier unavailable — fall through to OCR

    # ── Step 2: OCR ───────────────────────────────────────────────────
    tesseract_cmd = current_app.config.get("TESSERACT_CMD", "")
    try:
        raw_text = extract_text(image_path, tesseract_cmd).strip()
    except ValueError as exc:
        return None, {}, f"The uploaded file is not a valid image ({exc})"
    except RuntimeError:
        return None, {}, "OCR is currently unavailable on the server"
    except OSError as exc:
        logger.exception("OCR I/O error: %s", exc)
        return None, {}, "OCR processing failed"
    except Exception:
        logger.exception("OCR unexpected error")
        return None, {}, "OCR is currently unavailable on the server"

    # ── Step 2a: plain photo ──────────────────────────────────────────
    if len(raw_text) < 15:
        result = {
            "engine":     "screenshot_ocr",
            "verdict":    "safe",
            "confidence": 90.0,
            "risk":       10.0,
            "reasons":    ["No readable text was found — treated as a plain photo."],
            "tips":       ["Verify any claims in an image through a trusted source."],
        }
        extras = {
            "analysis_type": "photo",
            "content":        raw_text,
            "safe_probability":  90.0,
            "scam_probability":  10.0,
        }
        return result, extras, None

    fields = parse_fields(raw_text)
    looks_like_payment = bool(
        fields.get("amount")
        or fields.get("upi_id")
        or fields.get("transaction_id")
        or _PAYMENT_KW_RE.search(raw_text)
    )

    # ── Step 2b: URL in image ─────────────────────────────────────────
    url_candidate = find_url_in_text(raw_text)
    if url_candidate and not looks_like_payment:
        result = classify_url(url_candidate)
        if result is None:
            return None, {}, "URL detection model is currently unavailable"
        extras = {
            "analysis_type": "image-url",
            "content":        raw_text[:MAX_CONTENT_CHARS],
        }
        return result, extras, None

    # ── Step 2c: payment screenshot rules ────────────────────────────
    if looks_like_payment:
        analysis = _ocr_analyze(raw_text, fields)
        result = {
            "engine":     "screenshot_ocr",
            "verdict":    analysis["verdict"],
            "confidence": analysis["confidence"],
            "risk":       analysis["risk"],
            "reasons":    analysis["reasons"],
            "tips":       _ocr_safety_tips(analysis["verdict"]),
        }
        extras = {
            "analysis_type":   "payment-screenshot",
            "content":          raw_text[:MAX_CONTENT_CHARS],
            "safe_probability":  round(100 - analysis["risk"], 2),
            "scam_probability":  round(analysis["risk"], 2),
        }
        return result, extras, None

    # ── Step 2d: image text → DistilBERT ─────────────────────────────
    from backend.utils.distilbert_loader import model as _dmodel, tokenizer as _dtok, predict_message
    if _dmodel is None or _dtok is None:
        return None, {}, "AI model is currently unavailable"

    try:
        pred = predict_message(to_english(raw_text[:MAX_CONTENT_CHARS], language))
    except Exception:
        logger.exception("detect_image DistilBERT fallback failed")
        return None, {}, "Analysis failed due to an internal error"

    if pred is None:
        return None, {}, "AI model is currently unavailable"

    result = {
        "engine":     "DistilBERT",
        "verdict":    "scam" if pred["prediction"] == "SCAM" else "safe",
        "confidence": float(pred["confidence"]),
        "risk":       float(pred["scam_probability"]),
        "reasons":    ["Readable text in the image was analyzed by DistilBERT."],
        "tips":       [],
    }
    extras = {
        "analysis_type":   "image-text",
        "content":          raw_text[:MAX_CONTENT_CHARS],
        "safe_probability":  round(float(pred["safe_probability"]), 2),
        "scam_probability":  round(float(pred["scam_probability"]), 2),
    }
    return result, extras, None


def detect_voice(
    audio_path: str, language: str
) -> tuple[dict | None, dict, str | None]:
    """
    Transcribe audio with Whisper then classify with DistilBERT.

    Returns (model_result, extras, error).
    """
    from backend.utils.voice_transcribe import transcribe_audio
    from backend.utils.distilbert_loader import model as _dmodel, tokenizer as _dtok, predict_message

    transcript, transcribe_error = transcribe_audio(audio_path)
    if transcribe_error or not transcript:
        return None, {}, transcribe_error or "No speech could be detected"

    if _dmodel is None or _dtok is None:
        return None, {}, "AI model is currently unavailable"

    if len(transcript) > MAX_CONTENT_CHARS:
        transcript = transcript[:MAX_CONTENT_CHARS]

    try:
        pred = predict_message(to_english(transcript, language))
    except Exception:
        logger.exception("detect_voice classification failed")
        return None, {}, "Analysis failed due to an internal error"

    if pred is None:
        return None, {}, "AI model is currently unavailable"

    result = {
        "engine":     "Whisper + DistilBERT",
        "verdict":    "scam" if pred["prediction"] == "SCAM" else "safe",
        "confidence": float(pred["confidence"]),
        "risk":       float(pred["scam_probability"]),
        "reasons":    [],
        "tips":       [],
    }
    extras = {
        "transcription":     transcript,
        "analysis_type":     "voice-transcription",
        "safe_probability":  round(float(pred["safe_probability"]), 2),
        "scam_probability":  round(float(pred["scam_probability"]), 2),
    }
    return result, extras, None
