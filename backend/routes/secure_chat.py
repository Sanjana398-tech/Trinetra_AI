"""Authenticated server-to-server detection integration for Secure Chat."""

import hashlib
import hmac
import logging
import math
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlsplit

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from backend.db_models import ScanHistory, SecureChatAuthorizationCode, SystemLog, User
from backend.extensions import csrf, db
from backend.utils.classifiers import classify_message, classify_upi, classify_url
from backend.utils.localization import normalize_language, to_english, translate
from backend.utils.upi_features import is_valid_upi_id

logger = logging.getLogger(__name__)

secure_chat_bp = Blueprint("secure_chat", __name__)

_STATE_RE = re.compile(r"^[A-Za-z0-9._~-]{16,256}$")
_MAX_MESSAGE_CHARS = 4000
_MAX_URL_CHARS = 2048
_MAX_NOTE_CHARS = 1000


def _serializer():
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"],
        salt="secure-chat-integration-v1",
    )


def _authorized_service():
    expected = current_app.config.get("SECURE_CHAT_API_KEY", "")
    if not expected:
        return jsonify(error="Secure Chat integration is not configured"), 503

    provided = request.headers.get("X-Secure-Chat-Key", "")
    if not provided or not hmac.compare_digest(provided, expected):
        return jsonify(error="Unauthorized"), 401
    return None


def _verify_user_token():
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None, (jsonify(error="A valid account token is required"), 401)

    try:
        claims = _serializer().loads(
            token,
            max_age=current_app.config["SECURE_CHAT_TOKEN_TTL_SECONDS"],
        )
    except (BadSignature, SignatureExpired):
        return None, (jsonify(error="Invalid or expired account token"), 401)

    if not isinstance(claims, dict) or claims.get("aud") != "secure-chat":
        return None, (jsonify(error="Invalid account token"), 401)

    try:
        user_id = int(claims.get("sub"))
    except (TypeError, ValueError):
        return None, (jsonify(error="Invalid account token"), 401)

    user = db.session.get(User, user_id)
    if user is None:
        return None, (jsonify(error="Linked account not found"), 401)
    if not user.secure_chat_enabled:
        return None, (jsonify(error="Trinetra AI Protection is not enabled for this account"), 403)
    return user, None


def _save_scan(user, scan_type, content, result, language):
    reasons = [translate(reason, language) for reason in result.get("reasons", [])]
    tips = [translate(tip, language) for tip in result.get("tips", [])]
    record = ScanHistory(
        user_id=user.id,
        source="secure-chat",
        scan_type=scan_type,
        input_summary=content[:240],
        verdict=result["verdict"],
        confidence_score=float(result["confidence"]),
        risk_score=float(result["risk"]),
        explanation=" | ".join(reasons),
    )
    db.session.add(record)
    db.session.add(SystemLog(
        level="info",
        message=f"Secure Chat {scan_type} scan → {result['verdict']} ({result['confidence']}%).",
        source=f"api/secure-chat/{scan_type}",
    ))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Could not save Secure Chat scan")
        record = None

    verdict_label = translate(result["verdict"], language)
    detection_labels = {
        "DistilBERT": "SMS/DistilBERT",
        "url": "URL/XGBoost",
        "upi_gnn_xgboost": "UPI GNN + XGBoost",
    }
    return {
        "verdict": result["verdict"].title(),
        "confidence": round(float(result["confidence"]), 2),
        "risk_score": round(float(result["risk"]), 2),
        "explanation": " | ".join(reasons),
        "reasons": reasons,
        "tips": tips,
        "detection_type": detection_labels.get(result["engine"], result["engine"]),
        "language": language,
        "localized": {
            "verdict": verdict_label,
            "reasons": reasons,
            "tips": tips,
            "language": language,
        },
        "scan_id": record.id if record else None,
    }


@secure_chat_bp.route("/integrations/secure-chat/authorize", methods=["GET", "POST"])
@login_required
def authorize_secure_chat():
    state = request.values.get("state", "")
    if not _STATE_RE.fullmatch(state):
        return "A valid Secure Chat state value is required.", 400

    if request.method == "GET":
        return render_template(
            "integrations/secure_chat.html",
            state=state,
            enabled=current_user.secure_chat_enabled,
        )

    if request.form.get("consent") != "yes":
        return render_template(
            "integrations/secure_chat.html",
            state=state,
            enabled=current_user.secure_chat_enabled,
            error="Confirm that you want to enable Trinetra AI Protection.",
        ), 400

    redirect_uri = current_app.config.get("SECURE_CHAT_REDIRECT_URI", "")
    parsed_redirect = urlsplit(redirect_uri)
    local_http = parsed_redirect.hostname in {"localhost", "127.0.0.1"}
    if (
        not current_app.config.get("SECURE_CHAT_API_KEY")
        or not parsed_redirect.netloc
        or parsed_redirect.scheme not in ({"https", "http"} if local_http else {"https"})
    ):
        return "Secure Chat integration is not configured for authorization.", 503

    raw_code = secrets.token_urlsafe(32)
    auth_code = SecureChatAuthorizationCode(
        code_hash=hashlib.sha256(raw_code.encode("utf-8")).hexdigest(),
        user_id=current_user.id,
        expires_at=datetime.utcnow() + timedelta(
            seconds=current_app.config["SECURE_CHAT_CODE_TTL_SECONDS"]
        ),
    )
    current_user.secure_chat_enabled = True
    db.session.add(auth_code)
    db.session.commit()

    separator = "&" if "?" in redirect_uri else "?"
    return redirect(
        f"{redirect_uri}{separator}{urlencode({'code': raw_code, 'state': state})}",
        code=302,
    )


@secure_chat_bp.route("/integrations/secure-chat/revoke", methods=["POST"])
@login_required
def revoke_secure_chat():
    current_user.secure_chat_enabled = False
    db.session.commit()
    flash("Secure Chat access has been revoked.", "success")
    return redirect(url_for("dashboard.dashboard"))


@secure_chat_bp.route("/api/secure-chat/v1/token", methods=["POST"])
@csrf.exempt
def exchange_authorization_code():
    service_error = _authorized_service()
    if service_error:
        return service_error
    if not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 400

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required"), 400
    raw_code = body.get("code")
    if not isinstance(raw_code, str) or not raw_code:
        return jsonify(error="code is required"), 400

    code_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
    code_record = (
        SecureChatAuthorizationCode.query
        .filter_by(code_hash=code_hash)
        .with_for_update()
        .first()
    )
    now = datetime.utcnow()
    if code_record is None or code_record.used_at is not None or code_record.expires_at <= now:
        return jsonify(error="Invalid, expired, or already used authorization code"), 401

    user = db.session.get(User, code_record.user_id)
    if user is None or not user.secure_chat_enabled:
        return jsonify(error="Trinetra AI Protection is not enabled for this account"), 403

    consumed = (
        SecureChatAuthorizationCode.query
        .filter_by(id=code_record.id, used_at=None)
        .filter(SecureChatAuthorizationCode.expires_at > now)
        .update(
            {SecureChatAuthorizationCode.used_at: now},
            synchronize_session=False,
        )
    )
    if consumed != 1:
        db.session.rollback()
        return jsonify(error="Invalid, expired, or already used authorization code"), 401

    db.session.commit()
    token = _serializer().dumps({"sub": str(user.id), "aud": "secure-chat"})
    return jsonify(
        access_token=token,
        token_type="Bearer",
        expires_in=current_app.config["SECURE_CHAT_TOKEN_TTL_SECONDS"],
        trinetra_user_id=user.id,
    ), 200


@secure_chat_bp.route("/api/secure-chat/v1/detect", methods=["POST"])
@csrf.exempt
def detect_for_secure_chat():
    service_error = _authorized_service()
    if service_error:
        return service_error
    user, token_error = _verify_user_token()
    if token_error:
        return token_error
    if not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 400

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify(error="A JSON object is required"), 400
    detection_type = str(body.get("type", "")).strip().lower()
    requested_language = body.get("language", "en")
    language = normalize_language(requested_language if isinstance(requested_language, str) else "en")

    try:
        if detection_type in {"message", "text", "sms"}:
            content = body.get("text", body.get("message", ""))
            if not isinstance(content, str) or not content.strip():
                return jsonify(error="text is required"), 400
            content = content.strip()
            if len(content) > _MAX_MESSAGE_CHARS:
                return jsonify(error=f"text exceeds {_MAX_MESSAGE_CHARS} characters"), 400
            result = classify_message(to_english(content, language))
            scan_type = "message"
        elif detection_type == "url":
            content = body.get("url", "")
            if not isinstance(content, str) or not content.strip():
                return jsonify(error="url is required"), 400
            content = content.strip()
            if len(content) > _MAX_URL_CHARS:
                return jsonify(error=f"url exceeds {_MAX_URL_CHARS} characters"), 400
            result = classify_url(content)
            scan_type = "url"
        elif detection_type in {"upi", "payment"}:
            upi_id = body.get("upi_id", "")
            note = body.get("note", "")
            if not isinstance(upi_id, str) or not is_valid_upi_id(upi_id.strip()):
                return jsonify(error="a valid upi_id is required"), 400
            if not isinstance(note, str) or len(note) > _MAX_NOTE_CHARS:
                return jsonify(error=f"note must not exceed {_MAX_NOTE_CHARS} characters"), 400
            try:
                amount = float(body.get("amount", 0) or 0)
            except (TypeError, ValueError):
                return jsonify(error="amount must be a valid number"), 400
            if not math.isfinite(amount) or amount < 0 or amount > 10_000_000:
                return jsonify(error="amount is out of range"), 400
            content = f"{upi_id.strip()} | {amount:g} | {note.strip()}"
            result = classify_upi(upi_id.strip(), amount, note.strip())
            scan_type = "upi"
        else:
            return jsonify(error="type must be message, url, or upi"), 400
    except Exception:
        logger.exception("Secure Chat %s detection failed", detection_type)
        return jsonify(error="Analysis failed due to an internal error"), 500

    if result is None:
        return jsonify(error=f"{detection_type} detection model is currently unavailable"), 503

    return jsonify(_save_scan(user, scan_type, content, result, language)), 200