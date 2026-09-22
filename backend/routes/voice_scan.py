"""
TRINETRA AI - Voice Scam Detection Routes
============================================
Accepts an uploaded call-recording audio file, transcribes it with
Whisper, then classifies the transcript using the same DistilBERT model
used by Message Scan — but with voice-call specific reasons and tips.

A "paste transcript" fallback is also offered: if Whisper isn't
available, scam-language analysis can still be tested directly on a
transcript.
"""

import os
import uuid

from flask import Blueprint, render_template, request, current_app, session
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog
from backend.utils.voice_transcribe import transcribe_audio
from backend.utils.distilbert_loader import predict_message
from backend.utils.voice_reasons import generate_reasons, safety_tips
from backend.utils.localization import to_english

voice_scan_bp = Blueprint("voice_scan", __name__, url_prefix="/scan/voice")

MAX_TRANSCRIPT_CHARS = 4000


def _allowed_audio(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_AUDIO_EXTENSIONS"]


def _summarize(text: str, limit: int = 240) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _classify_voice(transcript: str) -> dict:
    """
    Run the transcript through DistilBERT and build the full result dict
    with voice-specific reasons and safety tips.
    """
    prediction = predict_message(transcript)

    if prediction["prediction"] == "SCAM":
        verdict = "scam"
    else:
        verdict = "safe"

    confidence = prediction["confidence"]
    # Risk = probability the call is a scam (regardless of verdict)
    risk = round(prediction["scam_probability"], 2)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk": risk,
        "reasons": generate_reasons(transcript, verdict, confidence),
        "tips": safety_tips(verdict),
        "safe_probability": prediction["safe_probability"],
        "scam_probability": prediction["scam_probability"],
    }


@voice_scan_bp.route("", methods=["GET", "POST"])
@login_required
def scan_voice():
    result = None
    submitted_transcript = ""

    if request.method == "POST":
        file = request.files.get("audio_file")
        pasted_transcript = (request.form.get("transcript_text") or "").strip()

        transcript = None
        transcribe_error = None
        source_note = ""

        # ------------------------------------------------------------------
        # Audio file path
        # ------------------------------------------------------------------
        if file and file.filename:
            if not _allowed_audio(file.filename):
                allowed = ", ".join(sorted(current_app.config["ALLOWED_AUDIO_EXTENSIONS"]))
                result = {"error": f"Unsupported audio format. Allowed formats: {allowed}."}
            else:
                filename = secure_filename(file.filename)
                temp_name = f"{uuid.uuid4().hex}_{filename}"
                temp_path = os.path.join(current_app.config["UPLOAD_FOLDER"], temp_name)
                try:
                    file.save(temp_path)
                    transcript, transcribe_error = transcribe_audio(temp_path)
                except Exception:
                    current_app.logger.exception("Voice transcription failed")
                    transcript, transcribe_error = (
                        None,
                        "Something went wrong processing that audio file.",
                    )
                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                source_note = "audio upload"

        # ------------------------------------------------------------------
        # Pasted transcript path
        # ------------------------------------------------------------------
        elif pasted_transcript:
            if len(pasted_transcript) > MAX_TRANSCRIPT_CHARS:
                result = {
                    "error": f"That transcript is too long (max {MAX_TRANSCRIPT_CHARS} characters)."
                }
            else:
                transcript = pasted_transcript
                submitted_transcript = pasted_transcript
                source_note = "pasted transcript"
        else:
            result = {"error": "Upload a call recording or paste a transcript to analyze."}

        # ------------------------------------------------------------------
        # Run DistilBERT classification
        # ------------------------------------------------------------------
        if result is None:
            if transcribe_error:
                result = {"error": transcribe_error}
            elif transcript:
                try:
                    analysis_transcript = to_english(
                        transcript,
                        session.get("language", "en"),
                    )
                    classification = _classify_voice(analysis_transcript)
                except Exception:
                    current_app.logger.exception("Voice classification failed")
                    result = {
                        "error": "The DistilBERT detection model is unavailable. "
                                 "Please check the model files in models/distilbert/.",
                        "transcript": transcript,
                    }
                else:
                    record = ScanHistory(
                        user_id=current_user.id,
                        scan_type="voice",
                        input_summary=(
                            f"Call transcript ({source_note}): {_summarize(transcript)}"
                        )[:240],
                        verdict=classification["verdict"],
                        confidence_score=classification["confidence"],
                        risk_score=classification["risk"],
                        explanation=" ".join(classification["reasons"]),
                    )
                    db.session.add(record)
                    db.session.add(
                        SystemLog(
                            level="info",
                            message=(
                                f"Voice scan ({source_note}) classified as "
                                f"{classification['verdict']} "
                                f"({classification['confidence']}%)."
                            ),
                            source="voice_scan",
                        )
                    )
                    db.session.commit()

                    result = {
                        **classification,
                        "transcript": transcript,
                        "record_id": record.id,
                    }

    return render_template(
        "scan/voice.html",
        active_page="voice-scan",
        page_title="Voice Scam Detection",
        result=result,
        submitted_transcript=submitted_transcript,
    )
