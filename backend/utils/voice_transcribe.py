"""
TRINETRA AI - Voice Transcription
====================================
Wraps OpenAI's Whisper for speech-to-text. Loaded lazily and cached in
memory (the model checkpoint is downloaded from OpenAI's servers on
first use if not already cached locally by the `whisper` package).

Every failure mode degrades gracefully — missing package, missing
ffmpeg, no internet for the first-time model download, or a corrupt
audio file all return a friendly (message, None) tuple instead of
raising, so the route can show a clear warning instead of crashing.
"""

import logging

from flask import current_app

logger = logging.getLogger(__name__)

_model_cache = {}


def _load_model():
    size = current_app.config.get("WHISPER_MODEL_SIZE", "tiny")
    if size in _model_cache:
        return _model_cache[size], None

    try:
        import whisper  # noqa: local import — heavy, optional dependency
    except ImportError:
        return None, (
            "The 'openai-whisper' package isn't installed. Run "
            "`pip install -r requirements.txt` and try again."
        )

    try:
        model = whisper.load_model(size)
    except Exception as exc:  # noqa: BLE001 - degrade gracefully for any load failure
        logger.exception("Failed to load Whisper model (%s)", size)
        return None, (
            f"Couldn't load the Whisper '{size}' model ({exc.__class__.__name__}). "
            "This usually means no internet connection was available to download it "
            "the first time, or ffmpeg isn't installed on this machine."
        )

    _model_cache[size] = model
    return model, None


def transcribe_audio(file_path: str):
    """
    Transcribe an audio file to text.

    Returns (transcript, error):
        transcript - the recognized text, or None on failure
        error      - human-readable reason when transcript is None, else None
    """
    model, error = _load_model()
    if model is None:
        return None, error

    try:
        result = model.transcribe(file_path, fp16=False)
    except Exception as exc:  # noqa: BLE001 - any decode/inference failure -> friendly message
        logger.exception("Whisper transcription failed for %s", file_path)
        return None, (
            f"Couldn't transcribe that audio file ({exc.__class__.__name__}). "
            "Make sure it's a valid WAV, MP3, M4A, or OGG file and try again."
        )

    text = (result.get("text") or "").strip()
    if not text:
        return None, "No speech could be detected in this audio file."
    return text, None
