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

Production note (Render / gunicorn):
    Whisper can take 20-120 s to initialise or transcribe on a CPU-only
    instance.  Running it on the calling thread would block the gunicorn
    worker until the platform proxy (Render's nginx uses ~30 s) kills the
    connection and returns a 502 to the client.

    To avoid this we offload the work to a ThreadPoolExecutor with a hard
    deadline of TRANSCRIBE_TIMEOUT_SECONDS (default 90 s).  If the
    deadline expires we return a friendly error so the route can respond
    quickly with HTTP 503 instead of silently hanging.
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from flask import current_app

logger = logging.getLogger(__name__)

_model_cache: dict = {}

# One reusable thread that lives for the process lifetime.  Whisper itself
# is not thread-safe when models are shared, but we serialise calls through
# the single thread so concurrent requests queue rather than corrupt state.
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whisper")

# Hard deadline passed to the executor.  Render's nginx proxy times out at
# ~30 s; we set the app-level deadline lower so Flask can still send a clean
# JSON error before the proxy cuts the connection.
_TRANSCRIBE_TIMEOUT_SECONDS = int(os.environ.get("WHISPER_TIMEOUT_SECONDS", "85"))


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


def _do_transcribe(file_path: str, model_size: str):
    """
    Worker function executed inside the dedicated Whisper thread.

    Separating model load + transcription into this function means the
    ThreadPoolExecutor can be given a timeout from the *calling* thread
    without the Whisper work ever touching the gunicorn request thread.
    """
    # Honour the app config that was resolved before the request context
    # ends; pass size explicitly since current_app is not available inside
    # the worker thread.
    size = model_size

    if size in _model_cache:
        model = _model_cache[size]
    else:
        try:
            import whisper
        except ImportError:
            return None, (
                "The 'openai-whisper' package isn't installed. Run "
                "`pip install -r requirements.txt` and try again."
            )
        try:
            model = whisper.load_model(size)
            _model_cache[size] = model
        except Exception as exc:
            logger.exception("Whisper worker: failed to load model (%s)", size)
            return None, (
                f"Couldn't load the Whisper '{size}' model ({exc.__class__.__name__}). "
                "This usually means no internet connection was available to download it "
                "the first time, or ffmpeg isn't installed on this machine."
            )

    try:
        result = model.transcribe(file_path, fp16=False)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Whisper worker: transcription failed for %s", file_path)
        return None, (
            f"Couldn't transcribe that audio file ({exc.__class__.__name__}). "
            "Make sure it's a valid WAV, MP3, M4A, or OGG file and try again."
        )

    text = (result.get("text") or "").strip()
    if not text:
        return None, "No speech could be detected in this audio file."
    return text, None


def transcribe_audio(file_path: str):
    """
    Transcribe an audio file to text, offloaded to a background thread.

    Returns (transcript, error):
        transcript - the recognized text, or None on failure
        error      - human-readable reason when transcript is None, else None

    Uses a ThreadPoolExecutor so that the gunicorn request thread is never
    blocked longer than WHISPER_TIMEOUT_SECONDS (default 85 s).  This
    prevents Render's 30 s proxy timeout from returning an empty 502 to
    the client before Flask has a chance to send a proper JSON error.
    """
    # Resolve config while we still have an app context (request thread).
    try:
        model_size = current_app.config.get("WHISPER_MODEL_SIZE", "tiny")
        timeout = _TRANSCRIBE_TIMEOUT_SECONDS
    except RuntimeError:
        # Outside app context (unit tests, etc.) — use env defaults.
        model_size = os.environ.get("WHISPER_MODEL_SIZE", "tiny")
        timeout = _TRANSCRIBE_TIMEOUT_SECONDS

    future = _executor.submit(_do_transcribe, file_path, model_size)
    try:
        transcript, error = future.result(timeout=timeout)
        return transcript, error
    except FuturesTimeoutError:
        future.cancel()
        logger.error(
            "Whisper transcription timed out after %s s for %s",
            timeout, file_path,
        )
        return None, (
            "Voice transcription timed out. "
            "The audio may be too long, or the model is still loading on first use. "
            "Please try again in a few seconds."
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error in transcribe_audio executor")
        return None, f"Transcription failed unexpectedly ({exc.__class__.__name__})."
