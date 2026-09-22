"""
TRINETRA AI - Configuration
============================
Centralized, environment-driven configuration. Never hardcode secrets:
values are read from environment variables (see .env.example) with safe
local-development fallbacks.
"""

import os
from pathlib import Path

# Project root = trinetra-ai/
BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_DIR = BASE_DIR / "database"
UPLOADS_DIR = BASE_DIR / "uploads"
MODELS_DIR = BASE_DIR / "models"

_TESSERACT_CANDIDATES = tuple(
    Path(path)
    for path in (
        os.environ.get("TESSERACT_CMD", ""),
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    )
    if path
)
TESSERACT_PATH = next(
    (str(path) for path in _TESSERACT_CANDIDATES if str(path) and path.exists()),
    "",
)

# Make sure runtime directories exist even on a fresh checkout.
# Note: no reports/ directory — PDF reports are generated in-memory
# (see backend/utils/report_generator.py) and streamed straight to the
# browser, never written to disk.
for _directory in (DATABASE_DIR, UPLOADS_DIR, MODELS_DIR):
    _directory.mkdir(parents=True, exist_ok=True)


class BaseConfig:
    """Shared configuration across all environments."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-key-change-me")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{DATABASE_DIR / 'trinetra.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload safety limits
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", 10)) * 1024 * 1024  # 10 MB default
    UPLOAD_FOLDER = str(UPLOADS_DIR)
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    ALLOWED_AUDIO_EXTENSIONS = {"wav", "mp3", "m4a", "ogg"}

    # ==========================
# AI Models
# ==========================

    DISTILBERT_MODEL_PATH = str(MODELS_DIR / "distilbert")

    URL_MODEL_PATH = str(MODELS_DIR / "xgboost" / "url_model.pkl")
    UPI_MODEL_PATH = str(MODELS_DIR / "upi_model.pkl")
    # Voice Scam Detection (Phase 4): smallest Whisper checkpoint by default —
    # fast and small enough to download on a typical dev/demo machine.
    # Options (speed vs accuracy): tiny < base < small < medium < large
    WHISPER_MODEL_SIZE = os.environ.get("WHISPER_MODEL_SIZE", "tiny")

    # Fake Payment Screenshot Detection (Phase 5): only needed if the
    # tesseract binary isn't already on PATH (common on Windows).
    TESSERACT_CMD = TESSERACT_PATH

    APP_NAME = "TRINETRA AI"
    APP_TAGLINE = "Smart Third-Eye Cyber Scam Detection System"

    # Auth / session cookies. HttpOnly + SameSite=Lax are safe defaults in
    # every environment; Secure (HTTPS-only) is turned on for production
    # below since local dev typically runs over plain http://localhost.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ENV = "development"
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False


class ProductionConfig(BaseConfig):
    DEBUG = False
    ENV = "production"
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False  # simplifies posting forms directly in tests
    SESSION_COOKIE_SECURE = False


_CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name: str = None):
    """Resolve a config class by name, falling back to FLASK_ENV / development."""
    name = name or os.environ.get("FLASK_ENV", "development")
    return _CONFIG_MAP.get(name, DevelopmentConfig)
