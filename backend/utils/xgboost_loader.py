import os
import logging

logger = logging.getLogger(__name__)


# ==========================================
# PROJECT ROOT
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


# ==========================================
# MODEL DIRECTORY
# ==========================================

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models",
    "xgboost"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_model.pkl"
)

FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "feature_columns.pkl"
)


# ==========================================
# HUGGING FACE CONFIG
# ==========================================

HF_REPO_ID = os.getenv(
    "URL_MODEL_HF_REPO_ID",
    "S45-s/trinetra-url-model"
)

HF_TOKEN = os.getenv("HF_TOKEN")


# ==========================================
# DOWNLOAD MODEL IF MISSING
# ==========================================

try:

    if not (
        os.path.exists(MODEL_PATH)
        and os.path.exists(FEATURE_PATH)
    ):

        logger.info(
            "URL model files not found locally. "
            "Downloading from Hugging Face..."
        )

        from huggingface_hub import snapshot_download

        os.makedirs(
            MODEL_DIR,
            exist_ok=True
        )

        snapshot_download(
            repo_id=HF_REPO_ID,
            repo_type="model",
            local_dir=MODEL_DIR,
            token=HF_TOKEN,
            allow_patterns=[
                "url_model.pkl",
                "feature_columns.pkl"
            ]
        )

        logger.info(
            "URL model files downloaded successfully."
        )

except Exception as e:

    logger.warning(
        "Could not download URL model from Hugging Face: %s",
        e
    )


# ==========================================
# INITIALIZE
# ==========================================

model = None
feature_columns = None


# ==========================================
# LOAD XGBOOST MODEL
# ==========================================

try:

    if os.path.exists(MODEL_PATH):

        import joblib

        model = joblib.load(
            MODEL_PATH
        )

        logger.info(
            "XGBoost URL model loaded from %s",
            MODEL_PATH
        )

    else:

        logger.warning(
            "XGBoost model not found at: %s",
            MODEL_PATH
        )

except Exception as e:

    logger.warning(
        "Error loading XGBoost model: %s",
        e
    )


# ==========================================
# LOAD FEATURE COLUMNS
# ==========================================

try:

    if os.path.exists(FEATURE_PATH):

        import joblib

        feature_columns = joblib.load(
            FEATURE_PATH
        )

        logger.info(
            "URL feature columns loaded from %s",
            FEATURE_PATH
        )

    else:

        logger.warning(
            "Feature columns not found at: %s",
            FEATURE_PATH
        )

except Exception as e:

    logger.warning(
        "Error loading feature columns: %s",
        e
    )


# ==========================================
# PREDICT URL
# ==========================================

def predict_url(features):

    if model is None:
        return None

    if feature_columns is None:
        return None

    try:

        if not hasattr(features, "columns"):
            return None

        missing = [
            col
            for col in feature_columns
            if col not in features.columns
        ]

        if missing:

            logger.warning(
                "Missing URL features: %s",
                missing
            )

            return None

        features = features[
            feature_columns
        ]

        prediction = model.predict(
            features
        )[0]

        probabilities = model.predict_proba(
            features
        )[0]

        safe_probability = float(
            probabilities[0] * 100
        )

        scam_probability = float(
            probabilities[1] * 100
        )

        if prediction == 1:

            verdict = "SCAM"
            confidence = scam_probability

        else:

            verdict = "SAFE"
            confidence = safe_probability

        return {
            "prediction": verdict,
            "confidence": round(
                confidence,
                2
            ),
            "safe_probability": round(
                safe_probability,
                2
            ),
            "scam_probability": round(
                scam_probability,
                2
            )
        }

    except Exception as e:

        logger.warning(
            "URL prediction error: %s",
            e
        )

        return None