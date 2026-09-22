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
# MODEL PATHS
# ==========================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "xgboost",
    "url_model.pkl"
)

FEATURE_PATH = os.path.join(
    BASE_DIR,
    "models",
    "xgboost",
    "feature_columns.pkl"
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
        model = joblib.load(MODEL_PATH)
        logger.info("XGBoost URL model loaded from %s", MODEL_PATH)

    else:

        logger.warning("XGBoost model not found at: %s", MODEL_PATH)

except Exception as e:

    logger.warning("Error loading XGBoost model: %s", e)


# ==========================================
# LOAD FEATURE COLUMNS
# ==========================================

try:

    if os.path.exists(FEATURE_PATH):

        import joblib
        feature_columns = joblib.load(FEATURE_PATH)
        logger.info("URL feature columns loaded from %s", FEATURE_PATH)

    else:

        logger.warning("Feature columns not found at: %s", FEATURE_PATH)

except Exception as e:

    logger.warning("Error loading feature columns: %s", e)


# ==========================================
# PREDICT URL
# ==========================================
def predict_url(features):

    if model is None:
        return None

    if feature_columns is None:
        return None

    try:

        # Ensure DataFrame
        if not hasattr(features, "columns"):
            return None

        # Check all required features exist
        missing = [
            col
            for col in feature_columns
            if col not in features.columns
        ]

        if missing:
            logger.warning("Missing URL features: %s", missing)
            return None

        # EXACT feature order used during training
        features = features[
            feature_columns
        ]

        # Prediction
        prediction = model.predict(features)[0]

        # Probabilities
        probabilities = model.predict_proba(features)[0]

        safe_probability = float(
            probabilities[0] * 100
        )

        scam_probability = float(
            probabilities[1] * 100
        )

        # Model prediction
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

        logger.warning("URL prediction error: %s", e)
        return None