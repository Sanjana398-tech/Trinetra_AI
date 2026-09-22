import logging

from flask import current_app

from transformers import DistilBertTokenizerFast
from transformers import DistilBertForSequenceClassification

import torch

logger = logging.getLogger(__name__)

_cache = {}

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def get_distilbert_model():

    if "distilbert_model" in _cache:
        return _cache["distilbert_model"]

    try:

        path = current_app.config["DISTILBERT_MODEL_PATH"]

        tokenizer = DistilBertTokenizerFast.from_pretrained(path)

        model = DistilBertForSequenceClassification.from_pretrained(path)

        model.to(device)

        model.eval()

        _cache["tokenizer"] = tokenizer
        _cache["distilbert_model"] = model

        logger.info("DistilBERT Loaded Successfully")

        return model

    except Exception as e:
        logger.exception(f"Failed to load DistilBERT model: {e}")
        return None


def get_tokenizer():

    if "tokenizer" not in _cache:
        get_distilbert_model()

    return _cache.get("tokenizer")


def get_url_model():

    import joblib

    if "url_model" in _cache:
        return _cache["url_model"]

    try:

        path = current_app.config["URL_MODEL_PATH"]

        model = joblib.load(path)

        _cache["url_model"] = model

        return model

    except Exception as e:
        logger.exception(f"Failed to load URL model: {e}")
        return None

def get_upi_model():

    import joblib

    if "upi_model" in _cache:
        return _cache["upi_model"]

    try:

        path = current_app.config["UPI_MODEL_PATH"]

        model = joblib.load(path)

        _cache["upi_model"] = model

        return model

    except Exception as e:
        logger.exception(f"Failed to load UPI model: {e}")
        return None


def get_upi_detector():
    """Load the saved GNN + XGBoost UPI detector once per process."""
    if "upi_detector" in _cache:
        return _cache["upi_detector"]

    try:
        from upi_detector import UPIDetector

        detector = UPIDetector()
        _cache["upi_detector"] = detector
        logger.info("UPI GNN + XGBoost detector loaded successfully")
        return detector
    except Exception as e:
        logger.exception(f"Failed to load UPI GNN + XGBoost detector: {e}")
        return None

def clear_cache():
    _cache.clear()