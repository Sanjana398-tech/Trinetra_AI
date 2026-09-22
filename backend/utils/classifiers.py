"""
TRINETRA AI - Shared Classification Helpers
===============================================
Thin wrappers around the trained models so every route that ends up
needing "classify this text as a message" or "classify this as a URL"
(Message Scan, QR Scan, Voice Scan) calls the same code instead of
re-implementing the same probability -> confidence/risk math.

Each function returns None if the underlying model isn't loaded yet
(see model_loader's graceful-fallback behavior) so callers can show a
friendly warning instead of crashing.
"""

from backend.utils.model_loader import (
    get_distilbert_model,
    get_tokenizer,
    get_upi_detector,
)

import torch
import pandas as pd
#from backend.utils.text_preprocess import clean_text
from backend.utils.message_reasons import generate_reasons as _message_reasons, safety_tips as _message_tips
from backend.utils.url_features import extract_url_features, explain_reasons as _url_reasons, safety_tips as _url_tips
from backend.utils.upi_features import explain_reasons as _upi_reasons, safety_tips as _upi_tips
from backend.utils.xgboost_loader import (
    model as _url_model,
    feature_columns as _url_feature_columns,
    predict_url as _predict_url,
)
from upi_detector import parse_upi_payload


def _risk_from_proba(classes, proba) -> float:
    """Weighted risk: full weight for 'scam' probability mass, partial for 'suspicious'."""
    weights = {"scam": 100, "suspicious": 55, "safe": 0}
    return round(sum(p * weights.get(cls, 0) for cls, p in zip(classes, proba)), 1)


def classify_message(text):

    model = get_distilbert_model()
    tokenizer = get_tokenizer()

    if model is None or tokenizer is None:
        return None

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=128
    )

    device = next(model.parameters()).device

    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():

        outputs = model(**inputs)

        probabilities = torch.softmax(outputs.logits, dim=1)

    confidence, prediction = torch.max(probabilities, dim=1)

    confidence = round(confidence.item() * 100, 2)

    prediction = prediction.item()

    verdict = "scam" if prediction == 1 else "safe"

# Risk = probability that the message is a scam
    risk = round(probabilities[0][1].item() * 100, 2)

    return {
        "engine": "DistilBERT",
        "verdict": verdict,
        "confidence": confidence,
        "risk": risk,
        "reasons": _message_reasons(text, verdict, confidence),
        "tips": _message_tips(verdict),
    }


def classify_url(url: str):
    """Classify a QR URL with the current 26-feature XGBoost model."""
    if _url_model is None or _url_feature_columns is None:
        return None

    features = extract_url_features(url)
    data = pd.DataFrame([features], columns=_url_feature_columns)
    prediction = _predict_url(data)
    if prediction is None:
        return None

    scam_probability = float(prediction["scam_probability"])
    if prediction["prediction"] == "SCAM" or scam_probability >= 70:
        verdict = "scam"
    elif scam_probability >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "engine": "url",
        "verdict": verdict,
        "confidence": float(prediction["confidence"]),
        "risk": scam_probability,
        "reasons": _url_reasons(url),
        "tips": _url_tips(verdict),
    }


def classify_upi(upi_id: str, amount: float = None, note: str = ""):
    """Classify a VPA or UPI payment URI with the saved GNN + XGBoost model."""
    detector = get_upi_detector()
    if detector is None:
        return None

    normalized_upi, amount_value, note_value, transaction = parse_upi_payload(
        upi_id, amount, note
    )
    prediction = detector.predict(normalized_upi, transaction)

    return {
        "engine": "upi_gnn_xgboost",
        "verdict": prediction["verdict"],
        "confidence": prediction["confidence"],
        "risk": prediction["risk"],
        "reasons": _upi_reasons(normalized_upi, amount_value, note_value),
        "tips": _upi_tips(prediction["verdict"]),
    }
