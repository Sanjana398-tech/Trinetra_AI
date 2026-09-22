import os
import logging

logger = logging.getLogger(__name__)

# ==========================================
# DISTILBERT MODEL PATH
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "distilbert"
)


# ==========================================
# DEVICE
# ==========================================

try:
    import torch
    DEVICE = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )
except (ImportError, OSError) as _torch_error:
    logger.warning(
        "PyTorch is unavailable; message classification is disabled: %s",
        _torch_error,
    )
    torch = None
    DEVICE = None


# ==========================================
# LOAD TOKENIZER + MODEL (graceful fallback)
# ==========================================

tokenizer = None
model = None

try:
    from transformers import (
        DistilBertTokenizerFast,
        DistilBertForSequenceClassification,
    )

    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_PATH)
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH)
    model.to(DEVICE)
    model.eval()
    logger.info("DistilBERT model loaded from %s on device=%s", MODEL_PATH, DEVICE)

except Exception as _load_error:
    logger.warning(
        "DistilBERT model could not be loaded (model=%s): %s — "
        "message classification is unavailable.",
        MODEL_PATH,
        _load_error,
    )
    model = None
    tokenizer = None


# ==========================================
# LABELS
# ==========================================

LABELS = {
    0: "SAFE",
    1: "SCAM"
}


# ==========================================
# PREDICTION FUNCTION
# ==========================================

def predict_message(text):
    """Run text through DistilBERT and return prediction dict.

    Returns None if the model is unavailable.
    """
    if model is None or tokenizer is None or torch is None:
        return None

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    )

    inputs = {
        key: value.to(DEVICE)
        for key, value in inputs.items()
    }

    with torch.no_grad():

        outputs = model(**inputs)

        probabilities = torch.softmax(
            outputs.logits,
            dim=1
        )[0]

    predicted_class = torch.argmax(
        probabilities
    ).item()

    confidence = probabilities[predicted_class].item() * 100

    safe_probability = probabilities[0].item() * 100
    scam_probability = probabilities[1].item() * 100

    return {
        "prediction": LABELS[predicted_class],
        "confidence": round(confidence, 2),
        "safe_probability": round(safe_probability, 2),
        "scam_probability": round(scam_probability, 2)
    }