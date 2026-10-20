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
# HUGGING FACE MODEL DOWNLOAD
# ==========================================

HF_REPO_ID = os.getenv(
    "HF_REPO_ID",
    "S45-s/trinetra-distilbert"
)

HF_TOKEN = os.getenv("HF_TOKEN")

try:
    from huggingface_hub import snapshot_download

    # Download only when the model file is missing.
    # Locally, your existing model will continue to be used.
    model_file = os.path.join(
        MODEL_PATH,
        "model.safetensors"
    )

    if not os.path.exists(model_file):
        logger.info(
            "DistilBERT model not found locally. Downloading from Hugging Face..."
        )

        snapshot_download(
            repo_id=HF_REPO_ID,
            repo_type="model",
            local_dir=MODEL_PATH,
            token=HF_TOKEN
        )

        logger.info(
            "DistilBERT model downloaded successfully."
        )
    else:
        logger.info(
            "DistilBERT model already exists locally."
        )

except Exception as download_error:
    logger.warning(
        "Could not download DistilBERT model from Hugging Face: %s",
        download_error
    )


# ==========================================
# DEVICE
# ==========================================

try:
    import torch

    DEVICE = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

except (ImportError, OSError) as torch_error:
    logger.warning(
        "PyTorch is unavailable; message classification is disabled: %s",
        torch_error,
    )

    torch = None
    DEVICE = None


# ==========================================
# LOAD TOKENIZER + MODEL
# ==========================================

tokenizer = None
model = None

try:
    from transformers import (
        DistilBertTokenizerFast,
        DistilBertForSequenceClassification,
    )

    tokenizer = DistilBertTokenizerFast.from_pretrained(
        MODEL_PATH
    )

    model = DistilBertForSequenceClassification.from_pretrained(
        MODEL_PATH
    )

    model.to(DEVICE)
    model.eval()

    logger.info(
        "DistilBERT model loaded from %s on device=%s",
        MODEL_PATH,
        DEVICE
    )

except Exception as load_error:
    logger.warning(
        "DistilBERT model could not be loaded (model=%s): %s — "
        "message classification is unavailable.",
        MODEL_PATH,
        load_error,
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
    """Run text through DistilBERT and return prediction dict."""

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