"""
TRINETRA AI - Train: URL Phishing Detection Model
=====================================================
Trains a Random Forest classifier on lexical/structural URL features
(datasets/urls_dataset.csv) and saves:

    models/url_model.pkl

Feature extraction lives in backend/utils/url_features.py and is
reused unchanged at inference time — no train/serve skew.

Run (from project root):
    python training/generate_datasets.py   # once, to create the CSVs
    python training/train_url_model.py
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from backend.utils.url_features import feature_vector, FEATURE_NAMES

DATASET_PATH = BASE_DIR / "datasets" / "urls_dataset.csv"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def main():
    if not DATASET_PATH.exists():
        print(f"Dataset not found at {DATASET_PATH}.")
        print("Run `python training/generate_datasets.py` first.")
        sys.exit(1)

    print(f"Loading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=["url", "label"])
    print(f"  {len(df)} rows, label distribution:\n{df['label'].value_counts()}")

    print("Extracting lexical features...")
    features = df["url"].apply(feature_vector)
    X = pd.DataFrame(features.tolist(), columns=FEATURE_NAMES)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=250, max_depth=12, class_weight="balanced", random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTest accuracy: {acc:.4f}\n")
    print("Classification report:")
    print(classification_report(y_test, y_pred))
    print("Confusion matrix (rows=actual, cols=predicted), labels =", sorted(y.unique()))
    print(confusion_matrix(y_test, y_pred, labels=sorted(y.unique())))

    print("\nFeature importances:")
    for name, importance in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: -x[1]):
        print(f"  {name:<24} {importance:.4f}")

    model_path = MODELS_DIR / "url_model.pkl"
    joblib.dump(model, model_path)
    print(f"\nSaved model -> {model_path}")


if __name__ == "__main__":
    main()
