"""
TRINETRA AI - Train: Message Scam Detection Model
=====================================================
Trains a TF-IDF + Logistic Regression classifier on
datasets/messages_dataset.csv and saves:

    models/tfidf_vectorizer.pkl
    models/message_model.pkl

Run (from project root):
    python training/generate_datasets.py   # once, to create the CSVs
    python training/train_message_model.py
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))  # allow `import backend...` when run as a script

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from backend.utils.text_preprocess import clean_text

DATASET_PATH = BASE_DIR / "datasets" / "messages_dataset.csv"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def main():
    if not DATASET_PATH.exists():
        print(f"Dataset not found at {DATASET_PATH}.")
        print("Run `python training/generate_datasets.py` first.")
        sys.exit(1)

    print(f"Loading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=["text", "label"])
    print(f"  {len(df)} rows, label distribution:\n{df['label'].value_counts()}")

    print("Cleaning text...")
    df["clean_text"] = df["text"].apply(clean_text)

    X_train, X_test, y_train, y_test = train_test_split(
        df["clean_text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    print("Vectorizing (TF-IDF, unigrams+bigrams)...")
    vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("Training Logistic Regression classifier...")
    model = LogisticRegression(max_iter=2000, class_weight="balanced", C=3.0)
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTest accuracy: {acc:.4f}\n")
    print("Classification report:")
    print(classification_report(y_test, y_pred))
    print("Confusion matrix (rows=actual, cols=predicted), labels =", sorted(df["label"].unique()))
    print(confusion_matrix(y_test, y_pred, labels=sorted(df["label"].unique())))

    vec_path = MODELS_DIR / "tfidf_vectorizer.pkl"
    model_path = MODELS_DIR / "message_model.pkl"
    joblib.dump(vectorizer, vec_path)
    joblib.dump(model, model_path)
    print(f"\nSaved vectorizer -> {vec_path}")
    print(f"Saved model      -> {model_path}")


if __name__ == "__main__":
    main()
