"""
TRINETRA AI - Message Dataset Cleaner
====================================
Reads all CSV files from datasets/raw/sms/, detects the message and label
columns automatically, converts labels to binary (0 = safe, 1 = scam),
removes duplicates/null/empty rows, applies basic text normalization, shuffles
rows, and saves a cleaned dataset to datasets/processed/final_messages.csv.

The script is intentionally modular so it can work with multiple dataset
formats such as:
- text,label
- message,label
- sms,label
- v1,v2 (ham/spam style)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
RAW_SMS_DIR = BASE_DIR / "datasets" / "raw" / "sms"
PROCESSED_DIR = BASE_DIR / "datasets" / "processed"
OUTPUT_PATH = PROCESSED_DIR / "final_messages.csv"

TEXT_COLUMN_ALIASES = {
    "text",
    "message",
    "sms",
    "content",
    "body",
    "msg",
    "body_text",
    "sentence",
    "review",
    "input",
}

LABEL_COLUMN_ALIASES = {
    "label",
    "class",
    "target",
    "category",
    "tag",
    "type",
    "output",
    "is_scam",
    "is_spam",
    "result",
    "y",
}

SAFE_LABELS = {
    "0",
    "safe",
    "ham",
    "legit",
    "legitimate",
    "normal",
    "non-spam",
    "not spam",
    "benign",
    "false",
    "no",
}

SCAM_LABELS = {
    "1",
    "scam",
    "spam",
    "suspicious",
    "phish",
    "phishing",
    "malicious",
    "fraud",
    "true",
    "yes",
}


def normalize_column_name(name: object) -> str:
    """Return a normalized column name for easier matching."""
    if not isinstance(name, str):
        return str(name)
    cleaned = name.strip().lower().replace("-", "_").replace(" ", "_")
    cleaned = re.sub(r"[^a-z0-9]+", "_", cleaned).strip("_")
    return cleaned


def clean_text(text: object) -> str:
    """Apply lightweight text cleaning used by the downstream model."""
    if text is None:
        return ""

    cleaned = str(text).strip().lower()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def normalize_label(value: object) -> int:
    """Map common label values to binary labels: 0 = safe, 1 = scam."""
    if value is None:
        return -1

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return 0 if int(value) == 0 else 1

    text = str(value).strip().lower()
    if not text:
        return -1

    if text in SAFE_LABELS:
        return 0
    if text in SCAM_LABELS:
        return 1

    # Anything that is not explicitly safe is treated as scam-like.
    return 1


def infer_text_column(df: pd.DataFrame, label_column: Optional[str]) -> Optional[str]:
    """Infer the text/message column from common aliases and heuristics."""
    for column in df.columns:
        normalized = normalize_column_name(column)
        if normalized in TEXT_COLUMN_ALIASES:
            return column

    if label_column is not None:
        for column in df.columns:
            if column == label_column:
                continue
            normalized = normalize_column_name(column)
            if normalized in {"v2", "message_text", "text_field", "content_field"}:
                return column

    # Fallback: if there is only one non-label column, use it.
    candidate_columns = [col for col in df.columns if col != label_column]
    if len(candidate_columns) == 1:
        return candidate_columns[0]

    return None


def infer_label_column(df: pd.DataFrame) -> Optional[str]:
    """Infer the label column by aliases first, then by label-like values."""
    for column in df.columns:
        normalized = normalize_column_name(column)
        if normalized in LABEL_COLUMN_ALIASES:
            return column

    for column in df.columns:
        sample_values = [str(v).strip().lower() for v in df[column].dropna().astype(str).head(50) if str(v).strip()]
        if any(value in SAFE_LABELS or value in SCAM_LABELS for value in sample_values):
            return column

    return None


def standardize_dataset(df: pd.DataFrame, source_name: str) -> pd.DataFrame:
    """Convert a single CSV file into a standardized text/label dataframe."""
    if df.empty:
        raise ValueError(f"{source_name} is empty.")

    label_column = infer_label_column(df)
    text_column = infer_text_column(df, label_column)

    if label_column is None or text_column is None:
        raise ValueError(
            f"Could not infer text/label columns from {source_name}. "
            f"Available columns: {list(df.columns)}"
        )

    standardized = df[[text_column, label_column]].copy()
    standardized.columns = ["text", "label"]
    standardized["text"] = standardized["text"].apply(clean_text)
    standardized["label"] = standardized["label"].apply(normalize_label)

    # Keep only rows with usable text and a valid label.
    standardized = standardized[standardized["label"] != -1]
    standardized = standardized[standardized["text"].str.len() > 0]
    return standardized


def read_csv_safely(csv_file: Path) -> pd.DataFrame:
    """Load a CSV file with a robust fallback strategy for different encodings."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return pd.read_csv(csv_file, keep_default_na=False, encoding=encoding)
        except UnicodeDecodeError:
            continue

    return pd.read_csv(csv_file, keep_default_na=False, encoding="utf-8", errors="ignore")


def load_raw_datasets(raw_dir: Path) -> pd.DataFrame:
    """Load and combine all CSV files from the raw SMS directory."""
    csv_files = sorted(raw_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {raw_dir}")

    frames: list[pd.DataFrame] = []
    for csv_file in csv_files:
        print(f"Loading {csv_file.name}...")
        frame = read_csv_safely(csv_file)
        standardized = standardize_dataset(frame, csv_file.name)
        frames.append(standardized)

    combined = pd.concat(frames, ignore_index=True)
    return combined


def clean_and_save(df: pd.DataFrame, output_path: Path) -> None:
    """Remove duplicates, shuffle rows, and save the final dataset."""
    cleaned = df.copy()

    # Remove duplicates after basic cleaning.
    cleaned = cleaned.drop_duplicates(subset=["text", "label"], keep="first")

    # Drop rows where the message became empty after normalization.
    cleaned = cleaned[cleaned["text"].str.len() > 0]

    # Shuffle for better training variety.
    cleaned = cleaned.sample(frac=1, random_state=42).reset_index(drop=True)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    cleaned.to_csv(output_path, index=False)
    print(f"Saved {len(cleaned)} cleaned rows to {output_path}")
    print(cleaned["label"].value_counts().sort_index())


def main() -> None:
    """Run the full preprocessing pipeline."""
    if not RAW_SMS_DIR.exists():
        raise FileNotFoundError(f"Input directory does not exist: {RAW_SMS_DIR}")

    combined = load_raw_datasets(RAW_SMS_DIR)
    clean_and_save(combined, OUTPUT_PATH)


if __name__ == "__main__":
    main()
