"""
Train the network-attack detector on CICIDS2017.

WHAT THIS DOES (in plain English)
---------------------------------
1. Loads the CICIDS2017 CSV files you downloaded into ../data/
2. Cleans them (the raw files have messy column names and some bad numbers)
3. Keeps only the Suricata-aligned features (see src/config.py)
4. Turns the many attack labels into a simple BENIGN vs ATTACK (0/1) target
5. Trains a Random Forest classifier
6. Prints honest evaluation metrics (accuracy, false-positive rate, etc.)
7. Saves the trained model to ../models/detector.joblib

HOW TO RUN (from the senior-ai/ project root):
    python -m src.detector.train

You need the dataset first — see the README "Get the dataset" section.
This script is intentionally heavily commented because it's your learning material.
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from src import config


def load_dataset() -> pd.DataFrame:
    """Load and concatenate every CICIDS2017 CSV found in the data/ folder."""
    csv_paths = sorted(config.DATA_DIR.glob("**/*.csv"))
    if not csv_paths:
        sys.exit(
            f"\nNo CSV files found in {config.DATA_DIR}.\n"
            "Download the CICIDS2017 'MachineLearningCVE' CSVs and put them there.\n"
            "See the README section 'Get the dataset' for the exact steps.\n"
        )

    print(f"Found {len(csv_paths)} CSV file(s). Loading...")
    frames = [pd.read_csv(p, low_memory=False) for p in csv_paths]
    df = pd.concat(frames, ignore_index=True)

    # The raw CICIDS2017 columns have leading/trailing spaces — normalize them so
    # our config feature names match exactly.
    df.columns = [c.strip() for c in df.columns]
    print(f"Loaded {len(df):,} rows and {len(df.columns)} columns.")
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Replace infinities / NaNs that CICIDS2017 contains in the rate columns."""
    df = df.replace([np.inf, -np.inf], np.nan)
    # Only the columns we actually use need to be finite; drop rows missing them.
    needed = config.SURICATA_ALIGNED_FEATURES + [config.LABEL_COLUMN]
    missing_cols = [c for c in needed if c not in df.columns]
    if missing_cols:
        sys.exit(
            "\nThese expected columns are missing from the dataset: "
            f"{missing_cols}\nDouble-check you downloaded the MachineLearningCVE "
            "(flow-feature CSV) version of CICIDS2017.\n"
        )
    before = len(df)
    df = df.dropna(subset=config.SURICATA_ALIGNED_FEATURES)
    print(f"Dropped {before - len(df):,} rows with bad/missing feature values.")
    return df


def build_xy(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Split into the feature matrix X and the binary target y (0=benign, 1=attack)."""
    X = df[config.SURICATA_ALIGNED_FEATURES].astype(float)
    # Anything that isn't the BENIGN label counts as an attack.
    y = (df[config.LABEL_COLUMN].str.strip() != config.BENIGN_LABEL).astype(int)
    print(
        f"Class balance -> benign: {(y == 0).sum():,}  attack: {(y == 1).sum():,}"
    )
    return X, y


def main() -> None:
    df = load_dataset()
    df = clean(df)
    X, y = build_xy(df)

    # Stratify keeps the benign/attack ratio the same in train and test sets.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    print(f"\nTraining on {len(X_train):,} rows, testing on {len(X_test):,} rows...")

    # class_weight="balanced" tells the model to care about the rare attack class
    # even though benign traffic dominates. n_jobs=-1 uses all CPU cores.
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print("Training done.\n")

    # ---- Honest evaluation -------------------------------------------------
    y_pred = model.predict(X_test)

    print("Classification report (precision/recall/f1):")
    print(classification_report(y_test, y_pred, target_names=["benign", "attack"]))

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    # False-positive rate = benign traffic wrongly flagged. The design doc wants < 5%.
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    print("Confusion matrix:")
    print(f"  true benign  -> predicted benign: {tn:,}   predicted attack: {fp:,}")
    print(f"  true attack  -> predicted benign: {fn:,}   predicted attack: {tp:,}")
    print(f"\nAccuracy:            {accuracy:.3%}   (design target >= 90%)")
    print(f"False-positive rate: {fpr:.3%}   (design target <  5%)")

    print("\nTop features driving detections:")
    importances = sorted(
        zip(config.SURICATA_ALIGNED_FEATURES, model.feature_importances_),
        key=lambda kv: kv[1],
        reverse=True,
    )
    for name, score in importances:
        print(f"  {score:6.3f}  {name}")

    # ---- Save the model + the exact feature order it expects ---------------
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(model, config.MODEL_PATH)
    config.FEATURE_COLUMNS_PATH.write_text(
        json.dumps(config.SURICATA_ALIGNED_FEATURES, indent=2)
    )
    print(f"\nSaved model -> {config.MODEL_PATH}")
    print(f"Saved feature list -> {config.FEATURE_COLUMNS_PATH}")
    print("\nNext: try `python -m src.detector.suricata_reader --demo`")


if __name__ == "__main__":
    main()
