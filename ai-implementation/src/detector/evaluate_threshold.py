"""
Evaluate the ALREADY-TRAINED model at one or more alert thresholds, on the
same held-out test set train.py reports metrics on.

WHY THIS EXISTS
----------------
train.py's printed metrics (accuracy, false-positive rate) are measured at the
default 0.50 decision boundary, not at config.ALERT_THRESHOLD. Whenever
ALERT_THRESHOLD changes (e.g. 95 -> 85), the precision/recall/false-positive
rate documented for the high-priority alert need to be recomputed at the new
value -- this script does that without retraining, by reusing the exact
train/test split train.py used (same random_state, so the test set is
identical) and reloading the saved model.

HOW TO RUN (from the ai-implementation/ project root):
    python -m src.detector.evaluate_threshold
    python -m src.detector.evaluate_threshold --thresholds 50,85,95
"""

from __future__ import annotations

import argparse

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src import config
from src.detector.train import build_xy


def load_and_clean_needed_columns() -> pd.DataFrame:
    """
    Same loading/cleaning as train.py's load_dataset()+clean(), but reads only
    the columns build_xy() actually needs (10 features + label) instead of all
    79 raw CICIDS2017 columns. train.py's full-width df.replace(inf, nan) call
    allocates a temporary array sized to the whole frame, which is fine once
    but is unnecessary memory pressure here since we only ever use 11 columns.
    """
    needed = set(config.SURICATA_ALIGNED_FEATURES + [config.LABEL_COLUMN])
    csv_paths = sorted(config.DATA_DIR.glob("**/*.csv"))
    if not csv_paths:
        raise SystemExit(
            f"\nNo CSV files found in {config.DATA_DIR}.\n"
            "Download the CICIDS2017 'MachineLearningCVE' CSVs and put them there.\n"
        )

    print(f"Found {len(csv_paths)} CSV file(s). Loading needed columns only...")
    frames = []
    for path in csv_paths:
        frame = pd.read_csv(
            path, low_memory=False, usecols=lambda c: c.strip() in needed
        )
        frame.columns = [c.strip() for c in frame.columns]
        frames.append(frame)
    df = pd.concat(frames, ignore_index=True)
    print(f"Loaded {len(df):,} rows.")

    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna(subset=config.SURICATA_ALIGNED_FEATURES)
    print(f"Dropped {before - len(df):,} rows with bad/missing feature values.")
    return df


def evaluate_at_threshold(y_true, attack_percent, threshold: float) -> dict:
    """Confusion-matrix-derived metrics at one 0-100 percent threshold."""
    y_pred = (attack_percent >= threshold).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn)

    return {
        "threshold": threshold,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "accuracy": accuracy,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--thresholds",
        default=f"{config.CLASSIFICATION_THRESHOLD},{config.ALERT_THRESHOLD},95",
        help="Comma-separated 0-100 percent thresholds to evaluate (default: "
        "current classification threshold, current alert threshold, and 95 "
        "for comparison against the prior alert threshold).",
    )
    args = parser.parse_args()
    thresholds = sorted({float(t) for t in args.thresholds.split(",")})

    if not config.MODEL_PATH.exists():
        raise SystemExit(
            f"No trained model at {config.MODEL_PATH}. Run "
            "`python -m src.detector.train` first."
        )
    model = joblib.load(config.MODEL_PATH)

    df = load_and_clean_needed_columns()
    X, y = build_xy(df)

    # Identical split to train.py -> same held-out test set the saved model
    # was already evaluated on, so these numbers are directly comparable.
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    print(f"Evaluating on {len(X_test):,} held-out rows (same split as train.py).\n")

    attack_percent = model.predict_proba(X_test)[:, 1] * 100.0
    y_true = y_test.to_numpy()

    header = f"{'threshold':>9} {'accuracy':>9} {'precision':>10} {'recall':>8} {'fpr':>8}   tp/fp/fn/tn"
    print(header)
    print("-" * len(header))
    for threshold in thresholds:
        m = evaluate_at_threshold(y_true, attack_percent, threshold)
        print(
            f"{m['threshold']:9.1f} {m['accuracy']:8.3%} {m['precision']:9.3%} "
            f"{m['recall']:7.3%} {m['fpr']:7.3%}   "
            f"{m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}"
        )


if __name__ == "__main__":
    main()
