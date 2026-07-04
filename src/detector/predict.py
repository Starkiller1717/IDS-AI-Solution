"""
Load the trained detector and score a single network flow.

This is the clean "contract" the rest of the system depends on:

    predict({...features...}) -> {"classification": "attack"/"normal",
                                  "score": 0-100,
                                  "is_alert_triggered": bool}

`suricata_reader.py` calls this for every live flow. Willow's dashboard / the
notification code only ever needs this dict.
"""

from __future__ import annotations

import functools

import pandas as pd

from src import config


@functools.lru_cache(maxsize=1)
def _load_model():
    """Load the model once and cache it (loading from disk every call is slow)."""
    import joblib

    if not config.MODEL_PATH.exists():
        raise FileNotFoundError(
            f"No trained model at {config.MODEL_PATH}. "
            "Run `python -m src.detector.train` first."
        )
    return joblib.load(config.MODEL_PATH)


def predict(features: dict) -> dict:
    """
    Score one flow.

    `features` must contain every key in config.SURICATA_ALIGNED_FEATURES.
    Returns a small dict with the classification, a 0-100 score, and whether
    that score crosses the high-priority alert threshold.
    """
    model = _load_model()

    # Build the feature vector IN THE EXACT ORDER the model was trained on.
    missing = [f for f in config.SURICATA_ALIGNED_FEATURES if f not in features]
    if missing:
        raise KeyError(f"Missing required features: {missing}")
    row = pd.DataFrame(
        [[float(features[f]) for f in config.SURICATA_ALIGNED_FEATURES]],
        columns=config.SURICATA_ALIGNED_FEATURES,
    )

    # predict_proba gives P(attack); scale it to the project's 0-100 score.
    attack_probability = model.predict_proba(row)[0][1]
    score = int(round(attack_probability * 100))

    return {
        "classification": (
            "attack" if score >= config.CLASSIFICATION_THRESHOLD else "normal"
        ),
        "score": score,
        "is_alert_triggered": score >= config.ALERT_THRESHOLD,
    }


if __name__ == "__main__":
    # Quick manual smoke test with made-up numbers (needs a trained model).
    demo_features = {
        "Destination Port": 80,
        "Flow Duration": 1000,
        "Total Fwd Packets": 2,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 120,
        "Total Length of Bwd Packets": 0,
        "Flow Bytes/s": 120000.0,
        "Flow Packets/s": 2000.0,
        "Fwd Packet Length Mean": 60.0,
        "Bwd Packet Length Mean": 0.0,
    }
    print(predict(demo_features))
