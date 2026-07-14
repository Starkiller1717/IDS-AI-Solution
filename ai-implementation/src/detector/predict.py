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
import json

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
    model = joblib.load(config.MODEL_PATH)
    _check_feature_alignment(model)
    return model


def _check_feature_alignment(model) -> None:
    """
    Fail loudly on train/inference feature drift.

    config.SURICATA_ALIGNED_FEATURES is the single source of truth. If the saved
    models/feature_columns.json artifact (the one handed to Daniel to deploy) or the
    model's own recorded feature order disagrees with it, we would silently score
    against a mismatched feature vector. Raise instead so drift is caught immediately
    rather than producing quietly wrong predictions.
    """
    expected = list(config.SURICATA_ALIGNED_FEATURES)

    if config.FEATURE_COLUMNS_PATH.exists():
        saved = json.loads(config.FEATURE_COLUMNS_PATH.read_text(encoding="utf-8"))
        if saved != expected:
            raise ValueError(
                "Feature drift: models/feature_columns.json does not match "
                "config.SURICATA_ALIGNED_FEATURES.\n"
                f"  artifact: {saved}\n"
                f"  config:   {expected}\n"
                "Retrain with `python -m src.detector.train` so they agree."
            )

    recorded = getattr(model, "feature_names_in_", None)
    if recorded is not None and list(recorded) != expected:
        raise ValueError(
            "Feature drift: the trained model expects a different feature order "
            "than config.SURICATA_ALIGNED_FEATURES.\n"
            f"  model:  {list(recorded)}\n"
            f"  config: {expected}\n"
            "Retrain with `python -m src.detector.train` so they agree."
        )


def _result_from_percent(attack_percent: float) -> dict:
    """
    Turn an attack probability (expressed as a 0-100 percentage) into the result
    contract.

    The classification and alert DECISIONS compare the raw, unrounded percentage
    against config.CLASSIFICATION_THRESHOLD and config.ALERT_THRESHOLD, not a
    rounded integer. `score` is a rounded display value only, so a borderline
    flow can read e.g. 85 while sitting just under the alert threshold. Shared by
    predict() and predict_batch() so the two can never diverge.
    """
    return {
        "classification": (
            "attack" if attack_percent >= config.CLASSIFICATION_THRESHOLD else "normal"
        ),
        "score": int(round(attack_percent)),
        "is_alert_triggered": attack_percent >= config.ALERT_THRESHOLD,
    }


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

    # predict_proba gives P(attack); express it as a 0-100 percentage. The decisions
    # in _result_from_percent use this raw value; only the reported score is rounded.
    attack_percent = float(model.predict_proba(row)[0][1]) * 100.0
    return _result_from_percent(attack_percent)


def predict_batch(features_list: list[dict]) -> list[dict]:
    """
    Score many flows at once.

    Same contract as predict() but accepts a list and returns a list, calling
    predict_proba() once on the full matrix instead of once per flow.
    Use this for --eve-once (finished files); keep predict() for live tailing.
    """
    if not features_list:
        return []

    model = _load_model()

    for features in features_list:
        missing = [f for f in config.SURICATA_ALIGNED_FEATURES if f not in features]
        if missing:
            raise KeyError(f"Missing required features: {missing}")

    rows = [
        [float(features[f]) for f in config.SURICATA_ALIGNED_FEATURES]
        for features in features_list
    ]
    matrix = pd.DataFrame(rows, columns=config.SURICATA_ALIGNED_FEATURES)

    probabilities = model.predict_proba(matrix)[:, 1]
    return [_result_from_percent(float(p) * 100.0) for p in probabilities]


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
