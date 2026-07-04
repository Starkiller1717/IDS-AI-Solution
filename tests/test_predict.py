"""Tests for classification and high-priority alert threshold behavior."""

import numpy as np
import pytest

from src import config
from src.detector import predict as predict_module


class FixedProbabilityModel:
    """Small model stub that returns one predetermined attack probability."""

    def __init__(self, attack_probability: float):
        self.attack_probability = attack_probability

    def predict_proba(self, _row):
        return [[1.0 - self.attack_probability, self.attack_probability]]


class FeatureDrivenProbabilityModel:
    """Use Destination Port as a deterministic 0-100 test score."""

    def predict_proba(self, rows):
        attack_probabilities = rows["Destination Port"].to_numpy(dtype=float) / 100
        return np.column_stack((1.0 - attack_probabilities, attack_probabilities))


def complete_feature_row() -> dict:
    return {name: 0 for name in config.SURICATA_ALIGNED_FEATURES}


def feature_row_for_score(score: int) -> dict:
    features = complete_feature_row()
    features["Destination Port"] = score
    return features


@pytest.mark.parametrize(
    ("attack_probability", "expected_score", "classification", "alert_triggered"),
    [
        (0.49, 49, "normal", False),
        (0.50, 50, "attack", False),
        (0.94, 94, "attack", False),
        (0.95, 95, "attack", True),
    ],
)
def test_classification_and_alert_thresholds_are_separate(
    monkeypatch,
    attack_probability,
    expected_score,
    classification,
    alert_triggered,
):
    monkeypatch.setattr(
        predict_module,
        "_load_model",
        lambda: FixedProbabilityModel(attack_probability),
    )

    result = predict_module.predict(complete_feature_row())

    assert result == {
        "classification": classification,
        "score": expected_score,
        "is_alert_triggered": alert_triggered,
    }


def test_predict_batch_matches_individual_predictions(monkeypatch):
    model = FeatureDrivenProbabilityModel()
    monkeypatch.setattr(predict_module, "_load_model", lambda: model)
    feature_rows = [feature_row_for_score(score) for score in (49, 50, 94, 95)]

    individual_results = [predict_module.predict(row) for row in feature_rows]
    batch_results = predict_module.predict_batch(feature_rows)

    assert batch_results == individual_results


def test_predict_batch_handles_empty_list():
    assert predict_module.predict_batch([]) == []


def test_predict_batch_rejects_missing_features(monkeypatch):
    monkeypatch.setattr(
        predict_module,
        "_load_model",
        lambda: FeatureDrivenProbabilityModel(),
    )

    with pytest.raises(KeyError, match="Missing required features"):
        predict_module.predict_batch([{}])
