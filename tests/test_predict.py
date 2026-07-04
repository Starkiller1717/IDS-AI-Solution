"""Tests for classification and high-priority alert threshold behavior."""

import pytest

from src import config
from src.detector import predict as predict_module


class FixedProbabilityModel:
    """Small model stub that returns one predetermined attack probability."""

    def __init__(self, attack_probability: float):
        self.attack_probability = attack_probability

    def predict_proba(self, _row):
        return [[1.0 - self.attack_probability, self.attack_probability]]


def complete_feature_row() -> dict:
    return {name: 0 for name in config.SURICATA_ALIGNED_FEATURES}


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
