"""Tests for the portability gate in src/smoke_test.py.

The smoke test's whole job is to FAIL on a broken checkout, so these tests
exercise its failure paths. Like the rest of the suite they need no trained
model and no dataset -- `check_predictions` (the one check that does) is not
tested here; it is covered by actually running `python -m src.smoke_test`.
"""

from __future__ import annotations

import json

import pytest

from src import config, smoke_test


def test_no_training_imports_passes_when_scoring_path_is_clean(monkeypatch):
    monkeypatch.setattr(smoke_test, "TRAINING_MODULES", ("src.detector.definitely_not_real",))
    smoke_test.check_no_training_imports()  # must not raise


def test_no_training_imports_fails_when_train_module_is_loaded(monkeypatch):
    """The doc's failure mode: an inference module importing train.py, whose
    module-level code then makes the CICIDS2017 CSVs a runtime dependency."""
    import sys
    import types

    monkeypatch.setitem(sys.modules, "src.detector.train", types.ModuleType("train"))

    with pytest.raises(smoke_test.SmokeFailure, match="training modules"):
        smoke_test.check_no_training_imports()


def test_artifacts_present_fails_with_actionable_message(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MODEL_PATH", tmp_path / "nope.joblib")

    with pytest.raises(smoke_test.SmokeFailure) as excinfo:
        smoke_test.check_artifacts_present()

    message = str(excinfo.value)
    assert "NOT in git" in message
    assert "src.detector.train" in message


def test_metadata_fails_on_feature_drift(monkeypatch, tmp_path):
    """A model built for a different feature set must not be scored against."""
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        json.dumps({"feature_columns": ["Destination Port"], "environment": {}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "MODEL_METADATA_PATH", metadata_path)

    with pytest.raises(smoke_test.SmokeFailure, match="feature_columns"):
        smoke_test.check_metadata()


def test_metadata_warns_but_passes_on_package_version_drift(monkeypatch, tmp_path, capsys):
    """A scikit-learn mismatch is reported loudly but is not fatal -- it usually
    still loads, and failing here would block a demo for a likely non-issue."""
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        json.dumps(
            {
                "model_version": "1.0.0",
                "feature_columns": list(config.SURICATA_ALIGNED_FEATURES),
                "environment": {"scikit-learn": "0.0.1-ancient"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "MODEL_METADATA_PATH", metadata_path)

    smoke_test.check_metadata()  # must not raise

    output = capsys.readouterr().out
    assert "differ from the ones that built this model" in output
    assert "0.0.1-ancient" in output
    assert "requirements-lock.txt" in output


def test_metadata_warns_when_file_is_absent(monkeypatch, tmp_path, capsys):
    """An older artifact with no metadata.json should still be usable."""
    monkeypatch.setattr(config, "MODEL_METADATA_PATH", tmp_path / "missing.json")

    smoke_test.check_metadata()  # must not raise

    assert "cannot verify" in capsys.readouterr().out


def test_main_returns_nonzero_when_a_check_fails(monkeypatch, capsys):
    """Exit code is the contract -- it's what makes this usable as a deploy
    health check on the Suricata VM."""

    def boom():
        raise smoke_test.SmokeFailure("simulated breakage")

    monkeypatch.setattr(smoke_test, "CHECKS", (("Boom", boom),))

    assert smoke_test.main() == 1

    output = capsys.readouterr().out
    assert "simulated breakage" in output
    assert "SMOKE TEST FAILED" in output


def test_main_returns_zero_when_all_checks_pass(monkeypatch, capsys):
    monkeypatch.setattr(smoke_test, "CHECKS", (("Fine", lambda: None),))

    assert smoke_test.main() == 0
    assert "SMOKE TEST PASSED" in capsys.readouterr().out
