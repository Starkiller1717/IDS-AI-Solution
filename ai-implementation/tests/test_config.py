"""Tests for src/config.py's environment-variable overrides.

Each setting must fall back to its current hardcoded default when the
matching env var is unset, and pick up the override when it is set -- that's
the whole point of Step 2 (portable deploy config without editing config.py
on the target machine).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from src import config as config_module


@pytest.fixture
def reload_config(monkeypatch):
    """Reload src.config after tweaking env vars, then restore the default state."""

    def _reload():
        return importlib.reload(config_module)

    yield _reload
    monkeypatch.undo()
    importlib.reload(config_module)


def test_model_path_defaults_when_env_unset(monkeypatch, reload_config):
    monkeypatch.delenv("MODEL_PATH", raising=False)
    cfg = reload_config()
    assert cfg.MODEL_PATH == cfg.MODELS_DIR / "detector.joblib"


def test_model_path_overridden_by_env(monkeypatch, reload_config, tmp_path):
    override = tmp_path / "custom.joblib"
    monkeypatch.setenv("MODEL_PATH", str(override))
    cfg = reload_config()
    assert cfg.MODEL_PATH == override


def test_eve_path_defaults_to_none_when_unset(monkeypatch, reload_config):
    monkeypatch.delenv("EVE_PATH", raising=False)
    cfg = reload_config()
    assert cfg.EVE_PATH is None


def test_eve_path_overridden_by_env(monkeypatch, reload_config, tmp_path):
    override = tmp_path / "eve.json"
    monkeypatch.setenv("EVE_PATH", str(override))
    cfg = reload_config()
    assert cfg.EVE_PATH == override


def test_incidents_path_defaults_when_env_unset(monkeypatch, reload_config):
    monkeypatch.delenv("INCIDENTS_PATH", raising=False)
    cfg = reload_config()
    assert cfg.INCIDENTS_PATH == cfg.PROJECT_ROOT / "output" / "incidents.jsonl"


def test_incidents_path_overridden_by_env(monkeypatch, reload_config, tmp_path):
    override = tmp_path / "incidents.jsonl"
    monkeypatch.setenv("INCIDENTS_PATH", str(override))
    cfg = reload_config()
    assert cfg.INCIDENTS_PATH == override


def test_report_backend_defaults_to_ollama(monkeypatch, reload_config):
    monkeypatch.delenv("REPORT_BACKEND", raising=False)
    cfg = reload_config()
    assert cfg.REPORT_BACKEND == "ollama"


def test_report_backend_overridden_by_env(monkeypatch, reload_config):
    monkeypatch.setenv("REPORT_BACKEND", "template")
    cfg = reload_config()
    assert cfg.REPORT_BACKEND == "template"


def test_ollama_host_defaults_to_localhost(monkeypatch, reload_config):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    cfg = reload_config()
    assert cfg.OLLAMA_HOST == "http://localhost:11434"


def test_ollama_host_overridden_by_env(monkeypatch, reload_config):
    monkeypatch.setenv("OLLAMA_HOST", "http://10.0.0.5:11434")
    cfg = reload_config()
    assert cfg.OLLAMA_HOST == "http://10.0.0.5:11434"
