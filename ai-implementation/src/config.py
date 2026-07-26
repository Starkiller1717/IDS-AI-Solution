"""
Central configuration shared by the whole AI pipeline.

WHY THIS FILE EXISTS
--------------------
The detector trains on CICIDS2017 columns, and at runtime `suricata_reader.py`
has to feed the model the *exact same* columns in the *exact same order*. If those
two ever disagree, predictions are garbage. Keeping the feature list in ONE place
(here) and importing it everywhere prevents that whole class of bug.

This is the most important design idea in the project: the model only ever sees
features that Suricata can actually produce live. See SURICATA_ALIGNED_FEATURES.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (everything is relative to the project root, so it works on any machine)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]   # .../senior-ai
DATA_DIR = PROJECT_ROOT / "data"                      # CICIDS2017 CSVs go here
MODELS_DIR = PROJECT_ROOT / "models"                  # trained model saved here

# Every path/setting below can be overridden by an environment variable of the
# same name (see .env.example). Unset -> falls back to the constant shown, so
# nothing changes for local dev. This is what lets a deploy target (e.g. the
# Suricata VM) point at its own paths without editing this tracked file.
MODEL_PATH = Path(os.getenv("MODEL_PATH", str(MODELS_DIR / "detector.joblib")))
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.json"
# Written by train.py next to the model: which package versions built it, when,
# and on what feature list. `detector.joblib` is a bare RandomForestClassifier
# and carries none of that, so without this file a teammate who loads the model
# in a different environment has no way to tell whether they're in a supported
# one. See src/smoke_test.py, which checks it.
MODEL_METADATA_PATH = MODELS_DIR / "metadata.json"

# Bump this whenever the model is retrained on different data, features, or
# hyperparameters. train.py stamps it into metadata.json so a prediction can
# always be traced back to the artifact that produced it.
MODEL_VERSION = "1.0.0"

# Path to a live/finished Suricata eve.json. No hardcoded default -- CLI flags
# (--eve / --eve-once) take precedence, but a deploy target can set this once
# (e.g. systemd Environment=EVE_PATH=/var/log/suricata/eve.json) and run
# suricata_reader.py with no flags at all.
EVE_PATH = Path(os.getenv("EVE_PATH")) if os.getenv("EVE_PATH") else None

# Where scored incidents get appended as JSON Lines. Single source of truth for
# both the app (incident_writer.py) and deploy-time tooling (promtail.yaml
# needs to tail this same path).
INCIDENTS_PATH = Path(os.getenv("INCIDENTS_PATH", str(PROJECT_ROOT / "output" / "incidents.jsonl")))

# ---------------------------------------------------------------------------
# Classification and alert thresholds
# ---------------------------------------------------------------------------
# The model's score answers two separate questions:
#   1. At 50+, does the model lean toward ATTACK rather than BENIGN?
#   2. At 85+, is the result strong enough to raise a high-priority alert?
#
# The alert threshold was raised from the original design doc's 70 to 95 per
# professor feedback, then lowered to 85 on 2026-07-14 after real captured
# traffic failed to cross 95. It only controls alerting; it does not trigger
# an automatic block or network lockdown.
CLASSIFICATION_THRESHOLD = 50
ALERT_THRESHOLD = 85

# ---------------------------------------------------------------------------
# Incident report backend
# ---------------------------------------------------------------------------
# "ollama" tries a local LLM (see reporting/report.py) for higher-quality prose.
# If the `ollama` package isn't installed or the Ollama app isn't running on
# this machine, generate_report() catches that and falls back to the template
# backend automatically, so leaving this on "ollama" is always safe. Set to
# "template" to skip the Ollama attempt entirely.
REPORT_BACKEND = os.getenv("REPORT_BACKEND", "ollama")
# llama3.1:8b (~4.9GB) needs more VRAM than this project's test hardware has
# (a 6GB laptop GPU) -- it OOM'd on GPU and was too slow on CPU fallback.
# llama3.2:3b (~2GB) fits comfortably with headroom and is fast enough for a
# short, fixed-format report; verified 2026-07-19.
OLLAMA_MODEL = "llama3.2:3b"
# The ollama Python package already reads OLLAMA_HOST from the environment on
# its own when it builds the default client -- report.py's ollama.chat() call
# picks it up with no code change needed. Exposed here too just so `config.py`
# stays the one place to look for every environment-driven setting.
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# ---------------------------------------------------------------------------
# SURICATA-ALIGNED FEATURE SET  (the key integration decision)
# ---------------------------------------------------------------------------
# CICIDS2017 has ~80 features, but Suricata's live `flow` events only expose a
# handful. We deliberately train on ONLY the features we can rebuild from a
# Suricata flow event, so the model that works in the notebook also works live.
#
# Each entry is the CICIDS2017 column name (after whitespace is stripped).
# The mapping from a live Suricata event to these is in `suricata_reader.py`.
SURICATA_ALIGNED_FEATURES: list[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
]

# CICIDS2017 marks normal traffic with this label; everything else is an attack.
BENIGN_LABEL = "BENIGN"

# The column in the CICIDS2017 CSVs that holds the ground-truth label.
LABEL_COLUMN = "Label"
