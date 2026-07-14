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

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (everything is relative to the project root, so it works on any machine)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]   # .../senior-ai
DATA_DIR = PROJECT_ROOT / "data"                      # CICIDS2017 CSVs go here
MODELS_DIR = PROJECT_ROOT / "models"                  # trained model saved here

MODEL_PATH = MODELS_DIR / "detector.joblib"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.json"

# ---------------------------------------------------------------------------
# Classification and alert thresholds
# ---------------------------------------------------------------------------
# The model's score answers two separate questions:
#   1. At 50+, does the model lean toward ATTACK rather than BENIGN?
#   2. At 95+, is the result strong enough to raise a high-priority alert?
#
# The alert threshold was raised from the original design doc's 70 to 95 per
# professor feedback, then lowered to 85 on 2026-07-14 after real captured
# traffic failed to cross 95. It only controls alerting; it does not trigger
# an automatic block or network lockdown.
CLASSIFICATION_THRESHOLD = 50
ALERT_THRESHOLD = 85

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
