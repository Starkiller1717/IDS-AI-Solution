# AI Detector — Technical Reference

---

## 1. What This Component Does

This component is a network intrusion detector. It does two things:

1. **Classifies network traffic** as `normal` or `attack` and assigns a severity
   score from 0–100.
2. **Generates a plain-language incident report** for any traffic flagged as an
   attack, so a non-technical user can understand what was detected.

It is designed to sit downstream of a network monitoring tool (Suricata), reading
the flow records Suricata produces and scoring each one in real time.

```
Network traffic → Suricata (produces flow records) → THIS COMPONENT → score + report
```

**Current status (July 4, 2026):** The trained model, standalone demo, template
report, standalone JSON Lines incident writer, and 16 automated tests work.
Classification uses score 50 and high-priority alerting uses score 95. Local Git
baseline `25a12b1` exists. Connecting reports and incident persistence to the live
tail, shared GitHub, and teammate integrations are not complete.

---

## 2. Requirements

- **Python 3.12**
- Python packages (see `requirements.txt`):
  - `pandas`, `numpy` — data loading and manipulation
  - `scikit-learn` — the Random Forest model, training/evaluation utilities
  - `joblib` — saving/loading the trained model to/from disk
  - `matplotlib`, `seaborn` — plotting in the notebooks
  - `jupyter` — for the interactive exploration/training notebooks
  - `pytest` — running the automated test suite
  - `ollama` (optional, commented out by default) — only needed if using the
    local-LLM report backend instead of the template backend
- **CICIDS2017 dataset** (only needed to train or retrain a model — not needed to
  run an already-trained model). Specifically the "MachineLearningCVE" flow-feature
  CSV files.
- A Suricata `eve.json` log file (only needed for live scoring against real
  traffic — a sample file is included for demos/tests).

### Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## 3. How Training Works

Training is handled by `src/detector/train.py` and is run offline, separately
from live scoring. The process:

1. **Load** — every CSV file under `data/` is read and concatenated into one
   table. Column names are stripped of stray whitespace (a quirk of the raw
   CICIDS2017 files).
2. **Clean** — infinite and missing values are replaced/dropped. Only rows with
   valid values in the features actually used for training are kept; everything
   else is discarded.
3. **Select features** — rather than using all ~80 columns CICIDS2017 provides,
   training uses only the 10 features listed in `SURICATA_ALIGNED_FEATURES`
   (`src/config.py`):

   | Feature | What it represents |
   |---|---|
   | Destination Port | Port the flow was directed at |
   | Flow Duration | How long the flow lasted |
   | Total Fwd Packets | Packets sent from source to destination |
   | Total Backward Packets | Packets sent from destination to source |
   | Total Length of Fwd Packets | Bytes sent from source to destination |
   | Total Length of Bwd Packets | Bytes sent from destination to source |
   | Flow Bytes/s | Byte throughput of the flow |
   | Flow Packets/s | Packet throughput of the flow |
   | Fwd Packet Length Mean | Average forward packet size |
   | Bwd Packet Length Mean | Average backward packet size |

   This is the central design decision of the whole system: the model is only
   ever trained on data it could realistically reconstruct from a live Suricata
   flow event. This keeps training and live inference consistent — a model
   trained on rich features it can't get live would be useless at runtime.

4. **Label the target** — every row's label is collapsed to a binary target:
   `BENIGN` → `0`, anything else (any attack type) → `1`. This makes it a binary
   classification problem (attack vs. not), rather than trying to name the
   specific attack type.
5. **Split** — the data is split 70% train / 30% test, stratified so both splits
   keep the same benign/attack ratio. The test set is never seen during training
   and is used only to measure how well the model generalizes.
6. **Train** — a `RandomForestClassifier` (100 decision trees) is fit on the
   training split. `class_weight="balanced"` compensates for benign traffic
   heavily outnumbering attack traffic in the dataset.
7. **Evaluate** — accuracy, false-positive rate, precision/recall, and a
   confusion matrix are printed against the held-out test split.
8. **Save** — the trained model is written to `models/detector.joblib`, and the
   exact feature list/order it was trained on is saved to
   `models/feature_columns.json` so prediction code can reproduce it exactly.

### Why Random Forest

A Random Forest was chosen because it: handles features on very different
scales (ports vs. byte counts vs. durations) without needing manual
normalization, is robust to outliers (common in raw network data), produces
probability estimates suitable for a 0–100 score, and exposes feature
importances that make detections explainable rather than a black box.

### Running training

```powershell
python -m src.detector.train
```

Or step through it interactively:

```powershell
jupyter notebook
# open notebooks/01_explore.ipynb, then notebooks/02_train.ipynb
```

---

## 4. How Prediction (Live Scoring) Works

Handled by `src/detector/predict.py`. Given a single flow's feature values:

1. The trained model is loaded from `models/detector.joblib` (cached in memory
   after the first call).
2. The input is checked to make sure all required features are present.
3. A feature vector is built in the exact column order recorded in
   `feature_columns.json`.
4. `model.predict_proba()` returns the probability the flow is an attack; this
   is scaled to a 0–100 score.
5. A result dictionary is returned:

```python
{
    "classification": "attack",   # or "normal"
    "score": 97,                   # 0-100
    "is_alert_triggered": True     # True when score >= ALERT_THRESHOLD
}
```

`CLASSIFICATION_THRESHOLD` is `50`: scores from 50–100 receive the `attack`
label. `ALERT_THRESHOLD` is `95`: scores from 95–100 raise a high-priority
alert. The alert threshold was raised from the original design-doc value of
`70` on 2026-06-25 per professor feedback. Alerts do not automatically block
traffic or lock down the network.

---

## 5. How Suricata Integration Works

Handled by `src/detector/suricata_reader.py`. Suricata writes one JSON line per
event to `eve.json`. For `flow`-type events, the function `flow_to_features()`
translates Suricata's field names into the model's feature names:

| Model Feature | Derived From |
|---|---|
| Destination Port | `dest_port` |
| Flow Duration | `flow.end − flow.start` |
| Total Fwd Packets | `flow.pkts_toserver` |
| Total Backward Packets | `flow.pkts_toclient` |
| Total Length of Fwd Packets | `flow.bytes_toserver` |
| Total Length of Bwd Packets | `flow.bytes_toclient` |
| Flow Bytes/s | `(bytes_toserver + bytes_toclient) / duration_seconds` |
| Flow Packets/s | `(pkts_toserver + pkts_toclient) / duration_seconds` |
| Fwd Packet Length Mean | `bytes_toserver / pkts_toserver` |
| Bwd Packet Length Mean | `bytes_toclient / pkts_toclient` |

Division-by-zero cases (e.g., a flow with zero packets in one direction) are
handled safely and default to `0`.

Two ways to run it:

```powershell
# Demo mode — shows the feature mapping and scores for built-in sample events
python -m src.detector.suricata_reader --demo

# Live mode — tails a real, growing eve.json file and scores each new flow as it appears
python -m src.detector.suricata_reader --eve <path-to-eve.json>

# One-shot mode — scores every flow in a FINISHED eve.json once and exits
# (e.g. output from offline `suricata -r file.pcap`). Added 2026-06-25 because
# --eve's tailing behavior seeks to end-of-file and never reads a static file.
python -m src.detector.suricata_reader --eve-once <path-to-eve.json>
```

In live/one-shot mode, flows scoring at or above the alert threshold are
surfaced for downstream handling (e.g., writing to a database or notifying a
dashboard).

**Real-world validation (2026-06-25):** ran a real ~894 MB pcap through an
actual Suricata 6.0.4 install (offline mode, `suricata -r`), producing a real
54,914-line `eve.json`. `flow_to_features()`'s field mapping matched Suricata's
real output exactly — no code changes were needed. None of the 54,914 flows
crossed the (then) 70 threshold (max score 47), but 53 flows scoring ≥30 all
originated from the same single host, which Suricata's own ET Open signature
engine also independently flagged (via an outdated-Flash policy hit) — two
independent detection methods converging on the same host using different
evidence. See `audit/CURRENT_STATE.md` for the full writeup.

---

## 6. How Incident Reports Work

Handled by `src/reporting/report.py`. Given a scored event,
`generate_report()` produces a short, plain-language summary intended for a
non-technical reader: what was detected, the source and destination details,
the model risk score, and recommended human-review steps. It explicitly states
that no automatic blocking or network lockdown occurred.

Two backends, selected via the `backend` argument:

- **`"template"` (default)** — fills a pre-written template with the event's
  details. No external dependencies; always works.
- **`"ollama"` (optional)** — sends the event to a locally running LLM (e.g.
  `llama3.1:8b` via [Ollama](https://ollama.ai)) for more natural prose. Falls
  back silently to the template backend if Ollama is not installed or not
  running.

```powershell
# Template report demo
python -m src.reporting.report
```

To use the Ollama backend: install the Ollama app, run `ollama pull llama3.1:8b`,
uncomment `ollama` in `requirements.txt` and reinstall, then call
`generate_report(event, backend="ollama")`. Prompt wording for this backend
lives in `src/reporting/prompts.py`.

Incident persistence is handled separately by
`src/reporting/incident_writer.py`. `append_incident(incident)` creates the
destination directory when needed and appends exactly one UTF-8 JSON object per
line to `output/incidents.jsonl`. The writer preserves prior records and returns
the path it wrote. It is not yet connected to live processing or report generation.

```python
from src.reporting.incident_writer import append_incident

path = append_incident({"score": 97, "report": "Review this incident."})
```

---

## 7. How to Use This Component

**To train or retrain a model:**
1. Place CICIDS2017 "MachineLearningCVE" CSV files in `data/`.
2. Run `python -m src.detector.train`.
3. A new `models/detector.joblib` and `models/feature_columns.json` are produced.

**To score traffic:**
- For a quick check with sample data: `python -m src.detector.suricata_reader --demo`
- Against a real Suricata log: `python -m src.detector.suricata_reader --eve <path>`
- Programmatically, from another Python module:

```python
from src.detector.predict import predict

result = predict(feature_dict)  # feature_dict has the 10 SURICATA_ALIGNED_FEATURES
print(result)  # {"classification": ..., "score": ..., "is_alert_triggered": ...}
```

**To generate a report for a detected attack:**

```python
from src.reporting.report import generate_report

report_text = generate_report(event)  # event includes flow info + score/classification
print(report_text)
```

**To run the automated tests** (no dataset or trained model required):

```powershell
pytest -q
```

---

## 8. Key Files

| File | Purpose |
|---|---|
| `src/config.py` | Single source of truth: feature list, file paths, classification/alert thresholds, label conventions |
| `src/detector/train.py` | Offline training on CICIDS2017 |
| `src/detector/predict.py` | Runtime scoring of a single flow |
| `src/detector/suricata_reader.py` | Parses `eve.json`, maps fields to model features, calls predict |
| `src/reporting/incident_writer.py` | Standalone append-only JSON Lines incident persistence |
| `src/reporting/report.py` | Incident report generation (template/Ollama backends) |
| `src/reporting/prompts.py` | Prompt templates for the Ollama report backend |
| `models/detector.joblib` | Trained model artifact (not committed to source control) |
| `models/feature_columns.json` | Exact feature list/order the saved model expects |
| `data/sample_eve.json` | Sample Suricata events for demos and tests |
| `notebooks/01_explore.ipynb` | Interactive data exploration |
| `notebooks/02_train.ipynb` | Interactive model training and tuning |
