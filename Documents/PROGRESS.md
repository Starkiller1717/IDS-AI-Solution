# AI Component — Progress & Technical Overview

**Author:** Madison  
**Date:** June 8, 2026 (Sprint 1); updated June 25, 2026 (Sprint 2 in progress)  
**Sprint:** 1 complete, 2 in progress

---

## What Has Been Accomplished

### Sprint 1 (complete)

| Task | Status |
|------|--------|
| Project scaffold (source code, tests, config) | Done |
| Python 3.12 virtual environment + all dependencies installed | Done |
| CICIDS2017 dataset (844 MB, 8 CSV files, 2.83M flows) downloaded and placed in `data/` | Done |
| Random Forest classifier trained on full dataset | Done |
| Model accuracy: **99.55%** (target ≥ 90%) | Done |
| False-positive rate: **0.41%** (target < 5%) | Done |
| Trained model saved to `models/detector.joblib` | Done |
| Live scoring verified: `--demo` prints per-flow scores 0–100 | Done |
| Template incident report working | Done |
| Full test suite passing (9 tests) | Done |

### Sprint 2 (in progress, started 2026-06-25)

| Task | Status |
|------|--------|
| Suricata 6.0.4 installed (WSL Ubuntu 22.04) | Done |
| Downloaded a real ~894 MB pcap and ran it through Suricata offline mode (`suricata -r`) → real 54,914-flow `eve.json` | Done |
| Validated `flow_to_features()` field mapping against real Suricata output | Done — exact match, no code changes needed |
| Added `--eve-once` mode to `suricata_reader.py` to score a finished `eve.json` once (the original `--eve` only tails a live, growing file) | Done |
| Scored all 54,914 real flows through the trained model | Done — 0 crossed the (then) 70 threshold; avg score 0.6, max 47 |
| Investigated the result: 53 flows scoring ≥30 all originated from one host (`10.0.0.45`) across 18 distinct external IPs | Done |
| Installed the full ET Open ruleset (`suricata-update`, 66,709 rules) and re-ran for a second, independent signal | Done — Suricata's own signatures also flagged `10.0.0.45` (via an outdated-Flash policy hit, consistent with mid-2015 exploit-kit targeting), though on different destination IPs than the ML model flagged |
| High-priority alert threshold raised from 70 → **95**, per professor feedback; classification remains at **50** | Done (`src/config.py`) |
| Dependency lock file (`requirements-lock.txt`) generated, pinning exact versions (`pandas==3.0.3`, `numpy==2.4.6`, `scikit-learn==1.9.0`, `joblib==1.5.3`) | Done |
| Git version control initialized for the project | **Still pending** |
| Real `eve.json` from Daniel's actual router VM | **Still pending** — the validation above used a self-sourced pcap, not Daniel's live Suricata instance |
| Willow's dashboard/DB contract | **Still pending** |
| `demo.py` added: wires `suricata_reader.handle_flow()` → `report.generate_report()` so the full pipeline runs end-to-end (`python demo.py`) | Done — first proof in the repo that detector and reporter work together, not just independently |

Full investigation writeup: see `audit/CURRENT_STATE.md` (2026-06-25 addendum).

---

## How the System Works

### Big Picture

The detector is one component in a three-person pipeline:

```
Attacker VM
    |
    v
Daniel's Router VM (Suricata)
    |  writes eve.json
    v
Madison's AI Detector  <-- this component
    |  scored attack events
    v
Willow's Dashboard / Database
```

Daniel's Suricata instance monitors all network traffic and writes a line of JSON to `eve.json` for every observed network flow. Madison's component reads those events, scores them with a machine learning model, and passes scored attacks downstream to Willow's dashboard.

---

### The Three Modules

#### 1. Training (`src/detector/train.py`)

Trains the model offline, before deployment. Runs once (or whenever retraining is needed).

1. Loads all 8 CICIDS2017 CSV files from `data/` — 2,830,743 network flow records covering normal traffic and 14 attack types (port scans, DDoS, brute force, web attacks, infiltration, etc.)
2. Strips the label column and collapses every non-BENIGN label into a single "attack" class — this is binary classification (BENIGN vs ATTACK)
3. Drops rows with infinite or missing values in the features we care about (2,867 rows removed)
4. Trains a `RandomForestClassifier` with 100 decision trees, using `class_weight="balanced"` to handle the 4:1 benign-to-attack imbalance
5. Evaluates on a held-out 30% test set, prints accuracy and false-positive rate
6. Saves the trained model to `models/detector.joblib` and the feature list to `models/feature_columns.json`

**Why Random Forest?** It handles mixed feature scales well, is robust to outliers (important for network data), and produces well-calibrated probabilities needed for the 0–100 score. It also surfaces feature importances, which helps explain detections.

#### 2. Prediction (`src/detector/predict.py`)

Scores a single flow at runtime. Called live by `suricata_reader.py` for every flow event.

1. Loads the trained model from disk on first call (cached in memory after that)
2. Validates that all required features are present in the input
3. Builds a feature vector in the exact column order the model was trained on
4. Calls `model.predict_proba()` to get P(attack), scales it to 0–100
5. Returns a dict:

```python
{
    "classification": "attack",   # or "normal"
    "score": 97,                   # 0–100
    "is_alert_triggered": True     # True when score >= 95
}
```

The two decisions are intentionally separate: `config.CLASSIFICATION_THRESHOLD`
is **50**, so scores from 50–100 are labeled `attack`; `config.ALERT_THRESHOLD`
is **95**, so only scores from 95–100 raise a high-priority alert. Alerting does
not automatically block traffic or lock down the network.

#### 3. Suricata Reader (`src/detector/suricata_reader.py`)

The integration layer between Daniel's Suricata output and the ML model.

Suricata writes events in a format like this (simplified):

```json
{
  "event_type": "flow",
  "src_ip": "10.0.0.66",
  "dest_port": 22,
  "proto": "TCP",
  "flow": {
    "pkts_toserver": 120,
    "pkts_toclient": 0,
    "bytes_toserver": 4800,
    "bytes_toclient": 0,
    "start": "2026-06-07T14:32:10.000000+0000",
    "end":   "2026-06-07T14:32:10.001000+0000"
  }
}
```

The `flow_to_features()` function translates this into the 10 CICIDS2017-style features the model expects:

| Model Feature | Derived From |
|--------------|--------------|
| Destination Port | `dest_port` |
| Flow Duration | `end` − `start` (in microseconds) |
| Total Fwd Packets | `pkts_toserver` |
| Total Backward Packets | `pkts_toclient` |
| Total Length of Fwd Packets | `bytes_toserver` |
| Total Length of Bwd Packets | `bytes_toclient` |
| Flow Bytes/s | `(bytes_toserver + bytes_toclient) / duration_s` |
| Flow Packets/s | `(pkts_toserver + pkts_toclient) / duration_s` |
| Fwd Packet Length Mean | `bytes_toserver / pkts_toserver` |
| Bwd Packet Length Mean | `bytes_toclient / pkts_toclient` |

In live mode (`--eve /path/to/eve.json`), the reader tails the file and scores each new flow as Suricata writes it. In one-shot mode (`--eve-once /path/to/eve.json`, added 2026-06-25), it scores every flow in a finished file once and exits — used to validate against a real, offline-mode-generated `eve.json`. High-priority alerts (score ≥ 95) are printed to stdout; this `print()` will be replaced with a database write once Willow's schema is agreed upon.

Note: `tail_eve()`/`handle_flow()` call `predict()` but never `generate_report()` — the detector and the incident reporter are not wired together in this live code path yet. `demo.py` (see below) is the one place in the repo where the full pipeline — flow → score → report — runs end-to-end; that wiring still needs to be promoted into `tail_eve()` once a downstream sink (Willow's DB/JSON contract) exists.

#### 4. Incident Reports (`src/reporting/report.py`)

Generates a plain-language summary of each detected attack, intended for non-technical users.

- **Template backend (default):** fills a pre-written template with the event's IP, score, port, timestamp, and attack type. Zero dependencies, always works.
- **Ollama backend (optional):** sends the event to a locally-running LLM (e.g. `llama3.1:8b`) for higher-quality prose. Falls back silently to the template if Ollama isn't installed or running.

Sample output (template backend):

```
Summary:
We detected port scan on your network and flagged it as a likely attack.

What we saw:
- Coming from IP address: 10.0.0.66 (device hardware ID / MAC: 08:00:27:ab:cd:ef)
- Type of activity: port scan
- Severity score: 92 out of 100
- Targeted port: 22
- Time detected: 2026-06-07T14:32:10

What this means for you:
Someone outside your normal devices was probing or attacking your network. A high
score means we are fairly confident this was not normal traffic.

Recommended actions:
- The system has flagged this source; keep it blocked / in lockdown for now.
- If you don't recognize this activity, leave the lockdown on until it stops.
- Note the time and IP above in case you need to report it to your provider.
```

---

### The Central Design Principle: Feature Alignment

The most important architectural decision is that the model **only trains on features that Suricata can produce live**. This is enforced by a single list in `src/config.py`:

```python
SURICATA_ALIGNED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    ...
]
```

Every module — `train.py`, `predict.py`, and `suricata_reader.py` — imports this list from `config.py`. If a feature is added or removed, it is changed in exactly one place, and all three modules stay in sync automatically. This prevents the most common failure mode in ML systems: a model trained on data that looks different from what it sees at runtime.

---

### Model Performance

Evaluated on a held-out 30% test set (848,363 flows):

| Metric | Result | Target |
|--------|--------|--------|
| Accuracy | 99.55% | ≥ 90% |
| False-positive rate | 0.41% | < 5% |
| Attack recall | 99% | — |
| Attack precision | 98% | — |

**Top features by importance:**

1. Destination Port (21.1%)
2. Bwd Packet Length Mean (20.9%)
3. Total Length of Fwd Packets (13.5%)
4. Fwd Packet Length Mean (11.2%)
5. Total Length of Bwd Packets (11.1%)

Destination port and packet size characteristics together account for over half the model's discriminating power — attacks tend to target specific ports and have asymmetric payload sizes compared to normal browsing or file transfers.

---

## File Structure

```
ai-implementation/
├── demo.py                        # End-to-end pipeline demo: flow → score → report
├── src/
│   ├── config.py                  # Single source of truth: features, paths, threshold
│   ├── detector/
│   │   ├── train.py               # Offline training on CICIDS2017
│   │   ├── predict.py             # Runtime scoring (called per flow)
│   │   └── suricata_reader.py     # Parses eve.json, calls predict, emits alerts
│   └── reporting/
│       ├── report.py              # Incident report generation
│       └── prompts.py             # LLM prompt templates (for Ollama backend)
├── models/
│   ├── detector.joblib            # Trained Random Forest (gitignored)
│   └── feature_columns.json      # Feature list saved alongside model
├── data/
│   ├── MachineLearningCVE/        # CICIDS2017 CSVs (gitignored, ~844 MB)
│   ├── pcaps/                     # Downloaded pcaps for offline Suricata runs (gitignored)
│   ├── suricata-logs/             # Suricata output incl. eve.json (gitignored)
│   └── sample_eve.json            # 4 sample Suricata events for tests/demo
├── tests/
│   ├── test_suricata_reader.py    # Unit tests for flow_to_features()
│   ├── test_report.py             # Unit tests for report generation
│   └── test_predict.py            # Classification vs. alert threshold tests
└── notebooks/
    ├── 01_explore.ipynb           # Data exploration
    └── 02_train.ipynb             # Interactive training and tuning
```

---

## What Comes Next (Sprint 2)

1. ~~**Get a real `eve.json` and verify field names match.**~~ Done 2026-06-25,
   self-sourced (own Suricata install + downloaded pcap) rather than from Daniel —
   exact match, no mapping changes needed. Still want Daniel's actual router VM
   output too, to confirm his specific config matches.
2. **Agree on output format with Willow** — replace the `print()` in `tail_eve()` with a database write or JSON file that Willow's dashboard can consume. **Still pending.**
3. **End-to-end test** — Daniel's Attacker VM runs an Nmap scan, it appears on Willow's dashboard with a score and a report. **Still pending** — requires both items above.
4. **Initialize git version control for this project.** **Still pending** — currently the single biggest risk to this work (no commit history, no recovery if something is overwritten).
