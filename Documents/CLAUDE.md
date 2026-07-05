# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cybersecurity threat detection system for a multi-VM lab network. This component (Madison's) trains a Random Forest classifier on CICIDS2017 network flow data, scores live Suricata EVE JSON flows, and generates incident reports. It connects to Daniel's Suricata router VM (upstream) and Willow's dashboard/database (downstream).

**Current status (2026-07-04):** Local Git baseline `25a12b1` exists at the
Senior Project root. Classification begins at score 50; high-priority alerting
begins at 95. Template report wording has been corrected to require human review
and state that no automatic blocking occurred. A standalone JSON Lines incident
writer and shared post-scoring incident builder are connected to live mode. The
test suite has 21 passing tests. Shared GitHub, Daniel integration, Willow's
dashboard contract, and controlled live-attack validation remain pending.

## Commands

**Setup (one-time):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
For an exact reproduction of the environment that trained/validated the current
model (not just the loose `>=` floors in `requirements.txt`), use
`pip install -r requirements-lock.txt` instead — generated 2026-06-25 via
`pip freeze | Set-Content -Encoding utf8 requirements-lock.txt` (note: plain
`pip freeze > requirements-lock.txt` in Windows PowerShell writes UTF-16 and
breaks the file — use `Set-Content -Encoding utf8`, not `>`).

**Run tests:**
```powershell
pytest -q                          # all tests (no dataset/model needed)
pytest tests/test_suricata_reader.py  # single test file
```

**Quick demos (no dataset/model required):**
```powershell
python -m src.detector.suricata_reader --demo   # Suricata flow → feature mapping
python -m src.reporting.report                  # template incident report
python demo.py                                  # full pipeline: flow → score → report, end-to-end
```

**Full workflow (requires CICIDS2017 dataset in `data/`):**
```powershell
python -m src.detector.train                    # train model → models/
python -m src.detector.suricata_reader --eve <path>       # tail a LIVE, growing eve.json
python -m src.detector.suricata_reader --eve-once <path>  # score a FINISHED eve.json once and exit
jupyter notebook                                # open 01_explore.ipynb or 02_train.ipynb
```

## Architecture

**Three modules in `src/`:**

- `detector/train.py` — Loads CICIDS2017 CSVs, trains Random Forest (binary: BENIGN vs ATTACK), saves model to `models/`
- `detector/predict.py` — Loads trained model, scores a single flow dict, returns `{classification, score, is_alert_triggered}`
- `detector/suricata_reader.py` — Parses Suricata EVE JSON, maps flow fields → model features via `flow_to_features()`, calls predict. Validated 2026-06-25 against real Suricata 6.0.4 output (offline `suricata -r` run on a downloaded pcap, 54,914 real flow events) — field names matched exactly, no mapping changes needed. Supports `--eve` (live tail) and `--eve-once` (score a finished file once, added 2026-06-25 for offline-mode testing).
- `reporting/incidents.py` — Builds one versioned incident schema and template report after scoring; shared by demo, live, and one-shot modes.
- `reporting/incident_writer.py` — Append-only UTF-8 JSON Lines persistence; live mode writes high-priority incidents to `output/incidents.jsonl`.
- `reporting/report.py` — Generates incident reports; template backend works offline, optional Ollama backend for higher quality
- `reporting/prompts.py` — System/user prompt templates for the Ollama LLM backend
- `config.py` — **Single source of truth** for everything shared: feature list, file paths, classification threshold (50), high-priority alert threshold (95), and benign label

**Central design principle:** `SURICATA_ALIGNED_FEATURES` in `config.py` is the one list used by training, prediction, and Suricata parsing. The model only trains on features Suricata can produce live — this prevents train/production feature drift.

**Data flow:**
```
Attacker VM → Router VM (Suricata/Daniel) → eve.json
  → suricata_reader.py (flow_to_features)
    → predict.py (score 0–100, classify at 50, alert at 95)
      → report.py (incident text)
        → incidents.py (shared structured incident)
          → incident_writer.py (live JSON Lines fallback)
          → Willow's dashboard/database
```

**Score output:** `P(attack) × 100`. Scores ≥50 receive the `attack`
classification. Scores ≥95 set `is_alert_triggered = True` and raise a
high-priority alert. No automatic blocking or network lockdown is performed.

**Report backends:** Template (always works) → Ollama (optional, falls back to template on failure) → Claude API (future).

## Key Files

- `demo.py` — Exercises the shared flow → prediction → incident → report path
  without writing repository output files
- `src/config.py` — Change features, thresholds, or paths here; everything else picks them up
- `src/reporting/incidents.py` — Builds the common post-scoring incident payload
- `src/reporting/incident_writer.py` — Appends one JSON-serializable incident per
  line without overwriting existing records
- `data/sample_eve.json` — 4 sample Suricata events for demos and tests (not training data)
- `data/` — CICIDS2017 MachineLearningCVE CSVs go here (gitignored; see `data/README.md` for download)
- `models/` — Trained model artifacts (gitignored)
- `notebooks/01_explore.ipynb` — Data exploration
- `notebooks/02_train.ipynb` — Model training and hyperparameter tuning

## Testing

Tests in `tests/` require no trained model or dataset:
- `test_suricata_reader.py` — validates `flow_to_features()` output (required fields, values, division-by-zero safety)
- `test_report.py` — validates incident facts, missing-field behavior, and
  containment-safety wording
- `test_predict.py` — validates that classification starts at 50 while
  high-priority alerting starts at 95
- `test_incident_writer.py` — validates parent-directory creation, append
  behavior, and valid JSON Lines with Unicode and embedded newlines
- `test_incident_pipeline.py` — validates shared incident construction,
  template-report inclusion, missing optional fields, and live persistence

## Dependencies

Python 3.12. Key packages: `pandas`, `numpy`, `scikit-learn`, `joblib`, `matplotlib`, `seaborn`, `jupyter`, `pytest`. Ollama is optional (commented out in `requirements.txt`).
