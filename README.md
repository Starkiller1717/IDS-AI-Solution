# AI-IDS: ML-Assisted Network Intrusion Detection

A three-VM lab network intrusion detection system. Suricata monitors traffic on
a VM, a Random Forest classifier scores each flow for attack likelihood,
and detected incidents (ML-flagged or Suricata-signature-flagged) are written
out, shipped through Loki, and visualized in Grafana.

This repo holds the ML detection + incident reporting component (`ai-implementation/`)
plus the observability stack config (`promtail.yaml`, `loki-config.yaml`,
`ai_incidents_dashboard.json`) that ships its output to a dashboard.

## Architecture

```
Attacker VM
   │
   ▼
(Suricata) ──writes──▶ eve.json
   │
   ▼
suricata_reader.py   (flow → 10 features; correlates alert signatures by flow_id)
   │
   ▼
predict.py            P(attack) via Random Forest
                       classify @ 0.50, high-priority alert @ 0.85
   │
   ▼
incidents.py           builds one incident when EITHER the ML threshold is
                        crossed OR a Suricata signature is correlated (hybrid
                        detection — a single-flow classifier alone can't see
                        multi-flow patterns like a port scan)
   │
   ▼
report.py              human-readable report (Ollama LLM, falls back to a
                        deterministic template if Ollama isn't available)
   │
   ▼
incident_writer.py  ──▶ output/incidents.jsonl
   │
   ▼
Promtail ──▶ Loki ──▶ Grafana dashboard (ai_incidents_dashboard.json)
```

Verified end-to-end on real infrastructure: a live `nmap -sS -T4` scan against
the Suricata VM produced a real incident that flowed through the full pipeline
above and rendered on the imported Grafana dashboard.

## Repo layout

```
ai-implementation/        # detection + reporting component (this is what you build/test)
  src/
    config.py              single source of truth: features, paths, thresholds
    detector/               train.py, predict.py, suricata_reader.py
    reporting/              incidents.py, incident_writer.py, report.py, prompts.py
    smoke_test.py           portability check — run this after any fresh checkout
  tests/                    75 tests, no dataset or trained model required
  models/                   trained model artifact (gitignored — see Setup)
  data/                     CICIDS2017 training CSVs go here (gitignored)
  suricata_rules/           custom Suricata rule powering hybrid detection
  scripts/package_artifacts.py   builds + CRC-verifies a model handoff zip
  demo.py                    flow → score → incident → report, no repo writes

promtail.yaml, loki-config.yaml     log shipping config for the observability VM
ai_incidents_dashboard.json         Grafana dashboard (import via ${DS_LOKI})
```

## Setup

```bash
cd ai-implementation
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements-lock.txt
```

The trained model is **not in git** (it's ~110 MB). Get it from a packaged
handoff zip (`scripts/package_artifacts.py` builds one) and unzip into `models/`,
or train your own — see [Training](#training) below.

Then verify the checkout actually works:

```bash
python -m src.smoke_test   # loads the real model, scores 2 known flows, exits 0/1
pytest -q                  # 75 tests, no model or dataset needed
```

`smoke_test.py` is the real portability gate — a green `pytest` run does **not**
imply the model loads correctly on this machine; `smoke_test` is what confirms
that.

## Quick demos (no dataset or model required)

```bash
python -m src.detector.suricata_reader --demo   # Suricata flow → feature mapping
python -m src.reporting.report                  # template incident report
python demo.py                                  # full pipeline, end-to-end
```

## Training

Requires the CICIDS2017 `MachineLearningCVE` CSVs in `data/` (see `data/README.md`).

```bash
python -m src.detector.train
```

Writes `models/detector.joblib`, `models/feature_columns.json`, and
`models/metadata.json` (model version, build date, feature list, thresholds,
and the exact package versions used — so anyone downstream can tell whether
their environment matches what trained the model).

Current model: Random Forest, 10 Suricata-derivable features, 99.55% accuracy /
0.41% false-positive rate at the classification threshold (0.26% FPR at the
high-priority alert threshold).

## Running against live Suricata output

```bash
python -m src.detector.suricata_reader --eve <path>       # tail a live, growing eve.json
python -m src.detector.suricata_reader --eve-once <path>  # score a finished eve.json once
```

Deploy targets can set `MODEL_PATH`, `EVE_PATH`, `INCIDENTS_PATH`,
`REPORT_BACKEND`, and `OLLAMA_HOST` via environment variables instead of CLI
flags or edited source — see `.env.example`.

## Log shipping / dashboard

1. Point `promtail.yaml`'s `ai_incidents` job at the real `output/incidents.jsonl`
   path on the deploy machine (replace `<PATH_TO_PROJECT_ROOT>`), and its
   `clients.url` at the Loki host (replace `<YOUR_LOKI_HOST_IP>`).
2. Run Loki with `loki-config.yaml`.
3. Add Loki as a Grafana data source and import `ai_incidents_dashboard.json`.

## Future Work
Future work would include:
- Training the model on additional data to catch a wider range of attacks
- Packaging project components to easily reproduce the environment
- Hardening the pipeline reading the eve.json file to prevent errors while reading eve.json
- Creating additional dashboards that are easier to read and understand
- Alert generation for users to learn when suspicious activity is occuring

## Lessons Learned
Components built in isolation is not the same
as a finished end to end integration. For future projects,
there should be more collaboration for integrating components, and integration should begin as soon as possible in development. 

Reproducability and packaging components also proved to be challenging through the duration of this project. Future projects should prioritize packaging components early to verify program functionality and reproducability on various machines. 


