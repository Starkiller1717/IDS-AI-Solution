# senior-ai — AI for "Countering Malicious Actors with AI"

This is **Madison's AI implementation** for the senior project. It contains the two
AI pieces the design docs assign to the AI Trainer role:

1. **Detector** — reads Suricata flow data, classifies *normal* vs *attack*, and
   gives a **0–100 model risk score**. Scores ≥50 are classified as attack-like;
   scores ≥95 raise a high-priority alert. Alerting does not automatically block
   traffic or lock down the network.
2. **Incident-report generator** — turns an attack event into a plain-language report.

It runs entirely on your laptop. You hand the finished model + `suricata_reader.py`
to Daniel to drop on the router VM, and your output (score + report) feeds Willow's
dashboard. Nothing here touches the project Word documents.

> **What's left to do?** See [Documents/TODO.md](Documents/TODO.md) for the
> check-off-as-you-go list and [../todo-7-4.md](../todo-7-4.md) for the current
> recovery plan.

## Current status — July 4, 2026

- Local Git repository initialized at the Senior Project root; baseline commit:
  `25a12b1`.
- Model classification threshold: 50.
- High-priority alert threshold: 95.
- Template report corrected to require human review and state that no automatic
  blocking or lockdown occurred.
- Test suite: **10 passed**.
- Standalone detector-to-report demo: working.
- Still pending: shared GitHub remote, live Daniel/Suricata integration,
  incident persistence, and Willow's dashboard contract.
- The trained model remains local and is intentionally excluded from regular Git
  because it is approximately 110 MB.

---

## How it fits the team
```
Attacker VM ─► Router VM (Suricata, Daniel) ─eve.json─►  THIS REPO  ─► DB / dashboard (Willow)
                                                         ├─ detector: score 0-100
                                                         └─ reporter: plain-language report
```
Your only "contract" with the rest of the system:
- input: a Suricata `flow` event → `predict()` returns
  `{classification, score, is_alert_triggered}`
- input: an attack event dict → `generate_report()` returns report text

---

## Setup (one time)
```powershell
# from inside senior-ai/
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```
(On Mac/Linux the activate line is `source .venv/bin/activate`.)

---

## Try it RIGHT NOW (no dataset needed)
These two work immediately so you can see the shape of things:
```powershell
# 1) See a Suricata flow turned into model features (mapping demo)
python -m src.detector.suricata_reader --demo

# 2) See a template incident report
python -m src.reporting.report

# 3) Run the tests that don't need a model/dataset
pytest -q
```

---

## Get the dataset (for actually training)
1. Download the **CICIDS2017 "MachineLearningCVE"** CSV files (flow-feature CSVs).
   Search Kaggle for "CICIDS2017 MachineLearningCVE", or use the official CIC /
   University of New Brunswick dataset page.
2. Drop the CSVs (or the whole `MachineLearningCVE` folder) into `data/`.
   See [data/README.md](data/README.md). They're gitignored — don't commit them.

---

## Train the detector
**Learn it step by step:**
```powershell
jupyter notebook
# open notebooks/01_explore.ipynb  then  notebooks/02_train.ipynb
```
**Or just run the script:**
```powershell
python -m src.detector.train
```
This prints accuracy + false-positive rate (design targets: **≥90% accuracy, <5% FP**)
and saves `models/detector.joblib`. After training, the demo in step 1 above will also
print real predictions for the sample flows.

---

## The order to build things (matches the plan)
1. ✅ Scaffolding (this repo) — done.
2. **Sprint 1:** get the dataset → run `01_explore` → `02_train` → hit decent metrics.
3. **Sprint 2:** sit with Daniel, grab a real `eve.json`, confirm the feature mapping in
   `src/detector/suricata_reader.py` matches his Suricata output, retrain if needed.
4. **Sprint 3:** end-to-end attack sims; turn on the Ollama report backend.
5. **Sprint 4:** tune false positives; write up test results (TC-01…TC-10).

---

## The key design idea (read this once)
The detector is trained on **only the features Suricata can produce live**, listed in
[`src/config.py`](src/config.py) as `SURICATA_ALIGNED_FEATURES`. That one list is shared
by training, prediction, and the Suricata reader, so they can never drift apart. If you
change it, update the mapping in `suricata_reader.py:flow_to_features` to match.

---

## Reports: template now, local AI later
`src/reporting/report.py` has `generate_report(event, backend=...)`:
- `backend="template"` (default) — works with zero setup. **Use this first.**
- `backend="ollama"` — local free LLM. Install the Ollama app, run
  `ollama pull llama3.1:8b`, uncomment `ollama` in `requirements.txt`, then pass
  `backend="ollama"`. If Ollama isn't running it automatically falls back to the template.
- Switching to the Claude API later is a third backend with the same signature.

---

## Layout
```
senior-ai/
├─ README.md            ← you are here
├─ requirements.txt
├─ data/                ← CICIDS2017 CSVs (you add) + sample_eve.json
├─ models/              ← trained model lands here
├─ notebooks/           ← 01_explore, 02_train (learn here)
├─ src/
│  ├─ config.py         ← paths + the shared feature list (the important one)
│  ├─ detector/         ← train.py, predict.py, suricata_reader.py
│  └─ reporting/        ← report.py, prompts.py
└─ tests/               ← run with `pytest`
```
