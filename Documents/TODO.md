# TODO — AI training & implementation checklist

A plain "what needs to be done" list for Madison (AI Trainer). Check items off as
you go. Things already built by the scaffold are checked. Order matters top-to-bottom.

> Quick mental model: **Part A** = teach the model to spot attacks (offline, on your
> laptop). **Part B** = plug that model into the live system (with Daniel & Willow).
> **Part C** = the incident-report writer. Do A first, it's the heart of your role.

---

## 0. Setup (do once)
- [x] Project scaffold, code, tests created (`senior-ai/`)
- [x] `python -m venv .venv` and activate it
- [x] `pip install -r requirements.txt`
- [x] Confirm it runs: `python -m src.detector.suricata_reader --demo` and `pytest -q`
- [x] Initialize local Git at the Senior Project root and preserve baseline commit
      `25a12b1`
- [ ] Create the shared GitHub remote, add collaborators, and push `main`

## Part A — Train the detector (your main deliverable)
- [x] **Download CICIDS2017** MachineLearningCVE CSVs into `data/` (see `data/README.md`)
- [ ] Run `notebooks/01_explore.ipynb` — look at attack types & class imbalance
- [ ] Run `notebooks/02_train.ipynb` — train your first Random Forest, see the metrics
- [x] Read the metrics honestly: is **accuracy ≥ 90%** and **false-positive rate < 5%**? → **99.55% accuracy, 0.41% FPR**
- [x] If not good enough: tune (try more trees, try XGBoost, adjust the score threshold) — not needed
- [x] Save the model (`python -m src.detector.train` writes `models/detector.joblib`)
- [x] Confirm scoring works: `python -m src.detector.suricata_reader --demo` now prints scores
- [x] Separate binary classification (score ≥50) from high-priority alerting
      (score ≥95)
- [x] Rename prediction alert output to `is_alert_triggered`

## Part B — Integration (with the team)
- [x] Get a **real `eve.json` sample** — 2026-06-25: self-sourced rather than from
      Daniel. Installed Suricata 6.0.4 in WSL, downloaded a real ~894 MB pcap, ran
      it offline (`suricata -r`) to produce a real 54,914-flow `eve.json`. Daniel's
      actual router VM output is still untested — get his real sample too when available.
- [x] Open it and check: do the `flow` events contain the fields
      `flow_to_features()` expects? (pkts/bytes to server/client, start/end)
      → **Confirmed 2026-06-25: exact match, every field present, no surprises.**
- [x] Fix the mapping in `src/detector/suricata_reader.py` if Suricata's fields differ
      → **Not needed — mapping was already correct against real output.**
- [x] **Retrain** on only the features that survive — **not needed**, nothing was dropped.
- [x] Test live: `python -m src.detector.suricata_reader --eve-once <path to eve.json>`
      (note: use `--eve-once` for a finished file, not `--eve` — that flag is for
      tailing a live, growing file and added 2026-06-25 specifically for this gap)
- [x] Wire the detector to the reporter so a flagged attack actually produces a report
      → done via `demo.py` (`python demo.py`) — proves `handle_flow()` → `generate_report()`
      end-to-end. Still **not** promoted into `tail_eve()` itself (next item).
- [ ] Agree with **Willow** on where scored attacks get written (DB table / JSON shape)
      and replace the `print()` in `tail_eve()` with that write (and promote the
      `demo.py` report-generation wiring into `tail_eve()` at the same time)
- [ ] End-to-end: Daniel's Attacker VM runs an Nmap scan → confirm it scores ≥ 95
      (threshold raised from 70 on 2026-06-25 per professor feedback)

## Part C — Incident reports
- [x] Template report works today (`python -m src.reporting.report`)
- [x] Correct template wording: human review, no automatic blocking/lockdown claims,
      and omit missing MAC addresses
- [x] Decide current report backend: ship the deterministic template; Ollama remains
      an optional future enhancement
- [ ] (Optional) Install Ollama app, `ollama pull llama3.1:8b`, uncomment `ollama` in
      `requirements.txt`, call `generate_report(event, backend="ollama")`
- [ ] Promote report generation into the live `tail_eve()` path

## Part D — Validate & document (Sprint 4)
- [x] Validate false positives against the held-out dataset: 0.41% at the model
      classification boundary and 0.15% at the high-priority alert threshold
- [ ] Write up results for test cases TC-01, TC-02, TC-03, TC-07, TC-10
- [ ] Add a short "AI model" section to the team's final report / design doc
- [ ] Hand Daniel: `models/detector.joblib`, `models/feature_columns.json`,
      and the `src/detector/` files to deploy on the router VM

---

## Definition of done (what "finished" looks like)
1. A trained model that hits ≥90% accuracy / <5% false positives on held-out test data.
2. `suricata_reader.py` reads Daniel's live `eve.json` and writes scored attacks where
   Willow's dashboard can read them.
3. Each detected attack produces a readable incident report.
4. An Nmap scan from the Attacker VM, end-to-end, shows up on the dashboard with a score
   and a report.

## Mapped to the sprints
- **Sprint 1:** Part A (train offline, good metrics) + template report
- **Sprint 2:** Part B (Suricata feature alignment + live scoring + DB hand-off)
- **Sprint 3:** end-to-end attack sims; turn on Ollama reports
- **Sprint 4:** Part D (tuning, test-case write-ups, deploy hand-off)
