# PROJECT_STATUS.md

> **Historical component table (June 22–25). Current status as of July 4:**
> local Git baseline `25a12b1` exists; classification starts at 50 and
> high-priority alerting at 95; prediction output uses `is_alert_triggered`;
> report safety wording is corrected; and 10 tests pass. Shared GitHub, live
> report persistence, Daniel integration, and Willow integration remain pending.
> Rows below are preserved as evidence of the earlier state.

Component inventory. "Evidence" cites a specific file, test, or command actually
run during this audit — not a doc claim. "Confidence" reflects how sure this audit
is in the Status given that evidence.

> **Addendum, 2026-06-25:** the table below is the 2026-06-22 snapshot, left as-is for
> the historical record. Two rows have materially changed since — see
> `CURRENT_STATE.md`'s 2026-06-25 addendum for full detail:
> - **Suricata flow→feature mapping:** was "Partial — only tested against hand-written
>   sample JSON, never a real Suricata capture." Now **validated against real Suricata
>   6.0.4 output** (offline `suricata -r` on a real ~894 MB pcap, 54,914 real flow
>   events) — exact field match, no changes needed.
> - **PCAP ingestion:** was "Missing — zero references to pcap anywhere in `src/`."
>   Now exercised end-to-end via Suricata's offline mode + a new `--eve-once` one-shot
>   scoring mode added to `suricata_reader.py`.
> - `RESPONSE_THRESHOLD` also changed, 70 → 95, per professor feedback (unrelated to the
>   two items above — a tuning decision, not a bug fix).
> - Still unchanged: no version control, no Daniel/Willow integration.

| Component | Status | Evidence | Confidence | Next Step |
|---|---|---|---|---|
| `src/config.py` (feature list, paths, threshold) | Working | Imported successfully by every other module; all tests pass against it | High | None |
| Training pipeline (`src/detector/train.py`) | Working | `models/detector.joblib` + `feature_columns.json` exist on disk (dated 2026-06-16); script logic reviewed and matches the saved feature list exactly | Medium-High (artifacts exist; exact 99.55%/0.41% metrics not re-run today) | Re-run `python -m src.detector.train` to reproduce metrics fresh and timestamp the confirmation |
| Prediction (`src/detector/predict.py`) | Working | Ran `python -m src.detector.predict` today — valid output. Also scored a real CICIDS2017 PortScan attack row pulled directly from the CSV → `score=100, is_response_triggered=True` | High | None |
| Suricata flow→feature mapping (`suricata_reader.flow_to_features`) | Partial | `python -m src.detector.suricata_reader --demo` runs correctly; `tests/test_suricata_reader.py` (3 tests) pass | Medium — only tested against hand-written sample JSON, never a real Suricata capture | Get a real `eve.json` sample from Daniel; diff field names against what the function expects |
| Live tailing (`suricata_reader.tail_eve`) | Partial | Code reviewed: follows file, parses JSON, calls `predict()`. Never run against a real file (no Suricata installed here) | Medium | Test against a real or synthetic growing `eve.json`; needs a downstream sink (see below) |
| Detector ↔ Reporter wiring | Missing (until this audit) | Grep of `src/` confirms `tail_eve()`/`handle_flow()` never call `generate_report()` — the two modules were never connected in `src/` | High | `demo.py` (added by this audit) is the first working wire-up; promote that logic into `tail_eve()` once a sink exists |
| Incident report — template backend (`report.py`) | Working | `python -m src.reporting.report` runs; `tests/test_report.py` (2 tests) pass | High | None — ship this for the demo |
| Incident report — Ollama backend | Missing/Unbuilt | `ollama` package commented out in `requirements.txt`; not installed in `.venv`; no evidence the code path has ever executed | High (that it's unverified) | Decide if needed for the capstone demo at all; template already satisfies the contract |
| Incident report — Claude API backend | Missing | Mentioned only as a one-line "future" comment in `report.py` | High | Out of scope unless explicitly requested |
| Test suite | Working | `pytest -q` → **5 passed**, 0.04s, no dataset/model required | High | None |
| `notebooks/01_explore.ipynb` | Partial | Has cached outputs through ~5 of 9 cells (was executed at some point, not confirmed current) | Medium | Re-run top to bottom before using in a presentation |
| `notebooks/02_train.ipynb` | Unknown | Every cell shows `execution_count: null`, zero cached output — never executed in this environment | Low confidence it currently runs cleanly (logic mirrors `train.py`, which does work, but the notebook itself is unverified) | Run it once, end to end, before relying on it for a live demo |
| Daniel integration (Suricata router VM) | Missing | No real `eve.json` anywhere in the repo; TODO.md explicitly lists this as not done | High | Request a real `eve.json` sample this week |
| Willow integration (dashboard/DB) | Missing | No DB client, API client, or queue code anywhere in `src/` (grep confirmed); only a `print()` placeholder exists | High | Get the dashboard's expected schema/endpoint from Willow; this is the actual blocker, not code effort |
| PCAP ingestion | Missing | Zero references to "pcap" anywhere in `src/` (grep confirmed) | High | Decide: pipe PCAPs through Suricata offline mode (`suricata -r file.pcap`) to produce `eve.json`, vs. building a dedicated PCAP reader |
| Version control (git) | Missing | No `.git` directory anywhere in the project tree | High | `git init` this repo immediately — see AUDIT_SUMMARY.md |
| `.gitignore` correctness | Partial | Covers `data/*.csv` and `data/MachineLearningCVE/`, but not `data/zips/MachineLearningCSV.zip` or `data/GeneratedLabelledFlows.zip` (~520 MB) | High | Update before first `git add` (see recommended `.gitignore` below) |
| Dependency pinning | Partial | `requirements.txt` has only `>=` floors; installed versions (`pandas==3.0.3`, `scikit-learn==1.9.0`, `numpy==2.4.6`) are well above them, with no lock file | High | Generate a pinned `requirements-lock.txt` from the working `.venv` |
| Top-level demo entrypoint (`demo.py`) | Working (new) | Written and run during this audit: `python demo.py` → maps 4 flows, scores them, and produces 1 triggered alert + full incident report | High | Promote into the README's quickstart section |

## Recommended `.gitignore` additions

The existing `.gitignore` is otherwise reasonable. Add:

```gitignore
# Source dataset zips (redundant once extracted into data/MachineLearningCVE/)
data/zips/
data/GeneratedLabelledFlows.zip

# Jupyter
.ipynb_checkpoints/

# Python tooling caches
.pytest_cache/
__pycache__/
*.pyc
```

(`.ipynb_checkpoints/` and `.pytest_cache/` are already present in the current
file — listed here only for completeness of the recommended block; the two new
lines are the actual gap.)
