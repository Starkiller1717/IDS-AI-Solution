# ARCHITECTURE.md

> **Historical audit snapshot (June 22–25). Current status as of July 4:**
> local Git baseline `25a12b1` exists; classification starts at 50 and
> high-priority alerting at 95; prediction output uses `is_alert_triggered`;
> report safety wording is corrected; and 10 tests pass. Shared GitHub, live
> report persistence, Daniel integration, and Willow integration remain pending.
> See `../Documents/PROGRESS.md` and `../../todo-7-4.md` for current status.

## Current architecture (what is actually built)

A single Python package (`src/`) with three independent, individually-tested
pieces. There is no server process, no database, no message queue, and no
network listener anywhere in this codebase — everything runs as a one-shot CLI
invocation or a foreground file-tail loop.

```
                         ┌─────────────────────────────┐
                         │   data/MachineLearningCVE/   │
                         │   *.csv  (CICIDS2017, local) │
                         └──────────────┬──────────────┘
                                        │  python -m src.detector.train
                                        ▼
                         ┌─────────────────────────────┐
                         │   models/detector.joblib     │
                         │   models/feature_columns.json│
                         └──────────────┬──────────────┘
                                        │  loaded by predict._load_model()
                                        ▼
  data/sample_eve.json   ┌─────────────────────────────┐
  (or a real eve.json) ──►  suricata_reader.py          │
  [event_type=="flow"]   │  flow_to_features()           │
                         │       │                        │
                         │       ▼                        │
                         │  predict.predict()             │──► {classification, score,
                         │       │                        │     is_response_triggered}
                         └───────┼────────────────────────┘
                                 │
                                 ▼
                         ┌─────────────────────────────┐
                         │  tail_eve(): print() ONLY     │   <-- dead end today
                         └─────────────────────────────┘

  (separately, never called by the above)
                         ┌─────────────────────────────┐
  event dict  ──────────►│  report.generate_report()    │──► incident report (str)
                         │  template / ollama backend    │
                         └─────────────────────────────┘
```

**The one thing this diagram makes obvious that prose doesn't:** the detector
path and the reporter path are two separate trees that never merge in `src/`.
`demo.py` (added by this audit) is the first piece of code in the repo that
calls both in sequence.

## Intended architecture (per CLAUDE.md / README.md / PROGRESS.md)

```
┌───────────────┐      ┌──────────────────────┐      ┌─────────────────────────┐      ┌──────────────────┐
│  Attacker VM   │ ───► │  Router VM            │ ───► │  THIS REPO (Madison)    │ ───► │  Willow's        │
│  (Nmap, etc.)  │      │  Suricata (Daniel)     │      │  detector + reporter    │      │  dashboard / DB   │
└───────────────┘      │  writes eve.json        │      │                         │      └──────────────────┘
                       └──────────────────────┘      │  flow_to_features()    │
                                                       │  → predict() → score    │
                                                       │  → generate_report()    │
                                                       └─────────────────────────┘
```

Three integration points are implied by this picture; **none of the three are
built today:**

1. **Daniel → this repo:** a real, running Suricata instance writing a real
   `eve.json` that `tail_eve()` reads. Today this is simulated with a 4-line
   hand-written `data/sample_eve.json`.
2. **This repo → Willow:** scored, triggered attacks need to land somewhere
   Willow's dashboard can read (DB row, API call, JSON file). Today the only
   downstream action is `print()`.
3. **PCAP → this repo:** referenced in planning docs but not represented in the
   diagram above at all, because there is no PCAP-handling code. The realistic
   shape of this integration is **PCAP → Suricata offline mode → eve.json →
   existing pipeline**, not a separate PCAP parser inside this repo.

## Inputs and outputs, by module

| Module / function | Input | Output |
|---|---|---|
| `train.py` `main()` | CSV files under `data/**/*.csv` (CICIDS2017 schema) | `models/detector.joblib`, `models/feature_columns.json`; stdout metrics |
| `predict.py` `predict(features)` | `dict` with the 10 keys in `config.SURICATA_ALIGNED_FEATURES` | `{"classification": str, "score": int 0-100, "is_response_triggered": bool}` |
| `suricata_reader.py` `flow_to_features(flow_event)` | one Suricata `flow`-type EVE JSON object | `dict` with the same 10 feature keys |
| `suricata_reader.py` `handle_flow(flow_event)` | one EVE JSON object (any `event_type`) | `predict()` output merged with `timestamp`/`attacker_ip`/`dest_ip`/`dest_port`/`proto`, or `None` if not a flow event |
| `suricata_reader.py` `tail_eve(path)` | path to a growing `eve.json` | stdout `print()` for triggered alerts only (no return value, no persistence) |
| `report.py` `generate_report(event, backend)` | `dict` with `timestamp`, `attacker_ip`, `attack_type`, `score`, `dest_port`, `proto` (all optional, degrades gracefully) | plain-text incident report `str` |
| `demo.py` (new) | nothing (self-contained) | stdout: full pipeline trace + at least one generated report |

## Integration points (ranked by how blocked they are)

1. **Willow's data contract** — fully blocked. No schema/endpoint has been
   agreed on, so there's nothing concrete to build against yet even if someone
   wanted to write the DB/API client today.
2. **Daniel's real `eve.json` schema** — blocked on getting a sample. The
   mapping code is written and unit-tested against the *documented* Suricata
   `flow` schema, but no one has confirmed his actual build matches it.
3. **PCAP testing** — blocked on a decision (offline Suricata vs. dedicated
   parser), not on missing code per se. See INTEGRATION_PLAN.md.
4. **Detector ↔ Reporter wiring** — **not blocked on anyone else.** This was a
   same-repo gap and `demo.py` already closes it for demo purposes; promoting
   that into `tail_eve()` itself is pure local work.
