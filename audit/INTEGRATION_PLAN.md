# INTEGRATION_PLAN.md

A realistic 6-week plan from current state (working detector + reporter,
zero real integration, no version control) to a demo-ready integrated system.
Each week assumes teammate availability is uncertain — every week has a fallback
that requires no input from Daniel or Willow.

## Week 1 — De-risk the local foundation (no teammates needed)

- `git init` this repo. This is overdue, not optional — do it before anything else.
- Fix `.gitignore` (see PROJECT_STATUS.md) before the first commit, so the 520 MB
  of dataset zips never get staged.
- Pin dependencies: `pip freeze > requirements-lock.txt` from the current working
  `.venv`, so the exact environment that trained `detector.joblib` is reproducible.
- Re-run `python -m src.detector.train` once to confirm the 99.55%/0.41% metrics
  reproduce, and timestamp that confirmation in PROGRESS.md.
- Run `notebooks/02_train.ipynb` top to bottom at least once (it has never been
  executed) so it's known-good before anyone presents it.
- **Fallback:** none needed — this entire week is self-contained.

## Week 2 — Local demo hardening (no teammates needed)

- Promote `demo.py`'s detector→reporter wiring into `tail_eve()` itself, behind a
  flag or just unconditionally, so the live-tailing path also produces reports,
  not just scores.
- Build a small library of synthetic EVE flows that are *known* to score above
  and below the threshold (the `VERIFIED_ATTACK_FLOW` in `demo.py` is the first
  one) so future demos don't accidentally rely on flows that score 0.
- Write 2-3 PCAP files (or download small labeled ones) and manually run them
  through Suricata's offline mode if Suricata is available on any machine:
  `suricata -r sample.pcap -l ./suricata-logs/` → inspect `eve.json` → feed
  through `tail_eve()`/`demo.py`-style scoring.
- **Fallback if no Suricata access at all this week:** keep testing exclusively
  against `data/sample_eve.json`-style hand-written flows; document explicitly
  that PCAP testing is blocked on Suricata access, not on missing code.

## Week 3 — Daniel integration attempt

- Ask Daniel for: (a) a real `eve.json` sample (even 50 lines is enough), and
  (b) confirmation of his Suricata version and `flow`-event config.
- Diff his real field names/types against what `flow_to_features()` expects.
  Patch the mapping function if anything differs; re-run the test suite.
- If a real Suricata instance is reachable, run `tail_eve()` against it live for
  at least 10 minutes during normal use, then again during a deliberate Nmap
  scan from an attacker machine.
- **Fallback if Daniel is unavailable or his VM isn't ready:** synthesize the most
  realistic `eve.json` possible from the actual CICIDS2017 rows (this audit
  already proved a real attack row maps cleanly to a triggering flow — see
  `demo.py`). Document that the mapping is "validated against the documented
  Suricata schema and against real attack feature distributions, not yet against
  a live Suricata process" and proceed to Week 4 anyway. This is not a blocker for
  the local demo.

## Week 4 — Willow integration attempt

- Get the exact contract from Willow: what does her dashboard read — a DB table
  (which engine, which schema), a REST endpoint, or a JSON/log file it tails?
- Implement exactly that as a new, small function (e.g. `report.py`'s output and
  `predict()`'s output both feed it) — keep it isolated so it can be swapped if
  the contract changes.
- Replace the `print()` in `tail_eve()` with a call to that function.
- **Fallback if Willow is unavailable or her schema isn't ready:** write scored
  attacks + reports to a local JSON-lines file (`output/incidents.jsonl`) as a
  stand-in sink. This is a real, demoable artifact ("here's what would have gone
  to the dashboard") and is a trivial swap later — it's the same shape of change
  either way (replace one function body).

## Week 5 — End-to-end rehearsal + buffer

- Full run-through: attacker action → Suricata (real or simulated) → `eve.json`
  → detector → report → sink (real dashboard or the JSON-lines fallback).
- Time-box debugging to this week specifically — it is the week most likely to
  reveal integration surprises (timestamp formats, missing fields, encoding).
- **Fallback:** if real Daniel/Willow integration isn't ready by the end of this
  week, the local demo (Week 1-2 deliverable) is already complete and
  presentable on its own — treat Week 5 as "try to upgrade the demo," not as a
  blocking dependency for having *a* working demo.

## Week 6 — Polish, writeup, handoff package

- Export `01_explore.ipynb` and (now-verified) `02_train.ipynb` to HTML for the
  written report (`jupyter nbconvert --to html`).
- Write up the TC-01/02/03/07/10 test case results referenced in TODO.md.
- Package the handoff artifacts for Daniel (the `src/detector/` files + model) and
  for Willow (the sink contract + sample output), independent of whether live
  integration happened — these are useful even in the fallback scenario.
- **Fallback:** none needed — this week is documentation/packaging regardless of
  how Weeks 3-5 went.

## Priority ordering, explicit

1. **Local demo environment** (Weeks 1-2) is prioritized first and is fully
   achievable solo. It is the floor under every other outcome in this plan.
2. **PCAP and EVE JSON testing** is prioritized second, deliberately scoped
   around Suricata's *offline* mode so it doesn't actually require a teammate's
   live VM to start making progress.
3. **Daniel and Willow integration** come third and fourth because they are the
   two items genuinely outside this audit's control — both weeks are designed
   so a no-show from either teammate degrades the plan gracefully instead of
   blocking it.
