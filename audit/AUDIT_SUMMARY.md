# AUDIT_SUMMARY.md

Audit date: 2026-06-22. Method: read every file in the repo, ran the test suite
and every documented demo command, pulled real rows from the training CSVs to
independently verify the model, and grepped for claimed-but-unverified
integrations (Suricata, Ollama, Willow's DB, PCAP). See CURRENT_STATE.md,
PROJECT_STATUS.md, ARCHITECTURE.md for the full evidence trail.

> **Addendum, 2026-06-25:** the single highest-uncertainty item this audit could not
> resolve locally — Suricata field-mapping validated against real output — has been
> resolved, self-sourced rather than via Daniel (see `CURRENT_STATE.md`'s addendum for
> the full writeup, including a real 894 MB pcap run through a real Suricata 6.0.4
> install with zero mapping changes needed, and a follow-up investigation that got
> independent corroboration from Suricata's own signature engine on the same host).
> `RESPONSE_THRESHOLD` was also raised 70 → 95 per professor feedback. **Still true:**
> "what should be done tonight" item #1 below (git) — this is still the highest-risk
> open item in the project, three days after this audit and unchanged.

## Is the project salvageable?

Yes, clearly. The hard part — a trained model that actually separates attack
from benign traffic on real labeled data — is done and independently verified in
this audit (a real attack row from the PortScan CSV scores 100/100 through the
live `predict()` path, not just claimed in a doc). What's missing is mostly
integration work and process hygiene (git), not a redesign or a rewrite.

## What percentage complete is the project?

Roughly **60-65% of the AI Trainer role's own scope** (detector + reporter,
per CLAUDE.md), and **roughly 30-35% of the full three-person integrated system**
those two numbers differ a lot, and presenting only the higher one would be
misleading:

- Detector (train/predict/mapping): ~85% — works, tested, verified against real
  attack data; the only real gaps are no real-Suricata validation and unpinned
  dependencies.
- Reporter (template backend): ~90% — works, tested, contract is stable.
- Detector ↔ Reporter wiring: was 0% in `src/` before this audit, now ~70% (a
  working standalone script exists; it hasn't been promoted into `tail_eve()`
  itself yet).
- Daniel integration: ~5% (the mapping code exists and is unit-tested against a
  documented schema; zero contact with real Suricata output).
- Willow integration: 0% (no code, no agreed contract).
- PCAP support: 0% (no code; not even a documented workaround until this audit).
- Process hygiene (version control): 0% (no `.git` anywhere).

## What is the highest risk area?

**No version control**, full stop. It's not the most "interesting" finding, but
it's the one where the downside is unbounded — a corrupted file, an accidental
overwrite, or a OneDrive sync conflict could lose work with no way to recover it.
Every other gap in this audit (Willow's contract, Daniel's eve.json, PCAP
support) is a known, scoped, recoverable amount of future work. This one is a
silent, compounding risk that gets worse the longer it's left alone.

Second highest: **the detector and reporter were never connected in the actual
codebase.** Both pieces individually work and are tested, but until this audit
nothing in `src/` proved they work *together*. That's now closed by `demo.py`,
but it's worth naming as a near-miss: a grader or teammate reading `src/` alone
would have had no way to see the two halves form a pipeline.

## What should be done tonight?

1. `git init` + fix `.gitignore` + first commit (NEXT_10_TASKS.md #1). Five
   minutes of work that eliminates the highest-risk item above.
2. Run `python demo.py` once to see the working end-to-end pipeline.
3. Skim CURRENT_STATE.md's "what has NOT been validated" section so the gaps are
   front of mind before talking to teammates or a professor about status.

## What should be requested from teammates immediately?

- **From Daniel:** any real `eve.json` sample (even 20-50 lines), plus
  confirmation of his Suricata version/config. This is the single
  highest-uncertainty item this audit could not resolve locally.
- **From Willow:** the exact shape of what her dashboard expects to receive
  (DB table + schema, REST endpoint, or a file it tails). Don't wait for a
  perfect answer — even "not decided yet" is useful, because it justifies using
  the JSON-lines fallback in INTEGRATION_PLAN.md Week 4 now instead of blocking.

## What is the minimum passing capstone demo?

`python demo.py` — a trained Random Forest (verified against real CICIDS2017
attack rows) scoring a Suricata-shaped flow and automatically producing a
human-readable incident report, with `pytest -q` (5/5 passing) as supporting
evidence the components are tested. This requires no teammate availability, no
Suricata install, and no Ollama install, and was confirmed working in this
session. See DEMO_PLAN.md for how to talk about it honestly (it's a verified,
synthetic-but-data-grounded example, not a live capture) and what to say if
asked to go further.
