# DEMO_PLAN.md

> **Updated status, July 4:** the local Git baseline is `25a12b1`,
> classification begins at 50, high-priority alerting begins at 95, report
> wording has been corrected, and 10 tests pass. The demo remains standalone;
> live-tail report persistence and teammate integrations are still pending.

## Minimum viable capstone demo (achievable right now, solo, offline)

This requires nothing from Daniel, Willow, Suricata, or Ollama. Confirmed working
today:

```powershell
pytest -q              # 10 passed — shows the code is tested
python demo.py          # the full pipeline, end to end
```

`python demo.py` does, and shows, all of the following in one run:
1. Loads sample Suricata-style `flow` events (including one shaped after a real
   CICIDS2017 PortScan attack row, verified to score 100 against the trained
   model).
2. Converts each to the model's 10 features (`flow_to_features`).
3. Scores each with the trained Random Forest (`predict`).
4. For the one that crosses the threshold, generates a full plain-language
   incident report (`generate_report`).

This is the actual minimum bar: **trained model + live-shaped input + a score +
a human-readable report, in one command, with no external dependencies.** It was
not possible before this audit because nothing in `src/` called both halves of
the pipeline in sequence — `demo.py` is the missing connective tissue.

Talking points for this version:
- "Trained on 2.83M real labeled network flows (CICIDS2017)."
- "Only uses the 10 features a live Suricata sensor can actually produce — no
  train/production feature mismatch."
- "Detected attack → human-readable report, automatically."
- Be upfront that the score-100 example is a synthetic flow shaped after a real
  attack row, not a live capture — don't overstate it as "live Suricata."

## Ideal demo (if Weeks 1-4 of INTEGRATION_PLAN.md land)

1. A real attacker VM runs an Nmap scan (or similar) against a target on the lab
   network.
2. Daniel's Suricata instance writes real `flow` events to `eve.json`.
3. This repo's `suricata_reader.py` tails that file live and scores each flow as
   it arrives.
4. A triggered detection produces an incident report and lands on Willow's actual
   dashboard (or the JSON-lines fallback file, presented as "what the dashboard
   would show").
5. The presenter narrates the whole chain live: attack → capture → score → report
   → dashboard, in real time.

This is the target end state, not the fallback floor — it depends on at least
one of Daniel/Willow's pieces being reachable, which is exactly the uncertainty
INTEGRATION_PLAN.md's fallbacks are designed around.

## Contingency demos

**If Suricata is unavailable (no install, no VM access):**
Use `demo.py` and/or `--demo` exactly as today — present it explicitly as "this
is the detector and reporter validated against Suricata's documented schema and
against real attack feature distributions pulled from the training data; live
capture integration is the next step, blocked on VM access." This is a true and
defensible statement, not a workaround dressed up as the real thing.

**If Grafana / a dashboard is unavailable:**
Fall back to the `output/incidents.jsonl` sink described in INTEGRATION_PLAN.md
Week 4, and show it with `Get-Content output\incidents.jsonl | ConvertFrom-Json`
or just opened in a text editor. Frame it as "the exact payload the dashboard
would consume" rather than apologizing for missing a UI — the AI Trainer role's
deliverable is the score + report, not the dashboard rendering.

**If Daniel and/or Willow are unavailable on demo day:**
The minimum viable demo above does not depend on either of them and is already
a complete, coherent story end-to-end (trained model → live-shaped scoring →
human-readable report). Lead with that, and describe the integration plan
(INTEGRATION_PLAN.md) as "designed, fallback-tested, ready to execute" rather
than presenting their absence as a gap in your work.

**If asked "does this actually catch real attacks, not just toy examples?":**
Point to the verified evidence from this audit: a feature vector pulled directly
from a real labeled attack row in `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
scores 100/100 through the actual trained model — this is real dataset evidence,
not a hand-tuned example built to look good.
