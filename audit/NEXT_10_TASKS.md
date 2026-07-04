# NEXT_10_TASKS.md

Ordered by impact and uncertainty reduction — earlier items either prevent
irreversible loss (no version control) or resolve the biggest unknowns cheaply.
Exact commands are given wherever possible.

## 1. Initialize git and make the first commit
**Why first:** there is currently zero version control. Every hour of work from
here forward is unrecoverable if something goes wrong until this exists.
```powershell
git init
# fix .gitignore first (see PROJECT_STATUS.md) — add data/zips/ and
# data/GeneratedLabelledFlows.zip before staging anything
git add .
git commit -m "Initial commit: detector, reporter, tests, audit docs"
```

## 2. Run the new end-to-end demo and confirm it on this machine
**Why:** proves the detector + reporter actually work together before anyone
demos it live.
```powershell
python demo.py
```
Expect: 4 flows scored, 1 triggered alert, 1 full incident report printed.

## 3. Re-run training once and timestamp the confirmation
**Why:** the 99.55%/0.41% metrics currently come from a doc, not a verified run
in this session.
```powershell
python -m src.detector.train
```
Record the printed accuracy/FPR/feature-importance output into PROGRESS.md with
today's date.

## 4. Run `notebooks/02_train.ipynb` end to end at least once
**Why:** it has never been executed (all cells show `execution_count: null`).
Don't present it in a demo until this is confirmed.
```powershell
jupyter notebook
# open notebooks/02_train.ipynb, Run All
```

## 5. Pin the actual working dependency versions
**Why:** `requirements.txt` only has `>=` floors; the installed env is much newer
than the floors with no lock file, so a teammate's fresh install could diverge.
```powershell
pip freeze > requirements-lock.txt
```

## 6. Build 2-3 more synthetic EVE flows that reliably trigger (and a couple that reliably don't)
**Why:** the only bundled sample data (`data/sample_eve.json`) never crosses the
threshold against the real model — a fresh demo of `--demo` alone looks like
"nothing detected." `demo.py` proves one triggering flow already works; add
2-3 more attack archetypes (DDoS-style flood, brute force) by pulling real rows
from the other CSVs the same way this audit did for PortScan:
```python
import pandas as pd
from src import config
df = pd.read_csv(config.DATA_DIR / "MachineLearningCVE" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                  usecols=lambda c: c.strip() in set(config.SURICATA_ALIGNED_FEATURES + [config.LABEL_COLUMN]))
```

## 7. Request a real `eve.json` sample from Daniel this week
**Why:** the single highest-uncertainty item that someone else, not you, can
resolve quickly. Even 20-50 lines is enough to diff field names against
`flow_to_features()`'s assumptions.

## 8. Get Willow's dashboard/DB contract (or pick the JSON-lines fallback now)
**Why:** `tail_eve()`'s only downstream action is `print()`. Whether the real
contract or the fallback (`output/incidents.jsonl`) is used, this removes the
single largest "not built" gap in PROJECT_STATUS.md. Don't wait on Willow if
she's unresponsive — implement the fallback this week regardless, it's a clean
swap later.

## 9. Test PCAP → Suricata offline mode → eve.json once, on any one PCAP file
**Why:** resolves whether "PCAP testing" is realistic with the current toolchain
before committing to it in the integration plan.
```powershell
suricata -r path\to\sample.pcap -l .\suricata-logs\
# then feed .\suricata-logs\eve.json through:
python -m src.detector.suricata_reader --eve .\suricata-logs\eve.json
```
If Suricata isn't installed anywhere accessible, document that explicitly as a
blocked external dependency rather than silently dropping PCAP support.

## 10. Clean up the ~520 MB of redundant dataset zips
**Why:** lowest priority (no functional impact), but cheap and reduces accidental
git bloat risk now that task #1 has initialized version control.
```powershell
Remove-Item -Recurse -Force .\data\zips
Remove-Item -Force .\data\GeneratedLabelledFlows.zip
```
Confirm `python -m src.detector.train` still works afterward (it only globs
`data/**/*.csv`, so this should be a no-op functionally).
