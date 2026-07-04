# What "Training" Means — and How to Talk About It

**Author:** Madison  
**Audience:** Teammates, professors, and anyone reviewing the senior project

---

## Part 1 — What Training Actually Means

### The core idea

"Training a model" sounds technical, but the concept is simple: **you show a computer thousands of labeled examples and it learns the pattern that separates them.**

In this project specifically:

- We have 2.83 million records of real network traffic
- Each record is labeled either **BENIGN** (normal) or **ATTACK**
- The model reads all of them, finds the patterns that distinguish attacks from normal traffic, and stores those patterns internally
- After training, when it sees a *new* flow it has never seen before, it can predict which category it belongs to

A useful analogy: imagine teaching someone to recognize spam email by showing them 10,000 emails, half of which are spam and half are not, each labeled. After seeing enough examples, they'd start noticing patterns ("it always says 'URGENT' and has a weird link") without you ever writing down a rule. That's training.

### What the model actually learned

This project uses a **Random Forest** — a collection of 100 decision trees. Each tree independently looks at a network flow and votes "attack" or "benign." The final answer is the majority vote across all 100 trees.

Each individual tree asks a chain of yes/no questions about the flow, for example:

```
Is the destination port < 1024?
  └─ YES → Is the forward packet count > 50?
              └─ YES → ATTACK (likely port scan)
              └─ NO  → BENIGN
  └─ NO  → Is the flow duration < 100 microseconds?
              └─ YES → ATTACK (likely DoS burst)
              └─ NO  → BENIGN
```

With 100 trees each asking slightly different questions, the combined vote is much more reliable than any single tree.

### What features the model uses

The model only looks at 10 numbers per network flow:

| Feature | Plain English |
|---------|--------------|
| Destination Port | Which service was being contacted (port 22 = SSH, 80 = web, etc.) |
| Flow Duration | How long the connection lasted |
| Total Fwd Packets | How many packets the client sent |
| Total Backward Packets | How many packets the server sent back |
| Total Length of Fwd Packets | Total bytes sent by the client |
| Total Length of Bwd Packets | Total bytes sent by the server |
| Flow Bytes/s | Data transfer rate |
| Flow Packets/s | Packet rate |
| Fwd Packet Length Mean | Average size of client packets |
| Bwd Packet Length Mean | Average size of server packets |

These 10 numbers are enough because attacks have recognizable signatures: a port scan sends tiny packets to many ports with almost no response; a DDoS floods packets at an extreme rate; a brute-force attack has many small forward packets and few replies.

### Why these 10 features specifically

CICIDS2017 has 79 features, but most of them (inter-arrival timing variance, TCP flag counts, etc.) are not available from Daniel's Suricata network monitor. We deliberately trained on *only* the features Suricata can produce live, so the model that works on our dataset will also work on real traffic. This is called **feature alignment** and it prevents the most common failure mode in deployed ML systems.

### What the results mean

After training, the model was tested on 848,363 flows it had never seen:

| Metric | Result | What it means |
|--------|--------|---------------|
| **Accuracy** | 99.55% | Out of 848K flows, it got 99.55% correct |
| **False-positive rate** | 0.41% | Only 0.41% of normal traffic was wrongly flagged as an attack |
| **Attack recall** | 99% | It correctly caught 99% of all real attacks |
| **Attack precision** | 98% | When it said "attack," it was right 98% of the time |

These exceed the project's design targets (≥ 90% accuracy, < 5% FPR).

---

## Part 2 — How It Is Implemented

### The workflow from data to live detection

```
1. Download data         CICIDS2017 CSVs (real network captures, pre-labeled)
        ↓
2. Train                 python -m src.detector.train
        ↓
3. Saved model           models/detector.joblib
        ↓
4. Live scoring          python -m src.detector.suricata_reader --eve /path/to/eve.json
        ↓
5. Alert + report        scored attack dict → incident report → Willow's dashboard
```

### Step-by-step

**Step 1 — The dataset**  
CICIDS2017 was created by the Canadian Institute for Cybersecurity. They set up a realistic lab network, ran real attack tools against it for a week, and captured all the traffic. Then they extracted 79 numerical features from each flow and labeled every row. We use 8 of the 10 daily CSV files (~844 MB total, 2.83M flows).

**Step 2 — Training the model**  
Running `python -m src.detector.train` does five things in sequence:
1. Loads and combines all 8 CSVs
2. Drops rows with invalid numbers (infinity, NaN) — about 2,867 rows
3. Collapses all attack labels (DoS, PortScan, Brute Force, etc.) into a single "attack" class
4. Splits data 70/30 into training and test sets
5. Trains 100 decision trees in parallel across all CPU cores

On a modern laptop this takes a few minutes. The output is two files:
- `models/detector.joblib` — the trained model (binary file, ~100 MB)
- `models/feature_columns.json` — the list of 10 features the model expects, in order

**Step 3 — Scoring live traffic**  
When Daniel's Suricata writes a new flow to `eve.json`, `suricata_reader.py`
reads it, extracts the 10 features, and calls `predict()`. The model's attack
probability is scaled to a **0–100 model risk score**. Scores **≥50** receive the
`attack` classification. Scores **≥95** raise a high-priority alert. Alerting
does not automatically block traffic or lock down the network.

**Step 4 — Incident report**  
Every flagged attack produces a plain-language report with the attacker IP, score, targeted port, and recommended actions. This goes to Willow's dashboard so non-technical users can understand what happened.

### Files involved

```
src/config.py              — Feature list and classification/alert thresholds
src/detector/train.py      — Training script
src/detector/predict.py    — Runtime scoring (called per flow)
src/detector/suricata_reader.py  — Reads eve.json, calls predict
src/reporting/report.py    — Generates incident reports
models/detector.joblib     — The trained model (produced by train.py)
```

---

## Part 3 — How to Share This

### With your teammates (Daniel and Willow)

**What Daniel needs to know:**
- `suricata_reader.py` expects Suricata `flow` events with fields: `pkts_toserver`, `pkts_toclient`, `bytes_toserver`, `bytes_toclient`, `flow.start`, `flow.end`, `dest_port`, `src_ip`, `dest_ip`, `proto`
- The reader tails `eve.json` live — point it at his log file: `python -m src.detector.suricata_reader --eve /var/log/suricata/eve.json`
- He should share a sample `eve.json` so we can verify the field names match before Sprint 2

**What Willow needs to know:**
- Every scored flow produces a dict with: `classification`, `score`, `is_alert_triggered`, `timestamp`, `attacker_ip`, `dest_ip`, `dest_port`, `proto`
- The incident report is a plain text string from `generate_report(event)`
- The `print()` in `tail_eve()` in `suricata_reader.py` is the placeholder — replace it with whatever DB write or API call her dashboard needs

**What to hand off:**
- `models/detector.joblib` — the trained model file
- `models/feature_columns.json` — the feature list
- The `src/detector/` folder — all three Python files
- This document

### With your professor

The key points to emphasize in a presentation or writeup:

1. **The problem:** Network intrusion detection is hard to automate because attack traffic looks superficially similar to normal traffic. Rule-based systems miss novel attacks.

2. **The approach:** Supervised machine learning. Train on a labeled dataset of real attack and normal traffic, learn statistical patterns, generalize to new unseen traffic.

3. **The design decision that matters:** Feature alignment. Most ML projects train on whatever features are available, then discover the model can't run in production because those features don't exist at runtime. We constrained the training to only the 10 features Suricata produces live.

4. **The results:** 99.55% accuracy, 0.41% false-positive rate. The design document targets were 90% and 5% respectively — we exceeded both.

5. **What's next:** Sprint 2 is underway — as of 2026-06-25, a real Suricata 6.0.4 instance has been run offline against a real ~894 MB pcap, producing a real 54,914-flow `eve.json` that validated the feature mapping with zero changes needed. Still pending: live integration with Daniel's actual router VM and Willow's dashboard contract.

### For a general audience (non-technical)

If explaining to someone unfamiliar with machine learning:

> "We taught a computer to recognize cyberattacks the same way you'd teach a person — by showing it thousands of examples of both normal and malicious network traffic, each one labeled. After seeing enough examples, it learns to spot the patterns. Now, when it sees new traffic it's never seen before, it can predict in real time whether it looks like an attack. We tested it on over 800,000 examples it hadn't seen during training and it was correct 99.5% of the time, with fewer than half a percent of false alarms."

### Sharing the notebooks

The two Jupyter notebooks (`01_explore.ipynb`, `02_train.ipynb`) are the most visual way to demonstrate the work:

- `01_explore.ipynb` shows charts of the data — attack type distribution, feature comparisons between benign and attack traffic
- `02_train.ipynb` walks through training step by step and shows the confusion matrix as a heatmap

These can be exported to PDF or HTML for inclusion in a report:
```powershell
.\.venv\Scripts\jupyter.exe nbconvert --to html notebooks/01_explore.ipynb
.\.venv\Scripts\jupyter.exe nbconvert --to html notebooks/02_train.ipynb
```
The output HTML files can be opened in any browser and attached to a report or emailed.
