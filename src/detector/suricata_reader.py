"""
Read live Suricata EVE JSON, turn each flow into model features, and score it.

THE INTEGRATION GLUE
--------------------
Daniel's Suricata writes one JSON object per line to `eve.json`. We only care
about `event_type == "flow"` records. This file:
  1. translates a Suricata flow event into the CICIDS2017-style features the
     model expects (see flow_to_features), and
  2. runs predict() on them, and
  3. (in the real system) writes attacks to the DB Willow's dashboard reads.

Run a self-contained demo (no Suricata, no dataset needed for the mapping part):
    python -m src.detector.suricata_reader --demo

Tail a real Suricata log once a trained model exists:
    python -m src.detector.suricata_reader --eve /var/log/suricata/eve.json
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path

from src import config
from src.reporting.incident_writer import DEFAULT_INCIDENTS_PATH, append_incident
from src.reporting.incidents import build_incident


def flow_to_features(flow_event: dict) -> dict:
    """
    Map ONE Suricata 'flow' EVE event to the model's feature dict.

    This mapping is the heart of the "feature alignment" work in the plan.
    Suricata exposes packet/byte counts per direction and flow timestamps; we
    derive the CICIDS2017-style features from those. If you add/remove a feature
    in config.SURICATA_ALIGNED_FEATURES, update this mapping to match.
    """
    flow = flow_event.get("flow", {})

    pkts_to_server = flow.get("pkts_toserver", 0)   # client -> server  = "forward"
    pkts_to_client = flow.get("pkts_toclient", 0)   # server -> client  = "backward"
    bytes_to_server = flow.get("bytes_toserver", 0)
    bytes_to_client = flow.get("bytes_toclient", 0)

    # Flow duration in microseconds (CICIDS2017's unit), from the flow timestamps.
    duration_us = _duration_microseconds(flow.get("start"), flow.get("end"))
    duration_s = duration_us / 1_000_000 if duration_us else 0.0

    total_bytes = bytes_to_server + bytes_to_client
    total_pkts = pkts_to_server + pkts_to_client

    return {
        "Destination Port": flow_event.get("dest_port", 0),
        "Flow Duration": duration_us,
        "Total Fwd Packets": pkts_to_server,
        "Total Backward Packets": pkts_to_client,
        "Total Length of Fwd Packets": bytes_to_server,
        "Total Length of Bwd Packets": bytes_to_client,
        "Flow Bytes/s": (total_bytes / duration_s) if duration_s else 0.0,
        "Flow Packets/s": (total_pkts / duration_s) if duration_s else 0.0,
        "Fwd Packet Length Mean": (bytes_to_server / pkts_to_server) if pkts_to_server else 0.0,
        "Bwd Packet Length Mean": (bytes_to_client / pkts_to_client) if pkts_to_client else 0.0,
    }


def _duration_microseconds(start: str | None, end: str | None) -> float:
    """Suricata timestamps look like '2025-01-01T12:00:00.123456+0000'."""
    if not start or not end:
        return 0.0
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
    try:
        t0 = datetime.strptime(start, fmt)
        t1 = datetime.strptime(end, fmt)
        return max((t1 - t0).total_seconds() * 1_000_000, 0.0)
    except ValueError:
        return 0.0


def handle_flow(flow_event: dict) -> dict | None:
    """Score one flow event and return a result record, or None if not a flow."""
    if flow_event.get("event_type") != "flow":
        return None

    # Imported here so the --demo mapping check works even without a trained model.
    from src.detector.predict import predict

    features = flow_to_features(flow_event)
    result = predict(features)
    result.update(
        {
            "timestamp": flow_event.get("timestamp"),
            "attacker_ip": flow_event.get("src_ip"),
            "dest_ip": flow_event.get("dest_ip"),
            "dest_port": flow_event.get("dest_port"),
            "proto": flow_event.get("proto"),
        }
    )
    return result


def process_live_event(
    flow_event: dict,
    incidents_path: str | Path = DEFAULT_INCIDENTS_PATH,
) -> dict | None:
    """Score one live event and persist it when it becomes an incident."""
    prediction = handle_flow(flow_event)
    if prediction is None:
        return None

    incident = build_incident(flow_event, prediction)
    if incident is None:
        return None

    append_incident(incident, incidents_path)
    return incident


def tail_eve(eve_path: Path) -> None:
    """Follow a Suricata EVE file and persist new high-priority incidents."""
    print(f"Tailing {eve_path} ... (Ctrl+C to stop)")
    with eve_path.open("r", encoding="utf-8") as f:
        f.seek(0, 2)  # jump to end so we only read NEW lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            incident = process_live_event(event)
            if incident is not None:
                alert_info = {
                    key: value
                    for key, value in incident.items()
                    if key != "report"
                }
                print(f"[ALERT score={incident['ml_score']}] {alert_info}")
                print(incident["report"])
                print(f"[incident] appended to {DEFAULT_INCIDENTS_PATH}")


def run_demo() -> None:
    """Show the mapping on the bundled sample, no Suricata required."""
    sample = config.PROJECT_ROOT / "data" / "sample_eve.json"
    print(f"Mapping demo using {sample}\n")
    for line in sample.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if event.get("event_type") != "flow":
            continue
        feats = flow_to_features(event)
        print(f"src={event.get('src_ip')} dport={event.get('dest_port')}")
        print(f"  features -> {feats}")
        # Only score if a model has been trained; otherwise just show features.
        if config.MODEL_PATH.exists():
            print(f"  prediction -> {handle_flow(event)}")
        else:
            print("  (train a model with `python -m src.detector.train` to score this)")
        print()


def score_eve_file(eve_path: Path) -> None:
    """
    Read a FINISHED eve.json once (e.g. from offline `suricata -r`) and score every flow.

    This is the repeatable testing harness for "run this against a different pcap and
    see what happens" — not the polished presentation demo (that's `demo.py`, which
    uses one fixed, guaranteed-to-trigger synthetic flow). Point this at any real
    pcap's eve.json and it scores every flow, generating a full incident report for
    anything that crosses the threshold, the same way `demo.py` does.

    Reads the whole file first, then calls predict_proba() once on the full matrix
    (batch prediction) instead of once per flow. Much faster for large captures.
    """
    from src.detector.predict import predict_batch

    print(f"Loading {eve_path}...")
    flow_events = []
    features_list = []
    skipped = 0
    with eve_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if event.get("event_type") != "flow":
                continue
            flow_events.append(event)
            features_list.append(flow_to_features(event))

    print(f"Loaded {len(flow_events):,} flow events ({skipped} malformed lines skipped).")
    if not flow_events:
        print("No flow events found — nothing to score.")
        return

    print("Scoring all flows in one batch...")
    results = predict_batch(features_list)

    triggered_count = 0
    for event, result in zip(flow_events, results):
        incident = build_incident(event, result)
        if incident is None:
            continue

        triggered_count += 1
        alert_info = {
            key: value
            for key, value in incident.items()
            if key != "report"
        }
        print(f"[ALERT score={incident['ml_score']}] {alert_info}")
        print(incident["report"])

    print(f"\nDone. {len(flow_events):,} flows scored, {triggered_count} crossed the threshold.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Score Suricata flows with the AI detector.")
    parser.add_argument("--eve", type=Path, help="Path to a live, growing Suricata eve.json to tail.")
    parser.add_argument(
        "--eve-once", type=Path,
        help="Path to a FINISHED eve.json (e.g. from offline `suricata -r`) to score once and exit.",
    )
    parser.add_argument("--demo", action="store_true", help="Run the bundled mapping demo.")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.eve_once:
        score_eve_file(args.eve_once)
    elif args.eve:
        tail_eve(args.eve)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
