"""
End-to-end capstone demo: Suricata-style flow -> features -> score -> incident report.

WHY THIS FILE EXISTS
---------------------
The detector, incident builder, and report generator share the same processing
path used by live and one-shot modes. This script exercises that path without
Suricata, Daniel's VM, or Willow's dashboard.

The bundled `data/sample_eve.json` flows are deliberately mild and never cross
the high-priority alert threshold against the real trained model (see
AUDIT_SUMMARY.md).
So this script adds one additional flow shaped like a real CICIDS2017 PortScan
attack row (verified against the trained model to score 100) to guarantee at
least one triggered alert + generated report when a model is present.

Run:
    python demo.py
"""

from __future__ import annotations

import json

from src import config
from src.detector.suricata_reader import (
    extract_signature,
    flow_to_features,
    handle_flow,
)
from src.reporting.incidents import build_incident

# A flow shaped after a real CICIDS2017 PortScan attack row (dest_port 80, 2 tiny
# forward packets, 1 tiny backward packet, ~738us duration). Verified separately
# to score 100 / is_alert_triggered=True against models/detector.joblib. Its flow_id
# matches the alert in data/sample_eve.json, so the demo shows the correlated Suricata
# signature appearing in the incident report.
VERIFIED_ATTACK_FLOW = {
    "timestamp": "2026-06-07T14:32:10.000000+0000",
    "flow_id": 990001112223,
    "event_type": "flow",
    "src_ip": "10.0.0.66",
    "dest_ip": "10.0.0.1",
    "dest_port": 80,
    "proto": "TCP",
    "flow": {
        "pkts_toserver": 2,
        "pkts_toclient": 1,
        "bytes_toserver": 8,
        "bytes_toclient": 2,
        "start": "2026-06-07T14:32:10.000000+0000",
        "end": "2026-06-07T14:32:10.000738+0000",
    },
}


def load_sample_events() -> list[dict]:
    """Read every event (flows AND alerts) from the bundled sample."""
    sample_path = config.PROJECT_ROOT / "data" / "sample_eve.json"
    events = []
    for line in sample_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def signatures_by_flow_id(events: list[dict]) -> dict:
    """Map flow_id -> Suricata signature for every alert event in the sample."""
    signatures = {}
    for event in events:
        if event.get("event_type") == "alert":
            signature = extract_signature(event)
            flow_id = event.get("flow_id")
            if signature and flow_id is not None:
                signatures[flow_id] = signature
    return signatures


def main() -> None:
    if not config.MODEL_PATH.exists():
        print(
            f"No trained model at {config.MODEL_PATH}.\n"
            "Run `python -m src.detector.train` first, then re-run this demo."
        )
        return

    print("=" * 70)
    print("CAPSTONE DEMO: flow -> features -> score -> incident report")
    print("=" * 70)

    events = load_sample_events()
    signatures = signatures_by_flow_id(events)
    flows = [event for event in events if event.get("event_type") == "flow"]
    flows.append(VERIFIED_ATTACK_FLOW)

    triggered_count = 0
    for flow_event in flows:
        feats = flow_to_features(flow_event)
        result = handle_flow(flow_event)

        print(f"\nsrc={result['attacker_ip']} dest_port={result['dest_port']}")
        print(f"  features -> {feats}")
        print(f"  prediction -> {result}")

        signature = signatures.get(flow_event.get("flow_id"))
        incident = build_incident(flow_event, result, suricata_signature=signature)
        if incident is None:
            continue

        triggered_count += 1
        print("  ALERT -> incident report generated:\n")
        print(incident["report"])

    print("=" * 70)
    print(
        f"Done. {triggered_count} of the demo flows triggered a high-priority "
        f"alert (raw model probability >= {config.ALERT_THRESHOLD}; the displayed "
        f"0-100 score is a rounded value and is not what the decision compares)."
    )


if __name__ == "__main__":
    main()
