"""
End-to-end capstone demo: Suricata-style flow -> features -> score -> incident report.

WHY THIS FILE EXISTS
---------------------
`suricata_reader.tail_eve()` calls predict() but never calls generate_report() —
the detector and the incident-report generator are two correct, independently
tested modules that are not wired together anywhere in the live code path. This
script is that missing wire-up, so there is one command that shows the whole
pipeline working end-to-end without Suricata, Daniel's VM, or Willow's dashboard.

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
from src.detector.suricata_reader import flow_to_features, handle_flow
from src.reporting.report import generate_report

# A flow shaped after a real CICIDS2017 PortScan attack row (dest_port 80, 2 tiny
# forward packets, 1 tiny backward packet, ~738us duration). Verified separately
# to score 100 / is_alert_triggered=True against models/detector.joblib.
VERIFIED_ATTACK_FLOW = {
    "timestamp": "2026-06-07T14:32:10.000000+0000",
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


def load_sample_flows() -> list[dict]:
    sample_path = config.PROJECT_ROOT / "data" / "sample_eve.json"
    flows = []
    for line in sample_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if event.get("event_type") == "flow":
            flows.append(event)
    flows.append(VERIFIED_ATTACK_FLOW)
    return flows


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

    triggered_count = 0
    for flow_event in load_sample_flows():
        feats = flow_to_features(flow_event)
        result = handle_flow(flow_event)

        print(f"\nsrc={result['attacker_ip']} dest_port={result['dest_port']}")
        print(f"  features -> {feats}")
        print(f"  prediction -> {result}")

        if result["is_alert_triggered"]:
            triggered_count += 1
            report = generate_report(
                {
                    "timestamp": result["timestamp"],
                    "attacker_ip": result["attacker_ip"],
                    "attack_type": "suspicious flow",
                    "score": result["score"],
                    "dest_port": result["dest_port"],
                    "proto": result["proto"],
                },
                backend="template",
            )
            print("  ALERT -> incident report generated:\n")
            print(report)

    print("=" * 70)
    print(
        f"Done. {triggered_count} of the demo flows triggered a high-priority "
        f"alert (score >= {config.ALERT_THRESHOLD})."
    )


if __name__ == "__main__":
    main()
