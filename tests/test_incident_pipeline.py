"""Tests for shared post-scoring incident construction and live persistence."""

import json

from src.detector.suricata_reader import process_live_event
from src.reporting.incidents import build_incident


FLOW_EVENT = {
    "timestamp": "2026-07-04T12:00:00.000000+0000",
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
        "start": "2026-07-04T12:00:00.000000+0000",
        "end": "2026-07-04T12:00:00.000738+0000",
    },
}

ALERT_PREDICTION = {
    "classification": "attack",
    "score": 100,
    "is_alert_triggered": True,
}


def test_build_incident_returns_none_without_high_priority_alert(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("a non-alert must not generate a report")

    monkeypatch.setattr(
        "src.reporting.incidents.generate_report",
        fail_if_called,
    )

    incident = build_incident(
        FLOW_EVENT,
        {
            "classification": "attack",
            "score": 82,
            "is_alert_triggered": False,
        },
    )

    assert incident is None


def test_build_incident_uses_consistent_schema_and_template_report():
    incident = build_incident(FLOW_EVENT, ALERT_PREDICTION)

    assert incident == {
        "schema_version": "1.0",
        "timestamp": "2026-07-04T12:00:00.000000+0000",
        "source_ip": "10.0.0.66",
        "destination_ip": "10.0.0.1",
        "destination_port": 80,
        "protocol": "TCP",
        "classification": "attack",
        "ml_score": 100,
        "alert_triggered": True,
        "attack_type": "high-risk network flow",
        "suricata_signature": None,
        "report": incident["report"],
        "automated_block_performed": False,
    }
    assert "high-risk network flow" in incident["report"]
    assert "10.0.0.66" in incident["report"]
    assert "100" in incident["report"]
    assert "No automatic blocking or network lockdown was performed" in incident["report"]


def test_build_incident_handles_missing_optional_flow_fields():
    incident = build_incident(
        {"event_type": "flow"},
        ALERT_PREDICTION,
    )

    assert incident["timestamp"] is None
    assert incident["source_ip"] is None
    assert incident["destination_ip"] is None
    assert incident["destination_port"] is None
    assert incident["protocol"] is None
    assert "an unknown address" in incident["report"]
    assert "an unknown time" in incident["report"]


def test_process_live_event_persists_alert_as_jsonl(tmp_path, monkeypatch):
    output_path = tmp_path / "live" / "incidents.jsonl"
    monkeypatch.setattr(
        "src.detector.predict.predict",
        lambda features: ALERT_PREDICTION.copy(),
    )

    incident = process_live_event(FLOW_EVENT, output_path)

    assert json.loads(output_path.read_text(encoding="utf-8")) == incident
    assert incident["report"].startswith("Summary:")


def test_process_live_event_does_not_persist_non_alert(tmp_path, monkeypatch):
    output_path = tmp_path / "incidents.jsonl"
    monkeypatch.setattr(
        "src.detector.predict.predict",
        lambda features: {
            "classification": "normal",
            "score": 12,
            "is_alert_triggered": False,
        },
    )

    incident = process_live_event(FLOW_EVENT, output_path)

    assert incident is None
    assert not output_path.exists()


def test_build_incident_includes_correlated_signature():
    incident = build_incident(
        FLOW_EVENT,
        ALERT_PREDICTION,
        suricata_signature="ET SCAN Potential Nmap port scan",
    )

    assert incident["suricata_signature"] == "ET SCAN Potential Nmap port scan"
    assert "ET SCAN Potential Nmap port scan" in incident["report"]


def test_process_live_event_threads_signature_into_incident(tmp_path, monkeypatch):
    output_path = tmp_path / "incidents.jsonl"
    monkeypatch.setattr(
        "src.detector.predict.predict",
        lambda features: ALERT_PREDICTION.copy(),
    )

    incident = process_live_event(
        FLOW_EVENT, output_path, suricata_signature="ET SCAN Test Signature"
    )

    assert incident["suricata_signature"] == "ET SCAN Test Signature"
    assert "ET SCAN Test Signature" in incident["report"]


def test_score_eve_file_correlates_signatures_and_survives_bad_lines(
    tmp_path, monkeypatch, capsys
):
    from src.detector import suricata_reader

    eve_path = tmp_path / "eve.json"
    eve_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_type": "flow",
                        "flow_id": 111,
                        "src_ip": "10.0.0.66",
                        "dest_ip": "10.0.0.1",
                        "dest_port": 80,
                        "proto": "TCP",
                        "flow": {"pkts_toserver": 2, "pkts_toclient": 1},
                    }
                ),
                json.dumps(
                    {
                        "event_type": "alert",
                        "flow_id": 111,
                        "alert": {"signature": "ET SCAN Test Signature"},
                    }
                ),
                json.dumps(
                    {
                        "event_type": "flow",
                        "flow_id": 222,
                        "src_ip": "10.0.0.9",
                        "dest_ip": "10.0.0.1",
                        "dest_port": 443,
                        "proto": "TCP",
                        "flow": {"pkts_toserver": 1, "pkts_toclient": 0},
                    }
                ),
                "{ this is not valid json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "src.detector.predict.predict_batch",
        lambda features_list: [ALERT_PREDICTION.copy() for _ in features_list],
    )

    suricata_reader.score_eve_file(eve_path)
    out = capsys.readouterr().out

    # flow 111 has a matching alert (order-independent); flow 222 does not.
    assert "ET SCAN Test Signature" in out
    assert "none reported for this flow" in out
    # One signature collected, one malformed JSON line skipped, both flows scored.
    assert "1 Suricata alert signatures collected" in out
    assert "1 malformed lines skipped" in out
    assert "2 flows scored, 2 crossed the threshold" in out
