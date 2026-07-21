"""
Tests for the Suricata-flow -> features mapping.

These do NOT need a trained model — they only check the feature translation,
which is the part most likely to silently break during integration.
"""

import math

from src import config
from src.detector.suricata_reader import _num, extract_signature, flow_to_features

# A made-up "port scan"-style flow: one tiny packet out, nothing back.
SCAN_FLOW = {
    "event_type": "flow",
    "src_ip": "10.0.0.66",
    "dest_ip": "10.0.0.1",
    "dest_port": 22,
    "proto": "TCP",
    "flow": {
        "pkts_toserver": 1,
        "pkts_toclient": 0,
        "bytes_toserver": 40,
        "bytes_toclient": 0,
        "start": "2026-06-07T14:32:10.000000+0000",
        "end": "2026-06-07T14:32:10.001000+0000",
    },
}


def test_mapping_produces_every_required_feature():
    feats = flow_to_features(SCAN_FLOW)
    # The model will break at runtime if any expected feature is missing.
    for name in config.SURICATA_ALIGNED_FEATURES:
        assert name in feats, f"mapping is missing feature: {name}"


def test_mapping_values_are_sensible():
    feats = flow_to_features(SCAN_FLOW)
    assert feats["Destination Port"] == 22
    assert feats["Total Fwd Packets"] == 1
    assert feats["Total Backward Packets"] == 0
    assert feats["Total Length of Fwd Packets"] == 40
    # 0.001 s duration -> 1000 microseconds
    assert feats["Flow Duration"] == 1000.0


def test_zero_duration_does_not_divide_by_zero():
    flow = {"event_type": "flow", "dest_port": 80, "flow": {"pkts_toserver": 1}}
    feats = flow_to_features(flow)  # start/end missing -> duration 0
    assert feats["Flow Bytes/s"] == 0.0
    assert feats["Flow Packets/s"] == 0.0


def test_null_and_string_counters_do_not_crash():
    # A malformed flow with null / string / bad counters must score as zeros,
    # not raise, so one bad event can't terminate live processing.
    flow = {
        "event_type": "flow",
        "dest_port": None,
        "flow": {
            "pkts_toserver": None,
            "pkts_toclient": "oops",
            "bytes_toserver": None,
            "bytes_toclient": 40,
            "start": 12345,          # non-string timestamp
            "end": None,
        },
    }
    feats = flow_to_features(flow)
    for name in config.SURICATA_ALIGNED_FEATURES:
        assert name in feats
    assert feats["Destination Port"] == 0.0
    assert feats["Total Fwd Packets"] == 0.0
    assert feats["Total Backward Packets"] == 0.0
    assert feats["Total Length of Bwd Packets"] == 40.0
    assert feats["Flow Duration"] == 0.0


def test_num_rejects_non_finite_numeric_values():
    assert _num(float("nan")) == 0.0
    assert _num(float("inf")) == 0.0
    assert _num(float("-inf")) == 0.0


def test_num_rejects_non_finite_string_values():
    # json.loads() turns tokens like NaN/Infinity into these string forms too.
    assert _num("NaN") == 0.0
    assert _num("Infinity") == 0.0
    assert _num("-Infinity") == 0.0


def test_non_finite_counters_score_as_zero_not_nan():
    flow = {
        "event_type": "flow",
        "dest_port": float("nan"),
        "flow": {
            "pkts_toserver": float("inf"),
            "pkts_toclient": "NaN",
            "bytes_toserver": "-Infinity",
            "bytes_toclient": 40,
        },
    }
    feats = flow_to_features(flow)
    for value in feats.values():
        assert math.isfinite(value)
    assert feats["Destination Port"] == 0.0
    assert feats["Total Fwd Packets"] == 0.0
    assert feats["Total Backward Packets"] == 0.0
    assert feats["Total Length of Fwd Packets"] == 0.0
    assert feats["Total Length of Bwd Packets"] == 40.0


def test_non_dict_flow_object_does_not_crash():
    for broken in ({"event_type": "flow", "flow": None},
                   {"event_type": "flow", "flow": "not-an-object"},
                   {"event_type": "flow"}):
        feats = flow_to_features(broken)
        assert feats["Total Fwd Packets"] == 0.0
        assert feats["Flow Bytes/s"] == 0.0


def test_extract_signature_reads_alert_events_only():
    alert = {
        "event_type": "alert",
        "alert": {"signature": "ET SCAN Potential Nmap port scan"},
    }
    assert extract_signature(alert) == "ET SCAN Potential Nmap port scan"
    # Flow events, missing/empty alert objects -> no signature.
    assert extract_signature({"event_type": "flow"}) is None
    assert extract_signature({"alert": None}) is None
    assert extract_signature({"alert": {}}) is None


def test_extract_signature_excludes_low_severity_informational_alerts():
    # Severity 3 (Suricata's lowest tier) is informational noise -- e.g. "ET INFO"
    # traffic like Spotify P2P chatter -- and must not surface as a correlated
    # signature now that a signature alone is enough to trigger an incident.
    noisy_alert = {
        "event_type": "alert",
        "alert": {"signature": "ET INFO Spotify P2P Client", "severity": 3},
    }
    assert extract_signature(noisy_alert) is None

    scan_alert = {
        "event_type": "alert",
        "alert": {"signature": "LOCAL SCAN Potential TCP port scan", "severity": 2},
    }
    assert extract_signature(scan_alert) == "LOCAL SCAN Potential TCP port scan"
