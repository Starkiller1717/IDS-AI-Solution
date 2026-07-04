"""Tests for the incident-report generator (no model or dataset needed)."""

from src.reporting.report import generate_report

SAMPLE_EVENT = {
    "timestamp": "2026-06-07T14:32:10",
    "attacker_ip": "10.0.0.66",
    "attacker_mac": "08:00:27:ab:cd:ef",
    "attack_type": "port scan",
    "score": 92,
    "dest_port": 22,
    "proto": "TCP",
}


def test_template_report_includes_key_facts():
    report = generate_report(SAMPLE_EVENT, backend="template")
    # The design doc (TC-10) requires attacker IP, attack type, and actions.
    assert "10.0.0.66" in report
    assert "port scan" in report
    assert "Recommended actions" in report
    assert "92" in report
    assert "Source MAC address: 08:00:27:ab:cd:ef" in report


def test_report_handles_missing_fields_gracefully():
    # Even with an almost-empty event, it should not crash.
    report = generate_report({"score": 80}, backend="template")
    assert "Summary" in report
    assert "80" in report
    assert "Source MAC address" not in report


def test_report_does_not_claim_automatic_containment_or_external_source():
    report = generate_report(
        {
            "timestamp": "2026-07-04T12:00:00",
            "source_ip": "10.0.0.45",
            "attack_type": "high-risk network flow",
            "score": 97,
            "dest_port": 443,
            "proto": "TCP",
        },
        backend="template",
    )
    lowered = report.lower()

    assert "source ip address: 10.0.0.45" in lowered
    assert "outside" not in lowered
    assert "keep it blocked" not in lowered
    assert "leave the lockdown on" not in lowered
    assert "no automatic blocking or network lockdown was performed" in lowered
