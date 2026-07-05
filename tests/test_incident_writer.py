"""Tests for the standalone JSON Lines incident writer."""

import json

from src.reporting.incident_writer import append_incident


def _read_incidents(path):
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return [json.loads(line) for line in lines]


def test_append_incident_creates_nested_parent_directories(tmp_path):
    output_path = tmp_path / "nested" / "incident-data" / "incidents.jsonl"
    incident = {"attack_type": "port scan", "score": 91}

    written_path = append_incident(incident, output_path)

    assert written_path == output_path
    assert output_path.parent.is_dir()
    assert _read_incidents(output_path) == [incident]


def test_append_incident_preserves_existing_records(tmp_path):
    output_path = tmp_path / "incidents.jsonl"
    first = {"id": 1, "attack_type": "port scan"}
    second = {"id": 2, "attack_type": "denial of service"}

    append_incident(first, output_path)
    append_incident(second, output_path)

    assert _read_incidents(output_path) == [first, second]


def test_each_line_is_valid_json_and_preserves_unicode_and_newlines(tmp_path):
    output_path = tmp_path / "incidents.jsonl"
    incidents = [
        {
            "id": 1,
            "summary": "Café traffic from Montréal\nSecond report line",
        },
        {
            "id": 2,
            "summary": "Suspicious payload: 漢字",
        },
    ]

    for incident in incidents:
        append_incident(incident, output_path)

    contents = output_path.read_text(encoding="utf-8")
    lines = [line for line in contents.splitlines() if line.strip()]

    assert contents.endswith("\n")
    assert len(lines) == len(incidents)
    assert [json.loads(line) for line in lines] == incidents
    assert "Café" in contents
    assert "\\n" in contents
