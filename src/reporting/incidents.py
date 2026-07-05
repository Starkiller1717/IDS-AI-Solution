"""Build a consistent incident record from a scored Suricata flow."""

from __future__ import annotations

from src.reporting.report import generate_report


INCIDENT_SCHEMA_VERSION = "1.0"
DEFAULT_ATTACK_TYPE = "high-risk network flow"


def build_incident(
    flow_event: dict,
    prediction: dict,
    suricata_signature: str | None = None,
) -> dict | None:
    """Return a structured incident for an alert, or ``None`` otherwise.

    ``suricata_signature`` is the name of any Suricata alert correlated to this flow
    (by ``flow_id``); it stays ``None`` when Suricata did not also flag the flow.
    """
    if not prediction.get("is_alert_triggered", False):
        return None

    report_event = {
        "attack_type": DEFAULT_ATTACK_TYPE,
        "score": prediction.get("score"),
        "suricata_signature": suricata_signature,
    }
    optional_report_fields = {
        "timestamp": flow_event.get("timestamp"),
        "source_ip": flow_event.get("src_ip"),
        "dest_port": flow_event.get("dest_port"),
        "proto": flow_event.get("proto"),
    }
    report_event.update(
        {
            key: value
            for key, value in optional_report_fields.items()
            if value is not None
        }
    )

    return {
        "schema_version": INCIDENT_SCHEMA_VERSION,
        "timestamp": flow_event.get("timestamp"),
        "source_ip": flow_event.get("src_ip"),
        "destination_ip": flow_event.get("dest_ip"),
        "destination_port": flow_event.get("dest_port"),
        "protocol": flow_event.get("proto"),
        "classification": prediction.get("classification"),
        "ml_score": prediction.get("score"),
        "alert_triggered": True,
        "attack_type": DEFAULT_ATTACK_TYPE,
        "suricata_signature": suricata_signature,
        "report": generate_report(report_event, backend="template"),
        "automated_block_performed": False,
    }
