"""Build a consistent incident record from a scored Suricata flow."""

from __future__ import annotations

from src import config
from src.reporting.report import generate_report


INCIDENT_SCHEMA_VERSION = "1.0"
DEFAULT_ATTACK_TYPE = "high-risk network flow"


def _attack_type_from_signature(signature: str) -> str:
    """Turn a raw Suricata signature into a short, human-readable attack type.

    Suricata signatures conventionally lead with an all-caps ruleset/category
    tag (e.g. "ET SCAN", "LOCAL SCAN") followed by a plain-language
    description, optionally with further detail after a " - ". Strip the tag
    and any trailing detail so the report can say what actually happened
    (e.g. "potential TCP port scan") instead of a generic label.
    """
    words = signature.split()
    i = 0
    while i < len(words) and words[i].isupper():
        i += 1
    description = " ".join(words[i:]) or signature
    description = description.split(" - ", 1)[0]
    return description[0].lower() + description[1:] if description else description


def build_incident(
    flow_event: dict,
    prediction: dict,
    suricata_signature: str | None = None,
    backend: str | None = None,
) -> dict | None:
    """Return a structured incident for an alert, or ``None`` otherwise.

    ``suricata_signature`` is the name of any Suricata alert correlated to this flow
    (by ``flow_id``); it stays ``None`` when Suricata did not also flag the flow.

    ``backend`` selects the report generator (``"ollama"`` or ``"template"``);
    it defaults to ``config.REPORT_BACKEND`` so the whole pipeline switches
    backends from one place.

    An incident is built when EITHER the ML model crosses its high-priority alert
    threshold OR Suricata itself correlated a signature to this flow. A single-flow
    ML classifier can't see scan-shaped behavior across many flows the way a
    threshold-based Suricata rule can, so a Suricata-native detection is treated as
    its own sufficient basis for an incident, not just a decoration on an ML alert.
    """
    if not prediction.get("is_alert_triggered", False) and suricata_signature is None:
        return None

    attack_type = (
        _attack_type_from_signature(suricata_signature)
        if suricata_signature
        else DEFAULT_ATTACK_TYPE
    )

    report_event = {
        "attack_type": attack_type,
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
        "attack_type": attack_type,
        "suricata_signature": suricata_signature,
        "report": generate_report(report_event, backend=backend or config.REPORT_BACKEND),
        "automated_block_performed": False,
    }
