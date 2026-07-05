"""Append structured incidents to a JSON Lines file."""

from __future__ import annotations

import json
from pathlib import Path

from src import config


DEFAULT_INCIDENTS_PATH = config.PROJECT_ROOT / "output" / "incidents.jsonl"


def append_incident(
    incident: dict,
    output_path: str | Path = DEFAULT_INCIDENTS_PATH,
) -> Path:
    """Append one JSON-serializable incident and return the destination path."""
    serialized = json.dumps(incident, ensure_ascii=False, allow_nan=False)
    path = Path(output_path)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as output_file:
        output_file.write(serialized + "\n")

    return path
