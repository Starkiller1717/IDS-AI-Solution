"""
Generate a human-readable incident report from a structured attack event.

THE CONTRACT (freeze this early — Willow's dashboard depends on it):

    generate_report(event: dict) -> str

`event` is expected to contain (missing keys degrade gracefully):
    timestamp, attacker_ip, attacker_mac, attack_type, score, dest_port, proto,
    suricata_signature

BACKENDS
--------
- "template"  : fill-in-the-blanks, no AI. Always works, zero setup. DEFAULT.
- "ollama"    : local open model (e.g. llama3.1:8b) via the Ollama app. Free,
                offline, higher quality. Falls back to the template if Ollama
                isn't running, so the pipeline never breaks.

Switching to Claude later would be a third backend with the same signature.
"""

from __future__ import annotations

import json

from src.reporting import prompts


def generate_report(event: dict, backend: str = "template") -> str:
    """Produce a plain-language incident report. See module docstring for `event`."""
    if backend == "ollama":
        try:
            return _ollama_report(event)
        except Exception as exc:  # Ollama not installed/running, model missing, etc.
            print(f"[report] Ollama backend failed ({exc}); using template instead.")
            return _template_report(event)
    return _template_report(event)


# ---------------------------------------------------------------------------
# Backend 1: template (no AI). Build this first; it unblocks everyone else.
# ---------------------------------------------------------------------------
def _template_report(event: dict) -> str:
    ip = event.get("source_ip") or event.get("attacker_ip") or "an unknown address"
    mac = event.get("attacker_mac")
    attack_type = event.get("attack_type") or "high-risk network flow"
    score = event.get("score", "?")
    when = event.get("timestamp", "an unknown time")
    port = event.get("dest_port")
    proto = event.get("proto")
    signature = event.get("suricata_signature")

    observed_details = [
        f"- Source IP address: {ip}",
        f"- Reported activity: {attack_type}",
        f"- Model risk score: {score} out of 100",
    ]
    if signature:
        observed_details.append(f"- Associated Suricata signature: {signature}")
    else:
        observed_details.append("- Associated Suricata signature: none reported for this flow")
    if mac:
        observed_details.append(f"- Source MAC address: {mac}")
    if port is not None:
        observed_details.append(f"- Destination port: {port}")
    if proto:
        observed_details.append(f"- Protocol: {proto}")
    observed_details.append(f"- Time detected: {when}")

    return f"""\
Summary:
A {attack_type} was detected and flagged for human review.

What we saw:
{chr(10).join(observed_details)}

What this means for you:
The network flow matched patterns the detection model associates with attack
traffic. This alert does not prove malicious activity by itself and should be
reviewed alongside the related Suricata event and expected network activity.

Recommended actions:
- Verify whether you recognize the source IP address and destination service.
- Review related Suricata alerts and look for repeated or unexpected activity.
- Continue monitoring and escalate the incident if the activity cannot be explained.
- No automatic blocking or network lockdown was performed.
"""


# ---------------------------------------------------------------------------
# Backend 2: local LLM via Ollama. Same input, nicer prose.
# ---------------------------------------------------------------------------
def _ollama_report(event: dict, model: str = "llama3.1:8b") -> str:
    import ollama  # imported lazily so the template backend has zero dependencies

    user_prompt = prompts.REPORT_INSTRUCTIONS.format(
        event_json=json.dumps(event, indent=2, default=str)
    )
    response = ollama.chat(
        model=model,
        messages=[
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    return response["message"]["content"].strip()


if __name__ == "__main__":
    sample_event = {
        "timestamp": "2026-06-07T14:32:10",
        "attacker_ip": "10.0.0.66",
        "attacker_mac": "08:00:27:ab:cd:ef",
        "attack_type": "port scan",
        "score": 92,
        "dest_port": 22,
        "proto": "TCP",
    }
    print(generate_report(sample_event, backend="template"))
