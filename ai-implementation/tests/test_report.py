"""Tests for the incident-report generator (no model or dataset needed)."""

import sys
import types

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


def test_report_states_suricata_signature_status():
    with_sig = generate_report(
        {"score": 97, "suricata_signature": "ET SCAN Potential Nmap port scan"},
        backend="template",
    )
    assert "Associated Suricata signature: ET SCAN Potential Nmap port scan" in with_sig

    without_sig = generate_report({"score": 97}, backend="template")
    assert "none reported for this flow" in without_sig


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


def test_ollama_backend_sends_prompt_and_returns_model_output(monkeypatch):
    """generate_report(backend="ollama") should call ollama.chat with the event
    data embedded in the prompt and return its (trimmed) response, without
    needing the real `ollama` package or a running server."""
    captured = {}

    def fake_chat(model, messages):
        captured["model"] = model
        captured["messages"] = messages
        return {
            "message": {
                "content": "  A calm plain-language report.\n\n"
                "No automatic blocking or network lockdown was performed.  "
            }
        }

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(chat=fake_chat))

    report = generate_report(SAMPLE_EVENT, backend="ollama")

    assert report == (
        "A calm plain-language report.\n\n"
        "No automatic blocking or network lockdown was performed."
    )
    assert captured["model"] == "llama3.2:3b"
    assert captured["messages"][0]["role"] == "system"
    assert captured["messages"][1]["role"] == "user"
    assert "10.0.0.66" in captured["messages"][1]["content"]


def test_ollama_backend_appends_disclaimer_if_model_omits_it(monkeypatch):
    """The no-automatic-blocking line is mandatory, not a suggestion (see
    Documents/PROGRESS.md) -- enforce it in code, since LLM instruction-following
    isn't guaranteed even with an explicit prompt request."""
    monkeypatch.setitem(
        sys.modules,
        "ollama",
        types.SimpleNamespace(
            chat=lambda model, messages: {"message": {"content": "Everything is fine now."}}
        ),
    )

    report = generate_report(SAMPLE_EVENT, backend="ollama")

    assert report == (
        "Everything is fine now.\n\n"
        "No automatic blocking or network lockdown was performed."
    )


def test_ollama_backend_falls_back_to_template_when_chat_fails(monkeypatch, capsys):
    """If Ollama is installed but errors at call time (e.g. the app isn't
    running), the pipeline must still produce a usable report, not crash."""

    def fake_chat(model, messages):
        raise ConnectionError("Ollama is not running")

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(chat=fake_chat))

    report = generate_report(SAMPLE_EVENT, backend="ollama")

    assert "Summary:" in report
    assert "10.0.0.66" in report
    assert "Ollama backend failed" in capsys.readouterr().out


def test_ollama_backend_falls_back_when_package_not_installed(monkeypatch, capsys):
    """Same safety net when the `ollama` package itself isn't installed at all
    (the state of this dev machine) -- `import ollama` raises ImportError."""
    monkeypatch.setitem(sys.modules, "ollama", None)

    report = generate_report(SAMPLE_EVENT, backend="ollama")

    assert "Summary:" in report
    assert "Ollama backend failed" in capsys.readouterr().out


def test_default_backend_is_ollama_with_automatic_fallback(monkeypatch, capsys):
    """generate_report()'s default backend should be config.REPORT_BACKEND
    ("ollama"), not silently stuck on template."""
    monkeypatch.setitem(sys.modules, "ollama", None)

    report = generate_report(SAMPLE_EVENT)

    assert "Ollama backend failed" in capsys.readouterr().out
    assert "Summary:" in report
