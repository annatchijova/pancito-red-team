"""OpenAI is an unsealed narrator, selected explicitly and kept secret-free."""

from __future__ import annotations

import sys
from types import SimpleNamespace


def test_openai_responses_api_narrates_only_an_already_sealed_verdict(
    monkeypatch,
):
    from service import app as service_app

    key_canary = "sk-openai-narration-canary"
    calls = []

    class FakeResponses:
        def create(self, *, model, input):
            calls.append({"model": model, "input": input})
            return SimpleNamespace(output_text="MALICE, score 3/4, T1055.")

    class FakeOpenAI:
        def __init__(self):
            self.responses = FakeResponses()

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    monkeypatch.setenv("PANCITO_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", key_canary)
    monkeypatch.setenv("OPENAI_MODEL", "gpt-6-astra")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "TRUE")

    result = service_app._faithful_narrate(
        {"state": "MALICE", "score": "3/4", "mitre_techniques": ["T1055"]}
    )

    assert result == "MALICE, score 3/4, T1055."
    assert calls == [{
        "model": "gpt-6-astra",
        "input": (
            "Report this SEALED forensic verdict to the analyst in one sentence. "
            "It is final and you must report it exactly, not reinterpret it.\n"
            "State: MALICE. Score: 3/4. MITRE: T1055."
        ),
    }]
    assert key_canary not in repr(calls)


def test_health_reports_openai_posture_without_exposing_the_key(monkeypatch):
    from service import app as service_app

    key_canary = "sk-openai-health-canary"
    monkeypatch.setenv("PANCITO_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", key_canary)
    monkeypatch.setenv("OPENAI_MODEL", "gpt-6-astra")

    health = service_app.health()

    assert health["model_provider"] == "openai"
    assert health["model"] == "gpt-6-astra"
    assert health["model_backend"] == "openai-api"
    assert health["model_available"] is True
    assert health["vertex_ai"] is False
    assert health["llm_in_decision_path"] is False
    assert key_canary not in repr(health)


def test_invalid_provider_degrades_health_honestly(monkeypatch):
    from service import app as service_app

    monkeypatch.setenv("PANCITO_MODEL_PROVIDER", "auto")

    health = service_app.health()

    assert health["model_provider"] == "invalid"
    assert health["model_available"] is False
    assert health["commander_planner"] == "deterministic-fallback"
