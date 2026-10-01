"""Model-provider selection is explicit, secret-free, and outside the verdict."""

from __future__ import annotations

import json

import pytest

from agent.model_provider import (
    ModelConfigurationError,
    model_configuration,
    model_for_adk,
    model_reachable,
)


OPENAI_KEY_CANARY = "sk-openai-provider-canary-must-never-leak"


def test_default_provider_remains_google_even_when_both_keys_exist():
    environment = {
        "GEMINI_API_KEY": "google-key-canary",
        "OPENAI_API_KEY": OPENAI_KEY_CANARY,
    }

    config = model_configuration(environment)

    assert config.provider == "google"
    assert config.model == "gemini-3.5-flash"
    assert config.available is True
    assert config.backend == "developer-api"


def test_openai_selection_is_explicit_and_public_posture_never_contains_key():
    environment = {
        "PANCITO_MODEL_PROVIDER": "openai",
        "OPENAI_API_KEY": OPENAI_KEY_CANARY,
        "OPENAI_MODEL": "gpt-6-astra",
    }

    config = model_configuration(environment)
    serialized = json.dumps(config.public(), sort_keys=True)

    assert config.provider == "openai"
    assert config.model == "gpt-6-astra"
    assert config.qualified_model == "openai/gpt-6-astra"
    assert config.available is True
    assert config.credential_environment == "OPENAI_API_KEY"
    assert OPENAI_KEY_CANARY not in repr(config)
    assert OPENAI_KEY_CANARY not in serialized
    assert config.public()["llm_in_decision_path"] is False


def test_openai_model_build_uses_provider_prefix_without_receiving_the_key():
    environment = {
        "PANCITO_MODEL_PROVIDER": "openai",
        "OPENAI_API_KEY": OPENAI_KEY_CANARY,
        "OPENAI_MODEL": "gpt-6-astra",
    }
    calls = []

    def factory(*, model):
        calls.append(model)
        return {"adapter": "litellm", "model": model}

    result = model_for_adk(environment, lite_llm_factory=factory)

    assert result == {"adapter": "litellm", "model": "openai/gpt-6-astra"}
    assert calls == ["openai/gpt-6-astra"]
    assert OPENAI_KEY_CANARY not in repr(result)


def test_missing_openai_key_fails_closed_before_adapter_construction():
    environment = {"PANCITO_MODEL_PROVIDER": "openai"}
    called = False

    def factory(*, model):
        nonlocal called
        called = True
        return model

    assert model_reachable(environment) is False
    with pytest.raises(ModelConfigurationError, match="OPENAI_API_KEY"):
        model_for_adk(environment, lite_llm_factory=factory)
    assert called is False


@pytest.mark.parametrize(
    "environment,match",
    [
        ({"PANCITO_MODEL_PROVIDER": "unknown"}, "must be one of"),
        (
            {
                "PANCITO_MODEL_PROVIDER": "openai",
                "OPENAI_API_KEY": "present",
                "OPENAI_MODEL": "openai/gpt-6-astra",
            },
            "OPENAI_MODEL is invalid",
        ),
    ],
)
def test_invalid_provider_or_model_is_rejected_at_configuration_boundary(
    environment, match
):
    with pytest.raises(ModelConfigurationError, match=match):
        model_configuration(environment)


def test_google_model_remains_a_native_adk_identifier():
    environment = {
        "PANCITO_MODEL_PROVIDER": "google",
        "GEMINI_API_KEY": "google-key-canary",
        "annaconda_GEMINI_MODEL": "gemini-3.5-flash",
    }

    assert model_for_adk(environment) == "gemini-3.5-flash"
