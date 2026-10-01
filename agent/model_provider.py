"""Explicit model-provider selection for the unsealed agent/narration layer."""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable


DEFAULT_GOOGLE_MODEL = "gemini-3.5-flash"
DEFAULT_OPENAI_MODEL = "gpt-6-astra"
_PROVIDERS = frozenset({"google", "openai"})
_OPENAI_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ModelConfigurationError(ValueError):
    """The requested narrative/agent provider cannot be used safely."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ModelConfigurationError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise ModelConfigurationError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ModelConfigurationError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class ModelConfiguration:
    """Public provider posture; credential material is deliberately absent."""

    provider: str
    model: str
    qualified_model: str
    backend: str
    available: bool
    credential_environment: str

    def public(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": self.model,
            "qualified_model": self.qualified_model,
            "backend": self.backend,
            "available": self.available,
            "credential_environment": self.credential_environment,
            "llm_in_decision_path": False,
        }


def model_configuration(
    environ: Mapping[str, str] | None = None,
) -> ModelConfiguration:
    """Resolve one explicit provider without retaining any credential value."""
    environment = os.environ if environ is None else environ
    if not isinstance(environment, Mapping):
        raise TypeError("environ must be a mapping")
    provider = environment.get("PANCITO_MODEL_PROVIDER", "google")
    if not isinstance(provider, str):
        raise ModelConfigurationError("PANCITO_MODEL_PROVIDER must contain text")
    provider = provider.strip().lower()
    if provider not in _PROVIDERS:
        raise ModelConfigurationError(
            "PANCITO_MODEL_PROVIDER must be one of: google, openai"
        )

    if provider == "openai":
        model = _text(
            environment.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL),
            "OPENAI_MODEL",
            128,
        )
        if not _OPENAI_MODEL_RE.fullmatch(model):
            raise ModelConfigurationError("OPENAI_MODEL is invalid")
        return ModelConfiguration(
            provider="openai",
            model=model,
            qualified_model=f"openai/{model}",
            backend="openai-api",
            available=bool(environment.get("OPENAI_API_KEY")),
            credential_environment="OPENAI_API_KEY",
        )

    model = _text(
        environment.get("annaconda_GEMINI_MODEL", DEFAULT_GOOGLE_MODEL),
        "annaconda_GEMINI_MODEL",
        128,
    )
    vertex = environment.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() == "TRUE"
    if vertex:
        available = bool(environment.get("GOOGLE_CLOUD_PROJECT"))
        backend = "vertex-ai"
        credential_environment = "GOOGLE_CLOUD_PROJECT"
    else:
        available = bool(
            environment.get("GEMINI_API_KEY") or environment.get("GOOGLE_API_KEY")
        )
        backend = "developer-api"
        credential_environment = "GEMINI_API_KEY or GOOGLE_API_KEY"
    return ModelConfiguration(
        provider="google",
        model=model,
        qualified_model=model,
        backend=backend,
        available=available,
        credential_environment=credential_environment,
    )


def _default_lite_llm_factory(*, model: str) -> Any:
    try:
        from google.adk.models.lite_llm import LiteLlm
    except ImportError as exc:
        raise ModelConfigurationError(
            "OpenAI provider requires the service dependencies: litellm and openai"
        ) from exc
    try:
        return LiteLlm(model=model)
    except ImportError as exc:
        raise ModelConfigurationError(
            "OpenAI provider requires the service dependencies: litellm and openai"
        ) from exc


def model_for_adk(
    environ: Mapping[str, str] | None = None,
    *,
    lite_llm_factory: Callable[..., Any] | None = None,
) -> Any:
    """Return the native Gemini id or ADK's OpenAI-capable LiteLLM adapter."""
    config = model_configuration(environ)
    # A native Google model identifier is safe to construct offline; ADK does
    # not contact the provider until a turn runs. OpenAI's adapter is gated here
    # because selecting it without its credential is a configuration error and
    # must not silently fall through to another provider.
    if config.provider == "openai" and not config.available:
        raise ModelConfigurationError(
            f"{config.provider} provider is unavailable: set "
            f"{config.credential_environment}"
        )
    if config.provider == "google":
        return config.model
    factory = lite_llm_factory or _default_lite_llm_factory
    return factory(model=config.qualified_model)


def model_reachable(environ: Mapping[str, str] | None = None) -> bool:
    try:
        return model_configuration(environ).available
    except ModelConfigurationError:
        return False


def model_id(environ: Mapping[str, str] | None = None) -> str:
    return model_configuration(environ).model


def model_provider(environ: Mapping[str, str] | None = None) -> str:
    return model_configuration(environ).provider


def model_unavailable_message(environ: Mapping[str, str] | None = None) -> str:
    try:
        config = model_configuration(environ)
    except ModelConfigurationError as exc:
        return f"invalid model configuration: {exc}"
    if config.available:
        return "model provider is available"
    return (
        f"{config.provider} provider is unavailable: set "
        f"{config.credential_environment}"
    )
