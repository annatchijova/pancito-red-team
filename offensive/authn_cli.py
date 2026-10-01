"""Strict manifest and CLI boundary for the loopback authentication experiment."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from offensive.authn import AuthnPlan, AuthnPlanError, run_authn_experiment
from offensive.bola import BearerCredential
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError


_MAX_MANIFEST_BYTES = 65_536
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "authorization_reference",
        "authorized_by",
        "operator_acknowledged",
        "target_origin",
        "protected_path",
        "valid_principal_id",
        "valid_token_env",
        "protected_canary_env",
        "invalid_bearer_env",
        "timeout_ms",
        "max_response_bytes",
    }
)


class AuthnManifestError(ValueError):
    """The manifest, secret references, or local file boundary is invalid."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuthnManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise AuthnManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise AuthnManifestError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise AuthnManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise AuthnManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthnManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class AuthnManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    protected_path: str
    valid_principal_id: str
    valid_token_env: str
    protected_canary_env: str
    invalid_bearer_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, str, str]:
        return (
            self.valid_token_env,
            self.protected_canary_env,
            self.invalid_bearer_env,
        )


@dataclass(frozen=True)
class ResolvedAuthnSecrets:
    valid_token: SecretValue = field(repr=False)
    protected_canary: SecretValue = field(repr=False)
    invalid_bearer: SecretValue = field(repr=False)


def parse_authn_manifest(raw: bytes) -> AuthnManifest:
    """Parse bounded UTF-8 JSON and reject unknown or ambiguous configuration."""
    if not isinstance(raw, bytes):
        raise TypeError("authentication manifest must be bytes")
    if not raw:
        raise AuthnManifestError("authentication manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise AuthnManifestError(
            f"authentication manifest exceeds {_MAX_MANIFEST_BYTES} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthnManifestError("authentication manifest must be UTF-8 JSON") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except AuthnManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise AuthnManifestError(f"invalid authentication manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AuthnManifestError("authentication manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise AuthnManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise AuthnManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise AuthnManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise AuthnManifestError("operator_acknowledged must be literal true")

    experiment_id = _text(data, "experiment_id", 128)
    principal_id = _text(data, "valid_principal_id", 128)
    if not _ID_RE.fullmatch(experiment_id):
        raise AuthnManifestError(
            "experiment_id must match [A-Za-z0-9._-]{1,128}"
        )
    if not _ID_RE.fullmatch(principal_id):
        raise AuthnManifestError(
            "valid_principal_id must match [A-Za-z0-9._-]{1,128}"
        )

    environment_names = tuple(
        _text(data, name, 128)
        for name in (
            "valid_token_env",
            "protected_canary_env",
            "invalid_bearer_env",
        )
    )
    if any(not _ENV_NAME_RE.fullmatch(name) for name in environment_names):
        raise AuthnManifestError(
            "secret environment names must match [A-Z][A-Z0-9_]{0,127}"
        )
    if len(set(environment_names)) != len(environment_names):
        raise AuthnManifestError("secret environment names must be distinct")

    timeout_ms = data["timeout_ms"]
    maximum = data["max_response_bytes"]
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
        raise AuthnManifestError("timeout_ms must be an integer")
    if isinstance(maximum, bool) or not isinstance(maximum, int):
        raise AuthnManifestError("max_response_bytes must be an integer")

    manifest = AuthnManifest(
        schema_version=1,
        experiment_id=experiment_id,
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        protected_path=_text(data, "protected_path", 2_048),
        valid_principal_id=principal_id,
        valid_token_env=environment_names[0],
        protected_canary_env=environment_names[1],
        invalid_bearer_env=environment_names[2],
        timeout_ms=timeout_ms,
        max_response_bytes=maximum,
    )
    try:
        _build_plan(
            manifest,
            ResolvedAuthnSecrets(
                valid_token=SecretValue("manifest-validation-valid-token"),
                protected_canary=SecretValue("MANIFEST-VALIDATION-PROTECTED-CANARY"),
                invalid_bearer=SecretValue("manifest-validation-invalid-bearer"),
            ),
        )
    except AuthnPlanError as exc:
        raise AuthnManifestError(str(exc)) from exc
    return manifest


def read_authn_manifest(path: str | Path) -> AuthnManifest:
    """Read a bounded regular file without following a final-component symlink."""
    try:
        raw = read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_MANIFEST_BYTES,
            label="authentication manifest",
        )
    except LocalArtifactError as exc:
        raise AuthnManifestError(str(exc)) from exc
    return parse_authn_manifest(raw)


def resolve_authn_secrets(
    manifest: AuthnManifest, environ: Mapping[str, str]
) -> ResolvedAuthnSecrets:
    """Resolve all required values atomically; there is no partial fallback."""
    if not isinstance(manifest, AuthnManifest):
        raise TypeError("manifest must be an AuthnManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise AuthnManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    resolved: list[SecretValue] = []
    for name in manifest.secret_environment_names:
        value = environ[name]
        if not isinstance(value, str):
            raise AuthnManifestError(f"environment variable {name} must contain text")
        try:
            resolved.append(SecretValue(value))
        except SecretValueError as exc:
            raise AuthnManifestError(f"environment variable {name} is invalid") from exc
    revealed = [item.reveal() for item in resolved]
    if len(set(revealed)) != len(revealed):
        raise AuthnManifestError("resolved token, canary, and invalid bearer must be distinct")
    return ResolvedAuthnSecrets(
        valid_token=resolved[0],
        protected_canary=resolved[1],
        invalid_bearer=resolved[2],
    )


def _build_plan(manifest: AuthnManifest, secrets: ResolvedAuthnSecrets) -> AuthnPlan:
    return AuthnPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        protected_path=manifest.protected_path,
        protected_canary=secrets.protected_canary.reveal(),
        invalid_bearer=secrets.invalid_bearer.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def preflight_authn_manifest(
    manifest: AuthnManifest, secrets: ResolvedAuthnSecrets
) -> dict[str, object]:
    """Validate an executable plan while performing exactly zero requests."""
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "target_origin": manifest.target_origin,
        "authorization_reference": manifest.authorization_reference,
        "secret_sources": list(manifest.secret_environment_names),
        "request_count": 0,
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def execute_authn_manifest(
    manifest: AuthnManifest, secrets: ResolvedAuthnSecrets
) -> dict[str, object]:
    """Execute only after the manifest and every secret have passed validation."""
    plan = _build_plan(manifest, secrets)
    valid = BearerCredential(
        manifest.valid_principal_id, secrets.valid_token.reveal()
    )
    return run_authn_experiment(plan, valid=valid)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-authn",
        description=(
            "Run a bounded authentication-enforcement differential against loopback."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict JSON experiment manifest")
    args = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        manifest = read_authn_manifest(args.manifest)
        secrets = resolve_authn_secrets(manifest, environment)
        result = (
            preflight_authn_manifest(manifest, secrets)
            if args.dry_run
            else execute_authn_manifest(manifest, secrets)
        )
    except (AuthnManifestError, AuthnPlanError) as exc:
        print(f"PANCITO_AUTHN_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
