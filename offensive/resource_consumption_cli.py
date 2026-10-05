"""Strict manifest and CLI boundary for the loopback resource-consumption experiment."""

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

from offensive.bola import BearerCredential
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.resource_consumption import (
    ResourceConsumptionPlan,
    ResourceConsumptionPlanError,
    run_resource_consumption_experiment,
)
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
        "probed_path",
        "valid_principal_id",
        "valid_token_env",
        "success_canary_env",
        "declared_limit",
        "control_requests",
        "probe_requests",
        "timeout_ms",
        "max_response_bytes",
    }
)
_INTEGER_FIELDS = (
    "schema_version",
    "declared_limit",
    "control_requests",
    "probe_requests",
    "timeout_ms",
    "max_response_bytes",
)


class ResourceConsumptionManifestError(ValueError):
    """The manifest, secret references, or local file boundary is invalid."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ResourceConsumptionManifestError(
            f"{name} must be non-empty text without outer whitespace")
    if len(value) > maximum:
        raise ResourceConsumptionManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ResourceConsumptionManifestError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise ResourceConsumptionManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise ResourceConsumptionManifestError(
        f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ResourceConsumptionManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _integer(data: dict[str, Any], name: str) -> int:
    value = data.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResourceConsumptionManifestError(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class ResourceConsumptionManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    probed_path: str
    valid_principal_id: str
    valid_token_env: str
    success_canary_env: str
    declared_limit: int
    control_requests: int
    probe_requests: int
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, str]:
        return (self.valid_token_env, self.success_canary_env)


@dataclass(frozen=True)
class ResolvedResourceConsumptionSecrets:
    valid_token: SecretValue = field(repr=False)
    success_canary: SecretValue = field(repr=False)


def parse_resource_consumption_manifest(raw: bytes) -> ResourceConsumptionManifest:
    """Parse bounded UTF-8 JSON and reject unknown or ambiguous configuration."""
    if not isinstance(raw, bytes):
        raise TypeError("resource-consumption manifest must be bytes")
    if not raw:
        raise ResourceConsumptionManifestError(
            "resource-consumption manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ResourceConsumptionManifestError(
            f"resource-consumption manifest exceeds {_MAX_MANIFEST_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ResourceConsumptionManifestError(
            "resource-consumption manifest must be UTF-8 JSON") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ResourceConsumptionManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise ResourceConsumptionManifestError(
            f"invalid resource-consumption manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ResourceConsumptionManifestError(
            "resource-consumption manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise ResourceConsumptionManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise ResourceConsumptionManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise ResourceConsumptionManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise ResourceConsumptionManifestError("operator_acknowledged must be literal true")

    experiment_id = _text(data, "experiment_id", 128)
    principal_id = _text(data, "valid_principal_id", 128)
    if not _ID_RE.fullmatch(experiment_id):
        raise ResourceConsumptionManifestError(
            "experiment_id must match [A-Za-z0-9._-]{1,128}")
    if not _ID_RE.fullmatch(principal_id):
        raise ResourceConsumptionManifestError(
            "valid_principal_id must match [A-Za-z0-9._-]{1,128}")

    environment_names = tuple(
        _text(data, name, 128)
        for name in ("valid_token_env", "success_canary_env")
    )
    if any(not _ENV_NAME_RE.fullmatch(name) for name in environment_names):
        raise ResourceConsumptionManifestError(
            "secret environment names must match [A-Z][A-Z0-9_]{0,127}")
    if len(set(environment_names)) != len(environment_names):
        raise ResourceConsumptionManifestError("secret environment names must be distinct")

    integers = {name: _integer(data, name) for name in _INTEGER_FIELDS}

    manifest = ResourceConsumptionManifest(
        schema_version=1,
        experiment_id=experiment_id,
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        probed_path=_text(data, "probed_path", 2_048),
        valid_principal_id=principal_id,
        valid_token_env=environment_names[0],
        success_canary_env=environment_names[1],
        declared_limit=integers["declared_limit"],
        control_requests=integers["control_requests"],
        probe_requests=integers["probe_requests"],
        timeout_ms=integers["timeout_ms"],
        max_response_bytes=integers["max_response_bytes"],
    )
    try:
        _build_plan(
            manifest,
            ResolvedResourceConsumptionSecrets(
                valid_token=SecretValue("manifest-validation-valid-token"),
                success_canary=SecretValue("MANIFEST-VALIDATION-SUCCESS-CANARY"),
            ),
        )
    except ResourceConsumptionPlanError as exc:
        raise ResourceConsumptionManifestError(str(exc)) from exc
    return manifest


def read_resource_consumption_manifest(path: str | Path) -> ResourceConsumptionManifest:
    """Read a bounded regular file without following a final-component symlink."""
    try:
        raw = read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_MANIFEST_BYTES,
            label="resource-consumption manifest",
        )
    except LocalArtifactError as exc:
        raise ResourceConsumptionManifestError(str(exc)) from exc
    return parse_resource_consumption_manifest(raw)


def resolve_resource_consumption_secrets(
    manifest: ResourceConsumptionManifest, environ: Mapping[str, str]
) -> ResolvedResourceConsumptionSecrets:
    """Resolve all required values atomically; there is no partial fallback."""
    if not isinstance(manifest, ResourceConsumptionManifest):
        raise TypeError("manifest must be a ResourceConsumptionManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise ResourceConsumptionManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing))
    resolved: list[SecretValue] = []
    for name in manifest.secret_environment_names:
        value = environ[name]
        if not isinstance(value, str):
            raise ResourceConsumptionManifestError(
                f"environment variable {name} must contain text")
        try:
            resolved.append(SecretValue(value))
        except SecretValueError as exc:
            raise ResourceConsumptionManifestError(
                f"environment variable {name} is invalid") from exc
    revealed = [item.reveal() for item in resolved]
    if len(set(revealed)) != len(revealed):
        raise ResourceConsumptionManifestError(
            "resolved token and success canary must be distinct")
    return ResolvedResourceConsumptionSecrets(
        valid_token=resolved[0],
        success_canary=resolved[1],
    )


def _build_plan(
    manifest: ResourceConsumptionManifest,
    secrets: ResolvedResourceConsumptionSecrets,
) -> ResourceConsumptionPlan:
    return ResourceConsumptionPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        probed_path=manifest.probed_path,
        success_canary=secrets.success_canary.reveal(),
        declared_limit=manifest.declared_limit,
        control_requests=manifest.control_requests,
        probe_requests=manifest.probe_requests,
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def preflight_resource_consumption_manifest(
    manifest: ResourceConsumptionManifest,
    secrets: ResolvedResourceConsumptionSecrets,
) -> dict[str, object]:
    """Validate an executable plan while performing exactly zero requests."""
    plan = _build_plan(manifest, secrets)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "target_origin": manifest.target_origin,
        "authorization_reference": manifest.authorization_reference,
        "secret_sources": list(manifest.secret_environment_names),
        "declared_limit": manifest.declared_limit,
        "request_count": 0,
        "maximum_request_count": plan.maximum_request_count,
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def execute_resource_consumption_manifest(
    manifest: ResourceConsumptionManifest,
    secrets: ResolvedResourceConsumptionSecrets,
) -> dict[str, object]:
    """Execute only after the manifest and every secret have passed validation."""
    plan = _build_plan(manifest, secrets)
    valid = BearerCredential(manifest.valid_principal_id, secrets.valid_token.reveal())
    return run_resource_consumption_experiment(plan, valid=valid)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-resource-consumption",
        description=(
            "Run a bounded resource-consumption (rate-limit) differential against "
            "loopback."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict JSON experiment manifest")
    args = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        manifest = read_resource_consumption_manifest(args.manifest)
        secrets = resolve_resource_consumption_secrets(manifest, environment)
        result = (
            preflight_resource_consumption_manifest(manifest, secrets)
            if args.dry_run
            else execute_resource_consumption_manifest(manifest, secrets)
        )
    except (ResourceConsumptionManifestError, ResourceConsumptionPlanError) as exc:
        print(f"PANCITO_RESOURCE_CONSUMPTION_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
