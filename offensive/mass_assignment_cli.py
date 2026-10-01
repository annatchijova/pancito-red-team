"""Strict CLI boundary for the loopback mass-assignment experiment."""

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
from offensive.mass_assignment import (
    MassAssignmentPlan,
    MassAssignmentPlanError,
    run_mass_assignment_experiment,
)
from offensive.secrets import SecretValue, SecretValueError


_MAX_MANIFEST_BYTES = 65_536
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "authorization_reference",
        "authorized_by",
        "operator_acknowledged",
        "target_origin",
        "resource_path",
        "readback_path",
        "allowed_field",
        "protected_field",
        "actor_principal_id",
        "observer_principal_id",
        "actor_token_env",
        "observer_token_env",
        "baseline_allowed_env",
        "baseline_protected_env",
        "control_allowed_env",
        "negative_allowed_env",
        "negative_protected_env",
        "timeout_ms",
        "max_response_bytes",
    }
)
_ENV_FIELDS = (
    "actor_token_env",
    "observer_token_env",
    "baseline_allowed_env",
    "baseline_protected_env",
    "control_allowed_env",
    "negative_allowed_env",
    "negative_protected_env",
)


class MassAssignmentManifestError(ValueError):
    """The manifest or its secret references violate the execution boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise MassAssignmentManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise MassAssignmentManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise MassAssignmentManifestError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise MassAssignmentManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise MassAssignmentManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MassAssignmentManifestError(f"duplicate key {key!r}")
        value[key] = item
    return value


@dataclass(frozen=True)
class MassAssignmentManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    resource_path: str
    readback_path: str
    allowed_field: str
    protected_field: str
    actor_principal_id: str
    observer_principal_id: str
    actor_token_env: str
    observer_token_env: str
    baseline_allowed_env: str
    baseline_protected_env: str
    control_allowed_env: str
    negative_allowed_env: str
    negative_protected_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, ...]:
        return tuple(getattr(self, name) for name in _ENV_FIELDS)


@dataclass(frozen=True)
class ResolvedMassAssignmentSecrets:
    actor_token: SecretValue = field(repr=False)
    observer_token: SecretValue = field(repr=False)
    baseline_allowed: SecretValue = field(repr=False)
    baseline_protected: SecretValue = field(repr=False)
    control_allowed: SecretValue = field(repr=False)
    negative_allowed: SecretValue = field(repr=False)
    negative_protected: SecretValue = field(repr=False)


def _build_plan(
    manifest: MassAssignmentManifest, secrets: ResolvedMassAssignmentSecrets
) -> MassAssignmentPlan:
    return MassAssignmentPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        resource_path=manifest.resource_path,
        readback_path=manifest.readback_path,
        allowed_field=manifest.allowed_field,
        protected_field=manifest.protected_field,
        baseline_allowed=secrets.baseline_allowed.reveal(),
        baseline_protected=secrets.baseline_protected.reveal(),
        control_allowed=secrets.control_allowed.reveal(),
        negative_allowed=secrets.negative_allowed.reveal(),
        negative_protected=secrets.negative_protected.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def parse_mass_assignment_manifest(raw: bytes) -> MassAssignmentManifest:
    if not isinstance(raw, bytes):
        raise TypeError("mass-assignment manifest must be bytes")
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise MassAssignmentManifestError("mass-assignment manifest size is invalid")
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise MassAssignmentManifestError("manifest must be UTF-8 JSON") from exc
    except MassAssignmentManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise MassAssignmentManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MassAssignmentManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise MassAssignmentManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise MassAssignmentManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise MassAssignmentManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise MassAssignmentManifestError("operator_acknowledged must be literal true")

    experiment_id = _text(data, "experiment_id", 128)
    actor_id = _text(data, "actor_principal_id", 128)
    observer_id = _text(data, "observer_principal_id", 128)
    if not all(_ID_RE.fullmatch(item) for item in (experiment_id, actor_id, observer_id)):
        raise MassAssignmentManifestError("experiment and principal identifiers are invalid")
    if actor_id == observer_id:
        raise MassAssignmentManifestError("actor and observer principals must differ")
    environment_names = tuple(_text(data, name, 128) for name in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(name) for name in environment_names):
        raise MassAssignmentManifestError("secret environment variable name is invalid")
    if len(set(environment_names)) != len(environment_names):
        raise MassAssignmentManifestError("secret environment variable names must be distinct")
    timeout_ms = data["timeout_ms"]
    maximum = data["max_response_bytes"]
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
        raise MassAssignmentManifestError("timeout_ms must be an integer")
    if isinstance(maximum, bool) or not isinstance(maximum, int):
        raise MassAssignmentManifestError("max_response_bytes must be an integer")

    manifest = MassAssignmentManifest(
        schema_version=1,
        experiment_id=experiment_id,
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        resource_path=_text(data, "resource_path", 2_048),
        readback_path=_text(data, "readback_path", 2_048),
        allowed_field=_text(data, "allowed_field", 128),
        protected_field=_text(data, "protected_field", 128),
        actor_principal_id=actor_id,
        observer_principal_id=observer_id,
        actor_token_env=environment_names[0],
        observer_token_env=environment_names[1],
        baseline_allowed_env=environment_names[2],
        baseline_protected_env=environment_names[3],
        control_allowed_env=environment_names[4],
        negative_allowed_env=environment_names[5],
        negative_protected_env=environment_names[6],
        timeout_ms=timeout_ms,
        max_response_bytes=maximum,
    )
    validation = ResolvedMassAssignmentSecrets(
        *(SecretValue(f"manifest-validation-secret-{index}") for index in range(7))
    )
    try:
        _build_plan(manifest, validation)
    except MassAssignmentPlanError as exc:
        raise MassAssignmentManifestError(str(exc)) from exc
    return manifest


def read_mass_assignment_manifest(path: str | Path) -> MassAssignmentManifest:
    try:
        raw = read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_MANIFEST_BYTES,
            label="mass-assignment manifest",
        )
    except LocalArtifactError as exc:
        raise MassAssignmentManifestError(str(exc)) from exc
    return parse_mass_assignment_manifest(raw)


def resolve_mass_assignment_secrets(
    manifest: MassAssignmentManifest, environ: Mapping[str, str]
) -> ResolvedMassAssignmentSecrets:
    if not isinstance(manifest, MassAssignmentManifest):
        raise TypeError("manifest must be a MassAssignmentManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise MassAssignmentManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    resolved: list[SecretValue] = []
    for name in manifest.secret_environment_names:
        value = environ[name]
        if not isinstance(value, str):
            raise MassAssignmentManifestError(f"environment variable {name} must be text")
        try:
            resolved.append(SecretValue(value))
        except SecretValueError as exc:
            raise MassAssignmentManifestError(
                f"environment variable {name} is invalid"
            ) from exc
    if len({item.reveal() for item in resolved}) != len(resolved):
        raise MassAssignmentManifestError("all resolved secrets must be distinct")
    return ResolvedMassAssignmentSecrets(*resolved)


def preflight_mass_assignment_manifest(
    manifest: MassAssignmentManifest, secrets: ResolvedMassAssignmentSecrets
) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "target_origin": manifest.target_origin,
        "resource_path": manifest.resource_path,
        "readback_path": manifest.readback_path,
        "method": "PATCH",
        "secret_sources": list(manifest.secret_environment_names),
        "request_count": 0,
        "maximum_request_count": 9,
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def execute_mass_assignment_manifest(
    manifest: MassAssignmentManifest, secrets: ResolvedMassAssignmentSecrets
) -> dict[str, object]:
    return run_mass_assignment_experiment(
        _build_plan(manifest, secrets),
        actor=BearerCredential(manifest.actor_principal_id, secrets.actor_token.reveal()),
        observer=BearerCredential(
            manifest.observer_principal_id, secrets.observer_token.reveal()
        ),
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-mass-assignment",
        description="Run a bounded property-authorization differential on loopback.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict JSON experiment manifest")
    args = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        manifest = read_mass_assignment_manifest(args.manifest)
        secrets = resolve_mass_assignment_secrets(manifest, environment)
        result = (
            preflight_mass_assignment_manifest(manifest, secrets)
            if args.dry_run
            else execute_mass_assignment_manifest(manifest, secrets)
        )
    except (MassAssignmentManifestError, MassAssignmentPlanError) as exc:
        print(f"PANCITO_MASS_ASSIGNMENT_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
