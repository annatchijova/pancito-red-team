"""Strict CLI boundary for the reversible stale-authority experiment."""

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
from offensive.secrets import SecretValue, SecretValueError
from offensive.stale_authority import (
    StaleAuthorityPlan,
    StaleAuthorityPlanError,
    run_stale_authority_experiment,
)


_MAX_BYTES = 65_536
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ENV_FIELDS = (
    "actor_token_env", "admin_token_env", "resource_canary_env",
    "active_marker_env", "revoked_marker_env",
)
_FIELDS = frozenset({
    "schema_version", "experiment_id", "authorization_reference", "authorized_by",
    "operator_acknowledged", "target_origin", "resource_path", "membership_path",
    "membership_field", "actor_principal_id", "admin_principal_id", *_ENV_FIELDS,
    "timeout_ms", "max_response_bytes",
})


class StaleAuthorityManifestError(ValueError):
    """The manifest or its secret references violate the boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise StaleAuthorityManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise StaleAuthorityManifestError(f"{name} is outside its text boundary")
    return value


def _reject_float(_value: str) -> None:
    raise StaleAuthorityManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise StaleAuthorityManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StaleAuthorityManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class StaleAuthorityManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    resource_path: str
    membership_path: str
    membership_field: str
    actor_principal_id: str
    admin_principal_id: str
    actor_token_env: str
    admin_token_env: str
    resource_canary_env: str
    active_marker_env: str
    revoked_marker_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, ...]:
        return tuple(getattr(self, name) for name in _ENV_FIELDS)


@dataclass(frozen=True)
class ResolvedStaleAuthoritySecrets:
    actor_token: SecretValue = field(repr=False)
    admin_token: SecretValue = field(repr=False)
    resource_canary: SecretValue = field(repr=False)
    active_marker: SecretValue = field(repr=False)
    revoked_marker: SecretValue = field(repr=False)


def _build_plan(manifest, secrets) -> StaleAuthorityPlan:
    return StaleAuthorityPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        resource_path=manifest.resource_path,
        membership_path=manifest.membership_path,
        membership_field=manifest.membership_field,
        resource_canary=secrets.resource_canary.reveal(),
        active_marker=secrets.active_marker.reveal(),
        revoked_marker=secrets.revoked_marker.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def parse_stale_authority_manifest(raw: bytes) -> StaleAuthorityManifest:
    if not isinstance(raw, bytes):
        raise TypeError("stale-authority manifest must be bytes")
    if not raw or len(raw) > _MAX_BYTES:
        raise StaleAuthorityManifestError("stale-authority manifest size is invalid")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise StaleAuthorityManifestError("manifest must be UTF-8 JSON") from exc
    except StaleAuthorityManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise StaleAuthorityManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise StaleAuthorityManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise StaleAuthorityManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise StaleAuthorityManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise StaleAuthorityManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise StaleAuthorityManifestError("operator_acknowledged must be literal true")
    identifiers = tuple(_text(data, name, 128) for name in (
        "experiment_id", "actor_principal_id", "admin_principal_id"))
    if any(not _ID_RE.fullmatch(value) for value in identifiers):
        raise StaleAuthorityManifestError("experiment and principal identifiers are invalid")
    if identifiers[1] == identifiers[2]:
        raise StaleAuthorityManifestError("actor and admin principals must be distinct")
    env_names = tuple(_text(data, name, 128) for name in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(name) for name in env_names):
        raise StaleAuthorityManifestError("secret environment name is invalid")
    if len(set(env_names)) != len(env_names):
        raise StaleAuthorityManifestError("secret environment names must be distinct")
    for name in ("timeout_ms", "max_response_bytes"):
        if isinstance(data[name], bool) or not isinstance(data[name], int):
            raise StaleAuthorityManifestError(f"{name} must be an integer")
    manifest = StaleAuthorityManifest(
        1, identifiers[0], _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), True, _text(data, "target_origin", 512),
        _text(data, "resource_path", 2_048), _text(data, "membership_path", 2_048),
        _text(data, "membership_field", 128), identifiers[1], identifiers[2],
        *env_names, data["timeout_ms"], data["max_response_bytes"],
    )
    validation = ResolvedStaleAuthoritySecrets(*(
        SecretValue(f"manifest-validation-secret-{index}") for index in range(5)
    ))
    try:
        _build_plan(manifest, validation)
    except StaleAuthorityPlanError as exc:
        raise StaleAuthorityManifestError(str(exc)) from exc
    return manifest


def read_stale_authority_manifest(path: str | Path) -> StaleAuthorityManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX_BYTES,
                                        label="stale-authority manifest")
    except LocalArtifactError as exc:
        raise StaleAuthorityManifestError(str(exc)) from exc
    return parse_stale_authority_manifest(raw)


def resolve_stale_authority_secrets(manifest, environ: Mapping[str, str]):
    if not isinstance(manifest, StaleAuthorityManifest) or not isinstance(environ, Mapping):
        raise TypeError("manifest and environment types are invalid")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise StaleAuthorityManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing))
    try:
        values = [SecretValue(environ[name]) for name in manifest.secret_environment_names]
    except (SecretValueError, TypeError) as exc:
        raise StaleAuthorityManifestError("a secret environment value is invalid") from exc
    if len({value.reveal() for value in values}) != len(values):
        raise StaleAuthorityManifestError("all resolved secrets must be distinct")
    return ResolvedStaleAuthoritySecrets(*values)


def preflight_stale_authority_manifest(manifest, secrets) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "secret_sources": list(manifest.secret_environment_names), "request_count": 0,
        "maximum_request_count": 7, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False,
    }


def execute_stale_authority_manifest(manifest, secrets) -> dict[str, object]:
    return run_stale_authority_experiment(
        _build_plan(manifest, secrets),
        actor=BearerCredential(manifest.actor_principal_id, secrets.actor_token.reveal()),
        admin=BearerCredential(manifest.admin_principal_id, secrets.admin_token.reveal()),
    )


def main(argv: Sequence[str] | None = None, *, environ=None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-stale-authority")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_stale_authority_manifest(args.manifest)
        secrets = resolve_stale_authority_secrets(manifest, os.environ if environ is None else environ)
        result = (preflight_stale_authority_manifest(manifest, secrets) if args.dry_run
                  else execute_stale_authority_manifest(manifest, secrets))
    except (StaleAuthorityManifestError, StaleAuthorityPlanError) as exc:
        print(f"PANCITO_STALE_AUTHORITY_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
