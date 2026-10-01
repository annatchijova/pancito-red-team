"""Strict manifest boundary for the loopback nested-BOLA differential."""

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
from offensive.nested_bola import (
    NestedBolaPlan,
    NestedBolaPlanError,
    run_nested_bola_experiment,
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
        "owner_control_path",
        "peer_control_path",
        "cross_child_path",
        "parent_segment_index",
        "child_segment_index",
        "owner_principal_id",
        "peer_principal_id",
        "owner_token_env",
        "peer_token_env",
        "owner_canary_env",
        "peer_canary_env",
        "timeout_ms",
        "max_response_bytes",
    }
)
_ENV_FIELDS = (
    "owner_token_env",
    "peer_token_env",
    "owner_canary_env",
    "peer_canary_env",
)


class NestedBolaManifestError(ValueError):
    """The nested-BOLA manifest or its secret references are invalid."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise NestedBolaManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise NestedBolaManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise NestedBolaManifestError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise NestedBolaManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise NestedBolaManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NestedBolaManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class NestedBolaManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    owner_control_path: str
    peer_control_path: str
    cross_child_path: str
    parent_segment_index: int
    child_segment_index: int
    owner_principal_id: str
    peer_principal_id: str
    owner_token_env: str
    peer_token_env: str
    owner_canary_env: str
    peer_canary_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, ...]:
        return tuple(getattr(self, name) for name in _ENV_FIELDS)


@dataclass(frozen=True)
class ResolvedNestedBolaSecrets:
    owner_token: SecretValue = field(repr=False)
    peer_token: SecretValue = field(repr=False)
    owner_canary: SecretValue = field(repr=False)
    peer_canary: SecretValue = field(repr=False)


def _build_plan(
    manifest: NestedBolaManifest, secrets: ResolvedNestedBolaSecrets
) -> NestedBolaPlan:
    return NestedBolaPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        owner_control_path=manifest.owner_control_path,
        peer_control_path=manifest.peer_control_path,
        cross_child_path=manifest.cross_child_path,
        parent_segment_index=manifest.parent_segment_index,
        child_segment_index=manifest.child_segment_index,
        owner_canary=secrets.owner_canary.reveal(),
        peer_canary=secrets.peer_canary.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def parse_nested_bola_manifest(raw: bytes) -> NestedBolaManifest:
    if not isinstance(raw, bytes):
        raise TypeError("nested-BOLA manifest must be bytes")
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise NestedBolaManifestError("nested-BOLA manifest size is invalid")
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise NestedBolaManifestError("manifest must be UTF-8 JSON") from exc
    except NestedBolaManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise NestedBolaManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise NestedBolaManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise NestedBolaManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise NestedBolaManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise NestedBolaManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise NestedBolaManifestError("operator_acknowledged must be literal true")

    experiment_id = _text(data, "experiment_id", 128)
    owner_id = _text(data, "owner_principal_id", 128)
    peer_id = _text(data, "peer_principal_id", 128)
    if not all(_ID_RE.fullmatch(item) for item in (experiment_id, owner_id, peer_id)):
        raise NestedBolaManifestError("experiment and principal identifiers are invalid")
    if owner_id == peer_id:
        raise NestedBolaManifestError("owner and peer principals must be distinct")
    environment_names = tuple(_text(data, name, 128) for name in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(name) for name in environment_names):
        raise NestedBolaManifestError("secret environment variable name is invalid")
    if len(set(environment_names)) != len(environment_names):
        raise NestedBolaManifestError("secret environment variable names must be distinct")
    integer_fields = (
        "parent_segment_index",
        "child_segment_index",
        "timeout_ms",
        "max_response_bytes",
    )
    if any(
        isinstance(data[name], bool) or not isinstance(data[name], int)
        for name in integer_fields
    ):
        raise NestedBolaManifestError("indexes and limits must be integers")

    manifest = NestedBolaManifest(
        schema_version=1,
        experiment_id=experiment_id,
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        owner_control_path=_text(data, "owner_control_path", 2_048),
        peer_control_path=_text(data, "peer_control_path", 2_048),
        cross_child_path=_text(data, "cross_child_path", 2_048),
        parent_segment_index=data["parent_segment_index"],
        child_segment_index=data["child_segment_index"],
        owner_principal_id=owner_id,
        peer_principal_id=peer_id,
        owner_token_env=environment_names[0],
        peer_token_env=environment_names[1],
        owner_canary_env=environment_names[2],
        peer_canary_env=environment_names[3],
        timeout_ms=data["timeout_ms"],
        max_response_bytes=data["max_response_bytes"],
    )
    validation = ResolvedNestedBolaSecrets(
        SecretValue("manifest-validation-owner-token"),
        SecretValue("manifest-validation-peer-token"),
        SecretValue("MANIFEST-VALIDATION-OWNER-CANARY"),
        SecretValue("MANIFEST-VALIDATION-PEER-CANARY"),
    )
    try:
        _build_plan(manifest, validation)
    except NestedBolaPlanError as exc:
        raise NestedBolaManifestError(str(exc)) from exc
    return manifest


def read_nested_bola_manifest(path: str | Path) -> NestedBolaManifest:
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="nested-BOLA manifest"
        )
    except LocalArtifactError as exc:
        raise NestedBolaManifestError(str(exc)) from exc
    return parse_nested_bola_manifest(raw)


def resolve_nested_bola_secrets(
    manifest: NestedBolaManifest, environ: Mapping[str, str]
) -> ResolvedNestedBolaSecrets:
    if not isinstance(manifest, NestedBolaManifest):
        raise TypeError("manifest must be a NestedBolaManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise NestedBolaManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    resolved: list[SecretValue] = []
    for name in manifest.secret_environment_names:
        try:
            resolved.append(SecretValue(environ[name]))
        except (SecretValueError, TypeError) as exc:
            raise NestedBolaManifestError(
                f"environment variable {name} is invalid"
            ) from exc
    if len({item.reveal() for item in resolved}) != len(resolved):
        raise NestedBolaManifestError("all resolved secrets must be distinct")
    return ResolvedNestedBolaSecrets(*resolved)


def preflight_nested_bola_manifest(
    manifest: NestedBolaManifest, secrets: ResolvedNestedBolaSecrets
) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "target_origin": manifest.target_origin,
        "method": "GET",
        "secret_sources": list(manifest.secret_environment_names),
        "request_count": 0,
        "maximum_request_count": 3,
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def execute_nested_bola_manifest(
    manifest: NestedBolaManifest, secrets: ResolvedNestedBolaSecrets
) -> dict[str, object]:
    return run_nested_bola_experiment(
        _build_plan(manifest, secrets),
        owner=BearerCredential(manifest.owner_principal_id, secrets.owner_token.reveal()),
        peer=BearerCredential(manifest.peer_principal_id, secrets.peer_token.reveal()),
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-nested-bola",
        description="Run a bounded nested-resource authorization differential.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict JSON experiment manifest")
    args = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        manifest = read_nested_bola_manifest(args.manifest)
        secrets = resolve_nested_bola_secrets(manifest, environment)
        result = (
            preflight_nested_bola_manifest(manifest, secrets)
            if args.dry_run
            else execute_nested_bola_manifest(manifest, secrets)
        )
    except (NestedBolaManifestError, NestedBolaPlanError) as exc:
        print(f"PANCITO_NESTED_BOLA_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
