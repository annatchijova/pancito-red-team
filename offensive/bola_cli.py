"""Strict manifest and CLI boundary for the loopback-only BOLA experiment."""

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

from offensive.bola import (
    BearerCredential,
    BolaPlan,
    BolaPlanError,
    run_bola_experiment,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file


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
        "owner_path",
        "peer_control_path",
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


class BolaManifestError(ValueError):
    """The manifest, secret references, or local file boundary is invalid."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise BolaManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise BolaManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise BolaManifestError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise BolaManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise BolaManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BolaManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class SecretValue:
    """A secret that redacts string representations and resists serialization."""

    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._value, str) or not self._value:
            raise BolaManifestError("secret value must be non-empty text")
        if len(self._value) > 8_192:
            raise BolaManifestError("secret value exceeds 8192 characters")
        if any(unicodedata.category(char).startswith("C") for char in self._value):
            raise BolaManifestError("secret value contains control characters")

    def __str__(self) -> str:
        return "***"

    def __repr__(self) -> str:
        return "SecretValue(***)"

    def reveal(self) -> str:
        """Return the value only at the credential/plan construction boundary."""
        return self._value


@dataclass(frozen=True)
class BolaManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    owner_path: str
    peer_control_path: str
    owner_principal_id: str
    peer_principal_id: str
    owner_token_env: str
    peer_token_env: str
    owner_canary_env: str
    peer_canary_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, str, str, str]:
        return (
            self.owner_token_env,
            self.peer_token_env,
            self.owner_canary_env,
            self.peer_canary_env,
        )


@dataclass(frozen=True)
class ResolvedBolaSecrets:
    owner_token: SecretValue = field(repr=False)
    peer_token: SecretValue = field(repr=False)
    owner_canary: SecretValue = field(repr=False)
    peer_canary: SecretValue = field(repr=False)


def parse_bola_manifest(raw: bytes) -> BolaManifest:
    """Parse bounded UTF-8 JSON and reject unknown or ambiguous configuration."""
    if not isinstance(raw, bytes):
        raise TypeError("BOLA manifest must be bytes")
    if not raw:
        raise BolaManifestError("BOLA manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise BolaManifestError(f"BOLA manifest exceeds {_MAX_MANIFEST_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BolaManifestError("BOLA manifest must be UTF-8 JSON") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except BolaManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise BolaManifestError(f"invalid BOLA manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BolaManifestError("BOLA manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise BolaManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise BolaManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise BolaManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise BolaManifestError("operator_acknowledged must be literal true")

    experiment_id = _text(data, "experiment_id", 128)
    if not _ID_RE.fullmatch(experiment_id):
        raise BolaManifestError(
            "experiment_id must match [A-Za-z0-9._-]{1,128}"
        )
    owner_principal_id = _text(data, "owner_principal_id", 128)
    peer_principal_id = _text(data, "peer_principal_id", 128)
    if owner_principal_id == peer_principal_id:
        raise BolaManifestError("owner and peer principal IDs must be distinct")
    for name in (owner_principal_id, peer_principal_id):
        if not _ID_RE.fullmatch(name):
            raise BolaManifestError(
                "principal IDs must match [A-Za-z0-9._-]{1,128}"
            )

    environment_names = tuple(
        _text(data, field_name, 128)
        for field_name in (
            "owner_token_env",
            "peer_token_env",
            "owner_canary_env",
            "peer_canary_env",
        )
    )
    if any(not _ENV_NAME_RE.fullmatch(name) for name in environment_names):
        raise BolaManifestError(
            "secret environment names must match [A-Z][A-Z0-9_]{0,127}"
        )
    if len(set(environment_names)) != len(environment_names):
        raise BolaManifestError("secret environment names must be distinct")

    timeout_ms = data["timeout_ms"]
    maximum = data["max_response_bytes"]
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
        raise BolaManifestError("timeout_ms must be an integer")
    if isinstance(maximum, bool) or not isinstance(maximum, int):
        raise BolaManifestError("max_response_bytes must be an integer")

    manifest = BolaManifest(
        schema_version=1,
        experiment_id=experiment_id,
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        owner_path=_text(data, "owner_path", 2_048),
        peer_control_path=_text(data, "peer_control_path", 2_048),
        owner_principal_id=owner_principal_id,
        peer_principal_id=peer_principal_id,
        owner_token_env=environment_names[0],
        peer_token_env=environment_names[1],
        owner_canary_env=environment_names[2],
        peer_canary_env=environment_names[3],
        timeout_ms=timeout_ms,
        max_response_bytes=maximum,
    )
    try:
        _build_plan(
            manifest,
            ResolvedBolaSecrets(
                owner_token=SecretValue("manifest-validation-owner-token"),
                peer_token=SecretValue("manifest-validation-peer-token"),
                owner_canary=SecretValue("MANIFEST-VALIDATION-OWNER-CANARY"),
                peer_canary=SecretValue("MANIFEST-VALIDATION-PEER-CANARY"),
            ),
        )
    except BolaPlanError as exc:
        raise BolaManifestError(str(exc)) from exc
    return manifest


def read_bola_manifest(path: str | Path) -> BolaManifest:
    """Read a bounded regular file without following a final-component symlink."""
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="BOLA manifest"
        )
    except LocalArtifactError as exc:
        raise BolaManifestError(str(exc)) from exc
    return parse_bola_manifest(raw)


def resolve_bola_secrets(
    manifest: BolaManifest, environ: Mapping[str, str]
) -> ResolvedBolaSecrets:
    """Resolve all required values atomically; there is no partial fallback."""
    if not isinstance(manifest, BolaManifest):
        raise TypeError("manifest must be a BolaManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise BolaManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    resolved: list[SecretValue] = []
    for name in manifest.secret_environment_names:
        value = environ[name]
        if not isinstance(value, str):
            raise BolaManifestError(f"environment variable {name} must contain text")
        try:
            resolved.append(SecretValue(value))
        except BolaManifestError as exc:
            raise BolaManifestError(f"environment variable {name} is invalid") from exc
    revealed = [item.reveal() for item in resolved]
    if len(set(revealed)) != len(revealed):
        raise BolaManifestError("resolved token and canary values must be distinct")
    return ResolvedBolaSecrets(
        owner_token=resolved[0],
        peer_token=resolved[1],
        owner_canary=resolved[2],
        peer_canary=resolved[3],
    )


def _build_plan(manifest: BolaManifest, secrets: ResolvedBolaSecrets) -> BolaPlan:
    return BolaPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        owner_path=manifest.owner_path,
        peer_control_path=manifest.peer_control_path,
        owner_canary=secrets.owner_canary.reveal(),
        peer_canary=secrets.peer_canary.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def preflight_bola_manifest(
    manifest: BolaManifest, secrets: ResolvedBolaSecrets
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


def execute_bola_manifest(
    manifest: BolaManifest, secrets: ResolvedBolaSecrets
) -> dict[str, object]:
    """Execute only after the manifest and every secret have passed validation."""
    plan = _build_plan(manifest, secrets)
    owner = BearerCredential(
        manifest.owner_principal_id, secrets.owner_token.reveal()
    )
    peer = BearerCredential(manifest.peer_principal_id, secrets.peer_token.reveal())
    return run_bola_experiment(plan, owner=owner, peer=peer)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-bola",
        description="Run a bounded BOLA differential experiment against loopback.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict JSON experiment manifest")
    args = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        manifest = read_bola_manifest(args.manifest)
        secrets = resolve_bola_secrets(manifest, environment)
        result = (
            preflight_bola_manifest(manifest, secrets)
            if args.dry_run
            else execute_bola_manifest(manifest, secrets)
        )
    except (BolaManifestError, BolaPlanError) as exc:
        print(f"PANCITO_BOLA_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
