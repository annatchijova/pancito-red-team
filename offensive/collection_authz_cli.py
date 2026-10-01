"""Strict CLI for the loopback collection authorization differential."""

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
from offensive.collection_authz import (
    CollectionAuthorizationPlan,
    CollectionAuthorizationPlanError,
    run_collection_authorization_experiment,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError


_MAX_MANIFEST_BYTES = 65_536
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ENV_FIELDS = (
    "alpha_token_env",
    "bravo_token_env",
    "alpha_canary_env",
    "bravo_canary_env",
)
_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "authorization_reference",
        "authorized_by",
        "operator_acknowledged",
        "target_origin",
        "alpha_collection_path",
        "bravo_collection_path",
        "alpha_principal_id",
        "bravo_principal_id",
        *_ENV_FIELDS,
        "timeout_ms",
        "max_response_bytes",
    }
)


class CollectionAuthorizationManifestError(ValueError):
    """A collection authorization manifest is invalid or outside the boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise CollectionAuthorizationManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise CollectionAuthorizationManifestError(
            f"{name} exceeds {maximum} characters"
        )
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise CollectionAuthorizationManifestError(
            f"{name} contains control characters"
        )
    return value


def _reject_float(_value: str) -> None:
    raise CollectionAuthorizationManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise CollectionAuthorizationManifestError(
        f"non-finite JSON value {value!r} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionAuthorizationManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class CollectionAuthorizationManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    alpha_collection_path: str
    bravo_collection_path: str
    alpha_principal_id: str
    bravo_principal_id: str
    alpha_token_env: str
    bravo_token_env: str
    alpha_canary_env: str
    bravo_canary_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self) -> tuple[str, ...]:
        return tuple(getattr(self, name) for name in _ENV_FIELDS)


@dataclass(frozen=True)
class ResolvedCollectionAuthorizationSecrets:
    alpha_token: SecretValue = field(repr=False)
    bravo_token: SecretValue = field(repr=False)
    alpha_canary: SecretValue = field(repr=False)
    bravo_canary: SecretValue = field(repr=False)


def _build_plan(
    manifest: CollectionAuthorizationManifest,
    secrets: ResolvedCollectionAuthorizationSecrets,
) -> CollectionAuthorizationPlan:
    return CollectionAuthorizationPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        alpha_collection_path=manifest.alpha_collection_path,
        bravo_collection_path=manifest.bravo_collection_path,
        alpha_canary=secrets.alpha_canary.reveal(),
        bravo_canary=secrets.bravo_canary.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def parse_collection_authorization_manifest(
    raw: bytes,
) -> CollectionAuthorizationManifest:
    if not isinstance(raw, bytes):
        raise TypeError("collection authorization manifest must be bytes")
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise CollectionAuthorizationManifestError(
            "collection authorization manifest size is invalid"
        )
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise CollectionAuthorizationManifestError(
            "manifest must be UTF-8 JSON"
        ) from exc
    except CollectionAuthorizationManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise CollectionAuthorizationManifestError(
            f"invalid manifest JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise CollectionAuthorizationManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise CollectionAuthorizationManifestError(
            "unknown fields: " + ", ".join(unknown)
        )
    if missing:
        raise CollectionAuthorizationManifestError(
            "missing fields: " + ", ".join(missing)
        )
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise CollectionAuthorizationManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise CollectionAuthorizationManifestError(
            "operator_acknowledged must be literal true"
        )

    identifiers = tuple(
        _text(data, name, 128)
        for name in ("experiment_id", "alpha_principal_id", "bravo_principal_id")
    )
    if any(not _ID_RE.fullmatch(value) for value in identifiers):
        raise CollectionAuthorizationManifestError("identifiers are invalid")
    if identifiers[1] == identifiers[2]:
        raise CollectionAuthorizationManifestError("principal identifiers must differ")
    environment_names = tuple(_text(data, name, 128) for name in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(value) for value in environment_names):
        raise CollectionAuthorizationManifestError(
            "secret environment variable name is invalid"
        )
    if len(set(environment_names)) != len(environment_names):
        raise CollectionAuthorizationManifestError(
            "secret environment variable names must be distinct"
        )
    if any(
        isinstance(data[name], bool) or not isinstance(data[name], int)
        for name in ("timeout_ms", "max_response_bytes")
    ):
        raise CollectionAuthorizationManifestError("limits must be integers")

    manifest = CollectionAuthorizationManifest(
        schema_version=1,
        experiment_id=identifiers[0],
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        alpha_collection_path=_text(data, "alpha_collection_path", 2_048),
        bravo_collection_path=_text(data, "bravo_collection_path", 2_048),
        alpha_principal_id=identifiers[1],
        bravo_principal_id=identifiers[2],
        alpha_token_env=environment_names[0],
        bravo_token_env=environment_names[1],
        alpha_canary_env=environment_names[2],
        bravo_canary_env=environment_names[3],
        timeout_ms=data["timeout_ms"],
        max_response_bytes=data["max_response_bytes"],
    )
    validation = ResolvedCollectionAuthorizationSecrets(
        SecretValue("manifest-validation-alpha-token"),
        SecretValue("manifest-validation-bravo-token"),
        SecretValue("MANIFEST-VALIDATION-ALPHA-CANARY"),
        SecretValue("MANIFEST-VALIDATION-BRAVO-CANARY"),
    )
    try:
        _build_plan(manifest, validation)
    except CollectionAuthorizationPlanError as exc:
        raise CollectionAuthorizationManifestError(str(exc)) from exc
    return manifest


def read_collection_authorization_manifest(
    path: str | Path,
) -> CollectionAuthorizationManifest:
    try:
        raw = read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_MANIFEST_BYTES,
            label="collection authorization manifest",
        )
    except LocalArtifactError as exc:
        raise CollectionAuthorizationManifestError(str(exc)) from exc
    return parse_collection_authorization_manifest(raw)


def resolve_collection_authorization_secrets(
    manifest: CollectionAuthorizationManifest,
    environ: Mapping[str, str],
) -> ResolvedCollectionAuthorizationSecrets:
    if not isinstance(manifest, CollectionAuthorizationManifest):
        raise TypeError("manifest must be a CollectionAuthorizationManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise CollectionAuthorizationManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    try:
        values = [
            SecretValue(environ[name]) for name in manifest.secret_environment_names
        ]
    except (SecretValueError, TypeError) as exc:
        raise CollectionAuthorizationManifestError(
            "a secret environment value is invalid"
        ) from exc
    if len({value.reveal() for value in values}) != len(values):
        raise CollectionAuthorizationManifestError(
            "all resolved secrets must be distinct"
        )
    return ResolvedCollectionAuthorizationSecrets(*values)


def preflight_collection_authorization_manifest(
    manifest: CollectionAuthorizationManifest,
    secrets: ResolvedCollectionAuthorizationSecrets,
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


def execute_collection_authorization_manifest(
    manifest: CollectionAuthorizationManifest,
    secrets: ResolvedCollectionAuthorizationSecrets,
) -> dict[str, object]:
    return run_collection_authorization_experiment(
        _build_plan(manifest, secrets),
        alpha=BearerCredential(
            manifest.alpha_principal_id, secrets.alpha_token.reveal()
        ),
        bravo=BearerCredential(
            manifest.bravo_principal_id, secrets.bravo_token.reveal()
        ),
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(prog="pancito-collection-authz")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_collection_authorization_manifest(args.manifest)
        secrets = resolve_collection_authorization_secrets(
            manifest, os.environ if environ is None else environ
        )
        result = (
            preflight_collection_authorization_manifest(manifest, secrets)
            if args.dry_run
            else execute_collection_authorization_manifest(manifest, secrets)
        )
    except (
        CollectionAuthorizationManifestError,
        CollectionAuthorizationPlanError,
    ) as exc:
        print(f"PANCITO_COLLECTION_AUTHZ_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
