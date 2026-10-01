"""Strict manifest CLI for asynchronous export authorization lifecycles."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.async_export_authz import (
    AsyncExportAuthorizationPlan,
    AsyncExportAuthorizationPlanError,
    run_async_export_authorization_experiment,
)
from offensive.bola import BearerCredential
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError

_MAX = 65_536
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ENV_FIELDS = (
    "alpha_token_env", "bravo_token_env", "alpha_canary_env", "bravo_canary_env",
)
_FIELDS = frozenset({
    "schema_version", "experiment_id", "authorization_reference", "authorized_by",
    "operator_acknowledged", "target_origin", "alpha_create_path", "bravo_create_path",
    "alpha_jobs_path", "bravo_jobs_path", "alpha_principal_id", "bravo_principal_id",
    *_ENV_FIELDS, "timeout_ms", "max_response_bytes",
})


class AsyncExportAuthorizationManifestError(ValueError):
    """An async export manifest is invalid or exceeds its boundary."""


def _reject_float(_value: str) -> None:
    raise AsyncExportAuthorizationManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise AsyncExportAuthorizationManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AsyncExportAuthorizationManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise AsyncExportAuthorizationManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(unicodedata.category(char).startswith("C") for char in value):
        raise AsyncExportAuthorizationManifestError(f"{name} is outside its text boundary")
    return value


@dataclass(frozen=True)
class AsyncExportAuthorizationManifest:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    target_origin: str
    alpha_create_path: str
    bravo_create_path: str
    alpha_jobs_path: str
    bravo_jobs_path: str
    alpha_principal_id: str
    bravo_principal_id: str
    environment_names: tuple[str, ...]
    timeout_ms: int
    max_response_bytes: int


@dataclass(frozen=True)
class ResolvedAsyncExportAuthorizationSecrets:
    alpha_token: SecretValue
    bravo_token: SecretValue
    alpha_canary: SecretValue
    bravo_canary: SecretValue


def _build_plan(manifest: AsyncExportAuthorizationManifest,
                secrets: ResolvedAsyncExportAuthorizationSecrets):
    return AsyncExportAuthorizationPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=True,
        target_origin=manifest.target_origin,
        alpha_create_path=manifest.alpha_create_path,
        bravo_create_path=manifest.bravo_create_path,
        alpha_jobs_path=manifest.alpha_jobs_path,
        bravo_jobs_path=manifest.bravo_jobs_path,
        alpha_canary=secrets.alpha_canary.reveal(),
        bravo_canary=secrets.bravo_canary.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def parse_async_export_authorization_manifest(raw: bytes) -> AsyncExportAuthorizationManifest:
    if not isinstance(raw, bytes):
        raise TypeError("async export manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise AsyncExportAuthorizationManifestError("manifest size is invalid")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise AsyncExportAuthorizationManifestError("manifest must be UTF-8 JSON") from exc
    except AsyncExportAuthorizationManifestError:
        raise
    except (json.JSONDecodeError, TypeError, RecursionError) as exc:
        raise AsyncExportAuthorizationManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AsyncExportAuthorizationManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise AsyncExportAuthorizationManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise AsyncExportAuthorizationManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise AsyncExportAuthorizationManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise AsyncExportAuthorizationManifestError("operator_acknowledged must be literal true")
    experiment_id = _text(data, "experiment_id", 128)
    alpha_id, bravo_id = _text(data, "alpha_principal_id", 128), _text(data, "bravo_principal_id", 128)
    if (not _ID_RE.fullmatch(experiment_id) or not _ID_RE.fullmatch(alpha_id)
            or not _ID_RE.fullmatch(bravo_id) or alpha_id == bravo_id):
        raise AsyncExportAuthorizationManifestError("principal and experiment identifiers are invalid")
    environment_names = tuple(_text(data, key, 128) for key in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(name) for name in environment_names) or len(set(environment_names)) != 4:
        raise AsyncExportAuthorizationManifestError("secret environment names must be valid and distinct")
    if any(isinstance(data[key], bool) or not isinstance(data[key], int)
           for key in ("timeout_ms", "max_response_bytes")):
        raise AsyncExportAuthorizationManifestError("limits must be integers")
    values = AsyncExportAuthorizationManifest(
        experiment_id, _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), _text(data, "target_origin", 512),
        _text(data, "alpha_create_path", 2048), _text(data, "bravo_create_path", 2048),
        _text(data, "alpha_jobs_path", 2048), _text(data, "bravo_jobs_path", 2048),
        alpha_id, bravo_id, environment_names, data["timeout_ms"], data["max_response_bytes"],
    )
    placeholders = ResolvedAsyncExportAuthorizationSecrets(
        *(SecretValue(f"manifest-check-{index}") for index in range(4))
    )
    try:
        _build_plan(values, placeholders)
    except AsyncExportAuthorizationPlanError as exc:
        raise AsyncExportAuthorizationManifestError(str(exc)) from exc
    return values


def resolve_async_export_authorization_secrets(
    manifest: AsyncExportAuthorizationManifest, environ: Mapping[str, str]
) -> ResolvedAsyncExportAuthorizationSecrets:
    if not isinstance(manifest, AsyncExportAuthorizationManifest) or not isinstance(environ, Mapping):
        raise TypeError("manifest and environment mapping have invalid types")
    missing = [name for name in manifest.environment_names if not environ.get(name)]
    if missing:
        raise AsyncExportAuthorizationManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    try:
        values = tuple(SecretValue(environ[name]) for name in manifest.environment_names)
    except (SecretValueError, TypeError) as exc:
        raise AsyncExportAuthorizationManifestError("a secret environment value is invalid") from exc
    if len({value.reveal() for value in values}) != 4:
        raise AsyncExportAuthorizationManifestError("credentials and canaries must all differ")
    return ResolvedAsyncExportAuthorizationSecrets(*values)


def preflight_async_export_authorization_manifest(manifest, secrets) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "secret_sources": list(manifest.environment_names), "request_count": 0,
        "maximum_request_count": 12, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False,
    }


def execute_async_export_authorization_manifest(manifest, secrets):
    return run_async_export_authorization_experiment(
        _build_plan(manifest, secrets),
        alpha=BearerCredential(manifest.alpha_principal_id, secrets.alpha_token.reveal()),
        bravo=BearerCredential(manifest.bravo_principal_id, secrets.bravo_token.reveal()),
    )


def read_async_export_authorization_manifest(path: str | Path) -> AsyncExportAuthorizationManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="async export manifest")
    except LocalArtifactError as exc:
        raise AsyncExportAuthorizationManifestError(str(exc)) from exc
    return parse_async_export_authorization_manifest(raw)


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-async-export-authz")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_async_export_authorization_manifest(args.manifest)
        secrets = resolve_async_export_authorization_secrets(
            manifest, os.environ if environ is None else environ
        )
        result = (preflight_async_export_authorization_manifest(manifest, secrets)
                  if args.dry_run else execute_async_export_authorization_manifest(manifest, secrets))
    except (AsyncExportAuthorizationManifestError, AsyncExportAuthorizationPlanError) as exc:
        print(f"PANCITO_ASYNC_EXPORT_AUTHZ_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
