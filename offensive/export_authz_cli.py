"""Strict manifest CLI for the bounded loopback export authorization test."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.bola import BearerCredential
from offensive.export_authz import ExportAuthorizationPlan, ExportAuthorizationPlanError
from offensive.export_authz import run_export_authorization_experiment
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError

_MAX = 65_536
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ENV_FIELDS = ("alpha_token_env", "bravo_token_env", "alpha_canary_env", "bravo_canary_env")
_FIELDS = frozenset({
    "schema_version", "experiment_id", "authorization_reference", "authorized_by",
    "operator_acknowledged", "target_origin", "alpha_export_path", "bravo_export_path",
    "tenant_segment_index", "alpha_principal_id", "bravo_principal_id", *_ENV_FIELDS,
    "timeout_ms", "max_response_bytes",
})


class ExportAuthorizationManifestError(ValueError):
    """An export authorization manifest is invalid or outside its boundary."""


def _reject_constant(value: str) -> None:
    raise ExportAuthorizationManifestError(f"non-finite JSON value {value!r} is not permitted")


def _reject_float(_value: str) -> None:
    raise ExportAuthorizationManifestError("floating-point values are not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExportAuthorizationManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class ExportAuthorizationManifest:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    target_origin: str
    alpha_export_path: str
    bravo_export_path: str
    tenant_segment_index: int
    alpha_principal_id: str
    bravo_principal_id: str
    environment_names: tuple[str, ...]
    timeout_ms: int
    max_response_bytes: int


@dataclass(frozen=True)
class ResolvedExportAuthorizationSecrets:
    alpha_token: SecretValue
    bravo_token: SecretValue
    alpha_canary: SecretValue
    bravo_canary: SecretValue


def parse_export_authorization_manifest(raw: bytes) -> ExportAuthorizationManifest:
    if not isinstance(raw, bytes):
        raise TypeError("export authorization manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise ExportAuthorizationManifestError("manifest size is invalid")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ExportAuthorizationManifestError("manifest must be UTF-8 JSON") from exc
    except ExportAuthorizationManifestError:
        raise
    except (json.JSONDecodeError, TypeError, RecursionError) as exc:
        raise ExportAuthorizationManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ExportAuthorizationManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise ExportAuthorizationManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise ExportAuthorizationManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise ExportAuthorizationManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise ExportAuthorizationManifestError("operator_acknowledged must be literal true")
    def text(name: str, maximum: int) -> str:
        value = data[name]
        if (not isinstance(value, str) or not value or value != value.strip()
                or len(value) > maximum or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise ExportAuthorizationManifestError(f"{name} is outside its text boundary")
        return value
    experiment_id = text("experiment_id", 128)
    alpha_id, bravo_id = text("alpha_principal_id", 128), text("bravo_principal_id", 128)
    if (not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", experiment_id)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", alpha_id)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", bravo_id)
            or alpha_id == bravo_id):
        raise ExportAuthorizationManifestError("principal and experiment identifiers are invalid")
    envs = tuple(text(name, 128) for name in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(name) for name in envs) or len(set(envs)) != len(envs):
        raise ExportAuthorizationManifestError("secret environment names must be valid and distinct")
    integer_fields = ("tenant_segment_index", "timeout_ms", "max_response_bytes")
    if any(isinstance(data[key], bool) or not isinstance(data[key], int) for key in integer_fields):
        raise ExportAuthorizationManifestError("limits and tenant segment index must be integers")
    values = ExportAuthorizationManifest(
        experiment_id, text("authorization_reference", 512), text("authorized_by", 256),
        text("target_origin", 512), text("alpha_export_path", 2048),
        text("bravo_export_path", 2048), data["tenant_segment_index"], alpha_id, bravo_id,
        envs, data["timeout_ms"], data["max_response_bytes"],
    )
    placeholders = ResolvedExportAuthorizationSecrets(*(SecretValue(f"manifest-check-{i}") for i in range(4)))
    try:
        _build_plan(values, placeholders)
    except ExportAuthorizationPlanError as exc:
        raise ExportAuthorizationManifestError(str(exc)) from exc
    return values


def _build_plan(manifest: ExportAuthorizationManifest, secrets: ResolvedExportAuthorizationSecrets):
    return ExportAuthorizationPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=True,
        target_origin=manifest.target_origin,
        alpha_export_path=manifest.alpha_export_path,
        bravo_export_path=manifest.bravo_export_path,
        tenant_segment_index=manifest.tenant_segment_index,
        alpha_canary=secrets.alpha_canary.reveal(),
        bravo_canary=secrets.bravo_canary.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def resolve_export_authorization_secrets(manifest: ExportAuthorizationManifest,
                                         environ: Mapping[str, str]) -> ResolvedExportAuthorizationSecrets:
    if not isinstance(manifest, ExportAuthorizationManifest) or not isinstance(environ, Mapping):
        raise TypeError("manifest and environment mapping have invalid types")
    missing = [name for name in manifest.environment_names if not environ.get(name)]
    if missing:
        raise ExportAuthorizationManifestError("missing or empty secret environment variables: " + ", ".join(missing))
    try:
        values = tuple(SecretValue(environ[name]) for name in manifest.environment_names)
    except (SecretValueError, TypeError) as exc:
        raise ExportAuthorizationManifestError("a secret environment value is invalid") from exc
    if len({value.reveal() for value in values}) != len(values):
        raise ExportAuthorizationManifestError("credentials and canaries must all differ")
    return ResolvedExportAuthorizationSecrets(*values)


def preflight_export_authorization_manifest(manifest, secrets) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {"schema_version": 1, "experiment_id": manifest.experiment_id,
            "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
            "secret_sources": list(manifest.environment_names), "request_count": 0,
            "maximum_request_count": 3, "active_probe_performed": False,
            "model_used": False, "part_of_forensic_verdict": False}


def execute_export_authorization_manifest(manifest, secrets):
    return run_export_authorization_experiment(
        _build_plan(manifest, secrets),
        alpha=BearerCredential(manifest.alpha_principal_id, secrets.alpha_token.reveal()),
        bravo=BearerCredential(manifest.bravo_principal_id, secrets.bravo_token.reveal()),
    )


def read_export_authorization_manifest(path: str | Path) -> ExportAuthorizationManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="export authorization manifest")
    except LocalArtifactError as exc:
        raise ExportAuthorizationManifestError(str(exc)) from exc
    return parse_export_authorization_manifest(raw)


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-export-authz")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_export_authorization_manifest(args.manifest)
        secrets = resolve_export_authorization_secrets(manifest, os.environ if environ is None else environ)
        result = (preflight_export_authorization_manifest(manifest, secrets) if args.dry_run
                  else execute_export_authorization_manifest(manifest, secrets))
    except (ExportAuthorizationManifestError, ExportAuthorizationPlanError) as exc:
        print(f"PANCITO_EXPORT_AUTHZ_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
