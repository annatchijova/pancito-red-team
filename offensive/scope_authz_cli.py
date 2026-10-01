"""Strict CLI for the loopback token-scope authorization differential."""

from __future__ import annotations

import argparse, json, os, re, sys, unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from offensive.bola import BearerCredential
from offensive.scope_authz import (
    ScopeAuthorizationPlan, ScopeAuthorizationPlanError,
    run_scope_authorization_experiment,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError

_MAX = 65_536
_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ENV_FIELDS = ("broad_token_env", "narrow_token_env", "privileged_canary_env", "narrow_canary_env")
_FIELDS = frozenset({"schema_version", "experiment_id", "authorization_reference",
    "authorized_by", "operator_acknowledged", "target_origin", "privileged_resource_path",
    "narrow_control_path", "broad_principal_id", "narrow_principal_id", *_ENV_FIELDS,
    "timeout_ms", "max_response_bytes"})


class ScopeAuthorizationManifestError(ValueError):
    """A SCOPE manifest is invalid or exceeds the active boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ScopeAuthorizationManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(unicodedata.category(c).startswith("C") for c in value):
        raise ScopeAuthorizationManifestError(f"{name} is outside its text boundary")
    return value


def _reject_float(_value):
    raise ScopeAuthorizationManifestError("floating-point values are not permitted")


def _reject_constant(value):
    raise ScopeAuthorizationManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScopeAuthorizationManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class ScopeAuthorizationManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    privileged_resource_path: str
    narrow_control_path: str
    broad_principal_id: str
    narrow_principal_id: str
    broad_token_env: str
    narrow_token_env: str
    privileged_canary_env: str
    narrow_canary_env: str
    timeout_ms: int
    max_response_bytes: int

    @property
    def secret_environment_names(self):
        return tuple(getattr(self, name) for name in _ENV_FIELDS)


@dataclass(frozen=True)
class ResolvedScopeAuthorizationSecrets:
    broad_token: SecretValue = field(repr=False)
    narrow_token: SecretValue = field(repr=False)
    privileged_canary: SecretValue = field(repr=False)
    narrow_canary: SecretValue = field(repr=False)


def _build(manifest, secrets):
    return ScopeAuthorizationPlan(
        manifest.experiment_id, manifest.authorization_reference, manifest.authorized_by,
        manifest.operator_acknowledged, manifest.target_origin, manifest.privileged_resource_path,
        manifest.narrow_control_path, secrets.privileged_canary.reveal(),
        secrets.narrow_canary.reveal(), manifest.timeout_ms, manifest.max_response_bytes)


def parse_scope_authorization_manifest(raw: bytes):
    if not isinstance(raw, bytes):
        raise TypeError("SCOPE manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise ScopeAuthorizationManifestError("SCOPE manifest size is invalid")
    try:
        data = json.loads(raw.decode(), object_pairs_hook=_unique,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ScopeAuthorizationManifestError("manifest must be UTF-8 JSON") from exc
    except ScopeAuthorizationManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise ScopeAuthorizationManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeAuthorizationManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise ScopeAuthorizationManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise ScopeAuthorizationManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise ScopeAuthorizationManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise ScopeAuthorizationManifestError("operator_acknowledged must be literal true")
    ids = tuple(_text(data, name, 128) for name in
                ("experiment_id", "broad_principal_id", "narrow_principal_id"))
    if any(not _ID.fullmatch(value) for value in ids) or ids[1] == ids[2]:
        raise ScopeAuthorizationManifestError("identifiers must be valid and distinct")
    envs = tuple(_text(data, name, 128) for name in _ENV_FIELDS)
    if any(not _ENV.fullmatch(value) for value in envs) or len(set(envs)) != 4:
        raise ScopeAuthorizationManifestError("secret environment names must be valid and distinct")
    if any(isinstance(data[name], bool) or not isinstance(data[name], int)
           for name in ("timeout_ms", "max_response_bytes")):
        raise ScopeAuthorizationManifestError("limits must be integers")
    manifest = ScopeAuthorizationManifest(
        1, ids[0], _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), True, _text(data, "target_origin", 512),
        _text(data, "privileged_resource_path", 2048), _text(data, "narrow_control_path", 2048),
        ids[1], ids[2], *envs, data["timeout_ms"], data["max_response_bytes"])
    try:
        _build(manifest, ResolvedScopeAuthorizationSecrets(*(
            SecretValue(f"manifest-validation-secret-{index}") for index in range(4))))
    except ScopeAuthorizationPlanError as exc:
        raise ScopeAuthorizationManifestError(str(exc)) from exc
    return manifest


def read_scope_authorization_manifest(path: str | Path):
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="SCOPE manifest")
    except LocalArtifactError as exc:
        raise ScopeAuthorizationManifestError(str(exc)) from exc
    return parse_scope_authorization_manifest(raw)


def resolve_scope_authorization_secrets(manifest, environ: Mapping[str, str]):
    if not isinstance(manifest, ScopeAuthorizationManifest):
        raise TypeError("manifest must be a ScopeAuthorizationManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise ScopeAuthorizationManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing))
    try:
        values = [SecretValue(environ[name]) for name in manifest.secret_environment_names]
    except (SecretValueError, TypeError) as exc:
        raise ScopeAuthorizationManifestError("a secret environment value is invalid") from exc
    if len({value.reveal() for value in values}) != 4:
        raise ScopeAuthorizationManifestError("all resolved secrets must be distinct")
    return ResolvedScopeAuthorizationSecrets(*values)


def preflight_scope_authorization_manifest(manifest, secrets):
    _build(manifest, secrets)
    return {"schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "secret_sources": list(manifest.secret_environment_names), "request_count": 0,
        "maximum_request_count": 3, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False}


def execute_scope_authorization_manifest(manifest, secrets):
    return run_scope_authorization_experiment(
        _build(manifest, secrets),
        broad=BearerCredential(manifest.broad_principal_id, secrets.broad_token.reveal()),
        narrow=BearerCredential(manifest.narrow_principal_id, secrets.narrow_token.reveal()))


def main(argv: Sequence[str] | None = None, *, environ=None):
    parser = argparse.ArgumentParser(prog="pancito-scope-authz")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_scope_authorization_manifest(args.manifest)
        secrets = resolve_scope_authorization_secrets(manifest,
                                                         os.environ if environ is None else environ)
        result = (preflight_scope_authorization_manifest(manifest, secrets)
                  if args.dry_run else execute_scope_authorization_manifest(manifest, secrets))
    except (ScopeAuthorizationManifestError, ScopeAuthorizationPlanError) as exc:
        print(f"PANCITO_SCOPE_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
