"""Strict CLI for the bounded loopback search authorization differential."""

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
from offensive.search_authz import SearchAuthorizationPlan, SearchAuthorizationPlanError
from offensive.search_authz import run_search_authorization_experiment
from offensive.secrets import SecretValue, SecretValueError


_MAX = 65_536
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ENV_FIELDS = (
    "alpha_token_env",
    "bravo_token_env",
    "alpha_query_env",
    "bravo_query_env",
    "alpha_canary_env",
    "bravo_canary_env",
)
_FIELDS = frozenset(
    {
        "schema_version", "experiment_id", "authorization_reference", "authorized_by",
        "operator_acknowledged", "target_origin", "search_path", "query_parameter",
        "alpha_principal_id", "bravo_principal_id", *_ENV_FIELDS,
        "timeout_ms", "max_response_bytes",
    }
)


class SearchAuthorizationManifestError(ValueError):
    """A search authorization manifest is invalid or outside its boundary."""


def _reject_float(_value: str) -> None:
    raise SearchAuthorizationManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise SearchAuthorizationManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SearchAuthorizationManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise SearchAuthorizationManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(unicodedata.category(char).startswith("C") for char in value):
        raise SearchAuthorizationManifestError(f"{name} is outside its text boundary")
    return value


@dataclass(frozen=True)
class SearchAuthorizationManifest:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    target_origin: str
    search_path: str
    query_parameter: str
    alpha_principal_id: str
    bravo_principal_id: str
    environment_names: tuple[str, ...]
    timeout_ms: int
    max_response_bytes: int


@dataclass(frozen=True)
class ResolvedSearchAuthorizationSecrets:
    alpha_token: SecretValue = field(repr=False)
    bravo_token: SecretValue = field(repr=False)
    alpha_query: SecretValue = field(repr=False)
    bravo_query: SecretValue = field(repr=False)
    alpha_canary: SecretValue = field(repr=False)
    bravo_canary: SecretValue = field(repr=False)


def _build_plan(manifest: SearchAuthorizationManifest, secrets: ResolvedSearchAuthorizationSecrets):
    return SearchAuthorizationPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=True,
        target_origin=manifest.target_origin,
        search_path=manifest.search_path,
        query_parameter=manifest.query_parameter,
        alpha_query=secrets.alpha_query.reveal(),
        bravo_query=secrets.bravo_query.reveal(),
        alpha_canary=secrets.alpha_canary.reveal(),
        bravo_canary=secrets.bravo_canary.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
    )


def parse_search_authorization_manifest(raw: bytes) -> SearchAuthorizationManifest:
    if not isinstance(raw, bytes):
        raise TypeError("search authorization manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise SearchAuthorizationManifestError("search authorization manifest size is invalid")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise SearchAuthorizationManifestError("manifest must be UTF-8 JSON") from exc
    except SearchAuthorizationManifestError:
        raise
    except (json.JSONDecodeError, TypeError, RecursionError) as exc:
        raise SearchAuthorizationManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SearchAuthorizationManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise SearchAuthorizationManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise SearchAuthorizationManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise SearchAuthorizationManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise SearchAuthorizationManifestError("operator_acknowledged must be literal true")
    identifiers = tuple(_text(data, key, 128) for key in
                        ("experiment_id", "alpha_principal_id", "bravo_principal_id"))
    if any(not _ID_RE.fullmatch(value) for value in identifiers) or identifiers[1] == identifiers[2]:
        raise SearchAuthorizationManifestError("identifiers must be valid and distinct")
    envs = tuple(_text(data, key, 128) for key in _ENV_FIELDS)
    if any(not _ENV_RE.fullmatch(value) for value in envs) or len(set(envs)) != len(envs):
        raise SearchAuthorizationManifestError("secret environment names must be valid and distinct")
    if any(isinstance(data[key], bool) or not isinstance(data[key], int)
           for key in ("timeout_ms", "max_response_bytes")):
        raise SearchAuthorizationManifestError("limits must be integers")
    manifest = SearchAuthorizationManifest(
        identifiers[0], _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), _text(data, "target_origin", 512),
        _text(data, "search_path", 2048), _text(data, "query_parameter", 64),
        identifiers[1], identifiers[2], envs, data["timeout_ms"], data["max_response_bytes"],
    )
    placeholder = ResolvedSearchAuthorizationSecrets(*(
        SecretValue(f"manifest-validation-secret-{index}") for index in range(6)
    ))
    try:
        _build_plan(manifest, placeholder)
    except SearchAuthorizationPlanError as exc:
        raise SearchAuthorizationManifestError(str(exc)) from exc
    return manifest


def read_search_authorization_manifest(path: str | Path) -> SearchAuthorizationManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="search authorization manifest")
    except LocalArtifactError as exc:
        raise SearchAuthorizationManifestError(str(exc)) from exc
    return parse_search_authorization_manifest(raw)


def resolve_search_authorization_secrets(
    manifest: SearchAuthorizationManifest, environ: Mapping[str, str]
) -> ResolvedSearchAuthorizationSecrets:
    if not isinstance(manifest, SearchAuthorizationManifest) or not isinstance(environ, Mapping):
        raise TypeError("manifest and environment mapping have invalid types")
    missing = [name for name in manifest.environment_names if not environ.get(name)]
    if missing:
        raise SearchAuthorizationManifestError("missing or empty secret environment variables: " + ", ".join(missing))
    try:
        values = [SecretValue(environ[name]) for name in manifest.environment_names]
    except (SecretValueError, TypeError) as exc:
        raise SearchAuthorizationManifestError("a secret environment value is invalid") from exc
    if len({value.reveal() for value in values}) != len(values):
        raise SearchAuthorizationManifestError("all resolved secrets and queries must be distinct")
    return ResolvedSearchAuthorizationSecrets(*values)


def preflight_search_authorization_manifest(manifest, secrets) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "secret_sources": list(manifest.environment_names), "request_count": 0,
        "maximum_request_count": 3, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False,
    }


def execute_search_authorization_manifest(manifest, secrets):
    plan = _build_plan(manifest, secrets)
    return run_search_authorization_experiment(
        plan,
        alpha=BearerCredential(manifest.alpha_principal_id, secrets.alpha_token.reveal()),
        bravo=BearerCredential(manifest.bravo_principal_id, secrets.bravo_token.reveal()),
    )


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-search-authz")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_search_authorization_manifest(args.manifest)
        secrets = resolve_search_authorization_secrets(manifest, os.environ if environ is None else environ)
        result = (preflight_search_authorization_manifest(manifest, secrets) if args.dry_run
                  else execute_search_authorization_manifest(manifest, secrets))
    except (SearchAuthorizationManifestError, SearchAuthorizationPlanError) as exc:
        print(f"PANCITO_SEARCH_AUTHZ_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
