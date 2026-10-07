"""Strict CLI for the loopback GraphQL batching-exposure differential."""

from __future__ import annotations

import argparse, json, re, sys, unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.graphql_batching import (
    GraphqlBatchingPlan, GraphqlBatchingPlanError,
    run_graphql_batching_experiment,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file

_MAX = 65_536
_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset({"schema_version", "experiment_id", "authorization_reference",
    "authorized_by", "operator_acknowledged", "target_origin", "endpoint_path",
    "batch_size", "timeout_ms", "max_response_bytes"})


class GraphqlBatchingManifestError(ValueError):
    """A GRAPHQL_BATCHING manifest is invalid or exceeds the active boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise GraphqlBatchingManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(unicodedata.category(c).startswith("C") for c in value):
        raise GraphqlBatchingManifestError(f"{name} is outside its text boundary")
    return value


def _reject_float(_value):
    raise GraphqlBatchingManifestError("floating-point values are not permitted")


def _reject_constant(value):
    raise GraphqlBatchingManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GraphqlBatchingManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class GraphqlBatchingManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    endpoint_path: str
    batch_size: int
    timeout_ms: int
    max_response_bytes: int


def _build(manifest: GraphqlBatchingManifest) -> GraphqlBatchingPlan:
    return GraphqlBatchingPlan(
        manifest.experiment_id, manifest.authorization_reference, manifest.authorized_by,
        manifest.operator_acknowledged, manifest.target_origin, manifest.endpoint_path,
        manifest.batch_size, manifest.timeout_ms, manifest.max_response_bytes)


def parse_graphql_batching_manifest(raw: bytes) -> GraphqlBatchingManifest:
    if not isinstance(raw, bytes):
        raise TypeError("GRAPHQL_BATCHING manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise GraphqlBatchingManifestError("GRAPHQL_BATCHING manifest size is invalid")
    try:
        data = json.loads(raw.decode(), object_pairs_hook=_unique,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise GraphqlBatchingManifestError("manifest must be UTF-8 JSON") from exc
    except GraphqlBatchingManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise GraphqlBatchingManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise GraphqlBatchingManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise GraphqlBatchingManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise GraphqlBatchingManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise GraphqlBatchingManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise GraphqlBatchingManifestError("operator_acknowledged must be literal true")
    if not _ID.fullmatch(_text(data, "experiment_id", 128)):
        raise GraphqlBatchingManifestError("experiment_id is invalid")
    if any(isinstance(data[name], bool) or not isinstance(data[name], int)
           for name in ("batch_size", "timeout_ms", "max_response_bytes")):
        raise GraphqlBatchingManifestError("limits must be integers")
    manifest = GraphqlBatchingManifest(
        1, data["experiment_id"], _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), True, _text(data, "target_origin", 512),
        _text(data, "endpoint_path", 2048), data["batch_size"],
        data["timeout_ms"], data["max_response_bytes"])
    try:
        _build(manifest)
    except GraphqlBatchingPlanError as exc:
        raise GraphqlBatchingManifestError(str(exc)) from exc
    return manifest


def read_graphql_batching_manifest(path: str | Path) -> GraphqlBatchingManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="GRAPHQL_BATCHING manifest")
    except LocalArtifactError as exc:
        raise GraphqlBatchingManifestError(str(exc)) from exc
    return parse_graphql_batching_manifest(raw)


def preflight_graphql_batching_manifest(manifest: GraphqlBatchingManifest) -> dict[str, object]:
    _build(manifest)
    return {"schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "endpoint_path": manifest.endpoint_path, "batch_size": manifest.batch_size,
        "request_count": 0, "maximum_request_count": 2, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False}


def execute_graphql_batching_manifest(manifest: GraphqlBatchingManifest) -> dict[str, object]:
    return run_graphql_batching_experiment(_build(manifest))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-graphql-batching")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_graphql_batching_manifest(args.manifest)
        result = (preflight_graphql_batching_manifest(manifest) if args.dry_run
                  else execute_graphql_batching_manifest(manifest))
    except (GraphqlBatchingManifestError, GraphqlBatchingPlanError) as exc:
        print(f"PANCITO_GRAPHQL_BATCHING_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
