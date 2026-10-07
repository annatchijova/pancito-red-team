"""Strict CLI for the loopback CORS canary-origin reflection differential."""

from __future__ import annotations

import argparse, json, re, sys, unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.cors_misconfiguration import (
    CorsMisconfigurationPlan, CorsMisconfigurationPlanError,
    run_cors_misconfiguration_experiment,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file

_MAX = 65_536
_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset({"schema_version", "experiment_id", "authorization_reference",
    "authorized_by", "operator_acknowledged", "target_origin", "probe_path",
    "canary_origin", "timeout_ms", "max_response_bytes"})


class CorsMisconfigurationManifestError(ValueError):
    """A CORS_MISCONFIGURATION manifest is invalid or exceeds the active boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise CorsMisconfigurationManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(unicodedata.category(c).startswith("C") for c in value):
        raise CorsMisconfigurationManifestError(f"{name} is outside its text boundary")
    return value


def _reject_float(_value):
    raise CorsMisconfigurationManifestError("floating-point values are not permitted")


def _reject_constant(value):
    raise CorsMisconfigurationManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorsMisconfigurationManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class CorsMisconfigurationManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    probe_path: str
    canary_origin: str
    timeout_ms: int
    max_response_bytes: int


def _build(manifest: CorsMisconfigurationManifest) -> CorsMisconfigurationPlan:
    return CorsMisconfigurationPlan(
        manifest.experiment_id, manifest.authorization_reference, manifest.authorized_by,
        manifest.operator_acknowledged, manifest.target_origin, manifest.probe_path,
        manifest.canary_origin, manifest.timeout_ms, manifest.max_response_bytes)


def parse_cors_misconfiguration_manifest(raw: bytes) -> CorsMisconfigurationManifest:
    if not isinstance(raw, bytes):
        raise TypeError("CORS_MISCONFIGURATION manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise CorsMisconfigurationManifestError("CORS_MISCONFIGURATION manifest size is invalid")
    try:
        data = json.loads(raw.decode(), object_pairs_hook=_unique,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise CorsMisconfigurationManifestError("manifest must be UTF-8 JSON") from exc
    except CorsMisconfigurationManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise CorsMisconfigurationManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CorsMisconfigurationManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise CorsMisconfigurationManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise CorsMisconfigurationManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise CorsMisconfigurationManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise CorsMisconfigurationManifestError("operator_acknowledged must be literal true")
    if not _ID.fullmatch(_text(data, "experiment_id", 128)):
        raise CorsMisconfigurationManifestError("experiment_id is invalid")
    if any(isinstance(data[name], bool) or not isinstance(data[name], int)
           for name in ("timeout_ms", "max_response_bytes")):
        raise CorsMisconfigurationManifestError("limits must be integers")
    manifest = CorsMisconfigurationManifest(
        1, data["experiment_id"], _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), True, _text(data, "target_origin", 512),
        _text(data, "probe_path", 2048), _text(data, "canary_origin", 512),
        data["timeout_ms"], data["max_response_bytes"])
    try:
        _build(manifest)
    except CorsMisconfigurationPlanError as exc:
        raise CorsMisconfigurationManifestError(str(exc)) from exc
    return manifest


def read_cors_misconfiguration_manifest(path: str | Path) -> CorsMisconfigurationManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="CORS_MISCONFIGURATION manifest")
    except LocalArtifactError as exc:
        raise CorsMisconfigurationManifestError(str(exc)) from exc
    return parse_cors_misconfiguration_manifest(raw)


def preflight_cors_misconfiguration_manifest(manifest: CorsMisconfigurationManifest) -> dict[str, object]:
    _build(manifest)
    return {"schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "canary_origin": manifest.canary_origin, "request_count": 0,
        "maximum_request_count": 2, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False}


def execute_cors_misconfiguration_manifest(manifest: CorsMisconfigurationManifest) -> dict[str, object]:
    return run_cors_misconfiguration_experiment(_build(manifest))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-cors-misconfiguration")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_cors_misconfiguration_manifest(args.manifest)
        result = (preflight_cors_misconfiguration_manifest(manifest) if args.dry_run
                  else execute_cors_misconfiguration_manifest(manifest))
    except (CorsMisconfigurationManifestError, CorsMisconfigurationPlanError) as exc:
        print(f"PANCITO_CORS_MISCONFIGURATION_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
