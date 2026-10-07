"""Strict CLI for the loopback SSRF outbound-fetch canary differential."""

from __future__ import annotations

import argparse, json, re, sys, unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.ssrf_outbound_fetch import (
    SsrfOutboundFetchPlan, SsrfOutboundFetchPlanError,
    run_ssrf_outbound_fetch_experiment,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file

_MAX = 65_536
_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset({"schema_version", "experiment_id", "authorization_reference",
    "authorized_by", "operator_acknowledged", "target_origin", "probe_path",
    "url_parameter_name", "timeout_ms", "canary_grace_ms", "max_response_bytes"})


class SsrfOutboundFetchManifestError(ValueError):
    """An SSRF_OUTBOUND_FETCH manifest is invalid or exceeds the active boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise SsrfOutboundFetchManifestError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(unicodedata.category(c).startswith("C") for c in value):
        raise SsrfOutboundFetchManifestError(f"{name} is outside its text boundary")
    return value


def _reject_float(_value):
    raise SsrfOutboundFetchManifestError("floating-point values are not permitted")


def _reject_constant(value):
    raise SsrfOutboundFetchManifestError(f"non-finite JSON value {value!r} is not permitted")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SsrfOutboundFetchManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class SsrfOutboundFetchManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    probe_path: str
    url_parameter_name: str
    timeout_ms: int
    canary_grace_ms: int
    max_response_bytes: int


def _build(manifest: SsrfOutboundFetchManifest) -> SsrfOutboundFetchPlan:
    return SsrfOutboundFetchPlan(
        manifest.experiment_id, manifest.authorization_reference, manifest.authorized_by,
        manifest.operator_acknowledged, manifest.target_origin, manifest.probe_path,
        manifest.url_parameter_name, manifest.timeout_ms, manifest.canary_grace_ms,
        manifest.max_response_bytes)


def parse_ssrf_outbound_fetch_manifest(raw: bytes) -> SsrfOutboundFetchManifest:
    if not isinstance(raw, bytes):
        raise TypeError("SSRF_OUTBOUND_FETCH manifest must be bytes")
    if not raw or len(raw) > _MAX:
        raise SsrfOutboundFetchManifestError("SSRF_OUTBOUND_FETCH manifest size is invalid")
    try:
        data = json.loads(raw.decode(), object_pairs_hook=_unique,
                          parse_float=_reject_float, parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise SsrfOutboundFetchManifestError("manifest must be UTF-8 JSON") from exc
    except SsrfOutboundFetchManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise SsrfOutboundFetchManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SsrfOutboundFetchManifestError("manifest root must be an object")
    unknown, missing = sorted(set(data) - _FIELDS), sorted(_FIELDS - set(data))
    if unknown:
        raise SsrfOutboundFetchManifestError("unknown fields: " + ", ".join(unknown))
    if missing:
        raise SsrfOutboundFetchManifestError("missing fields: " + ", ".join(missing))
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise SsrfOutboundFetchManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise SsrfOutboundFetchManifestError("operator_acknowledged must be literal true")
    if not _ID.fullmatch(_text(data, "experiment_id", 128)):
        raise SsrfOutboundFetchManifestError("experiment_id is invalid")
    if any(isinstance(data[name], bool) or not isinstance(data[name], int)
           for name in ("timeout_ms", "canary_grace_ms", "max_response_bytes")):
        raise SsrfOutboundFetchManifestError("limits must be integers")
    manifest = SsrfOutboundFetchManifest(
        1, data["experiment_id"], _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), True, _text(data, "target_origin", 512),
        _text(data, "probe_path", 2048), _text(data, "url_parameter_name", 64),
        data["timeout_ms"], data["canary_grace_ms"], data["max_response_bytes"])
    try:
        _build(manifest)
    except SsrfOutboundFetchPlanError as exc:
        raise SsrfOutboundFetchManifestError(str(exc)) from exc
    return manifest


def read_ssrf_outbound_fetch_manifest(path: str | Path) -> SsrfOutboundFetchManifest:
    try:
        raw = read_bounded_regular_file(path, maximum_bytes=_MAX, label="SSRF_OUTBOUND_FETCH manifest")
    except LocalArtifactError as exc:
        raise SsrfOutboundFetchManifestError(str(exc)) from exc
    return parse_ssrf_outbound_fetch_manifest(raw)


def preflight_ssrf_outbound_fetch_manifest(manifest: SsrfOutboundFetchManifest) -> dict[str, object]:
    _build(manifest)
    return {"schema_version": 1, "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED", "target_origin": manifest.target_origin,
        "url_parameter_name": manifest.url_parameter_name, "request_count": 0,
        "maximum_request_count": 2, "active_probe_performed": False,
        "model_used": False, "part_of_forensic_verdict": False}


def execute_ssrf_outbound_fetch_manifest(manifest: SsrfOutboundFetchManifest) -> dict[str, object]:
    return run_ssrf_outbound_fetch_experiment(_build(manifest))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pancito-ssrf-outbound-fetch")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_ssrf_outbound_fetch_manifest(args.manifest)
        result = (preflight_ssrf_outbound_fetch_manifest(manifest) if args.dry_run
                  else execute_ssrf_outbound_fetch_manifest(manifest))
    except (SsrfOutboundFetchManifestError, SsrfOutboundFetchPlanError) as exc:
        print(f"PANCITO_SSRF_OUTBOUND_FETCH_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
