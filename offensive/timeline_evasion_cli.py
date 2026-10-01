"""Strict CLI for the fixed SIFT timeline composition audit."""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.timeline_evasion import (
    TimelineEvasionPlan,
    TimelineEvasionPlanError,
    run_timeline_evasion_differential,
)


_MAX_MANIFEST_BYTES = 16_384
_FIELDS = frozenset(
    {
        "schema_version",
        "experiment_id",
        "authorization_reference",
        "authorized_by",
        "operator_acknowledged",
    }
)


class TimelineEvasionManifestError(ValueError):
    """The manifest violates the closed timeline-audit boundary."""


def _reject_float(_value: str) -> None:
    raise TimelineEvasionManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise TimelineEvasionManifestError(
        f"non-finite JSON value {value!r} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TimelineEvasionManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise TimelineEvasionManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise TimelineEvasionManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise TimelineEvasionManifestError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class TimelineEvasionManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool


def parse_timeline_evasion_manifest(raw: bytes) -> TimelineEvasionManifest:
    if not isinstance(raw, bytes):
        raise TypeError("timeline-evasion manifest must be bytes")
    if not raw:
        raise TimelineEvasionManifestError("manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise TimelineEvasionManifestError(
            f"manifest exceeds {_MAX_MANIFEST_BYTES} bytes"
        )
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise TimelineEvasionManifestError("manifest must be UTF-8 JSON") from exc
    except TimelineEvasionManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise TimelineEvasionManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TimelineEvasionManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise TimelineEvasionManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise TimelineEvasionManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise TimelineEvasionManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise TimelineEvasionManifestError("operator_acknowledged must be literal true")
    return TimelineEvasionManifest(
        schema_version=1,
        experiment_id=_text(data, "experiment_id", 128),
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
    )


def read_timeline_evasion_manifest(path: str | Path) -> TimelineEvasionManifest:
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="timeline-evasion manifest"
        )
    except LocalArtifactError as exc:
        raise TimelineEvasionManifestError(str(exc)) from exc
    return parse_timeline_evasion_manifest(raw)


def _build_plan(manifest: TimelineEvasionManifest) -> TimelineEvasionPlan:
    try:
        return TimelineEvasionPlan(
            experiment_id=manifest.experiment_id,
            authorization_reference=manifest.authorization_reference,
            authorized_by=manifest.authorized_by,
            operator_acknowledged=manifest.operator_acknowledged,
        )
    except TimelineEvasionPlanError as exc:
        raise TimelineEvasionManifestError(str(exc)) from exc


def preflight_timeline_evasion_manifest(
    manifest: TimelineEvasionManifest,
) -> dict[str, object]:
    _build_plan(manifest)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "cells": list(_CELLS),
        "sample_source": "MODULE_OWNED_SYNTHETIC_FACTS",
        "sensor_run": False,
        "network_request_count": 0,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


_CELLS = (
    "CONTROL_SHARED_ENTITY",
    "MISSING_MFT",
    "PRODUCTION_SHAPED_PAIR",
)


def execute_timeline_evasion_manifest(
    manifest: TimelineEvasionManifest,
) -> dict[str, object]:
    return run_timeline_evasion_differential(_build_plan(manifest))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-timeline-evasion",
        description="Audit SIFT cross-source identity with fixed synthetic facts.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict authorization manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_timeline_evasion_manifest(args.manifest)
        result = (
            preflight_timeline_evasion_manifest(manifest)
            if args.dry_run
            else execute_timeline_evasion_manifest(manifest)
        )
    except TimelineEvasionManifestError as exc:
        print(f"PANCITO_TIMELINE_EVASION_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

