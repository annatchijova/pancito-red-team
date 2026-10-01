"""Strict CLI for the module-owned SIFT forensic-evasion differential."""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from offensive.forensic_evasion import (
    ForensicEvasionPlan,
    ForensicEvasionPlanError,
    run_forensic_evasion_differential,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file


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


class ForensicEvasionManifestError(ValueError):
    """The manifest violates the closed synthetic-experiment boundary."""


def _reject_float(_value: str) -> None:
    raise ForensicEvasionManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise ForensicEvasionManifestError(
        f"non-finite JSON value {value!r} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ForensicEvasionManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ForensicEvasionManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise ForensicEvasionManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ForensicEvasionManifestError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class ForensicEvasionManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool


def parse_forensic_evasion_manifest(raw: bytes) -> ForensicEvasionManifest:
    if not isinstance(raw, bytes):
        raise TypeError("forensic-evasion manifest must be bytes")
    if not raw:
        raise ForensicEvasionManifestError("manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ForensicEvasionManifestError(
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
        raise ForensicEvasionManifestError("manifest must be UTF-8 JSON") from exc
    except ForensicEvasionManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise ForensicEvasionManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ForensicEvasionManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise ForensicEvasionManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise ForensicEvasionManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise ForensicEvasionManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise ForensicEvasionManifestError(
            "operator_acknowledged must be literal true"
        )
    return ForensicEvasionManifest(
        schema_version=1,
        experiment_id=_text(data, "experiment_id", 128),
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
    )


def read_forensic_evasion_manifest(path: str | Path) -> ForensicEvasionManifest:
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="forensic-evasion manifest"
        )
    except LocalArtifactError as exc:
        raise ForensicEvasionManifestError(str(exc)) from exc
    return parse_forensic_evasion_manifest(raw)


def _build_plan(manifest: ForensicEvasionManifest) -> ForensicEvasionPlan:
    try:
        return ForensicEvasionPlan(
            experiment_id=manifest.experiment_id,
            authorization_reference=manifest.authorization_reference,
            authorized_by=manifest.authorized_by,
            operator_acknowledged=manifest.operator_acknowledged,
        )
    except ForensicEvasionPlanError as exc:
        raise ForensicEvasionManifestError(str(exc)) from exc


def preflight_forensic_evasion_manifest(
    manifest: ForensicEvasionManifest,
) -> dict[str, object]:
    _build_plan(manifest)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "cells": ["CONTROL", "LOG_WIPE", "TIMESTOMP"],
        "sample_source": "MODULE_OWNED_SYNTHETIC_FIXTURES",
        "sensor_run": False,
        "network_request_count": 0,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def execute_forensic_evasion_manifest(
    manifest: ForensicEvasionManifest,
) -> dict[str, object]:
    return run_forensic_evasion_differential(_build_plan(manifest))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-forensic-evasion",
        description="Validate two SIFT forensic sensors with fixed synthetic cells.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict authorization manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_forensic_evasion_manifest(args.manifest)
        result = (
            preflight_forensic_evasion_manifest(manifest)
            if args.dry_run
            else execute_forensic_evasion_manifest(manifest)
        )
    except ForensicEvasionManifestError as exc:
        print(f"PANCITO_FORENSIC_EVASION_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

