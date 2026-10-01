"""Strict coordinator for the Prefetch and Registry SIFT validations."""

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
from offensive.prefetch_evasion import (
    PrefetchEvasionPlan,
    PrefetchEvasionPlanError,
    run_prefetch_evasion_differential,
)
from offensive.registry_evasion import (
    RegistryEvasionPlan,
    RegistryEvasionPlanError,
    run_registry_evasion_differential,
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


class WindowsArtifactManifestError(ValueError):
    """The manifest violates the closed two-module validation boundary."""


def _reject_float(_value: str) -> None:
    raise WindowsArtifactManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise WindowsArtifactManifestError(
        f"non-finite JSON value {value!r} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WindowsArtifactManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise WindowsArtifactManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise WindowsArtifactManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise WindowsArtifactManifestError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class WindowsArtifactManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool


def parse_windows_artifact_manifest(raw: bytes) -> WindowsArtifactManifest:
    if not isinstance(raw, bytes):
        raise TypeError("Windows-artifact manifest must be bytes")
    if not raw:
        raise WindowsArtifactManifestError("manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise WindowsArtifactManifestError(
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
        raise WindowsArtifactManifestError("manifest must be UTF-8 JSON") from exc
    except WindowsArtifactManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise WindowsArtifactManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise WindowsArtifactManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise WindowsArtifactManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise WindowsArtifactManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise WindowsArtifactManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise WindowsArtifactManifestError("operator_acknowledged must be literal true")
    return WindowsArtifactManifest(
        schema_version=1,
        experiment_id=_text(data, "experiment_id", 128),
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
    )


def read_windows_artifact_manifest(path: str | Path) -> WindowsArtifactManifest:
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="Windows-artifact manifest"
        )
    except LocalArtifactError as exc:
        raise WindowsArtifactManifestError(str(exc)) from exc
    return parse_windows_artifact_manifest(raw)


def _plans(
    manifest: WindowsArtifactManifest,
) -> tuple[PrefetchEvasionPlan, RegistryEvasionPlan]:
    common = {
        "experiment_id": manifest.experiment_id,
        "authorization_reference": manifest.authorization_reference,
        "authorized_by": manifest.authorized_by,
        "operator_acknowledged": manifest.operator_acknowledged,
    }
    try:
        return PrefetchEvasionPlan(**common), RegistryEvasionPlan(**common)
    except (PrefetchEvasionPlanError, RegistryEvasionPlanError) as exc:
        raise WindowsArtifactManifestError(str(exc)) from exc


def preflight_windows_artifact_manifest(
    manifest: WindowsArtifactManifest,
) -> dict[str, object]:
    _plans(manifest)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "modules": ["PREFETCH_EVASION", "REGISTRY_EVASION"],
        "sample_source": "MODULE_OWNED_SYNTHETIC_FIXTURES",
        "sensor_run": False,
        "network_request_count": 0,
        "model_used": False,
        "part_of_forensic_verdict": False,
    }


def execute_windows_artifact_manifest(
    manifest: WindowsArtifactManifest,
) -> dict[str, object]:
    prefetch_plan, registry_plan = _plans(manifest)
    module_results = {
        "PREFETCH_EVASION": run_prefetch_evasion_differential(prefetch_plan),
        "REGISTRY_EVASION": run_registry_evasion_differential(registry_plan),
    }
    levels = {
        result["epistemic_level"] for result in module_results.values()
    }
    if "INCONCLUSIVE" in levels:
        level = "INCONCLUSIVE"
        reason = "ONE_OR_MORE_MODULES_INCONCLUSIVE"
    elif "FALSIFIED" in levels:
        level = "FALSIFIED"
        reason = "ONE_OR_MORE_MODULE_PREDICTIONS_FALSIFIED"
    else:
        level = "CONFIRMED_BY_INDUCTION"
        reason = "BOTH_MODULE_PREDICTIONS_CONFIRMED"
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "capability": "offline-windows-artifact-validation-suite",
        "module_results": module_results,
        "epistemic_level": level,
        "reason_code": reason,
        "module_count": 2,
        "maximum_module_count": 2,
        "network_request_count": 0,
        "impact_assessment": "BLUE_CONTROL_VALIDATION_ONLY",
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-windows-artifacts",
        description="Run fixed Prefetch and Registry SIFT validation cells.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict authorization manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_windows_artifact_manifest(args.manifest)
        result = (
            preflight_windows_artifact_manifest(manifest)
            if args.dry_run
            else execute_windows_artifact_manifest(manifest)
        )
    except WindowsArtifactManifestError as exc:
        print(f"PANCITO_WINDOWS_ARTIFACT_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
