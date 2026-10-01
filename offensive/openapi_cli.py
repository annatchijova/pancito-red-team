"""Command-line boundary for passive OpenAPI attack-surface triage."""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from offensive.handoff import (
    HandoffError,
    select_authn_candidate,
    select_bola_candidate,
    select_state_change_candidate,
)
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.openapi_surface import (
    AssetAnnotation,
    OpenApiTriageError,
    OpenApiTriagePlan,
    triage_openapi,
)


_MAX_MANIFEST_BYTES = 65_536
_MAX_OPENAPI_BYTES = 2_097_152
_FIELDS = frozenset(
    {
        "schema_version",
        "engagement_id",
        "authorization_reference",
        "authorized_by",
        "operator_acknowledged",
        "source_label",
        "asset_annotations",
    }
)
_ANNOTATION_FIELDS = frozenset({"entry_point", "value", "basis"})


class OpenApiCliError(ValueError):
    """The CLI manifest or local artifact boundary is invalid."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise OpenApiCliError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise OpenApiCliError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise OpenApiCliError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise OpenApiCliError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise OpenApiCliError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OpenApiCliError(f"duplicate key {key!r}")
        result[key] = value
    return result


def parse_triage_manifest(raw: bytes) -> OpenApiTriagePlan:
    """Parse a strict operator-authored plan without probing any target."""
    if not isinstance(raw, bytes):
        raise TypeError("triage manifest must be bytes")
    if not raw:
        raise OpenApiCliError("triage manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise OpenApiCliError(
            f"triage manifest exceeds {_MAX_MANIFEST_BYTES} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OpenApiCliError("triage manifest must be UTF-8 JSON") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except OpenApiCliError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise OpenApiCliError(f"invalid triage manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise OpenApiCliError("triage manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise OpenApiCliError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise OpenApiCliError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise OpenApiCliError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise OpenApiCliError("operator_acknowledged must be literal true")
    raw_annotations = data["asset_annotations"]
    if not isinstance(raw_annotations, list):
        raise OpenApiCliError("asset_annotations must be an array")
    if len(raw_annotations) > 10_000:
        raise OpenApiCliError("asset_annotations exceeds 10000 entries")

    annotations: list[AssetAnnotation] = []
    for index, value in enumerate(raw_annotations):
        if not isinstance(value, dict):
            raise OpenApiCliError(f"asset annotation {index} must be an object")
        unknown_annotation = sorted(set(value) - _ANNOTATION_FIELDS)
        missing_annotation = sorted(_ANNOTATION_FIELDS - set(value))
        if unknown_annotation:
            raise OpenApiCliError(
                "unknown annotation fields: " + ", ".join(unknown_annotation)
            )
        if missing_annotation:
            raise OpenApiCliError(
                "missing annotation fields: " + ", ".join(missing_annotation)
            )
        annotation_value = value["value"]
        if isinstance(annotation_value, bool) or not isinstance(annotation_value, int):
            raise OpenApiCliError(f"asset annotation {index} value must be an integer")
        try:
            annotations.append(
                AssetAnnotation(
                    entry_point=_text(value, "entry_point", 2_128),
                    value=annotation_value,
                    basis=_text(value, "basis", 512),
                )
            )
        except OpenApiTriageError as exc:
            raise OpenApiCliError(f"asset annotation {index}: {exc}") from exc

    try:
        return OpenApiTriagePlan(
            engagement_id=_text(data, "engagement_id", 128),
            authorization_reference=_text(data, "authorization_reference", 512),
            authorized_by=_text(data, "authorized_by", 256),
            operator_acknowledged=True,
            source_label=_text(data, "source_label", 512),
            asset_annotations=tuple(annotations),
        )
    except OpenApiTriageError as exc:
        raise OpenApiCliError(str(exc)) from exc


def read_triage_manifest(path: str | Path) -> OpenApiTriagePlan:
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="triage manifest"
        )
    except LocalArtifactError as exc:
        raise OpenApiCliError(str(exc)) from exc
    return parse_triage_manifest(raw)


def _read_openapi(path: str | Path) -> bytes:
    try:
        return read_bounded_regular_file(
            path, maximum_bytes=_MAX_OPENAPI_BYTES, label="OpenAPI document"
        )
    except LocalArtifactError as exc:
        raise OpenApiCliError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-openapi",
        description="Passively triage an authorized OpenAPI JSON artifact.",
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--select",
        metavar="CANDIDATE_ID",
        help="Emit one ranked BOLA candidate handoff instead of the full receipt",
    )
    selection.add_argument(
        "--select-authn",
        metavar="CANDIDATE_ID",
        help=(
            "Emit one ranked authentication candidate handoff instead of the "
            "full receipt"
        ),
    )
    selection.add_argument(
        "--select-state-change",
        metavar="CANDIDATE_ID",
        help=(
            "Emit one ranked public PATCH candidate handoff instead of the "
            "full receipt"
        ),
    )
    parser.add_argument("openapi", help="Path to an OpenAPI 3.x JSON document")
    parser.add_argument("manifest", help="Path to the strict triage plan JSON")
    args = parser.parse_args(argv)
    try:
        raw_openapi = _read_openapi(args.openapi)
        plan = read_triage_manifest(args.manifest)
        receipt = triage_openapi(raw_openapi, plan)
        result: dict[str, object] = receipt
        if args.select is not None:
            result = select_bola_candidate(receipt, args.select).to_receipt()
        elif args.select_authn is not None:
            result = select_authn_candidate(
                receipt, args.select_authn
            ).to_receipt()
        elif args.select_state_change is not None:
            result = select_state_change_candidate(
                receipt, args.select_state_change
            ).to_receipt()
    except (OpenApiCliError, OpenApiTriageError, HandoffError) as exc:
        print(f"PANCITO_OPENAPI_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
