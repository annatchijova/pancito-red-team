"""Strict local boundary for deterministic Red/Blue exercise evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.purple import (
    BlueObservation,
    BlueObservationError,
    evaluate_authn_detection,
    evaluate_bola_detection,
    evaluate_collection_authz_detection,
    evaluate_scope_authz_detection,
    evaluate_search_authz_detection,
    evaluate_export_authz_detection,
    evaluate_async_export_authz_detection,
    evaluate_forwarded_redirect_detection,
    evaluate_file_ingress_detection,
    evaluate_mass_assignment_detection,
    evaluate_nested_bola_detection,
    evaluate_stale_authority_detection,
    evaluate_function_authz_detection,
    evaluate_state_change_detection,
)


_MAX_RECEIPT_BYTES = 1_048_576
_MAX_OBSERVATION_BYTES = 65_536
_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "exercise_marker",
        "collection_status",
        "observed_steps",
        "alert_status",
        "alert_reference",
        "alert_depends_on_exercise_marker",
    }
)


class PurpleCliError(ValueError):
    """A local Purple input is invalid, ambiguous, or internally inconsistent."""


def _reject_float(_value: str) -> None:
    raise PurpleCliError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise PurpleCliError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PurpleCliError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _parse_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise TypeError(f"{label} must be bytes")
    if not raw:
        raise PurpleCliError(f"{label} must not be empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PurpleCliError(f"{label} must be UTF-8 JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except PurpleCliError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise PurpleCliError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PurpleCliError(f"{label} root must be an object")
    return value


def parse_blue_observation(raw: bytes) -> BlueObservation:
    """Parse the exact operator-asserted Blue observation schema."""
    if len(raw) > _MAX_OBSERVATION_BYTES:
        raise PurpleCliError(
            f"Blue observation exceeds {_MAX_OBSERVATION_BYTES} bytes"
        )
    data = _parse_json_object(raw, label="Blue observation")
    unknown = sorted(set(data) - _OBSERVATION_FIELDS)
    missing = sorted(_OBSERVATION_FIELDS - set(data))
    if unknown:
        raise PurpleCliError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise PurpleCliError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise PurpleCliError("schema_version must be integer 1")
    steps = data["observed_steps"]
    if not isinstance(steps, list):
        raise PurpleCliError("observed_steps must be an array")
    if len(steps) > 64:
        raise PurpleCliError("observed_steps exceeds 64 entries")
    try:
        return BlueObservation(
            exercise_marker=data["exercise_marker"],
            collection_status=data["collection_status"],
            observed_steps=tuple(steps),
            alert_status=data["alert_status"],
            alert_reference=data["alert_reference"],
            alert_depends_on_exercise_marker=data[
                "alert_depends_on_exercise_marker"
            ],
        )
    except BlueObservationError as exc:
        raise PurpleCliError(str(exc)) from exc


def parse_red_receipt(raw: bytes) -> dict[str, Any]:
    """Parse a bounded Red receipt; the selected evaluator validates its contract."""
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise PurpleCliError(f"Red receipt exceeds {_MAX_RECEIPT_BYTES} bytes")
    return _parse_json_object(raw, label="Red receipt")


def read_blue_observation(path: str | Path) -> BlueObservation:
    try:
        raw = read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_OBSERVATION_BYTES,
            label="Blue observation",
        )
    except LocalArtifactError as exc:
        raise PurpleCliError(str(exc)) from exc
    return parse_blue_observation(raw)


def _read_red_receipt(path: str | Path) -> bytes:
    try:
        return read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_RECEIPT_BYTES,
            label="Red receipt",
        )
    except LocalArtifactError as exc:
        raise PurpleCliError(str(exc)) from exc


def _read_blue_observation_raw(path: str | Path) -> bytes:
    try:
        return read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_OBSERVATION_BYTES,
            label="Blue observation",
        )
    except LocalArtifactError as exc:
        raise PurpleCliError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-purple",
        description=(
            "Evaluate one bounded Red receipt against operator-supplied Blue evidence."
        ),
    )
    parser.add_argument(
        "technique",
        choices=(
            "bola",
            "authn",
            "state-change",
            "file-ingress",
            "mass-assignment",
            "nested-bola",
            "stale-authority",
            "function-authz",
            "collection-authz",
            "scope-authz",
            "search-authz",
            "export-authz",
            "async-export-authz",
            "forwarded-redirect",
        ),
    )
    parser.add_argument("red_receipt", help="Path to the Red experiment receipt")
    parser.add_argument("blue_observation", help="Path to the Blue observation JSON")
    args = parser.parse_args(argv)
    try:
        receipt_raw = _read_red_receipt(args.red_receipt)
        observation_raw = _read_blue_observation_raw(args.blue_observation)
        receipt = parse_red_receipt(receipt_raw)
        observation = parse_blue_observation(observation_raw)
        evaluator = {
            "bola": evaluate_bola_detection,
            "authn": evaluate_authn_detection,
            "state-change": evaluate_state_change_detection,
            "file-ingress": evaluate_file_ingress_detection,
            "mass-assignment": evaluate_mass_assignment_detection,
            "nested-bola": evaluate_nested_bola_detection,
            "stale-authority": evaluate_stale_authority_detection,
            "function-authz": evaluate_function_authz_detection,
            "collection-authz": evaluate_collection_authz_detection,
            "scope-authz": evaluate_scope_authz_detection,
            "search-authz": evaluate_search_authz_detection,
            "export-authz": evaluate_export_authz_detection,
            "async-export-authz": evaluate_async_export_authz_detection,
            "forwarded-redirect": evaluate_forwarded_redirect_detection,
        }[args.technique]
        evaluation = evaluator(receipt, observation)
        result = {
            "schema_version": 1,
            "capability": "purple-detection-evaluation",
            "evaluation_type": args.technique.upper(),
            "experiment_id": receipt.get("experiment_id"),
            **evaluation,
            "source_provenance": {
                "red_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
                "blue_observation_sha256": hashlib.sha256(
                    observation_raw
                ).hexdigest(),
            },
            "evaluation_integrity": "UNSEALED_DETERMINISTIC_DERIVATION",
        }
    except (PurpleCliError, BlueObservationError) as exc:
        print(f"PANCITO_PURPLE_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
