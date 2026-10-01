"""Strict CLI for synthetic, reversible loopback file-ingress validation."""

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
from offensive.file_ingress import (
    FileIngressPlan,
    FileIngressPlanError,
    run_file_ingress_experiment,
)
from offensive.handoff import FileIngressCandidateHandoff, HandoffError
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError


_MAX_MANIFEST_BYTES = 65_536
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset({
    "schema_version", "experiment_id", "authorization_reference", "authorized_by",
    "operator_acknowledged", "target_origin", "upload_path",
    "readback_path_template", "upload_field", "observer_principal_id",
    "observer_token_env", "expected_max_bytes", "timeout_ms",
    "max_response_bytes", "candidate_handoff",
})
_REQUIRED = _FIELDS - {"candidate_handoff"}
_HANDOFF_FIELDS = frozenset({
    "candidate_id", "source_label", "source_sha256", "entry_point",
    "json_pointer", "epistemic_level", "integrity",
})


class FileIngressManifestError(ValueError):
    """The file-ingress manifest violates the closed execution boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise FileIngressManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum or any(
        unicodedata.category(char).startswith("C") for char in value
    ):
        raise FileIngressManifestError(f"{name} is invalid or too long")
    return value


def _reject_float(_value: str) -> None:
    raise FileIngressManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise FileIngressManifestError(f"non-finite value {value!r} is not permitted")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FileIngressManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class FileIngressManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    upload_path: str
    readback_path_template: str
    upload_field: str
    observer_principal_id: str
    observer_token_env: str
    expected_max_bytes: int
    timeout_ms: int
    max_response_bytes: int
    candidate_handoff: FileIngressCandidateHandoff | None = None


@dataclass(frozen=True)
class ResolvedFileIngressSecrets:
    observer_token: SecretValue = field(repr=False)


def parse_file_ingress_manifest(raw: bytes) -> FileIngressManifest:
    if not isinstance(raw, bytes):
        raise TypeError("file-ingress manifest must be bytes")
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise FileIngressManifestError("file-ingress manifest is empty or oversized")
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique,
            parse_float=_reject_float, parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise FileIngressManifestError("manifest must be UTF-8 JSON") from exc
    except FileIngressManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise FileIngressManifestError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FileIngressManifestError("manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_REQUIRED - set(data))
    if unknown:
        raise FileIngressManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise FileIngressManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise FileIngressManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise FileIngressManifestError("operator_acknowledged must be literal true")
    experiment_id = _text(data, "experiment_id", 128)
    principal_id = _text(data, "observer_principal_id", 128)
    if not _ID_RE.fullmatch(experiment_id) or not _ID_RE.fullmatch(principal_id):
        raise FileIngressManifestError("experiment and principal IDs are invalid")
    token_env = _text(data, "observer_token_env", 128)
    if not _ENV_RE.fullmatch(token_env):
        raise FileIngressManifestError("observer_token_env is invalid")
    for integer_name in ("expected_max_bytes", "timeout_ms", "max_response_bytes"):
        value = data[integer_name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise FileIngressManifestError(f"{integer_name} must be an integer")

    handoff = None
    if "candidate_handoff" in data:
        value = data["candidate_handoff"]
        if not isinstance(value, dict):
            raise FileIngressManifestError("candidate_handoff must be an object")
        unknown_handoff = sorted(set(value) - _HANDOFF_FIELDS)
        missing_handoff = sorted(_HANDOFF_FIELDS - set(value))
        if unknown_handoff or missing_handoff:
            raise FileIngressManifestError("candidate_handoff fields are inconsistent")
        if value["epistemic_level"] != "CANDIDATE" or value["integrity"] != "UNSEALED_TRIAGE_HANDOFF":
            raise FileIngressManifestError("candidate_handoff promoted or changed integrity")
        try:
            handoff = FileIngressCandidateHandoff(
                candidate_id=_text(value, "candidate_id", 128),
                source_label=_text(value, "source_label", 512),
                source_sha256=_text(value, "source_sha256", 64),
                entry_point=_text(value, "entry_point", 2_128),
                json_pointer=_text(value, "json_pointer", 2_048),
            )
        except HandoffError as exc:
            raise FileIngressManifestError(f"candidate_handoff: {exc}") from exc

    manifest = FileIngressManifest(
        1, experiment_id,
        _text(data, "authorization_reference", 512),
        _text(data, "authorized_by", 256), True,
        _text(data, "target_origin", 512), _text(data, "upload_path", 2_048),
        _text(data, "readback_path_template", 2_048),
        _text(data, "upload_field", 128), principal_id, token_env,
        data["expected_max_bytes"], data["timeout_ms"], data["max_response_bytes"],
        handoff,
    )
    try:
        _build_plan(manifest)
    except FileIngressPlanError as exc:
        raise FileIngressManifestError(str(exc)) from exc
    return manifest


def read_file_ingress_manifest(path: str | Path) -> FileIngressManifest:
    try:
        raw = read_bounded_regular_file(
            path, maximum_bytes=_MAX_MANIFEST_BYTES, label="file-ingress manifest"
        )
    except LocalArtifactError as exc:
        raise FileIngressManifestError(str(exc)) from exc
    return parse_file_ingress_manifest(raw)


def resolve_file_ingress_secrets(
    manifest: FileIngressManifest, environ: Mapping[str, str]
) -> ResolvedFileIngressSecrets:
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    value = environ.get(manifest.observer_token_env)
    if not isinstance(value, str) or not value:
        raise FileIngressManifestError(
            f"missing or empty secret environment variable: {manifest.observer_token_env}"
        )
    try:
        return ResolvedFileIngressSecrets(SecretValue(value))
    except SecretValueError as exc:
        raise FileIngressManifestError(
            f"environment variable {manifest.observer_token_env} is invalid"
        ) from exc


def _build_plan(manifest: FileIngressManifest) -> FileIngressPlan:
    return FileIngressPlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        upload_path=manifest.upload_path,
        readback_path_template=manifest.readback_path_template,
        upload_field=manifest.upload_field,
        expected_max_bytes=manifest.expected_max_bytes,
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
        candidate_handoff=manifest.candidate_handoff,
    )


def preflight_file_ingress_manifest(
    manifest: FileIngressManifest, secrets: ResolvedFileIngressSecrets
) -> dict[str, object]:
    _build_plan(manifest)
    if not isinstance(secrets, ResolvedFileIngressSecrets):
        raise TypeError("secrets must be ResolvedFileIngressSecrets")
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "target_origin": manifest.target_origin,
        "upload_path": manifest.upload_path,
        "secret_sources": [manifest.observer_token_env],
        "sample_source": "SYNTHETIC_INERT_GENERATED_IN_MEMORY",
        "request_count": 0,
        "maximum_request_count": 12,
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
        "candidate_provenance": (
            manifest.candidate_handoff.to_receipt() if manifest.candidate_handoff else None
        ),
    }


def execute_file_ingress_manifest(
    manifest: FileIngressManifest, secrets: ResolvedFileIngressSecrets
) -> dict[str, object]:
    return run_file_ingress_experiment(
        _build_plan(manifest),
        observer=BearerCredential(
            manifest.observer_principal_id, secrets.observer_token.reveal()
        ),
    )


def main(
    argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None
) -> int:
    parser = argparse.ArgumentParser(prog="pancito-file-ingress")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        manifest = read_file_ingress_manifest(args.manifest)
        secrets = resolve_file_ingress_secrets(
            manifest, os.environ if environ is None else environ
        )
        result = (
            preflight_file_ingress_manifest(manifest, secrets)
            if args.dry_run else execute_file_ingress_manifest(manifest, secrets)
        )
    except (FileIngressManifestError, FileIngressPlanError) as exc:
        print(f"PANCITO_FILE_INGRESS_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
