"""Strict CLI boundary for the reversible loopback state-change experiment."""

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
from offensive.handoff import HandoffError, StateChangeCandidateHandoff
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.secrets import SecretValue, SecretValueError
from offensive.state_change import (
    StateChangePlan,
    StateChangePlanError,
    run_state_change_experiment,
)


_MAX_MANIFEST_BYTES = 65_536
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FIELDS = frozenset({
    "schema_version",
    "experiment_id",
    "authorization_reference",
    "authorized_by",
    "operator_acknowledged",
    "target_origin",
    "resource_path",
    "readback_path",
    "marker_field",
    "observer_principal_id",
    "observer_token_env",
    "invalid_bearer_env",
    "baseline_marker_env",
    "control_marker_env",
    "anonymous_marker_env",
    "invalid_marker_env",
    "timeout_ms",
    "max_response_bytes",
    "candidate_handoff",
})
_REQUIRED_FIELDS = _FIELDS - {"candidate_handoff"}
_HANDOFF_FIELDS = frozenset({
    "candidate_id",
    "source_label",
    "source_sha256",
    "entry_point",
    "json_pointer",
    "epistemic_level",
    "integrity",
})


class StateChangeManifestError(ValueError):
    """The manifest or its secret references violate the execution boundary."""


def _text(data: dict[str, Any], name: str, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise StateChangeManifestError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise StateChangeManifestError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise StateChangeManifestError(f"{name} contains control characters")
    return value


def _reject_float(_value: str) -> None:
    raise StateChangeManifestError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise StateChangeManifestError(
        f"non-finite JSON value {value!r} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StateChangeManifestError(f"duplicate key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True)
class StateChangeManifest:
    schema_version: int
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    resource_path: str
    readback_path: str
    marker_field: str
    observer_principal_id: str
    observer_token_env: str
    invalid_bearer_env: str
    baseline_marker_env: str
    control_marker_env: str
    anonymous_marker_env: str
    invalid_marker_env: str
    timeout_ms: int
    max_response_bytes: int
    candidate_handoff: StateChangeCandidateHandoff | None = None

    @property
    def secret_environment_names(self) -> tuple[str, ...]:
        return (
            self.observer_token_env,
            self.invalid_bearer_env,
            self.baseline_marker_env,
            self.control_marker_env,
            self.anonymous_marker_env,
            self.invalid_marker_env,
        )


@dataclass(frozen=True)
class ResolvedStateChangeSecrets:
    observer_token: SecretValue = field(repr=False)
    invalid_bearer: SecretValue = field(repr=False)
    baseline_marker: SecretValue = field(repr=False)
    control_marker: SecretValue = field(repr=False)
    anonymous_marker: SecretValue = field(repr=False)
    invalid_marker: SecretValue = field(repr=False)


def parse_state_change_manifest(raw: bytes) -> StateChangeManifest:
    if not isinstance(raw, bytes):
        raise TypeError("state-change manifest must be bytes")
    if not raw:
        raise StateChangeManifestError("state-change manifest must not be empty")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise StateChangeManifestError(
            f"state-change manifest exceeds {_MAX_MANIFEST_BYTES} bytes"
        )
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise StateChangeManifestError(
            "state-change manifest must be UTF-8 JSON"
        ) from exc
    except StateChangeManifestError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise StateChangeManifestError(
            f"invalid state-change manifest JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise StateChangeManifestError("state-change manifest root must be an object")
    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_REQUIRED_FIELDS - set(data))
    if unknown:
        raise StateChangeManifestError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise StateChangeManifestError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise StateChangeManifestError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise StateChangeManifestError("operator_acknowledged must be literal true")

    experiment_id = _text(data, "experiment_id", 128)
    principal_id = _text(data, "observer_principal_id", 128)
    if not _ID_RE.fullmatch(experiment_id):
        raise StateChangeManifestError(
            "experiment_id must match [A-Za-z0-9._-]{1,128}"
        )
    if not _ID_RE.fullmatch(principal_id):
        raise StateChangeManifestError(
            "observer_principal_id must match [A-Za-z0-9._-]{1,128}"
        )
    environment_names = tuple(
        _text(data, name, 128)
        for name in (
            "observer_token_env",
            "invalid_bearer_env",
            "baseline_marker_env",
            "control_marker_env",
            "anonymous_marker_env",
            "invalid_marker_env",
        )
    )
    if any(not _ENV_NAME_RE.fullmatch(name) for name in environment_names):
        raise StateChangeManifestError(
            "secret environment names must match [A-Z][A-Z0-9_]{0,127}"
        )
    if len(set(environment_names)) != len(environment_names):
        raise StateChangeManifestError("secret environment names must be distinct")
    timeout_ms = data["timeout_ms"]
    maximum = data["max_response_bytes"]
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
        raise StateChangeManifestError("timeout_ms must be an integer")
    if isinstance(maximum, bool) or not isinstance(maximum, int):
        raise StateChangeManifestError("max_response_bytes must be an integer")

    handoff: StateChangeCandidateHandoff | None = None
    if "candidate_handoff" in data:
        raw_handoff = data["candidate_handoff"]
        if not isinstance(raw_handoff, dict):
            raise StateChangeManifestError("candidate_handoff must be an object")
        unknown_handoff = sorted(set(raw_handoff) - _HANDOFF_FIELDS)
        missing_handoff = sorted(_HANDOFF_FIELDS - set(raw_handoff))
        if unknown_handoff:
            raise StateChangeManifestError(
                "unknown candidate_handoff fields: " + ", ".join(unknown_handoff)
            )
        if missing_handoff:
            raise StateChangeManifestError(
                "missing candidate_handoff fields: " + ", ".join(missing_handoff)
            )
        if raw_handoff["epistemic_level"] != "CANDIDATE":
            raise StateChangeManifestError(
                "candidate_handoff epistemic_level must remain CANDIDATE"
            )
        if raw_handoff["integrity"] != "UNSEALED_TRIAGE_HANDOFF":
            raise StateChangeManifestError(
                "candidate_handoff integrity must be UNSEALED_TRIAGE_HANDOFF"
            )
        try:
            handoff = StateChangeCandidateHandoff(
                candidate_id=_text(raw_handoff, "candidate_id", 128),
                source_label=_text(raw_handoff, "source_label", 512),
                source_sha256=_text(raw_handoff, "source_sha256", 64),
                entry_point=_text(raw_handoff, "entry_point", 2_128),
                json_pointer=_text(raw_handoff, "json_pointer", 2_048),
            )
        except HandoffError as exc:
            raise StateChangeManifestError(f"candidate_handoff: {exc}") from exc

    manifest = StateChangeManifest(
        schema_version=1,
        experiment_id=experiment_id,
        authorization_reference=_text(data, "authorization_reference", 512),
        authorized_by=_text(data, "authorized_by", 256),
        operator_acknowledged=True,
        target_origin=_text(data, "target_origin", 512),
        resource_path=_text(data, "resource_path", 2_048),
        readback_path=_text(data, "readback_path", 2_048),
        marker_field=_text(data, "marker_field", 128),
        observer_principal_id=principal_id,
        observer_token_env=environment_names[0],
        invalid_bearer_env=environment_names[1],
        baseline_marker_env=environment_names[2],
        control_marker_env=environment_names[3],
        anonymous_marker_env=environment_names[4],
        invalid_marker_env=environment_names[5],
        timeout_ms=timeout_ms,
        max_response_bytes=maximum,
        candidate_handoff=handoff,
    )
    validation = ResolvedStateChangeSecrets(
        *(SecretValue(f"manifest-validation-secret-{index}") for index in range(6))
    )
    try:
        _build_plan(manifest, validation)
    except StateChangePlanError as exc:
        raise StateChangeManifestError(str(exc)) from exc
    return manifest


def read_state_change_manifest(path: str | Path) -> StateChangeManifest:
    try:
        raw = read_bounded_regular_file(
            path,
            maximum_bytes=_MAX_MANIFEST_BYTES,
            label="state-change manifest",
        )
    except LocalArtifactError as exc:
        raise StateChangeManifestError(str(exc)) from exc
    return parse_state_change_manifest(raw)


def resolve_state_change_secrets(
    manifest: StateChangeManifest, environ: Mapping[str, str]
) -> ResolvedStateChangeSecrets:
    if not isinstance(manifest, StateChangeManifest):
        raise TypeError("manifest must be a StateChangeManifest")
    if not isinstance(environ, Mapping):
        raise TypeError("environ must be a mapping")
    missing = [name for name in manifest.secret_environment_names if not environ.get(name)]
    if missing:
        raise StateChangeManifestError(
            "missing or empty secret environment variables: " + ", ".join(missing)
        )
    resolved: list[SecretValue] = []
    for name in manifest.secret_environment_names:
        value = environ[name]
        if not isinstance(value, str):
            raise StateChangeManifestError(
                f"environment variable {name} must contain text"
            )
        try:
            resolved.append(SecretValue(value))
        except SecretValueError as exc:
            raise StateChangeManifestError(
                f"environment variable {name} is invalid"
            ) from exc
    if len({item.reveal() for item in resolved}) != len(resolved):
        raise StateChangeManifestError("all resolved secrets must be distinct")
    return ResolvedStateChangeSecrets(*resolved)


def _build_plan(
    manifest: StateChangeManifest, secrets: ResolvedStateChangeSecrets
) -> StateChangePlan:
    return StateChangePlan(
        experiment_id=manifest.experiment_id,
        authorization_reference=manifest.authorization_reference,
        authorized_by=manifest.authorized_by,
        operator_acknowledged=manifest.operator_acknowledged,
        target_origin=manifest.target_origin,
        resource_path=manifest.resource_path,
        readback_path=manifest.readback_path,
        marker_field=manifest.marker_field,
        baseline_marker=secrets.baseline_marker.reveal(),
        control_marker=secrets.control_marker.reveal(),
        anonymous_marker=secrets.anonymous_marker.reveal(),
        invalid_marker=secrets.invalid_marker.reveal(),
        invalid_bearer=secrets.invalid_bearer.reveal(),
        timeout_ms=manifest.timeout_ms,
        max_response_bytes=manifest.max_response_bytes,
        candidate_handoff=manifest.candidate_handoff,
    )


def preflight_state_change_manifest(
    manifest: StateChangeManifest, secrets: ResolvedStateChangeSecrets
) -> dict[str, object]:
    _build_plan(manifest, secrets)
    return {
        "schema_version": 1,
        "experiment_id": manifest.experiment_id,
        "status": "VALIDATED_NOT_EXECUTED",
        "target_origin": manifest.target_origin,
        "resource_path": manifest.resource_path,
        "readback_path": manifest.readback_path,
        "method": "PATCH",
        "secret_sources": list(manifest.secret_environment_names),
        "request_count": 0,
        "maximum_request_count": 13,
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
        "candidate_provenance": (
            manifest.candidate_handoff.to_receipt()
            if manifest.candidate_handoff is not None
            else None
        ),
    }


def execute_state_change_manifest(
    manifest: StateChangeManifest, secrets: ResolvedStateChangeSecrets
) -> dict[str, object]:
    plan = _build_plan(manifest, secrets)
    observer = BearerCredential(
        manifest.observer_principal_id, secrets.observer_token.reveal()
    )
    return run_state_change_experiment(plan, observer=observer)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="pancito-state-change",
        description=(
            "Run a bounded, reversible public-state-change differential on loopback."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("manifest", help="Path to a strict JSON experiment manifest")
    args = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        manifest = read_state_change_manifest(args.manifest)
        secrets = resolve_state_change_secrets(manifest, environment)
        result = (
            preflight_state_change_manifest(manifest, secrets)
            if args.dry_run
            else execute_state_change_manifest(manifest, secrets)
        )
    except (StateChangeManifestError, StateChangePlanError) as exc:
        print(f"PANCITO_STATE_CHANGE_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
