"""Strict engagement manifests for the replay-only offensive boundary.

The manifest is operator-authored authorization data. It can select only
capabilities already present in the curated replay catalogue; it cannot add a
target, command, verdict, score, hash, or executable behavior.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file
from offensive.replay import AuthorizationError, AuthorizationGrant, scenario_catalog


_MAX_MANIFEST_BYTES = 65_536
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema_version",
    "engagement_id",
    "authorization_reference",
    "authorized_by",
    "operator_acknowledged",
    "target",
    "objective",
    "allowed_scenarios",
    "max_runs",
})


class EngagementFormatError(ValueError):
    """The engagement artifact is ambiguous, invalid, or authority-expanding."""


def _reject_float(_value: str) -> None:
    raise EngagementFormatError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise EngagementFormatError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EngagementFormatError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _required_text(data: dict[str, Any], field_name: str, *, maximum: int) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise EngagementFormatError(
            f"{field_name} must be non-empty text without outer whitespace"
        )
    if (len(value) > maximum
            or any(unicodedata.category(char).startswith("C") for char in value)):
        raise EngagementFormatError(f"{field_name} is invalid or too long")
    return value


@dataclass(frozen=True)
class EngagementPlan:
    schema_version: int
    engagement_id: str
    authorization_reference: str
    authorized_by: str
    target: str
    objective: str
    allowed_scenarios: tuple[str, ...]
    max_runs: int
    scope_sha256: str
    source_sha256: str
    source_path: Path = field(repr=False, compare=False)

    def to_grant(self) -> AuthorizationGrant:
        """Narrow this artifact to the executor's existing grant contract."""
        return AuthorizationGrant(
            authorization_id=self.engagement_id,
            target=self.target,
            objective=self.objective,
            allowed_scenarios=self.allowed_scenarios,
            max_runs=self.max_runs,
            authorized_by=self.authorized_by,
            authorization_reference=self.authorization_reference,
            scope_sha256=self.scope_sha256,
            source_sha256=self.source_sha256,
        )


def load_engagement(path: str | Path) -> EngagementPlan:
    """Load a bounded JSON manifest and fail closed on ambiguous input."""
    source_path = Path(path).absolute()
    try:
        raw = read_bounded_regular_file(
            source_path,
            maximum_bytes=_MAX_MANIFEST_BYTES,
            label="engagement manifest",
        )
    except LocalArtifactError as exc:
        raise EngagementFormatError(f"cannot read engagement manifest: {exc}") from exc
    if not raw:
        raise EngagementFormatError("engagement manifest must not be empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EngagementFormatError("engagement manifest must be UTF-8 JSON") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except EngagementFormatError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise EngagementFormatError(f"invalid engagement JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise EngagementFormatError("engagement manifest root must be an object")

    unknown = sorted(set(data) - _FIELDS)
    missing = sorted(_FIELDS - set(data))
    if unknown:
        raise EngagementFormatError(f"unknown fields: {', '.join(unknown)}")
    if missing:
        raise EngagementFormatError(f"missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise EngagementFormatError("schema_version must be integer 1")
    if data["operator_acknowledged"] is not True:
        raise EngagementFormatError("operator_acknowledged must be literal true")

    engagement_id = _required_text(data, "engagement_id", maximum=128)
    if not _ID_RE.fullmatch(engagement_id):
        raise EngagementFormatError(
            "engagement_id must match [A-Za-z0-9._-]{1,128}"
        )
    authorization_reference = _required_text(
        data, "authorization_reference", maximum=512
    )
    authorized_by = _required_text(data, "authorized_by", maximum=256)
    target = _required_text(data, "target", maximum=256)
    objective = _required_text(data, "objective", maximum=128)

    scenarios = data["allowed_scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise EngagementFormatError("allowed_scenarios must not be empty")
    if len(scenarios) > 100:
        raise EngagementFormatError("allowed_scenarios exceeds 100 entries")
    if any(not isinstance(item, str) or not _ID_RE.fullmatch(item)
           for item in scenarios):
        raise EngagementFormatError("allowed_scenarios contains an invalid ID")
    if len(set(scenarios)) != len(scenarios):
        raise EngagementFormatError("allowed_scenarios must not contain duplicates")
    catalogue_ids = {item["scenario_id"] for item in scenario_catalog()}
    outside_catalogue = sorted(set(scenarios) - catalogue_ids)
    if outside_catalogue:
        raise EngagementFormatError(
            "allowed_scenarios contains entries outside the curated catalogue: "
            + ", ".join(outside_catalogue)
        )

    max_runs = data["max_runs"]
    if isinstance(max_runs, bool) or not isinstance(max_runs, int):
        raise EngagementFormatError("max_runs must be an integer")
    if not 1 <= max_runs <= 100:
        raise EngagementFormatError("max_runs must be between 1 and 100")

    canonical = json.dumps(
        data, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    scope_sha256 = hashlib.sha256(canonical).hexdigest()
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if (not _SHA256_RE.fullmatch(scope_sha256)
            or not _SHA256_RE.fullmatch(source_sha256)):
        raise AssertionError("internal SHA-256 encoding failure")
    plan = EngagementPlan(
        schema_version=1,
        engagement_id=engagement_id,
        authorization_reference=authorization_reference,
        authorized_by=authorized_by,
        target=target,
        objective=objective,
        allowed_scenarios=tuple(scenarios),
        max_runs=max_runs,
        scope_sha256=scope_sha256,
        source_sha256=source_sha256,
        source_path=source_path,
    )
    try:
        plan.to_grant()
    except (AuthorizationError, TypeError, ValueError) as exc:
        raise EngagementFormatError(str(exc)) from exc
    return plan
