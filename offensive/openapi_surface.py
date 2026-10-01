"""Deterministic, passive attack-surface triage for OpenAPI JSON artifacts.

The output is a queue of candidates with provenance and falsifiers.  It does
not contact a target, infer runtime reachability from silence, or emit findings.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any


_MAX_DOCUMENT_BYTES = 2_097_152
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HTTP_METHODS = ("delete", "get", "head", "options", "patch", "post", "put", "trace")
_MUTATING_METHODS = frozenset({"DELETE", "PATCH", "POST", "PUT"})
_FILE_MEDIA_TYPES = frozenset({"application/octet-stream", "multipart/form-data"})
_REACHABILITY_POINTS = {
    "PUBLIC_DECLARED": 3,
    "AUTHENTICATED_DECLARED": 2,
    "UNKNOWN": 1,
}
_PLAUSIBILITY_POINTS = {
    "OBJECT_AUTHORIZATION_REVIEW": 3,
    "PUBLIC_STATE_CHANGE_REVIEW": 3,
    "FILE_INGRESS_REVIEW": 2,
}


class OpenApiTriageError(ValueError):
    """The artifact or its operator-supplied context is invalid or ambiguous."""


def _bounded_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise OpenApiTriageError(
            f"{name} must be non-empty text without outer whitespace"
        )
    if len(value) > maximum:
        raise OpenApiTriageError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise OpenApiTriageError(f"{name} contains control characters")
    return value


@dataclass(frozen=True)
class AssetAnnotation:
    """Operator-authored value judgment, kept distinct from observed structure."""

    entry_point: str
    value: int
    basis: str

    def __post_init__(self) -> None:
        _validate_entry_point(self.entry_point)
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise OpenApiTriageError("asset value must be an integer")
        if not 1 <= self.value <= 3:
            raise OpenApiTriageError("asset value must be between 1 and 3")
        _bounded_text(self.basis, "asset basis", 512)


@dataclass(frozen=True)
class OpenApiTriagePlan:
    """Authorization and human context for passive artifact triage."""

    engagement_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    source_label: str
    asset_annotations: tuple[AssetAnnotation, ...] = ()

    def __post_init__(self) -> None:
        engagement_id = _bounded_text(self.engagement_id, "engagement_id", 128)
        if not _ID_RE.fullmatch(engagement_id):
            raise OpenApiTriageError(
                "engagement_id must match [A-Za-z0-9._-]{1,128}"
            )
        _bounded_text(self.authorization_reference, "authorization_reference", 512)
        _bounded_text(self.authorized_by, "authorized_by", 256)
        _bounded_text(self.source_label, "source_label", 512)
        if self.operator_acknowledged is not True:
            raise OpenApiTriageError("operator_acknowledged must be literal true")
        if not isinstance(self.asset_annotations, tuple):
            raise OpenApiTriageError("asset_annotations must be a tuple")
        if any(not isinstance(item, AssetAnnotation) for item in self.asset_annotations):
            raise OpenApiTriageError(
                "asset_annotations must contain AssetAnnotation values"
            )
        entry_points = [item.entry_point for item in self.asset_annotations]
        if len(entry_points) != len(set(entry_points)):
            raise OpenApiTriageError("asset_annotations contains duplicate entry points")


def _validate_entry_point(value: object) -> str:
    entry_point = _bounded_text(value, "entry_point", 2_128)
    method, separator, path = entry_point.partition(" ")
    if not separator or method not in {item.upper() for item in _HTTP_METHODS}:
        raise OpenApiTriageError("entry_point must be 'METHOD /relative/path'")
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        raise OpenApiTriageError("entry_point must be 'METHOD /relative/path'")
    return entry_point


def _reject_float(_value: str) -> None:
    raise OpenApiTriageError("floating-point values are not permitted")


def _reject_constant(value: str) -> None:
    raise OpenApiTriageError(f"non-finite JSON value {value!r} is not permitted")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OpenApiTriageError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _parse_document(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise TypeError("OpenAPI document must be bytes")
    if not raw:
        raise OpenApiTriageError("OpenAPI document must not be empty")
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise OpenApiTriageError(
            f"OpenAPI document exceeds {_MAX_DOCUMENT_BYTES} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OpenApiTriageError("OpenAPI document must be UTF-8 JSON") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except OpenApiTriageError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise OpenApiTriageError(f"invalid OpenAPI JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise OpenApiTriageError("OpenAPI document root must be an object")
    version = document.get("openapi")
    if not isinstance(version, str) or not (
        version.startswith("3.0.") or version.startswith("3.1.")
    ):
        raise OpenApiTriageError("only OpenAPI 3.0 and 3.1 JSON are supported")
    if not isinstance(document.get("paths"), dict):
        raise OpenApiTriageError("OpenAPI paths must be an object")
    return document


def _classify_security(value: object) -> str:
    if not isinstance(value, list):
        raise OpenApiTriageError("security must be an array when declared")
    if not value or any(isinstance(requirement, dict) and not requirement for requirement in value):
        return "PUBLIC_DECLARED"
    if any(not isinstance(requirement, dict) for requirement in value):
        raise OpenApiTriageError("security requirements must be objects")
    return "AUTHENTICATED_DECLARED"


def _effective_reachability(document: dict[str, Any], operation: dict[str, Any]) -> str:
    if "security" in operation:
        return _classify_security(operation["security"])
    if "security" in document:
        return _classify_security(document["security"])
    return "UNKNOWN"


def _json_pointer(path: str, method: str) -> str:
    escaped = path.replace("~", "~0").replace("/", "~1")
    return f"/paths/{escaped}/{method.lower()}"


def _path_parameters(path: str, path_item: dict[str, Any], operation: dict[str, Any]) -> tuple[str, ...]:
    names = set(re.findall(r"\{([^{}]+)\}", path))
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        if source is None:
            continue
        if not isinstance(source, list):
            raise OpenApiTriageError("parameters must be arrays when declared")
        for parameter in source:
            if not isinstance(parameter, dict):
                raise OpenApiTriageError("parameter entries must be objects")
            if parameter.get("in") == "path" and isinstance(parameter.get("name"), str):
                names.add(parameter["name"])
    return tuple(sorted(names))


def _has_file_ingress(operation: dict[str, Any]) -> bool:
    request_body = operation.get("requestBody")
    if request_body is None:
        return False
    if not isinstance(request_body, dict):
        raise OpenApiTriageError("requestBody must be an object when declared")
    content = request_body.get("content", {})
    if not isinstance(content, dict):
        raise OpenApiTriageError("requestBody content must be an object")
    return bool(_FILE_MEDIA_TYPES.intersection(content))


def _candidate(
    *,
    candidate_type: str,
    entry_point: str,
    reachability: str,
    source_label: str,
    pointer: str,
    basis: str,
    falsifier: str,
    annotation: AssetAnnotation | None,
) -> dict[str, object]:
    identity = hashlib.sha256(
        f"{candidate_type}\x00{entry_point}".encode("utf-8")
    ).hexdigest()[:16]
    value = annotation.value if annotation is not None else None
    score = (
        _REACHABILITY_POINTS[reachability]
        * value
        * _PLAUSIBILITY_POINTS[candidate_type]
        if value is not None and reachability != "UNKNOWN"
        else None
    )
    return {
        "candidate_id": f"CANDIDATE-{identity}",
        "candidate_type": candidate_type,
        "entry_point": entry_point,
        "reachability": reachability,
        "asset_value": value,
        "asset_value_basis": annotation.basis if annotation is not None else None,
        "plausibility_basis": basis,
        "falsifier": falsifier,
        "priority_score": score,
        "epistemic_level": "CANDIDATE",
        "provenance": {
            "source_label": source_label,
            "json_pointer": pointer,
        },
    }


def _enumerate_operations(document: dict[str, Any]) -> list[dict[str, object]]:
    operations: list[dict[str, object]] = []
    for path in sorted(document["paths"]):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise OpenApiTriageError("path keys must be relative HTTP paths")
        path_item = document["paths"][path]
        if not isinstance(path_item, dict):
            raise OpenApiTriageError(f"path item {path!r} must be an object")
        for method in _HTTP_METHODS:
            if method not in path_item:
                continue
            operation = path_item[method]
            if not isinstance(operation, dict):
                raise OpenApiTriageError(
                    f"operation {method.upper()} {path} must be an object"
                )
            entry_point = f"{method.upper()} {path}"
            operations.append(
                {
                    "entry_point": entry_point,
                    "method": method.upper(),
                    "path": path,
                    "operation": operation,
                    "path_item": path_item,
                    "reachability": _effective_reachability(document, operation),
                    "path_parameters": _path_parameters(path, path_item, operation),
                    "file_ingress": _has_file_ingress(operation),
                    "json_pointer": _json_pointer(path, method),
                }
            )
    return operations


def triage_openapi(raw: bytes, plan: OpenApiTriagePlan) -> dict[str, object]:
    """Build a passive, reproducible candidate queue from an OpenAPI artifact."""
    if not isinstance(plan, OpenApiTriagePlan):
        raise TypeError("plan must be an OpenApiTriagePlan")
    document = _parse_document(raw)
    operations = _enumerate_operations(document)
    operation_ids = {str(item["entry_point"]) for item in operations}
    annotations = {item.entry_point: item for item in plan.asset_annotations}
    drifted = sorted(set(annotations) - operation_ids)
    if drifted:
        raise OpenApiTriageError(
            "asset annotation entry points not present in the document: "
            + ", ".join(drifted)
        )

    surfaces: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for item in operations:
        entry_point = str(item["entry_point"])
        reachability = str(item["reachability"])
        path_parameters = tuple(item["path_parameters"])
        surfaces.append(
            {
                "entry_point": entry_point,
                "reachability": reachability,
                "path_parameters": list(path_parameters),
                "file_ingress": bool(item["file_ingress"]),
                "provenance": {
                    "source_label": plan.source_label,
                    "json_pointer": item["json_pointer"],
                },
                "epistemic_level": "SURFACE",
            }
        )
        common = {
            "entry_point": entry_point,
            "reachability": reachability,
            "source_label": plan.source_label,
            "pointer": str(item["json_pointer"]),
            "annotation": annotations.get(entry_point),
        }
        if path_parameters and reachability == "AUTHENTICATED_DECLARED":
            candidates.append(
                _candidate(
                    candidate_type="OBJECT_AUTHORIZATION_REVIEW",
                    basis=(
                        "The authenticated operation accepts caller-selected path "
                        "object identifiers: " + ", ".join(path_parameters)
                    ),
                    falsifier=(
                        "Authorization enforcement binds the selected object to the "
                        "authenticated principal before data is returned."
                    ),
                    **common,
                )
            )
        if item["method"] in _MUTATING_METHODS and reachability == "PUBLIC_DECLARED":
            candidates.append(
                _candidate(
                    candidate_type="PUBLIC_STATE_CHANGE_REVIEW",
                    basis=(
                        "The document explicitly permits anonymous access to a "
                        f"state-changing {item['method']} operation."
                    ),
                    falsifier=(
                        "The state change is intentionally public and bounded, or a "
                        "runtime control rejects anonymous mutation."
                    ),
                    **common,
                )
            )
        if item["file_ingress"]:
            candidates.append(
                _candidate(
                    candidate_type="FILE_INGRESS_REVIEW",
                    basis=(
                        "The request body declares multipart/form-data or "
                        "application/octet-stream at a parser/storage boundary."
                    ),
                    falsifier=(
                        "A bounded parser validates type and size before the payload "
                        "reaches storage or an asynchronous consumer."
                    ),
                    **common,
                )
            )

    ranked = sorted(
        (item for item in candidates if item["priority_score"] is not None),
        key=lambda item: (
            -int(item["priority_score"]),
            str(item["entry_point"]),
            str(item["candidate_type"]),
        ),
    )
    below_the_line = []
    for item in sorted(
        (item for item in candidates if item["priority_score"] is None),
        key=lambda candidate: (
            str(candidate["entry_point"]), str(candidate["candidate_type"])
        ),
    ):
        value = dict(item)
        value["reason"] = (
            "REACHABILITY_UNKNOWN"
            if item["asset_value"] is not None
            else "ASSET_VALUE_UNANNOTATED"
        )
        below_the_line.append(value)

    return {
        "engagement_id": plan.engagement_id,
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "mode": "PASSIVE_ARTIFACT_TRIAGE",
        "source_label": plan.source_label,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "surfaces": sorted(surfaces, key=lambda item: str(item["entry_point"])),
        "candidate_queue": ranked,
        "below_the_line": below_the_line,
        "ranking_rule": (
            "reachability_points * operator_asset_value * plausibility_points; "
            "unknown reachability or missing asset value is not ranked"
        ),
        "coverage_gaps": [
            "Runtime reachability was not tested.",
            "Authorization implementation was not inspected.",
            "Routes absent from the supplied OpenAPI document were not enumerated.",
            "External references and downstream asynchronous consumers were not resolved.",
        ],
        "active_probe_performed": False,
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
