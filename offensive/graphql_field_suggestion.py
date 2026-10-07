"""Bounded GraphQL field-suggestion-leakage differential for a loopback lab.

Idea credit: the specific bug class this module tests -- a GraphQL server
that includes a "did you mean" field-name suggestion in its error response,
leaking schema field names even when introspection itself is disabled -- is
one of the checks in dolevf/graphql-cop (MIT). No code was ported; this
module reimplements the idea as a bounded, two-request Red/Blue differential
in PANCITO's own style. See ``ATTRIBUTIONS.md``.

The probe needs no knowledge of the target's real schema: every
spec-compliant GraphQL server exposes the meta-field ``__typename`` on every
type, so a deliberate one-character typo of it (``__typenam``) is a reliable
canary. Many GraphQL implementations' default error formatting proposes the
closest valid field name back to the caller -- which, for this typo, can only
be ``__typename`` itself. The oracle reads the parsed ``errors`` array
structurally and requires the suggestion to name that exact field; a server
that merely echoes the malformed query text back, or emits an unrelated
validation error, does not confirm the hypothesis.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from offensive.purple import exercise_marker, graphql_field_suggestion_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BASELINE_QUERY = "{__typename}"
_TYPO_QUERY = "{__typenam}"
_SUGGESTED_FIELD = "__typename"


class GraphqlFieldSuggestionPlanError(ValueError):
    """The GraphQL field-suggestion experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GraphqlFieldSuggestionPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise GraphqlFieldSuggestionPlanError(f"{name} is outside its text boundary")
    return value


def _target_origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed, port = urlsplit(raw), urlsplit(raw).port
    except ValueError as exc:
        raise GraphqlFieldSuggestionPlanError("target_origin is invalid") from exc
    if (parsed.scheme != "http" or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        raise GraphqlFieldSuggestionPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise GraphqlFieldSuggestionPlanError("target_origin must use literal loopback") from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise GraphqlFieldSuggestionPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object) -> str:
    raw = _text(value, "endpoint_path", 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise GraphqlFieldSuggestionPlanError("endpoint_path must be a relative path without query")
    return raw


@dataclass(frozen=True)
class GraphqlFieldSuggestionPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    endpoint_path: str
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise GraphqlFieldSuggestionPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise GraphqlFieldSuggestionPlanError("operator_acknowledged must be literal true")
        _target_origin(self.target_origin)
        _path(self.endpoint_path)
        if (isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int)
                or not 100 <= self.timeout_ms <= 10_000):
            raise GraphqlFieldSuggestionPlanError("timeout_ms is invalid")
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or not 1_024 <= self.max_response_bytes <= 1_048_576):
            raise GraphqlFieldSuggestionPlanError("max_response_bytes is invalid")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body: bytes | None
    truncated: bool
    request_succeeded: bool


def _post_query(plan: GraphqlFieldSuggestionPlan, origin: SplitResult, query: str) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port if origin.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        payload = json.dumps(
            {"query": query}, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        headers = {
            "User-Agent": "pancito-red-team/graphql-field-suggestion-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(payload)),
        }
        connection.request("POST", plan.endpoint_path, body=payload, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = None if truncated else captured
        return _Observation(response.status, body, truncated, True)
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, None, False, False)
    finally:
        if connection is not None:
            connection.close()


def _parse_body(body: bytes | None) -> object | None:
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _typename(parsed: object) -> str | None:
    if not isinstance(parsed, dict):
        return None
    data = parsed.get("data")
    if not isinstance(data, dict):
        return None
    name = data.get("__typename")
    return name if isinstance(name, str) and name else None


def _error_messages(parsed: object) -> list[str]:
    if not isinstance(parsed, dict):
        return []
    errors = parsed.get("errors")
    if not isinstance(errors, list):
        return []
    messages = []
    for entry in errors:
        if isinstance(entry, dict) and isinstance(entry.get("message"), str):
            messages.append(entry["message"])
    return messages


def _suggests_the_typo_fix(messages: list[str]) -> bool:
    for message in messages:
        if "did you mean" in message.lower() and _SUGGESTED_FIELD in message:
            return True
    return False


def run_graphql_field_suggestion_experiment(
    plan: GraphqlFieldSuggestionPlan,
) -> dict[str, object]:
    if not isinstance(plan, GraphqlFieldSuggestionPlan):
        raise TypeError("plan must be a GraphqlFieldSuggestionPlan")
    origin = _target_origin(plan.target_origin)

    baseline = _post_query(plan, origin, _BASELINE_QUERY)
    test = _post_query(plan, origin, _TYPO_QUERY)
    baseline_parsed = _parse_body(baseline.body)
    baseline_typename = _typename(baseline_parsed)
    baseline_passed = (
        baseline.request_succeeded and not baseline.truncated and baseline_typename is not None
    )

    if not baseline.request_succeeded:
        level, reason = "INCONCLUSIVE", "BASELINE_CONTROL_FAILED"
    elif baseline.truncated:
        level, reason = "INCONCLUSIVE", "BASELINE_RESPONSE_TRUNCATED"
    elif baseline_parsed is None:
        level, reason = "INCONCLUSIVE", "BASELINE_RESPONSE_UNPARSEABLE"
    elif baseline_typename is None:
        level, reason = "INCONCLUSIVE", "BASELINE_NOT_A_GRAPHQL_ENDPOINT"
    elif not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    else:
        test_parsed = _parse_body(test.body)
        if test_parsed is None:
            level, reason = "INCONCLUSIVE", "TEST_RESPONSE_UNPARSEABLE"
        elif _suggests_the_typo_fix(_error_messages(test_parsed)):
            level, reason = "CONFIRMED_BY_INDUCTION", "FIELD_SUGGESTION_DISCLOSED_SCHEMA_NAME"
        else:
            level, reason = "FALSIFIED", "FIELD_SUGGESTION_SUPPRESSED"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-graphql-field-suggestion-leakage-differential",
        "target_origin": plan.target_origin, "method": "POST",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "endpoint_path": plan.endpoint_path,
        "prediction": ("If default error formatting proposes field-name corrections, the "
                        "typo query's error message names the real field it is replacing."),
        "falsifier": ("The error response does not propose a field-name correction naming "
                       "the valid field, or the endpoint does not behave like GraphQL at all."),
        "epistemic_level": level, "reason_code": reason,
        "controls": {"baseline_control_passed": baseline_passed},
        "baseline_control": {
            "status": baseline.status, "typename": baseline_typename,
            "truncated": baseline.truncated, "request_succeeded": baseline.request_succeeded,
        },
        "test": {
            "status": test.status, "truncated": test.truncated,
            "request_succeeded": test.request_succeeded,
        },
        "request_count": 2, "maximum_request_count": 2,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": graphql_field_suggestion_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
