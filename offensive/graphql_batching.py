"""Bounded GraphQL request-batching exposure differential for a loopback lab.

Idea credit: the specific bug class this module tests -- a GraphQL endpoint
that accepts a JSON array of operations in a single HTTP request -- is one of
the checks in dolevf/graphql-cop (MIT). No code was ported; this module
reimplements the idea as a bounded, two-request Red/Blue differential in
PANCITO's own style. See ``ATTRIBUTIONS.md``.

Batching matters because many rate limiters and per-request authorization
checks count HTTP requests, not the operations inside a batched array -- so
batching can turn one allowed request into many effective operations. This
module tests only whether the feature is *accepted at all*, using nothing
but the already-harmless ``{__typename}`` query repeated a small, bounded
number of times (``batch_size``, capped low). It makes no attempt to measure
or demonstrate a rate-limit bypass, a brute-force amplification, or any
other downstream impact -- confirming a request-volume bypass would need a
second, paired experiment against a *specific* configured limit, which is a
different, not-yet-built claim. The oracle reads the parsed JSON body
structurally: confirmation requires a response that is itself a JSON array
of exactly ``batch_size`` well-formed GraphQL results, never merely a 200
status or a response that happens to be array-shaped for an unrelated
reason.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from offensive.purple import exercise_marker, graphql_batching_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BASELINE_QUERY = "{__typename}"


class GraphqlBatchingPlanError(ValueError):
    """The GraphQL batching experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GraphqlBatchingPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise GraphqlBatchingPlanError(f"{name} is outside its text boundary")
    return value


def _target_origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed, port = urlsplit(raw), urlsplit(raw).port
    except ValueError as exc:
        raise GraphqlBatchingPlanError("target_origin is invalid") from exc
    if (parsed.scheme != "http" or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        raise GraphqlBatchingPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise GraphqlBatchingPlanError("target_origin must use literal loopback") from exc
    effective_port = 80 if port is None else port
    if not address.is_loopback or not 1 <= effective_port <= 65_535:
        raise GraphqlBatchingPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object) -> str:
    raw = _text(value, "endpoint_path", 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise GraphqlBatchingPlanError("endpoint_path must be a relative path without query")
    return raw


@dataclass(frozen=True)
class GraphqlBatchingPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    endpoint_path: str
    batch_size: int = 3
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise GraphqlBatchingPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise GraphqlBatchingPlanError("operator_acknowledged must be literal true")
        _target_origin(self.target_origin)
        _path(self.endpoint_path)
        if (isinstance(self.batch_size, bool) or not isinstance(self.batch_size, int)
                or not 2 <= self.batch_size <= 10):
            raise GraphqlBatchingPlanError("batch_size must be an integer between 2 and 10")
        if (isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int)
                or not 100 <= self.timeout_ms <= 10_000):
            raise GraphqlBatchingPlanError("timeout_ms is invalid")
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or not 1_024 <= self.max_response_bytes <= 1_048_576):
            raise GraphqlBatchingPlanError("max_response_bytes is invalid")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body: bytes | None
    truncated: bool
    request_succeeded: bool


def _post(plan: GraphqlBatchingPlan, origin: SplitResult, payload: object) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(
            origin.hostname,
            origin.port if origin.port is not None else 80,
            timeout=plan.timeout_ms / 1_000,
        )
        body = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        headers = {
            "User-Agent": "pancito-red-team/graphql-batching-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(body)),
        }
        connection.request("POST", plan.endpoint_path, body=body, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        resp_body = None if truncated else captured
        return _Observation(response.status, resp_body, truncated, True)
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


def _all_results_are_well_formed_typename_results(parsed: object, expected_count: int) -> bool:
    if not isinstance(parsed, list) or len(parsed) != expected_count:
        return False
    return all(_typename(entry) is not None for entry in parsed)


def run_graphql_batching_experiment(plan: GraphqlBatchingPlan) -> dict[str, object]:
    if not isinstance(plan, GraphqlBatchingPlan):
        raise TypeError("plan must be a GraphqlBatchingPlan")
    origin = _target_origin(plan.target_origin)

    baseline = _post(plan, origin, {"query": _BASELINE_QUERY})
    test = _post(
        plan, origin, [{"query": _BASELINE_QUERY}] * plan.batch_size,
    )
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
        elif _all_results_are_well_formed_typename_results(test_parsed, plan.batch_size):
            level, reason = "CONFIRMED_BY_INDUCTION", "BATCHING_ACCEPTED"
        elif isinstance(test_parsed, list):
            level, reason = "INCONCLUSIVE", "TEST_BATCH_RESPONSE_MALFORMED"
        else:
            level, reason = "FALSIFIED", "BATCHING_REJECTED"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-graphql-batching-exposure-differential",
        "target_origin": plan.target_origin, "method": "POST",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "endpoint_path": plan.endpoint_path, "batch_size": plan.batch_size,
        "prediction": ("If the endpoint accepts batched operations, posting a JSON array "
                        "of harmless queries returns a JSON array of that many well-formed "
                        "results."),
        "falsifier": ("The response is not an array of exactly batch_size well-formed "
                       "results -- batching is rejected, ignored, or malformed."),
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
        "blue_objective": graphql_batching_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
