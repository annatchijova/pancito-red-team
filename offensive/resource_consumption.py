"""Bounded differential proof for a request-rate / resource-consumption control.

This experiment answers one OWASP API4:2023 question against an authorized
loopback lab: does a control throttle request volume above an operator-declared
limit, or is the resource served without restriction?

It follows the same bounded molde as the other active experiments: a literal
loopback origin only, a positive control that must pass before any negative
cell runs, a deterministic oracle (never a model), and an UNSEALED receipt that
claims no stronger conclusion than the evidence supports. It sends no payload
and reaches no host but the authorized loopback origin, and every request is
accounted for against a hard maximum fixed in the plan — the probe is bounded by
construction, not by convention.

Mapping to the shared epistemics, matching the authz differentials:
  * CONFIRMED_BY_INDUCTION  the control is ABSENT — an over-limit burst was
                            served in full and nothing was throttled.
  * FALSIFIED               the control is PRESENT — the limit fired (HTTP 429,
                            or 503 with Retry-After) within the over-limit burst.
  * INCONCLUSIVE            the positive control did not cleanly succeed, or the
                            over-limit burst was ambiguous (a failure, a
                            truncation, a redirect, or a mix).
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import exercise_marker, resource_consumption_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
# A response that genuinely refuses the request for rate reasons. A bare 503 is
# not counted as throttling unless it carries Retry-After, so an unrelated
# server error is never mistaken for a working control.
_THROTTLE_STATUSES = frozenset({429})
# The whole experiment may never send more than this many requests, whatever a
# plan asks for. The negative cell only needs to exceed the declared limit by a
# little to be decisive; it is not a flood.
_HARD_MAX_REQUESTS = 64

WITHIN_LIMIT_STEP = "WITHIN_LIMIT_CONTROL"
OVER_LIMIT_STEP = "OVER_LIMIT_TEST"


class ResourceConsumptionPlanError(ValueError):
    """The resource-consumption experiment is ambiguous or outside its boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ResourceConsumptionPlanError(
            f"{name} must be non-empty text without outer whitespace")
    if len(value) > maximum:
        raise ResourceConsumptionPlanError(f"{name} exceeds {maximum} characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ResourceConsumptionPlanError(f"{name} contains control characters")
    return value


def _loopback_origin(value: object) -> SplitResult:
    origin = _text(value, "target_origin", 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise ResourceConsumptionPlanError(
            "target_origin is not a valid HTTP origin") from exc
    if parsed.scheme != "http":
        raise ResourceConsumptionPlanError(
            "target_origin must use HTTP for this local-lab capability")
    if parsed.username is not None or parsed.password is not None:
        raise ResourceConsumptionPlanError(
            "target_origin must not contain user information")
    if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise ResourceConsumptionPlanError(
            "target_origin must be an exact origin without path or query")
    if port is None:
        port = 80
    if not 1 <= port <= 65_535:
        raise ResourceConsumptionPlanError("target_origin port is outside the valid range")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ResourceConsumptionPlanError(
            "target_origin must use a literal loopback IP address") from exc
    if not address.is_loopback:
        raise ResourceConsumptionPlanError("target_origin must use a loopback IP address")
    return parsed


def _relative_path(value: object) -> str:
    path = _text(value, "probed_path", 2_048)
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise ResourceConsumptionPlanError("probed_path must be a relative HTTP path")
    return path


def _bounded_count(value: object, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResourceConsumptionPlanError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ResourceConsumptionPlanError(
            f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class ResourceConsumptionPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    probed_path: str
    success_canary: str = field(repr=False)
    declared_limit: int = 1
    control_requests: int = 1
    probe_requests: int = 2
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        experiment_id = _text(self.experiment_id, "experiment_id", 128)
        if not _ID_RE.fullmatch(experiment_id):
            raise ResourceConsumptionPlanError(
                "experiment_id must match [A-Za-z0-9._-]{1,128}")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise ResourceConsumptionPlanError("operator_acknowledged must be literal true")
        _loopback_origin(self.target_origin)
        _relative_path(self.probed_path)
        _text(self.success_canary, "success_canary", 256)
        # The declared limit is the control the operator says should exist; the
        # control burst must stay within it and the probe burst must exceed it,
        # so the two cells sit on opposite sides of the threshold.
        _bounded_count(self.declared_limit, "declared_limit",
                       minimum=1, maximum=_HARD_MAX_REQUESTS - 1)
        _bounded_count(self.control_requests, "control_requests",
                       minimum=1, maximum=_HARD_MAX_REQUESTS - 1)
        _bounded_count(self.probe_requests, "probe_requests",
                       minimum=2, maximum=_HARD_MAX_REQUESTS - 1)
        if self.control_requests > self.declared_limit:
            raise ResourceConsumptionPlanError(
                "control_requests must not exceed the declared limit")
        if self.probe_requests <= self.declared_limit:
            raise ResourceConsumptionPlanError(
                "probe_requests must exceed the declared limit to test it")
        if self.control_requests + self.probe_requests > _HARD_MAX_REQUESTS:
            raise ResourceConsumptionPlanError(
                f"total requests must not exceed {_HARD_MAX_REQUESTS}")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int):
            raise ResourceConsumptionPlanError("timeout_ms must be an integer")
        if not 100 <= self.timeout_ms <= 10_000:
            raise ResourceConsumptionPlanError("timeout_ms must be between 100 and 10000")
        if (isinstance(self.max_response_bytes, bool)
                or not isinstance(self.max_response_bytes, int)):
            raise ResourceConsumptionPlanError("max_response_bytes must be an integer")
        if not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise ResourceConsumptionPlanError(
                "max_response_bytes must be between 1024 and 1048576")

    @property
    def maximum_request_count(self) -> int:
        return self.control_requests + self.probe_requests


@dataclass(frozen=True)
class _Observation:
    status: int | None
    captured_bytes: int
    truncated: bool
    request_succeeded: bool
    retry_after_present: bool
    success_canary_observed: bool

    @property
    def redirected(self) -> bool:
        return self.status is not None and 300 <= self.status <= 399

    @property
    def throttled(self) -> bool:
        if self.status in _THROTTLE_STATUSES:
            return True
        return self.status == 503 and self.retry_after_present

    @property
    def served(self) -> bool:
        return bool(
            self.request_succeeded
            and self.status is not None
            and 200 <= self.status <= 299
            and not self.truncated
            and self.success_canary_observed
        )


def _request(
    plan: ResourceConsumptionPlan,
    parsed_origin: SplitResult,
    *,
    step: str,
    bearer: str | None,
) -> _Observation:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(
            parsed_origin.hostname,
            parsed_origin.port or 80,
            timeout=plan.timeout_ms / 1_000,
        )
        headers = {
            "Accept": "application/json",
            "User-Agent": "pancito-red-team/resource-consumption-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "X-Pancito-Step": step,
        }
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        connection.request("GET", plan.probed_path, headers=headers)
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[: plan.max_response_bytes]
        return _Observation(
            status=response.status,
            captured_bytes=len(body),
            truncated=truncated,
            request_succeeded=True,
            retry_after_present=response.getheader("Retry-After") is not None,
            success_canary_observed=(
                not truncated and plan.success_canary.encode("utf-8") in body),
        )
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(
            status=None,
            captured_bytes=0,
            truncated=False,
            request_succeeded=False,
            retry_after_present=False,
            success_canary_observed=False,
        )
    finally:
        if connection is not None:
            connection.close()


def _burst(
    plan: ResourceConsumptionPlan,
    parsed_origin: SplitResult,
    *,
    step: str,
    bearer: str,
    count: int,
) -> list[_Observation]:
    # Sequential, not concurrent: one request at a time against loopback, each
    # fully read and closed before the next. This probes for a control, it does
    # not try to overwhelm the target.
    return [
        _request(plan, parsed_origin, step=step, bearer=bearer)
        for _ in range(count)
    ]


def _summarize(observations: list[_Observation]) -> dict[str, object]:
    return {
        "requests": len(observations),
        "served_count": sum(1 for item in observations if item.served),
        "throttled_count": sum(1 for item in observations if item.throttled),
        "failed_count": sum(1 for item in observations if not item.request_succeeded),
        "truncated_count": sum(1 for item in observations if item.truncated),
        "redirected_count": sum(1 for item in observations if item.redirected),
        "statuses": sorted({item.status for item in observations
                            if item.status is not None}),
    }


def _probe_ambiguity(observations: list[_Observation]) -> str | None:
    if any(not item.request_succeeded for item in observations):
        return "OVER_LIMIT_TEST_REQUEST_FAILED"
    if any(item.truncated for item in observations):
        return "OVER_LIMIT_TEST_RESPONSE_TRUNCATED"
    if any(item.redirected for item in observations):
        return "OVER_LIMIT_TEST_REDIRECTED"
    if not all(item.served for item in observations):
        return "OVER_LIMIT_TEST_ORACLE_NOT_SATISFIED"
    return None


def run_resource_consumption_experiment(
    plan: ResourceConsumptionPlan, *, valid: BearerCredential
) -> dict[str, object]:
    """Run one within-limit positive control and one bounded over-limit cell."""
    if not isinstance(plan, ResourceConsumptionPlan):
        raise TypeError("plan must be a ResourceConsumptionPlan")
    if not isinstance(valid, BearerCredential):
        raise TypeError("valid must be a BearerCredential")
    if valid.token == plan.success_canary:
        raise ResourceConsumptionPlanError(
            "valid token and success canary must be distinct")
    parsed_origin = _loopback_origin(plan.target_origin)

    control = _burst(plan, parsed_origin, step=WITHIN_LIMIT_STEP,
                     bearer=valid.token, count=plan.control_requests)
    control_served = all(item.served for item in control)
    control_throttled = any(item.throttled for item in control)

    probe: list[_Observation] = []
    if not control_served or control_throttled:
        epistemic_level = "INCONCLUSIVE"
        reason_code = (
            "THROTTLED_WITHIN_DECLARED_LIMIT" if control_throttled
            else "WITHIN_LIMIT_CONTROL_FAILED")
    else:
        probe = _burst(plan, parsed_origin, step=OVER_LIMIT_STEP,
                       bearer=valid.token, count=plan.probe_requests)
        if any(item.throttled for item in probe):
            epistemic_level = "FALSIFIED"
            reason_code = "RATE_LIMIT_ENFORCED_ABOVE_DECLARED_LIMIT"
        elif all(item.served for item in probe):
            epistemic_level = "CONFIRMED_BY_INDUCTION"
            reason_code = "NO_THROTTLING_ABOVE_DECLARED_LIMIT"
        else:
            epistemic_level = "INCONCLUSIVE"
            reason_code = _probe_ambiguity(probe) or "OVER_LIMIT_TEST_ORACLE_NOT_SATISFIED"

    return {
        "experiment_id": plan.experiment_id,
        "capability": "http-resource-consumption-differential",
        "target_origin": plan.target_origin,
        "method": "GET",
        "authorization": {
            "reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by,
            "operator_acknowledged": plan.operator_acknowledged,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION",
        },
        "prediction": (
            "If no resource-consumption control is enforced, a bounded burst "
            "above the declared limit is served in full and nothing is throttled."
        ),
        "falsifier": (
            "A within-limit control that is served cleanly followed by at least "
            "one throttled response in the over-limit burst falsifies the "
            "candidate: the limit is enforced."
        ),
        "declared_limit": plan.declared_limit,
        "request_count": len(control) + len(probe),
        "maximum_request_count": plan.maximum_request_count,
        "epistemic_level": epistemic_level,
        "reason_code": reason_code,
        "within_limit_control_passed": control_served and not control_throttled,
        "within_limit_control": _summarize(control),
        "over_limit_test": _summarize(probe),
        "blue_objective": resource_consumption_blue_objective(plan.experiment_id),
        "model_used": False,
        "part_of_forensic_verdict": False,
        "receipt_integrity": "UNSEALED",
    }
