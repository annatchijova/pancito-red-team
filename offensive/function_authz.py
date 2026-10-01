"""Bounded function-level authorization differential for a loopback lab."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit

from offensive.bola import BearerCredential
from offensive.purple import exercise_marker, function_authz_blue_objective


_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DENIAL = frozenset({401, 403, 404, 405})


class FunctionAuthorizationPlanError(ValueError):
    """The function-authorization experiment exceeds its strict boundary."""


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise FunctionAuthorizationPlanError(f"{name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        raise FunctionAuthorizationPlanError(f"{name} is outside its text boundary")
    return value


def _origin(value: object) -> SplitResult:
    raw = _text(value, "target_origin", 512)
    try:
        parsed, port = urlsplit(raw), urlsplit(raw).port
    except ValueError as exc:
        raise FunctionAuthorizationPlanError("target_origin is invalid") from exc
    if (parsed.scheme != "http" or parsed.username is not None or
            parsed.password is not None or not parsed.hostname or parsed.path or
            parsed.query or parsed.fragment):
        raise FunctionAuthorizationPlanError("target_origin must be an exact HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise FunctionAuthorizationPlanError("target_origin must use literal loopback") from exc
    if not address.is_loopback or not 1 <= (port or 80) <= 65_535:
        raise FunctionAuthorizationPlanError("target_origin must use valid loopback")
    return parsed


def _path(value: object, name: str) -> str:
    raw = _text(value, name, 2_048)
    parsed = urlsplit(raw)
    if (not raw.startswith("/") or raw.startswith("//") or "\\" in raw or
            "%" in raw or parsed.scheme or parsed.netloc or parsed.query or
            parsed.fragment or any(
                segment in {"", ".", ".."} for segment in raw.split("/")[1:]
            )):
        raise FunctionAuthorizationPlanError(f"{name} must be a relative path without query")
    return raw


@dataclass(frozen=True)
class FunctionAuthorizationPlan:
    experiment_id: str
    authorization_reference: str
    authorized_by: str
    operator_acknowledged: bool
    target_origin: str
    admin_path: str
    member_control_path: str
    admin_canary: str = field(repr=False)
    member_canary: str = field(repr=False)
    timeout_ms: int = 2_000
    max_response_bytes: int = 16_384

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(_text(self.experiment_id, "experiment_id", 128)):
            raise FunctionAuthorizationPlanError("experiment_id is invalid")
        _text(self.authorization_reference, "authorization_reference", 512)
        _text(self.authorized_by, "authorized_by", 256)
        if self.operator_acknowledged is not True:
            raise FunctionAuthorizationPlanError("operator_acknowledged must be literal true")
        _origin(self.target_origin)
        admin_path = _path(self.admin_path, "admin_path")
        member_path = _path(self.member_control_path, "member_control_path")
        if admin_path == member_path:
            raise FunctionAuthorizationPlanError("admin and member paths must differ")
        admin_canary = _text(self.admin_canary, "admin_canary", 256)
        member_canary = _text(self.member_canary, "member_canary", 256)
        if admin_canary == member_canary:
            raise FunctionAuthorizationPlanError("admin and member canaries must differ")
        if isinstance(self.timeout_ms, bool) or not isinstance(self.timeout_ms, int) or not 100 <= self.timeout_ms <= 10_000:
            raise FunctionAuthorizationPlanError("timeout_ms is invalid")
        if isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int) or not 1_024 <= self.max_response_bytes <= 1_048_576:
            raise FunctionAuthorizationPlanError("max_response_bytes is invalid")


@dataclass(frozen=True)
class _Observation:
    status: int | None
    body_sha256: str
    captured_bytes: int
    truncated: bool
    request_succeeded: bool
    admin_canary_observed: bool
    member_canary_observed: bool

    @property
    def redirected(self) -> bool:
        return self.status is not None and 300 <= self.status <= 399

    def public(self) -> dict[str, object]:
        return {"status": self.status, "body_sha256": self.body_sha256,
                "captured_bytes": self.captured_bytes, "truncated": self.truncated,
                "request_succeeded": self.request_succeeded, "redirected": self.redirected,
                "admin_canary_observed": self.admin_canary_observed,
                "member_canary_observed": self.member_canary_observed}


def _observe(plan, origin, path, credential, step) -> _Observation:
    connection = None
    try:
        connection = http.client.HTTPConnection(origin.hostname, origin.port or 80,
                                                timeout=plan.timeout_ms / 1_000)
        connection.request("GET", path, headers={
            "Authorization": f"Bearer {credential.token}", "Accept": "application/json",
            "User-Agent": "pancito-red-team/function-authz-lab",
            "X-Pancito-Exercise": exercise_marker(plan.experiment_id),
            "X-Pancito-Step": step,
        })
        response = connection.getresponse()
        captured = response.read(plan.max_response_bytes + 1)
        truncated = len(captured) > plan.max_response_bytes
        body = captured[:plan.max_response_bytes]
        return _Observation(response.status, "" if truncated else hashlib.sha256(body).hexdigest(),
            len(body), truncated, True, not truncated and plan.admin_canary.encode() in body,
            not truncated and plan.member_canary.encode() in body)
    except (OSError, http.client.HTTPException, TimeoutError):
        return _Observation(None, "", 0, False, False, False, False)
    finally:
        if connection is not None:
            connection.close()


def _control(item, expected: str) -> bool:
    seen = item.admin_canary_observed if expected == "admin" else item.member_canary_observed
    other = item.member_canary_observed if expected == "admin" else item.admin_canary_observed
    return bool(item.request_succeeded and item.status is not None and 200 <= item.status <= 299
                and not item.truncated and seen and not other)


def run_function_authorization_experiment(plan, *, admin, member) -> dict[str, object]:
    if not isinstance(plan, FunctionAuthorizationPlan):
        raise TypeError("plan must be a FunctionAuthorizationPlan")
    if not isinstance(admin, BearerCredential) or not isinstance(member, BearerCredential):
        raise TypeError("admin and member must be BearerCredential values")
    if admin.principal_id == member.principal_id or admin.token == member.token:
        raise FunctionAuthorizationPlanError("admin and member credentials must differ")
    if len({admin.token, member.token, plan.admin_canary, plan.member_canary}) != 4:
        raise FunctionAuthorizationPlanError("credentials and canaries must all differ")
    origin = _origin(plan.target_origin)
    admin_control = _observe(plan, origin, plan.admin_path, admin, "ADMIN_FUNCTION_CONTROL")
    member_control = _observe(plan, origin, plan.member_control_path, member, "MEMBER_FUNCTION_CONTROL")
    test = _observe(plan, origin, plan.admin_path, member, "MEMBER_ADMIN_FUNCTION_TEST")
    if not _control(admin_control, "admin"):
        level, reason = "INCONCLUSIVE", "ADMIN_CONTROL_FAILED"
    elif not _control(member_control, "member"):
        level, reason = "INCONCLUSIVE", "MEMBER_CONTROL_FAILED"
    elif not test.request_succeeded:
        level, reason = "INCONCLUSIVE", "TEST_REQUEST_FAILED"
    elif test.truncated:
        level, reason = "INCONCLUSIVE", "TEST_RESPONSE_TRUNCATED"
    elif test.redirected:
        level, reason = "INCONCLUSIVE", "TEST_REDIRECTED"
    elif test.status is not None and 200 <= test.status <= 299 and test.admin_canary_observed and not test.member_canary_observed:
        level, reason = "CONFIRMED_BY_INDUCTION", "MEMBER_OBSERVED_ADMIN_CANARY"
    elif test.status in _DENIAL and not test.admin_canary_observed:
        level, reason = "FALSIFIED", "MEMBER_ADMIN_FUNCTION_DENIED"
    else:
        level, reason = "INCONCLUSIVE", "TEST_ORACLE_NOT_SATISFIED"
    return {
        "experiment_id": plan.experiment_id, "capability": "http-function-authorization-differential",
        "target_origin": plan.target_origin, "method": "GET",
        "authorization": {"reference": plan.authorization_reference,
            "authorized_by": plan.authorized_by, "operator_acknowledged": True,
            "authentication": "UNVERIFIED_OPERATOR_ASSERTION"},
        "authorization_surface": {"actor": "AUTHENTICATED_MEMBER",
            "resource": "ADMINISTRATIVE_FUNCTION", "action": "READ"},
        "prediction": "If function-level authorization is absent, the member receives the admin canary.",
        "falsifier": "Both role controls succeed and the member is denied on the admin function.",
        "epistemic_level": level, "reason_code": reason,
        "controls": {"admin_control_passed": _control(admin_control, "admin"),
                     "member_control_passed": _control(member_control, "member")},
        "admin_control": admin_control.public(), "member_control": member_control.public(),
        "test": test.public(), "request_count": 3, "maximum_request_count": 3,
        "impact_assessment": "REQUIRES_HUMAN_CONTEXT",
        "blue_objective": function_authz_blue_objective(plan.experiment_id),
        "model_used": False, "part_of_forensic_verdict": False, "receipt_integrity": "UNSEALED",
    }
